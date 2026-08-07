"""Rate-limit storage with bounded state, and the limiter factory.

The credential endpoints are rate limited per remote address, so the
number of counters the limiter holds follows the number of distinct
addresses seen inside a window -- a quantity no client is required to
keep small. This module supplies the storage that bounds it and the
factory that builds the limiter against the configured store.

:class:`BoundedMemoryStorage` registers the
``bounded-memory`` scheme and holds its counters in this process. It caps
the number of tracked keys at ``settings.RATE_LIMIT_MAX_TRACKED_KEYS``:
once a hit carries the count past the cap, the keys whose windows have
already closed are dropped and, if that is not enough, the keys closest
to closing are evicted until the count is back under
:data:`RETAINED_KEY_RATIO` of the cap. The counter dictionary, the
per-key lock dictionary, the expiry dictionary and the moving-window
event dictionary are each covered, so the memory the limiter holds has a
ceiling that does not depend on how many addresses call.

The increment path also replaces the one the standard in-memory storage
provides, which schedules a sweep of every tracked key roughly every
10 milliseconds while traffic continues. Expiry here is driven by the
read path and by the capped sweep instead, so the cost of a hit does not
follow the number of keys held.

:func:`build_limiter` reads ``settings.RATE_LIMIT_STORAGE_URI``, which
accepts any scheme in
:data:`backend.app.core.config.RATE_LIMIT_STORAGE_SCHEMES`. A scheme
listed in :data:`backend.app.core.config.IN_PROCESS_RATE_LIMIT_SCHEMES`
counts inside one process, so several processes or replicas each keep
their own counters; one record naming the setting is emitted when such a
store is configured outside a local environment.

Usage::

    from backend.app.core.rate_limit import build_limiter

    limiter = build_limiter()
"""

import time
from typing import Any, Optional, Union

from limits.storage import MemoryStorage
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.app.core.config import (
    BOUNDED_MEMORY_SCHEME,
    IN_PROCESS_RATE_LIMIT_SCHEMES,
    LOCAL_ENVIRONMENT,
    rate_limit_storage_scheme,
    settings,
)
from backend.app.core.logging import get_logger

__all__ = [
    "IN_PROCESS_STORE_MESSAGE",
    "RETAINED_KEY_RATIO",
    "BoundedMemoryStorage",
    "build_limiter",
]

logger = get_logger(__name__)

#: Share of the key cap kept after an eviction pass, so the pass runs
#: once per batch of new keys rather than once per hit.
RETAINED_KEY_RATIO = 0.9

#: Message recorded when the configured store counts inside one process.
IN_PROCESS_STORE_MESSAGE = (
    "Rate-limit counters are held in this process, so each process "
    "counts separately"
)

# Smallest number of keys an eviction pass leaves in place.
_MIN_RETAINED_KEYS = 1


class BoundedMemoryStorage(MemoryStorage):
    """In-process rate-limit storage with a ceiling on tracked keys.

    Registered under the ``bounded-memory`` scheme, so
    ``storage_uri="bounded-memory://"`` selects it. The cap is read from
    ``settings.RATE_LIMIT_MAX_TRACKED_KEYS`` and may be overridden per
    instance with the ``max_tracked_keys`` storage option.
    """

    STORAGE_SCHEME = [BOUNDED_MEMORY_SCHEME]

    def __init__(
        self,
        uri: Optional[str] = None,
        wrap_exceptions: bool = False,
        **options: Union[float, str, bool]
    ) -> None:
        self.max_tracked_keys = _resolve_key_cap(
            options.pop("max_tracked_keys", None)
        )
        super().__init__(uri, wrap_exceptions=wrap_exceptions, **options)
        # The base class starts one sweep timer while constructing. The
        # capped sweep below replaces it.
        timer = getattr(self, "timer", None)
        if timer is not None:
            timer.cancel()

    def incr(
        self,
        key: str,
        expiry: float,
        elastic_expiry: bool = False,
        amount: int = 1,
    ) -> int:
        """Count ``amount`` hits against ``key`` and return the total.

        ``key`` is read first, which drops it when its window has already
        closed, and the window is stamped on the hit that opens it. The
        capped sweep runs afterwards.
        """
        self.get(key)
        with self.locks[key]:
            self.storage[key] += amount
            if elastic_expiry or self.storage[key] == amount:
                self.expirations[key] = time.time() + expiry
        self._bound_tracked_keys()
        return self.storage.get(key, 0)

    def _bound_tracked_keys(self) -> None:
        """Brings the number of tracked keys back under the cap.

        Does nothing while every dictionary sits within the cap. Once one
        does not, keys whose windows have closed are dropped first, and
        the keys closest to closing are evicted after that.
        """
        cap = self.max_tracked_keys
        if (
            len(self.expirations) <= cap
            and len(self.storage) <= cap
            and len(self.events) <= cap
        ):
            return
        retained = max(
            _MIN_RETAINED_KEYS, int(cap * RETAINED_KEY_RATIO)
        )
        with self.lock:
            self._drop_closed_windows()
            self._evict_nearest_expiry(retained)
            self._evict_untracked(retained)
            self._evict_events(retained)

    def _drop_closed_windows(self) -> None:
        """Clears every key whose window has already closed."""
        now = time.time()
        for key, deadline in list(self.expirations.items()):
            if deadline <= now:
                self.clear(key)

    def _evict_nearest_expiry(self, retained: int) -> None:
        """Clears the keys closest to closing, down to ``retained``."""
        overflow = len(self.expirations) - retained
        if overflow <= 0:
            return
        ordered = sorted(
            self.expirations.items(), key=lambda entry: entry[1]
        )
        for key, _ in ordered[:overflow]:
            self.clear(key)

    def _evict_untracked(self, retained: int) -> None:
        """Clears counters that carry no window, down to ``retained``."""
        if len(self.storage) <= retained:
            return
        for key in list(self.storage):
            if len(self.storage) <= retained:
                return
            if key not in self.expirations:
                self.clear(key)

    def _evict_events(self, retained: int) -> None:
        """Clears moving-window entries, down to ``retained`` keys."""
        overflow = len(self.events) - retained
        if overflow <= 0:
            return
        for key in list(self.events)[:overflow]:
            self.clear(key)


def _resolve_key_cap(override: Any) -> int:
    """Return the number of keys one storage instance may track.

    ``override`` is the ``max_tracked_keys`` storage option when one was
    supplied. A value that is not a positive whole number falls back to
    ``settings.RATE_LIMIT_MAX_TRACKED_KEYS``.
    """
    configured = int(settings.RATE_LIMIT_MAX_TRACKED_KEYS)
    if override is None:
        return configured
    try:
        candidate = int(override)
    except (TypeError, ValueError):
        return configured
    return candidate if candidate > 0 else configured


def build_limiter() -> Limiter:
    """Return the limiter the credential endpoints are decorated against.

    The limiter is keyed by remote address and counts in the store named
    by ``settings.RATE_LIMIT_STORAGE_URI``. One record naming the setting
    is emitted when that store counts inside a single process outside a
    local environment.
    """
    storage_uri = settings.RATE_LIMIT_STORAGE_URI
    scheme = rate_limit_storage_scheme(storage_uri)
    if (
        scheme in IN_PROCESS_RATE_LIMIT_SCHEMES
        and settings.ENVIRONMENT != LOCAL_ENVIRONMENT
    ):
        logger.warning(
            IN_PROCESS_STORE_MESSAGE,
            extra={
                "setting": "RATE_LIMIT_STORAGE_URI",
                "scheme": scheme,
                "environment": settings.ENVIRONMENT,
                "max_tracked_keys": (
                    settings.RATE_LIMIT_MAX_TRACKED_KEYS
                ),
            },
        )
    return Limiter(key_func=get_remote_address, storage_uri=storage_uri)
