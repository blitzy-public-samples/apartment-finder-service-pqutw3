"""Regression tests for the rate limiter's bounded in-process storage.

The credential endpoints are limited per remote address, so the number of
counters the limiter holds follows the number of distinct addresses seen
inside a window -- a quantity no caller is obliged to keep small. The
only thing standing between that and unbounded process memory is the
eviction machinery in :mod:`backend.app.core.rate_limit`, which the rest
of the suite never drives: every other module reaches the limiter through
the application, whose configured ceiling of 4096 tracked keys no test
approaches.

Each case here therefore constructs the storage directly with a small
ceiling and drives it past that ceiling, so the machinery runs. What is
asserted:

* a store inside its ceiling evicts nothing, so eviction is a response to
  overflow rather than something that happens on every hit
* the first response to overflow is to drop the keys whose windows have
  already closed, and a key whose window is still open survives that pass
* when dropping closed windows is not enough, the keys closest to closing
  are the ones evicted, and the ones furthest from closing are the ones
  kept, down to :data:`RETAINED_KEY_RATIO` of the ceiling
* a counter carrying no window at all is bounded by the same pass, and a
  counter that does carry one is not evicted by that pass
* moving-window entries are bounded by key alongside the counters
* the ceiling itself comes from ``RATE_LIMIT_MAX_TRACKED_KEYS`` and an
  unusable per-instance override falls back to it rather than to no
  ceiling at all
* the window reset header a refused caller reads is a whole number of
  seconds, and a response carrying no such header or a value that is not
  a number is left as it is rather than raising

The counts asserted are derived from the ceiling each case configures and
from :data:`RETAINED_KEY_RATIO`, not written as literals, so a change to
either is reported here rather than passing against a stale copy.

None of these cases touches the application's own limiter: each builds
its own storage instance, and the two that exercise the header path build
their own response object.
"""

import time

import pytest
from starlette.responses import Response

from backend.app.core.config import (
    BOUNDED_MEMORY_SCHEME,
    IN_PROCESS_RATE_LIMIT_SCHEMES,
    settings,
)
from backend.app.core.rate_limit import (
    FALLBACK_CLIENT_ADDRESS,
    FORWARDED_FOR_HEADER,
    RATE_LIMIT_RESET_HEADER,
    RETAINED_KEY_RATIO,
    BoundedMemoryStorage,
    HeaderWritingLimiter,
    _resolve_key_cap,
    build_limiter,
    client_address,
)

#: Ceiling each store under test is built with. It is small enough that a
#: case can carry a store past it in a handful of statements, and large
#: enough that the retained share is more than one key.
CEILING = 8

#: Keys a store holds once an eviction pass has completed, derived the
#: way the module derives it.
RETAINED = int(CEILING * RETAINED_KEY_RATIO)

#: Seconds a window is opened for when the case wants it to stay open for
#: the duration of that case.
OPEN_WINDOW = 300.0

#: Seconds a window is opened for when the case wants it already closed.
#: The store compares the deadline against the wall clock, so a negative
#: expiry is a window that closed before it was recorded.
CLOSED_WINDOW = -1.0


@pytest.fixture
def store():
    """Yields a bounded store holding at most :data:`CEILING` keys."""
    instance = BoundedMemoryStorage(max_tracked_keys=CEILING)
    try:
        yield instance
    finally:
        instance.reset()


def fill(store, count, expiry=OPEN_WINDOW, prefix="key"):
    """Counts one hit against ``count`` distinct keys and returns them."""
    keys = ["%s-%03d" % (prefix, index) for index in range(count)]
    for key in keys:
        store.incr(key, expiry)
    return keys


class TestTheCeilingIsRead:
    """The ceiling comes from configuration, with a usable override."""

    def test_the_configured_ceiling_is_the_default(self):
        instance = BoundedMemoryStorage()
        try:
            assert instance.max_tracked_keys == int(
                settings.RATE_LIMIT_MAX_TRACKED_KEYS
            )
        finally:
            instance.reset()

    def test_a_positive_override_is_used(self, store):
        assert store.max_tracked_keys == CEILING

    @pytest.mark.parametrize(
        "override",
        [
            pytest.param(None, id="absent"),
            pytest.param("not-a-number", id="not_numeric"),
            pytest.param("", id="empty"),
            pytest.param(0, id="zero"),
            pytest.param(-16, id="negative"),
            pytest.param(object(), id="not_a_number_at_all"),
        ],
    )
    def test_an_unusable_override_falls_back_to_the_configuration(
        self, override
    ):
        """An unusable override never means "no ceiling"."""
        assert _resolve_key_cap(override) == int(
            settings.RATE_LIMIT_MAX_TRACKED_KEYS
        )

    def test_a_numeric_string_override_is_accepted(self):
        assert _resolve_key_cap(str(CEILING)) == CEILING

    def test_the_store_registers_the_scheme_the_settings_name(self):
        assert BOUNDED_MEMORY_SCHEME in BoundedMemoryStorage.STORAGE_SCHEME
        assert BOUNDED_MEMORY_SCHEME in IN_PROCESS_RATE_LIMIT_SCHEMES

    def test_the_base_sweep_timer_is_cancelled(self, store):
        """The inherited sweep is replaced rather than left running."""
        timer = getattr(store, "timer", None)
        assert timer is None or not timer.is_alive()


class TestAStoreInsideItsCeilingEvictsNothing:
    """Eviction answers overflow; it is not part of every hit."""

    def test_every_key_is_kept_at_the_ceiling(self, store):
        keys = fill(store, CEILING)

        assert len(store.storage) == CEILING
        for key in keys:
            assert store.get(key) == 1

    def test_a_repeated_hit_accumulates_rather_than_evicting(self, store):
        store.incr("caller", OPEN_WINDOW)
        store.incr("caller", OPEN_WINDOW)

        assert store.get("caller") == 2
        assert len(store.storage) == 1


class TestOverflowDropsClosedWindowsFirst:
    """The keys whose windows have closed are the first to go."""

    def test_closed_windows_go_and_an_open_window_survives(self, store):
        survivor = "still-open"
        store.incr(survivor, OPEN_WINDOW)
        fill(store, CEILING, expiry=CLOSED_WINDOW, prefix="closed")

        assert len(store.storage) <= store.max_tracked_keys
        assert store.get(survivor) == 1
        assert store.storage.get(survivor) == 1

    def test_a_closed_window_is_not_reported_as_a_count(self, store):
        store.incr("closed", CLOSED_WINDOW)
        fill(store, CEILING, prefix="open")

        assert store.get("closed") == 0
        assert "closed" not in store.expirations

    def test_dropping_closed_windows_is_enough_on_its_own(self, store):
        """No open window is evicted while closed ones can be dropped."""
        open_keys = fill(store, RETAINED, prefix="open")
        fill(store, CEILING, expiry=CLOSED_WINDOW, prefix="closed")

        for key in open_keys:
            assert store.storage.get(key) == 1


class TestOverflowEvictsTheKeysNearestToClosing:
    """When closed windows are not enough, soonest-to-close goes first."""

    def test_the_store_returns_to_the_retained_share(self, store):
        fill(store, CEILING + 1)

        assert len(store.storage) <= RETAINED
        assert len(store.expirations) <= RETAINED
        assert RETAINED >= 1

    def test_the_windows_furthest_from_closing_are_the_ones_kept(
        self, store
    ):
        """Each key's window is opened further out than the last."""
        keys = []
        for index in range(CEILING + 1):
            key = "window-%03d" % index
            store.incr(key, OPEN_WINDOW + index)
            keys.append(key)

        kept = set(store.storage)
        assert kept, "the pass evicted every key"
        assert kept <= set(keys[-RETAINED:])
        for key in keys[: CEILING + 1 - RETAINED]:
            assert key not in kept

    def test_a_pass_leaves_at_least_one_key(self):
        """A ceiling of one still keeps the key that just arrived."""
        instance = BoundedMemoryStorage(max_tracked_keys=1)
        try:
            instance.incr("first", OPEN_WINDOW)
            instance.incr("second", OPEN_WINDOW)

            assert len(instance.storage) >= 1
            assert len(instance.storage) <= 1
        finally:
            instance.reset()


class TestCountersCarryingNoWindowAreBounded:
    """A counter with no expiry is bounded by the same pass."""

    def test_untracked_counters_are_evicted(self, store):
        for index in range(CEILING * 2):
            store.storage["untracked-%03d" % index] += 1
        store.incr("tracked", OPEN_WINDOW)

        assert len(store.storage) <= RETAINED

    def test_a_tracked_counter_survives_the_untracked_pass(self, store):
        store.incr("tracked", OPEN_WINDOW)
        for index in range(CEILING * 2):
            store.storage["untracked-%03d" % index] += 1
        store.incr("tracked", OPEN_WINDOW)

        assert store.storage.get("tracked") == 2
        assert len(store.storage) <= RETAINED


class TestMovingWindowEntriesAreBounded:
    """Moving-window entries are bounded by key alongside counters."""

    def test_the_event_keys_return_to_the_retained_share(self, store):
        for index in range(CEILING * 2):
            store.acquire_entry(
                "moving-%03d" % index, limit=2, expiry=int(OPEN_WINDOW)
            )
        assert len(store.events) == CEILING * 2

        store.incr("counter", OPEN_WINDOW)

        assert len(store.events) <= RETAINED

    def test_an_entry_is_still_acquired_while_inside_the_limit(
        self, store
    ):
        assert (
            store.acquire_entry(
                "moving", limit=2, expiry=int(OPEN_WINDOW)
            )
            is True
        )
        assert store.get_num_acquired("moving", int(OPEN_WINDOW)) == 1


class TestTheWindowResetHeaderIsAWholeNumber:
    """A refused caller reads seconds, not a fraction of one."""

    @staticmethod
    def _written(value):
        """Returns the reset header after the limiter has written it."""
        response = Response()
        if value is not None:
            response.headers[RATE_LIMIT_RESET_HEADER] = value
        limiter = HeaderWritingLimiter(key_func=lambda request: "test")
        limiter._inject_headers(response, None)
        return response.headers.get(RATE_LIMIT_RESET_HEADER)

    def test_a_fractional_reading_is_rewritten_as_seconds(self):
        assert self._written("1767225600.482") == "1767225600"

    def test_a_whole_number_is_left_as_it_is(self):
        assert self._written("1767225600") == "1767225600"

    def test_a_value_that_is_not_a_number_is_left_as_it_is(self):
        assert self._written("soon") == "soon"

    def test_an_absent_header_is_not_invented(self):
        assert self._written(None) is None

    def test_a_call_carrying_no_response_is_left_untouched(self):
        """The limiter is handed ``None`` for a call it admitted."""
        limiter = HeaderWritingLimiter(key_func=lambda request: "test")

        assert limiter._inject_headers(None, None) is None


class TestTheApplicationLimiterUsesTheBoundedStore:
    """The store under test is the one the application is built with."""

    def test_the_built_limiter_names_the_configured_store(self):
        limiter = build_limiter()

        assert isinstance(limiter, HeaderWritingLimiter)
        assert limiter._storage_uri == settings.RATE_LIMIT_STORAGE_URI

    def test_the_built_store_carries_the_configured_ceiling(self):
        limiter = build_limiter()
        storage = limiter._storage

        assert isinstance(storage, BoundedMemoryStorage)
        assert storage.max_tracked_keys == int(
            settings.RATE_LIMIT_MAX_TRACKED_KEYS
        )

    def test_the_configured_ceiling_is_a_positive_whole_number(self):
        assert int(settings.RATE_LIMIT_MAX_TRACKED_KEYS) > 0


class TestEvictionCostsDoNotFollowTheNumberOfKeys:
    """A hit does not sweep every tracked key."""

    def test_a_hit_inside_the_ceiling_reads_one_key(self, store):
        fill(store, CEILING - 1)
        opened = dict(store.expirations)

        store.incr("one-more", OPEN_WINDOW)

        for key, deadline in opened.items():
            assert store.expirations[key] == deadline

    def test_a_window_still_open_is_reported_until_it_closes(self, store):
        store.incr("open", OPEN_WINDOW)

        assert store.get_expiry("open") > time.time()
        assert store.get("open") == 1


def _request(peer=None, forwarded=None):
    """Returns a request carrying ``peer`` and ``forwarded``.

    The scope is the minimum a ``Request`` needs to report a client and a
    header, so the cases drive the real object rather than a stand-in for
    it.
    """
    from starlette.requests import Request

    headers = []
    if forwarded is not None:
        headers.append(
            (FORWARDED_FOR_HEADER.lower().encode(), forwarded.encode())
        )
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/auth/login",
        "headers": headers,
        "client": None if peer is None else (peer, 51234),
    }
    return Request(scope)


class TestTheAddressARequestIsCountedAgainst:
    """The counter key is the caller, and the caller cannot choose it.

    Behind proxies of our own the peer address is the innermost proxy, so
    counting against it puts every caller in one bucket and lets one
    caller exhaust the limit for all of them. Reading the forwarded chain
    without bounding it has the opposite failure: the caller writes the
    header and takes a fresh bucket per request. The hop count resolves
    both, and these cases assert each direction.
    """

    def test_no_hops_reads_the_peer_address(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 0)

        assert client_address(_request(peer="203.0.113.7")) == (
            "203.0.113.7"
        )

    def test_no_hops_ignores_the_forwarded_header_entirely(
        self, monkeypatch
    ):
        """A caller writing the header changes nothing while hops are 0."""
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 0)

        resolved = client_address(
            _request(peer="203.0.113.7", forwarded="198.51.100.23")
        )

        assert resolved == "203.0.113.7"

    def test_one_hop_reads_the_entry_the_proxy_wrote(self, monkeypatch):
        """The rightmost entry is the peer our own proxy accepted."""
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 1)

        resolved = client_address(
            _request(peer="10.0.0.9", forwarded="198.51.100.23")
        )

        assert resolved == "198.51.100.23"

    def test_one_hop_ignores_an_address_the_caller_prepended(
        self, monkeypatch
    ):
        """A spoofed entry sits left of the one the proxy wrote.

        This is the shape of the attack: the caller sends the header
        itself, and the proxy appends the address it actually accepted the
        connection from. Counting from the right-hand end reads the
        proxy's entry, so the spoofed value changes no key.
        """
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 1)

        spoofed = client_address(
            _request(
                peer="10.0.0.9",
                forwarded="192.0.2.1, 198.51.100.23",
            )
        )
        honest = client_address(
            _request(peer="10.0.0.9", forwarded="198.51.100.23")
        )

        assert spoofed == honest == "198.51.100.23"

    def test_two_hops_read_two_entries_from_the_end(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 2)

        resolved = client_address(
            _request(
                peer="10.0.0.9",
                forwarded="198.51.100.23, 10.0.1.4",
            )
        )

        assert resolved == "198.51.100.23"

    def test_a_shared_proxy_does_not_put_every_caller_in_one_bucket(
        self, monkeypatch
    ):
        """Two callers behind one proxy resolve to two different keys.

        Without the hop count both requests report the proxy's address and
        share a counter, which is the defect: one caller's traffic refuses
        the other's.
        """
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 1)

        first = client_address(
            _request(peer="10.0.0.9", forwarded="198.51.100.23")
        )
        second = client_address(
            _request(peer="10.0.0.9", forwarded="198.51.100.24")
        )

        assert first != second

        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 0)

        assert client_address(
            _request(peer="10.0.0.9", forwarded="198.51.100.23")
        ) == client_address(
            _request(peer="10.0.0.9", forwarded="198.51.100.24")
        )

    def test_a_chain_shorter_than_the_hop_count_falls_back(
        self, monkeypatch
    ):
        """A truncated chain narrows the identity rather than widening it."""
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 3)

        resolved = client_address(
            _request(peer="10.0.0.9", forwarded="198.51.100.23")
        )

        assert resolved == "10.0.0.9"

    def test_an_absent_header_falls_back_to_the_peer(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 1)

        assert client_address(_request(peer="10.0.0.9")) == "10.0.0.9"

    @pytest.mark.parametrize(
        "forwarded",
        [
            "not-an-address",
            "example.com",
            "999.999.999.999",
            "  ",
            "<script>",
            "198.51.100.23; DROP",
        ],
    )
    def test_an_entry_that_is_not_an_address_falls_back(
        self, monkeypatch, forwarded
    ):
        """Only an IP address may become a counter key."""
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 1)

        assert client_address(
            _request(peer="10.0.0.9", forwarded=forwarded)
        ) == "10.0.0.9"

    @pytest.mark.parametrize(
        "written,expected",
        [
            ("198.51.100.23", "198.51.100.23"),
            ("198.51.100.23:41234", "198.51.100.23"),
            ("2001:db8::1", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("[2001:db8::1]:41234", "2001:db8::1"),
            (" 198.51.100.23 ", "198.51.100.23"),
        ],
    )
    def test_every_form_a_proxy_writes_is_reduced_to_the_address(
        self, monkeypatch, written, expected
    ):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 1)

        assert client_address(
            _request(peer="10.0.0.9", forwarded=written)
        ) == expected

    def test_a_connection_reporting_no_peer_is_still_counted(
        self, monkeypatch
    ):
        """An unidentifiable caller gets a key rather than no key.

        Returning nothing would leave the request uncounted, so a fixed
        key is used and such requests are limited together.
        """
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 0)

        assert client_address(_request()) == FALLBACK_CLIENT_ADDRESS

    def test_the_default_hop_count_reads_no_forwarded_header(self):
        """The shipped default is the one a caller cannot influence."""
        assert settings.__fields__["TRUSTED_PROXY_HOPS"].default == 0

    def test_the_limiter_is_keyed_by_that_function(self):
        """The application's limiter uses this resolution, not the peer."""
        assert build_limiter()._key_func is client_address
