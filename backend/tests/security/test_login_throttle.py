"""Regression tests for SEC-07, the login throttle.

Failed logins answer 401 up to the configured threshold and 429 beyond
it, so repeated credential guessing against one account is bounded. The
throttled reply carries the sanitized error envelope, and the server
records the attempt under the correlation identifier the caller
receives.

The account counter keys on the normalized email address, and a
successful login empties that counter.

Two further layers are exercised here. The counter map is bounded, so a
flood of distinct addresses cannot exhaust memory and cannot drop a
lockout to make room; those cases address the reservation function
directly, because the bound is reached below the HTTP layer. And the
limiter the application registers is proven to be the one the harness
empties, with its rejection driven through the app so the handler that
answers it is under test.
"""
import logging
import time

import pytest
from conftest import reset_login_throttle
from limits import parse as parse_rate_limit
from limits.storage import MemoryStorage
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from slowapi.wrappers import Limit

from backend.app.api.endpoints import auth as auth_endpoint
from backend.app.core.config import settings
from backend.app.db.database import get_db
from backend.app.main import (
    _error_envelope,
    app,
    logger as application_logger,
)

LOGIN_PATH = "/auth/login"
REGISTER_PATH = "/auth/register"

# A secret no account registered in this module holds.
WRONG_SECRET = "Nqz7!Bmtlie-Ovsxa"

# A register body the request schema rejects on both fields.
MALFORMED_ADDRESS = "not-an-address"
UNUSABLE_SECRET = "tiny"

# SEC-08: the error envelope backend/app/main.py builds, read from the
# application itself
ENVELOPE_KEYS = frozenset(_error_envelope("a detail", "a correlation id"))

# SEC-08: the correlation key, located by the value it carries
_CORRELATION_PROBE = "correlation-key-probe"
CORRELATION_KEY = next(
    key
    for key, value in _error_envelope("a detail", _CORRELATION_PROBE).items()
    if value == _CORRELATION_PROBE
)

# Text naming the component that answered, or the stock limiter body.
FORBIDDEN_IN_BODY = (
    "Traceback",
    "slowapi",
    "Limiter",
    "AccountThrottled",
    "RateLimitExceeded",
    "sqlalchemy",
    "SQLAlchemy",
    ".py",
    "Rate limit exceeded",
)

# The uniform detail backend/app/api/endpoints/auth.py raises for an
# unknown address and for a wrong secret alike.
UNIFORM_LOGIN_DETAIL = "Incorrect email or password"

# SEC-07: the configured limit written in the notation the limiter
# parses, so the rejection driven below carries the real threshold
CONFIGURED_LIMIT = "{0}/{1} minute".format(
    settings.LOGIN_RATE_LIMIT_ATTEMPTS,
    settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES,
)

# SEC-07: a limiter storage key no route writes, so its presence and
# absence are attributable to this module alone
LIMITER_PROBE_KEY = "harness-limiter-probe"

# SEC-07: an account key no route writes, seeded to observe the prune
UNRELATED_ACCOUNT_KEY = "acct:unrelated-probe@example.com"

# SEC-07: the smallest cap that still admits one full attempt, which
# writes one account key and one address key
PROBE_CAP = 3

# SEC-07: addresses used only by the counter-cap cases; no account is
# registered for them, so every attempt is a credential failure
CAP_PROBE_EMAILS = (
    "cap-probe-1@example.com",
    "cap-probe-2@example.com",
    "cap-probe-3@example.com",
)

# SEC-07: keys standing in for other accounts under attack while the
# cap cases run; the reservation call never names them
LOCKED_KEYS = (
    "acct:locked-1@example.com",
    "acct:locked-2@example.com",
)
EVICTABLE_KEY = "acct:evictable@example.com"
RESERVED_ACCOUNT_KEY = "acct:reserved@example.com"
RESERVED_ADDRESS_KEY = "addr:reserved-probe"


def _limiter_rejection():
    """Build the rejection slowapi raises when a route limit is hit."""
    # SEC-07: the real exception the registered handler is keyed on. Its
    # stock detail spells the threshold and the window, so it is also
    # the input that proves the sanitized envelope withholds them.
    limit = Limit(
        limit=parse_rate_limit(CONFIGURED_LIMIT),
        key_func=get_remote_address,
        scope=None,
        per_method=False,
        methods=None,
        error_message=None,
        exempt_when=None,
        cost=1,
        override_defaults=False,
    )
    return RateLimitExceeded(limit)


@pytest.fixture
def limiter_refuses_every_request():
    """Make every request raise the limiter's own rejection."""
    # SEC-07: raised while dependencies resolve, so the reservation
    # never runs and no counter records the refused request
    rejection = _limiter_rejection()

    def refuse():
        raise rejection

    previous = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = refuse
    try:
        yield rejection
    finally:
        if previous is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous


@pytest.fixture(autouse=True)
def empty_login_counters(isolated_state):
    """Empty both login counters around every test in this module."""
    # SEC-07: no counter state crosses a test boundary
    reset_login_throttle()
    yield
    reset_login_throttle()


def _post_login(client, email, secret):
    return client.post(LOGIN_PATH, json={"email": email, "password": secret})


def _keys_with_prefix(prefix):
    return sorted(
        key
        for key in auth_endpoint._login_failures
        if key.startswith(prefix)
    )


def _account_keys():
    return _keys_with_prefix(auth_endpoint._ACCOUNT_KEY_PREFIX)


def _address_keys():
    return _keys_with_prefix(auth_endpoint._ADDRESS_KEY_PREFIX)


def _failure_count(key):
    entry = auth_endpoint._login_failures.get(key)
    return None if entry is None else entry[0]


def _without_correlation_id(reply):
    return {
        key: value
        for key, value in reply.json().items()
        if key != CORRELATION_KEY
    }


def test_failed_logins_answer_401_until_the_threshold_then_429(
    client, register_user
):
    """The attempt past the configured threshold answers 429.

    Every earlier failure answers 401.
    """
    account = register_user()
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS

    # SEC-07: one attempt past the configured threshold
    replies = [
        _post_login(client, account["email"], WRONG_SECRET)
        for _ in range(attempts + 1)
    ]

    # SEC-07: the whole sequence, not the final status alone
    statuses = [reply.status_code for reply in replies]
    assert statuses == [401] * attempts + [429]

    # SEC-08: every reply carries the sanitized envelope
    for reply in replies:
        assert set(reply.json()) == ENVELOPE_KEYS
        assert reply.json()[CORRELATION_KEY]

    # SEC-08: the rejections differ only in the correlation identifier
    rejections = [_without_correlation_id(reply) for reply in replies[:-1]]
    assert all(body == rejections[0] for body in rejections)


def test_throttled_reply_carries_the_uniform_envelope(
    client, register_user
):
    """The throttled reply matches the shape of every other rejection.

    Neither the threshold, the window, nor the stock limiter body
    reaches the caller.
    """
    account = register_user()
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    window = settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES

    rejected = None
    for _ in range(attempts):
        rejected = _post_login(client, account["email"], WRONG_SECRET)
    assert rejected.status_code == 401

    throttled = _post_login(client, account["email"], WRONG_SECRET)
    assert throttled.status_code == 429

    invalid = client.post(
        REGISTER_PATH,
        json={"email": MALFORMED_ADDRESS, "password": UNUSABLE_SECRET},
    )
    assert invalid.status_code == 422

    # SEC-08: one shape across the throttle, the credential rejection
    # and the schema rejection
    body = throttled.json()
    assert set(body) == ENVELOPE_KEYS
    assert set(body) == set(rejected.json())
    assert set(body) == set(invalid.json())

    assert body[CORRELATION_KEY]
    assert body[CORRELATION_KEY] != rejected.json()[CORRELATION_KEY]
    assert body["fields"] == []

    # SEC-07: the detail names neither the threshold nor the window
    assert str(attempts) not in body["detail"]
    assert str(window) not in body["detail"]

    # SEC-07: the stock limiter body reaches no caller
    assert "error" not in body
    for marker in FORBIDDEN_IN_BODY:
        assert marker not in throttled.text

    # SEC-08: no submitted value and no minted token reach the reply
    assert WRONG_SECRET not in throttled.text
    assert account["email"] not in throttled.text
    assert account["access_token"] not in throttled.text

    # SEC-07: the limiter publishes no rate-limit headers
    assert not [
        name
        for name in throttled.headers
        if name.lower().startswith("x-ratelimit")
    ]


def test_throttled_attempt_reaches_the_log(client, register_user, caplog):
    """One record carries the correlation identifier the caller sees.

    No submitted secret, minted token, cookie value, email address or
    client address appears in any record.
    """
    caplog.set_level(logging.WARNING, logger=application_logger.name)
    account = register_user()
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS

    for _ in range(attempts):
        _post_login(client, account["email"], WRONG_SECRET)
    throttled = _post_login(client, account["email"], WRONG_SECRET)
    assert throttled.status_code == 429

    messages = [
        record.getMessage()
        for record in caplog.records
        if record.name == application_logger.name
    ]

    # SEC-07: the throttled attempt is recorded, not dropped
    correlation_id = throttled.json()[CORRELATION_KEY]
    throttle_records = [text for text in messages if correlation_id in text]
    assert len(throttle_records) == 1
    assert str(throttled.status_code) in throttle_records[0]

    # SEC-07: a redacted account reference attributes the record
    account_key = auth_endpoint._account_key(account["email"])
    assert auth_endpoint._account_marker(account_key) in throttle_records[0]
    assert UNIFORM_LOGIN_DETAIL not in throttle_records[0]

    # SEC-08: one detail covers an unknown address and a wrong secret
    rejections = [
        text for text in messages if UNIFORM_LOGIN_DETAIL in text
    ]
    assert len(rejections) == attempts

    # SEC-07: the record carries no value an attacker could replay and
    # no identifier tying it to a person or a network location
    joined = "\n".join(messages)
    assert WRONG_SECRET not in joined
    assert account["password"] not in joined
    assert account["access_token"] not in joined
    assert account["email"] not in joined

    address_keys = _address_keys()
    assert len(address_keys) == 1
    client_address = address_keys[0][
        len(auth_endpoint._ADDRESS_KEY_PREFIX):
    ]
    assert client_address
    assert client_address not in joined


def test_account_counter_keys_on_the_normalized_email(
    client, register_user
):
    """Padded and uppercase spellings of one address share one counter."""
    account = register_user()
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    padded_uppercase = "  {0}  ".format(account["email"].upper())

    statuses = [
        _post_login(client, padded_uppercase, WRONG_SECRET).status_code
        for _ in range(attempts)
    ]
    assert statuses == [401] * attempts

    # SEC-07: counter keys on the normalized email
    canonical_key = auth_endpoint._account_key(account["email"])
    assert _account_keys() == [canonical_key]
    assert _failure_count(canonical_key) == attempts

    # SEC-07: the exact spelling reaches the counter the padded,
    # uppercase spelling filled, and the correct secret does not clear it
    refused = _post_login(client, account["email"], account["password"])
    assert refused.status_code == 429
    assert set(refused.json()) == ENVELOPE_KEYS


def test_successful_login_empties_the_account_counter(
    client, register_user
):
    """A success resets the account counter, so later failures start
    from zero.
    """
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    # SEC-07: the second run below needs one attempt of headroom
    assert attempts >= 2
    below_threshold = attempts - 1

    account = register_user()
    canonical_key = auth_endpoint._account_key(account["email"])

    first_run = [
        _post_login(client, account["email"], WRONG_SECRET).status_code
        for _ in range(below_threshold)
    ]
    assert first_run == [401] * below_threshold
    assert _failure_count(canonical_key) == below_threshold

    accepted = _post_login(client, account["email"], account["password"])
    assert accepted.status_code == 200

    # SEC-07: authentication empties the account and address counters
    assert _account_keys() == []
    assert _address_keys() == []

    # SEC-07: an emptied counter answers 401 again for a full run; a
    # retained count would answer 429 on the second attempt here
    second_run = [
        _post_login(client, account["email"], WRONG_SECRET).status_code
        for _ in range(below_threshold)
    ]
    assert second_run == [401] * below_threshold
    assert _failure_count(canonical_key) == below_threshold


def test_counter_expiry_uses_the_configured_window(client, register_user):
    """A counter entry expires one configured window after the attempt."""
    account = register_user()
    canonical_key = auth_endpoint._account_key(account["email"])
    window_seconds = settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES * 60

    before = time.monotonic()
    rejected = _post_login(client, account["email"], WRONG_SECRET)
    after = time.monotonic()
    assert rejected.status_code == 401

    count, expires_at = auth_endpoint._login_failures[canonical_key]
    assert count == 1

    # SEC-07: the expiry comes from the configured window
    assert before + window_seconds <= expires_at
    assert expires_at <= after + window_seconds


def test_an_elapsed_counter_is_pruned_before_the_next_attempt(
    client, register_user
):
    """An elapsed lockout no longer refuses the next attempt.

    The window bounds guessing for its own duration only. A counter that
    outlived its window would lock an account out indefinitely, and one
    that is never removed would also keep the map growing.
    """
    account = register_user()
    canonical_key = auth_endpoint._account_key(account["email"])
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    elapsed = time.monotonic() - 1

    # SEC-07: an exhausted counter whose window has already run out
    auth_endpoint._login_failures[canonical_key] = (attempts, elapsed)
    auth_endpoint._login_failures[UNRELATED_ACCOUNT_KEY] = (1, elapsed)

    reply = _post_login(client, account["email"], WRONG_SECRET)

    # SEC-07: the elapsed lockout is gone, so this is a fresh failure
    assert reply.status_code == 401
    assert _failure_count(canonical_key) == 1

    # SEC-07: every elapsed entry is dropped, not only the one consulted
    assert UNRELATED_ACCOUNT_KEY not in auth_endpoint._login_failures


def test_the_counter_map_never_exceeds_the_cap(client, monkeypatch):
    """A flood of distinct accounts cannot grow the counter map.

    Each attempt writes an account key and an address key, so an
    unbounded map is a memory-exhaustion vector reachable by an
    unauthenticated caller (CWE-367).
    """
    monkeypatch.setattr(
        auth_endpoint, "_LOGIN_FAILURE_TRACKING_CAP", PROBE_CAP
    )

    statuses = []
    sizes = []
    for email in CAP_PROBE_EMAILS:
        statuses.append(_post_login(client, email, WRONG_SECRET).status_code)
        sizes.append(len(auth_endpoint._login_failures))

    # SEC-07: the cap frees room instead of refusing a fresh attempt
    assert statuses == [401] * len(CAP_PROBE_EMAILS)
    assert sizes == [2, PROBE_CAP, PROBE_CAP]

    # SEC-07: the address counter carries the lockout progress and is
    # the last key eviction may take, so it survives every eviction
    address_keys = _address_keys()
    assert len(address_keys) == 1
    assert _failure_count(address_keys[0]) == len(CAP_PROBE_EMAILS)

    # SEC-07: room came from the account keys closest to expiry
    retained = [
        email
        for email in CAP_PROBE_EMAILS
        if auth_endpoint._account_key(email) in auth_endpoint._login_failures
    ]
    assert len(retained) == PROBE_CAP - 1


def test_a_key_at_the_limit_is_never_evicted(monkeypatch):
    """Eviction frees an unexhausted key, never a lockout.

    The bound is reached below the HTTP layer, so the reservation
    function is addressed directly. The exhausted key here expires
    first, so an eviction ordered by expiry alone would take it and
    hand a locked-out account a fresh allowance.
    """
    monkeypatch.setattr(
        auth_endpoint, "_LOGIN_FAILURE_TRACKING_CAP", PROBE_CAP
    )
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    window_seconds = settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES * 60
    now = time.monotonic()
    locked_entry = (attempts, now + 1)

    auth_endpoint._login_failures[LOCKED_KEYS[0]] = locked_entry
    auth_endpoint._login_failures[EVICTABLE_KEY] = (1, now + window_seconds)

    admitted = auth_endpoint._reserve_login_attempt(
        RESERVED_ACCOUNT_KEY, RESERVED_ADDRESS_KEY
    )

    # SEC-07: the attempt is admitted and the map stays at the cap
    assert admitted is True
    assert len(auth_endpoint._login_failures) == PROBE_CAP

    # SEC-07: the lockout stands, untouched
    assert auth_endpoint._login_failures[LOCKED_KEYS[0]] == locked_entry

    # SEC-07: the freed slot came from the key still below the limit
    assert EVICTABLE_KEY not in auth_endpoint._login_failures


def test_a_full_map_of_lockouts_denies_the_attempt(monkeypatch):
    """With nothing evictable the attempt is denied, not admitted.

    Denying is the only choice that neither drops a lockout nor grows
    the map past its cap, and it is unreachable through the HTTP layer
    because a key already at the limit refuses the attempt first.
    """
    monkeypatch.setattr(
        auth_endpoint, "_LOGIN_FAILURE_TRACKING_CAP", len(LOCKED_KEYS)
    )
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    window_seconds = settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES * 60
    now = time.monotonic()
    exhausted = {
        key: (attempts, now + window_seconds) for key in LOCKED_KEYS
    }
    auth_endpoint._login_failures.update(exhausted)

    admitted = auth_endpoint._reserve_login_attempt(
        RESERVED_ACCOUNT_KEY, RESERVED_ADDRESS_KEY
    )

    # SEC-07: the attempt is refused rather than counted
    assert admitted is False

    # SEC-07: no lockout was dropped and the map did not grow
    assert auth_endpoint._login_failures == exhausted


def test_the_registered_limiter_holds_its_state_in_process():
    """The application registers one limiter, backed by memory.

    An external store is the dependency the minimal fix avoids, so the
    throttle must need no service beyond the process.
    """
    limiter = app.state.limiter

    # SEC-07: the object the route module defines, not a second limiter
    assert limiter is auth_endpoint.limiter

    # SEC-07: in-process storage; no cache service is provisioned
    assert isinstance(limiter._storage, MemoryStorage)


def test_the_harness_reset_empties_the_limiter_storage():
    """Both throttle mechanisms are emptied between tests.

    The limiter storage outlives a test on its own, so a reset covering
    only the counter map would let one test's throttle state decide
    another's outcome.
    """
    storage = app.state.limiter._storage
    window_seconds = settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES * 60
    counter_key = auth_endpoint._account_key("reset-probe@example.com")

    try:
        storage.incr(LIMITER_PROBE_KEY, window_seconds)
        auth_endpoint._login_failures[counter_key] = (
            1, time.monotonic() + window_seconds
        )
        assert storage.get(LIMITER_PROBE_KEY) == 1

        reset_login_throttle()

        # SEC-07: both mechanisms are empty afterwards
        assert storage.get(LIMITER_PROBE_KEY) == 0
        assert auth_endpoint._login_failures == {}
    finally:
        storage.reset()
        auth_endpoint._login_failures.clear()


def test_a_limiter_rejection_answers_the_uniform_envelope(
    client, limiter_refuses_every_request
):
    """A limiter refusal answers 429 in the shape every rejection uses.

    The stock rejection spells the threshold and the window in its own
    detail, and neither may reach a caller (CWE-209).
    """
    rejection = limiter_refuses_every_request
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    window = settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES

    refused = _post_login(client, CAP_PROBE_EMAILS[0], WRONG_SECRET)

    assert refused.status_code == 429
    body = refused.json()
    assert set(body) == ENVELOPE_KEYS
    assert body[CORRELATION_KEY]
    assert body["fields"] == []

    # SEC-07: the raised detail is replaced, not forwarded
    assert rejection.detail not in refused.text
    assert str(attempts) not in body["detail"]
    assert str(window) not in body["detail"]
    for marker in FORBIDDEN_IN_BODY:
        assert marker not in refused.text

    # SEC-07: the refusal is raised before the reservation, so no
    # counter records a request the caller never had answered
    assert auth_endpoint._login_failures == {}


def test_a_limiter_rejection_reaches_the_log(
    client, limiter_refuses_every_request, caplog
):
    """The refusal is recorded under the caller's correlation identifier.

    A throttled attempt that reaches no record leaves an attack
    invisible, and a refusal answered by the generic handler would carry
    no throttle attribution at all.
    """
    caplog.set_level(logging.WARNING, logger=application_logger.name)
    rejection = limiter_refuses_every_request

    refused = _post_login(client, CAP_PROBE_EMAILS[0], WRONG_SECRET)
    assert refused.status_code == 429

    correlation_id = refused.json()[CORRELATION_KEY]
    records = [
        record.getMessage()
        for record in caplog.records
        if record.name == application_logger.name
        and correlation_id in record.getMessage()
    ]

    # SEC-07: exactly one record, carrying the threshold the client
    # never sees and naming the throttle rather than a generic failure
    assert len(records) == 1
    assert rejection.detail in records[0]
    assert "rate limit" in records[0]
    assert LOGIN_PATH in records[0]

    # SEC-08: no submitted value reaches the record
    assert WRONG_SECRET not in records[0]
    assert CAP_PROBE_EMAILS[0] not in records[0]
