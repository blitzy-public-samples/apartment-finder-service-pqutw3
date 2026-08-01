"""Regression tests for SEC-07, the login throttle.

Failed logins answer 401 up to the configured threshold and 429 beyond
it, so repeated credential guessing against one account is bounded. The
throttled reply carries the sanitized error envelope, and the server
records the attempt under the correlation identifier the caller
receives.

The account counter keys on the normalized email address, and a
successful login empties that counter.
"""
import logging
import time

import pytest
from conftest import reset_login_throttle

from backend.app.api.endpoints import auth as auth_endpoint
from backend.app.core.config import settings
from backend.app.main import _error_envelope, logger as application_logger

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
