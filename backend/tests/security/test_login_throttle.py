"""Regression tests for SEC-07, the login throttle.

Two controls answer a failed login. The limiter registered on the login
route refuses the attempt past the configured threshold for one client
address; an in-process counter refuses it for one account reached from
many addresses. The cases below exercise each control on its own and
both together, and check that every refusal carries the sanitized error
envelope and reaches the server log under the correlation identifier the
caller receives.

The account counter keys on the stored account identity - the same value
the credential query filters on - so two accounts differing only in case
are two counters, and a successful login empties its own counter alone.

One further case here belongs to the response rather than the counter:
an unknown address and a wrong secret both reach the hasher, so the
reply time discloses no more than the reply text does.

Two further layers are exercised here. The counter map is bounded, so a
flood of distinct addresses cannot exhaust memory and cannot drop a
lockout to make room; those cases address the reservation function
directly. And the limiter the application registers is proven to be the
one the harness empties, with its rejection driven through the app.

Both controls hold their state in the worker process that served the
request, so the bound measured here is the bound one worker applies.
Durable shared lockout is recorded as deferred in
``documentation/security/decision-log.md``.
"""
import itertools
import logging
import time

import pytest
from conftest import TEST_BASE_URL, VALID_PASSWORD, reset_login_throttle
from fastapi.testclient import TestClient
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

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
LOGOUT_PATH = "/auth/logout"

# SEC-07: the key slowapi files a route limit under
_LOGIN_ROUTE_KEY = "{0}.{1}".format(
    auth_endpoint.login_user.__module__,
    auth_endpoint.login_user.__name__,
)

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

# SEC-07: client addresses this module presents, none of them the address
# the shared harness client carries
_HOSTS = itertools.count(1)

# SEC-07: a limiter storage key no route writes, so its presence and
# absence are attributable to this module alone
LIMITER_PROBE_KEY = "harness-limiter-probe"

# SEC-07: an account key no route writes, seeded to observe the prune
UNRELATED_ACCOUNT_KEY = "acct:unrelated-probe@example.com"

# SEC-07: a cap smaller than the number of accounts the flood below
# names; the last attempt frees a slot to be admitted
PROBE_CAP = 3

# SEC-07: addresses used only by the counter-cap cases; no account is
# registered for them and every attempt is a credential failure
CAP_PROBE_EMAILS = (
    "cap-probe-1@example.com",
    "cap-probe-2@example.com",
    "cap-probe-3@example.com",
    "cap-probe-4@example.com",
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


def _registered_login_limit():
    """Return the limit object the login route actually carries.

    The value is read from the registered limiter, so the rejection
    driven below carries the shipped threshold and window.
    """
    registered = app.state.limiter._route_limits[_LOGIN_ROUTE_KEY]
    assert len(registered) == 1, registered
    return registered[0]


def _limiter_rejection():
    """Build the rejection slowapi raises when a route limit is hit."""
    # SEC-07: the real exception the registered handler is keyed on. Its
    # stock detail spells the threshold and the window, so it is also
    # the input that proves the sanitized envelope withholds them.
    return RateLimitExceeded(_registered_login_limit())


@pytest.fixture
def limiter_refuses_every_request():
    """Make every request raise the limiter's own rejection."""
    # SEC-07: raised while dependencies resolve; the reservation never
    # runs and no counter records the refused request
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
    """Empty the account counter and every address budget."""
    # SEC-07: no throttle state crosses a test boundary
    reset_login_throttle()
    yield
    reset_login_throttle()


def _client_at_a_new_address():
    """Return a client and the address it presents, used by no other."""
    # SEC-07: a fresh address carries a full, unspent address budget
    host = "throttle-probe-{0}".format(next(_HOSTS))
    probe = TestClient(
        app,
        base_url=TEST_BASE_URL,
        client=(host, 50000),
        raise_server_exceptions=False,
    )
    return probe, host


def _post_login(client, email, secret):
    return client.post(LOGIN_PATH, json={"email": email, "password": secret})


def _login_from_a_new_address(email, secret):
    # SEC-07: one attempt per address; the address budget never answers
    # and the account counter is the only control under test
    probe, _host = _client_at_a_new_address()
    return _post_login(probe, email, secret)


def _reset_address_layer():
    # SEC-07: empties the limiter storage only; the account counter is
    # the sole control answering the next attempt
    auth_endpoint.limiter.reset()


def _clear_account_layer():
    # SEC-07: empties the account counter only; the route limiter is
    # the sole control answering the next attempt
    auth_endpoint._login_failures.clear()


def _client_at(host):
    """Return a client whose recorded address is ``host``."""
    return TestClient(
        app,
        base_url=TEST_BASE_URL,
        client=(host, 50000),
        raise_server_exceptions=False,
    )


def _account_keys():
    return sorted(
        key
        for key in auth_endpoint._login_failures
        if key.startswith(auth_endpoint._ACCOUNT_KEY_PREFIX)
    )


def _failure_count(key):
    entry = auth_endpoint._login_failures.get(key)
    return None if entry is None else entry[0]


def _warning_messages(caplog):
    return [
        record.getMessage()
        for record in caplog.records
        if record.name == application_logger.name
    ]


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

    replies = [
        _post_login(client, account["email"], WRONG_SECRET)
        for _ in range(attempts + 1)
    ]

    statuses = [reply.status_code for reply in replies]
    assert statuses == [401] * attempts + [429]

    for reply in replies:
        assert set(reply.json()) == ENVELOPE_KEYS
        assert reply.json()[CORRELATION_KEY]

    rejections = [_without_correlation_id(reply) for reply in replies[:-1]]
    assert all(body == rejections[0] for body in rejections)


def test_the_login_route_carries_the_configured_address_budget():
    """The login route declares the address budget the settings describe.

    A budget declared on the route governs the request; the middleware
    defers to it.
    """
    declared = [
        item
        for name, items in auth_endpoint.limiter._route_limits.items()
        if name.endswith("login_user")
        for item in items
    ]
    assert len(declared) == 1

    # SEC-07: the threshold and the window come from the settings
    limit = declared[0].limit
    assert limit.amount == settings.LOGIN_RATE_LIMIT_ATTEMPTS
    expected_window = settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES * 60
    assert limit.get_expiry() == expected_window

    # SEC-07: the budget keys on the client address, and no callable
    # limit bypasses the declaration
    assert auth_endpoint.limiter._key_func is get_remote_address
    assert auth_endpoint.limiter._dynamic_route_limits == {}

    # SEC-07: the limit is filed under the endpoint the application
    # routes POST /auth/login to; no stale key holds it
    assert auth_endpoint.limiter._route_limits.get(_LOGIN_ROUTE_KEY)
    served = [
        "{0}.{1}".format(route.endpoint.__module__, route.endpoint.__name__)
        for route in app.routes
        if getattr(route, "path", None) == LOGIN_PATH
    ]
    assert served == [_LOGIN_ROUTE_KEY]


def test_register_and_logout_carry_no_route_limit(client, register_user):
    """Only the login route is throttled.

    Registering and logging out more times than the login threshold
    allows answers normally throughout.
    """
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS

    accounts = [register_user() for _ in range(attempts + 1)]
    assert len({account["email"] for account in accounts}) == attempts + 1

    statuses = [
        client.post(LOGOUT_PATH).status_code for _ in range(attempts + 1)
    ]
    assert statuses == [200] * (attempts + 1)

    # SEC-07: the login route is the only route carrying a limit
    assert list(auth_endpoint.limiter._route_limits) == [_LOGIN_ROUTE_KEY]
    assert auth_endpoint.limiter._dynamic_route_limits == {}
    assert auth_endpoint.limiter._application_limits == []
    assert auth_endpoint.limiter._default_limits == []


def test_the_account_counter_bounds_a_changing_client_address(
    register_user
):
    """Attempts against one account are bounded across client addresses.

    Every attempt below arrives from an address no earlier attempt used,
    so no address budget approaches its threshold.
    """
    account = register_user()
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    canonical_key = auth_endpoint._account_key(account["email"])

    statuses = [
        _login_from_a_new_address(account["email"], WRONG_SECRET).status_code
        for _ in range(attempts)
    ]
    assert statuses == [401] * attempts
    assert _account_keys() == [canonical_key]
    assert _failure_count(canonical_key) == attempts

    # SEC-07: the account counter refuses an address that has spent
    # nothing of its own budget, and the correct secret does not pass
    throttled = _login_from_a_new_address(
        account["email"], account["password"]
    )
    assert throttled.status_code == 429
    assert set(throttled.json()) == ENVELOPE_KEYS


def test_the_address_budget_bounds_a_changing_account(register_user):
    """Attempts from one address are bounded across accounts.

    Every attempt below names an account no earlier attempt named, so no
    account counter approaches its threshold.
    """
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    accounts = [register_user() for _ in range(attempts + 1)]
    probe, _host = _client_at_a_new_address()

    statuses = [
        _post_login(probe, account["email"], WRONG_SECRET).status_code
        for account in accounts[:attempts]
    ]
    assert statuses == [401] * attempts

    # SEC-07: one failure per account; every account counter sits
    # below the threshold
    assert all(_failure_count(key) == 1 for key in _account_keys())
    assert len(_account_keys()) == attempts

    # SEC-07: the spent address budget answers an account that has never
    # failed a login
    unnamed = accounts[-1]
    throttled = _post_login(probe, unnamed["email"], WRONG_SECRET)
    assert throttled.status_code == 429
    assert set(throttled.json()) == ENVELOPE_KEYS
    unnamed_key = auth_endpoint._account_key(unnamed["email"])
    assert unnamed_key not in _account_keys()

    # SEC-07: the refusal is scoped to the spent address
    elsewhere = _login_from_a_new_address(
        unnamed["email"], unnamed["password"]
    )
    assert elsewhere.status_code == 200


def test_throttled_reply_carries_the_uniform_envelope(
    client, register_user
):
    """The throttled reply matches the credential and schema-rejection
    envelope and reveals no threshold or limiter detail."""
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

    body = throttled.json()
    assert set(body) == ENVELOPE_KEYS
    assert set(body) == set(rejected.json())
    assert set(body) == set(invalid.json())

    assert body[CORRELATION_KEY]
    assert body[CORRELATION_KEY] != rejected.json()[CORRELATION_KEY]
    assert body["fields"] == []

    assert str(attempts) not in body["detail"]
    assert str(window) not in body["detail"]

    assert "error" not in body
    for marker in FORBIDDEN_IN_BODY:
        assert marker not in throttled.text

    assert WRONG_SECRET not in throttled.text
    assert account["email"] not in throttled.text
    assert account["access_token"] not in throttled.text

    assert not [
        name
        for name in throttled.headers
        if name.lower().startswith("x-ratelimit")
    ]


def test_the_account_throttle_reaches_the_log(register_user, caplog):
    """One record carries the correlation identifier the caller sees.

    No submitted secret, minted token, cookie value, email address or
    client address appears in any record. The account counter answers
    here, because the limiter storage is emptied between attempts.
    """
    caplog.set_level(logging.WARNING, logger=application_logger.name)
    account = register_user()
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    client_address = "throttle-log-{0}".format(next(_HOSTS))

    with _client_at(client_address) as attempts_client:
        for _ in range(attempts):
            _reset_address_layer()
            _post_login(attempts_client, account["email"], WRONG_SECRET)
        _reset_address_layer()
        throttled = _post_login(
            attempts_client, account["email"], WRONG_SECRET
        )
    assert throttled.status_code == 429

    messages = _warning_messages(caplog)

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

    # SEC-07: the address the harness sent reaches no record
    assert client_address not in joined


def test_the_address_throttle_reaches_the_log(
    client, register_user, caplog
):
    """The address budget records its refusal, rather than dropping it.

    The record carries the correlation identifier the caller sees and no
    submitted value.
    """
    caplog.set_level(logging.WARNING, logger=application_logger.name)
    account = register_user()
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS

    for _ in range(attempts):
        _post_login(client, account["email"], WRONG_SECRET)
    throttled = _post_login(client, account["email"], WRONG_SECRET)
    assert throttled.status_code == 429

    messages = _warning_messages(caplog)

    # SEC-07: the refused attempt is recorded, not dropped
    correlation_id = throttled.json()[CORRELATION_KEY]
    throttle_records = [text for text in messages if correlation_id in text]
    assert len(throttle_records) == 1
    assert LOGIN_PATH in throttle_records[0]

    # SEC-08: no submitted value and no minted token reach a record
    joined = "\n".join(messages)
    assert WRONG_SECRET not in joined
    assert account["password"] not in joined
    assert account["access_token"] not in joined
    assert account["email"] not in joined


def test_account_counter_keys_on_the_stored_identity(register_user):
    """Spellings the request model folds together share one counter.

    ``EmailStr`` strips surrounding space and lowercases the domain, so
    those spellings reach the credential query - and therefore the
    counter - as one identity. The counter key is that value, so it names
    exactly the row a successful attempt would authenticate.
    """
    account = register_user()
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    padded_uppercase_domain = "  {0}@{1}  ".format(
        account["email"].split("@")[0], account["email"].split("@")[1].upper()
    )

    statuses = [
        _login_from_a_new_address(
            padded_uppercase_domain, WRONG_SECRET
        ).status_code
        for _ in range(attempts)
    ]
    assert statuses == [401] * attempts

    # SEC-07: the counter key is the stored identity the query filters on
    canonical_key = auth_endpoint._account_key(account["email"])
    assert canonical_key.endswith(account["email"])
    assert _account_keys() == [canonical_key]
    assert _failure_count(canonical_key) == attempts

    # SEC-07: the exact spelling reaches the counter those spellings
    # filled, and the correct secret does not clear it
    refused = _login_from_a_new_address(
        account["email"], account["password"]
    )
    assert refused.status_code == 429
    assert set(refused.json()) == ENVELOPE_KEYS


# SEC-07: two stored accounts differing only in case are two identities
def test_case_variant_accounts_do_not_share_a_counter(register_user):
    """Exhausting one account's counter leaves the other's untouched.

    The credential query filters on the stored address exactly, so
    ``Victim@example.com`` and ``victim@example.com`` are two rows. A
    counter folding them together would let an attacker lock an account
    by guessing at a spelling they own.
    """
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    victim = register_user(email="throttle-victim@example.com")
    variant = register_user(email="Throttle-Victim@example.com")
    assert victim["email"] != variant["email"]
    assert victim["id"] != variant["id"]

    spent = [
        _login_from_a_new_address(variant["email"], WRONG_SECRET).status_code
        for _ in range(attempts)
    ]
    assert spent == [401] * attempts

    # SEC-07: the variant's counter is exhausted and the victim's is empty
    variant_key = auth_endpoint._account_key(variant["email"])
    victim_key = auth_endpoint._account_key(victim["email"])
    assert _account_keys() == [variant_key]
    assert _failure_count(variant_key) == attempts
    assert _failure_count(victim_key) is None

    # SEC-07: the exhausted variant is refused, the victim is not
    assert _login_from_a_new_address(
        variant["email"], variant["password"]
    ).status_code == 429
    accepted = _login_from_a_new_address(
        victim["email"], victim["password"]
    )
    assert accepted.status_code == 200, accepted.text


# SEC-07: a success on one case variant clears only its own counter
def test_a_success_on_one_variant_leaves_the_other_counter_standing(
    register_user
):
    """Authenticating one variant does not reset the other's counter.

    A shared key would let an attacker holding one spelling clear the
    counter guarding the account they are guessing at.
    """
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    assert attempts >= 2
    below_threshold = attempts - 1

    victim = register_user(email="reset-victim@example.com")
    attacker = register_user(email="Reset-Victim@example.com")
    victim_key = auth_endpoint._account_key(victim["email"])
    attacker_key = auth_endpoint._account_key(attacker["email"])

    guesses = [
        _login_from_a_new_address(victim["email"], WRONG_SECRET).status_code
        for _ in range(below_threshold)
    ]
    assert guesses == [401] * below_threshold
    assert _failure_count(victim_key) == below_threshold

    accepted = _login_from_a_new_address(
        attacker["email"], attacker["password"]
    )
    assert accepted.status_code == 200, accepted.text

    # SEC-07: the success emptied its own counter and no other
    assert _failure_count(attacker_key) is None
    assert _failure_count(victim_key) == below_threshold

    # SEC-07: the victim's remaining allowance is one attempt, not a full
    # window reopened by somebody else's success
    assert _login_from_a_new_address(
        victim["email"], WRONG_SECRET
    ).status_code == 401
    assert _login_from_a_new_address(
        victim["email"], WRONG_SECRET
    ).status_code == 429


# SEC-08: both credential branches perform the same hasher work
def test_an_unknown_address_and_a_wrong_secret_do_equal_hasher_work(
    register_user, monkeypatch
):
    """An absent account is verified against a stand-in hash.

    Returning before the hasher on the unknown-address branch leaves a
    timing difference the uniform response text does not close, so the
    account-existence oracle survives in the clock. The assertion counts
    hasher invocations rather than measuring wall-clock time, which is
    what a loaded runner makes unreliable.
    """
    account = register_user()
    verified = []
    original = auth_endpoint.verify_password

    def record(submitted, stored):
        verified.append(stored)
        return original(submitted, stored)

    monkeypatch.setattr(auth_endpoint, "verify_password", record)

    wrong_secret = _login_from_a_new_address(account["email"], WRONG_SECRET)
    unknown_address = _login_from_a_new_address(
        "absent-{0}".format(account["email"]), WRONG_SECRET
    )

    # SEC-08: one reply shape, one hasher call, whichever branch answered
    assert wrong_secret.status_code == 401
    assert unknown_address.status_code == 401
    assert _without_correlation_id(wrong_secret) == _without_correlation_id(
        unknown_address
    )
    assert len(verified) == 2

    # SEC-08: the stand-in carries the scheme and cost a stored hash does
    stored_prefix = verified[0].rsplit("$", 1)[0]
    assert verified[1].rsplit("$", 1)[0] == stored_prefix
    assert verified[1] == auth_endpoint._ABSENT_ACCOUNT_HASH
    assert verified[1] != account["password"]


# SEC-08: no submitted secret matches the stand-in hash
def test_the_stand_in_hash_authenticates_nobody(client):
    """A login naming an absent account is refused, not admitted."""
    response = _post_login(
        client, "nobody-at-all@example.com", VALID_PASSWORD
    )

    assert response.status_code == 401
    assert set(response.json()) == ENVELOPE_KEYS
    assert auth_endpoint._verified_credentials(None, VALID_PASSWORD) == (
        False, ""
    )


def test_successful_login_empties_the_account_counter(register_user):
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
        _login_from_a_new_address(account["email"], WRONG_SECRET).status_code
        for _ in range(below_threshold)
    ]
    assert first_run == [401] * below_threshold
    assert _failure_count(canonical_key) == below_threshold

    accepted = _login_from_a_new_address(
        account["email"], account["password"]
    )
    assert accepted.status_code == 200

    # SEC-07: authentication empties the counter
    assert _account_keys() == []
    assert auth_endpoint._login_failures == {}

    # SEC-07: an emptied counter answers 401 again for a full run. The
    # address layer is emptied first, so the second run reaches the
    # account counter.
    _reset_address_layer()
    second_run = [
        _login_from_a_new_address(account["email"], WRONG_SECRET).status_code
        for _ in range(below_threshold)
    ]
    assert second_run == [401] * below_threshold
    assert _failure_count(canonical_key) == below_threshold


def test_a_success_leaves_the_address_budget_spent(register_user):
    """A success clears the account counter and no part of the address
    budget.

    The address the success arrived from stays bound by what earlier
    attempts spent.
    """
    attempts = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    # SEC-07: one attempt of headroom for the success below
    assert attempts >= 2
    guessed = register_user()
    holder = register_user()
    probe, _host = _client_at_a_new_address()

    failures = [
        _post_login(probe, guessed["email"], WRONG_SECRET).status_code
        for _ in range(attempts - 1)
    ]
    assert failures == [401] * (attempts - 1)

    accepted = _post_login(probe, holder["email"], holder["password"])
    assert accepted.status_code == 200
    probe.cookies.clear()

    # SEC-07: the guessed account sits below its threshold and the
    # authenticated account holds no counter; only the spent address
    # budget answers the next attempt
    guessed_key = auth_endpoint._account_key(guessed["email"])
    assert _failure_count(guessed_key) == attempts - 1
    assert auth_endpoint._account_key(holder["email"]) not in _account_keys()

    throttled = _post_login(probe, holder["email"], holder["password"])
    assert throttled.status_code == 429
    assert set(throttled.json()) == ENVELOPE_KEYS

    # SEC-07: the refusal is scoped to the spent address
    elsewhere = _login_from_a_new_address(
        holder["email"], holder["password"]
    )
    assert elsewhere.status_code == 200


def test_counter_expiry_uses_the_configured_window(register_user):
    """A counter entry expires one configured window after the attempt."""
    account = register_user()
    canonical_key = auth_endpoint._account_key(account["email"])
    window_seconds = settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES * 60

    before = time.monotonic()
    rejected = _login_from_a_new_address(account["email"], WRONG_SECRET)
    after = time.monotonic()
    assert rejected.status_code == 401

    count, expires_at = auth_endpoint._login_failures[canonical_key]
    assert count == 1

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

    # SEC-07: the elapsed lockout is gone; this is a fresh failure
    assert reply.status_code == 401
    assert _failure_count(canonical_key) == 1

    # SEC-07: every elapsed entry is dropped, not only the one consulted
    assert UNRELATED_ACCOUNT_KEY not in auth_endpoint._login_failures


def test_the_counter_map_never_exceeds_the_cap(client, monkeypatch):
    """A flood of distinct accounts cannot grow the counter map.

    Each attempt writes one account key, so an unbounded map is a
    memory-exhaustion vector reachable by an unauthenticated caller
    (CWE-400).
    """
    monkeypatch.setattr(
        auth_endpoint, "_LOGIN_FAILURE_TRACKING_CAP", PROBE_CAP
    )

    statuses = []
    sizes = []
    for email in CAP_PROBE_EMAILS:
        statuses.append(_post_login(client, email, WRONG_SECRET).status_code)
        sizes.append(len(auth_endpoint._login_failures))

    # SEC-07: the cap frees room and admits a fresh attempt
    assert statuses == [401] * len(CAP_PROBE_EMAILS)
    assert sizes == [1, 2, PROBE_CAP, PROBE_CAP]

    # SEC-07: the map never grows past the cap, and every retained key
    # still carries the one attempt it counted
    assert len(auth_endpoint._login_failures) == PROBE_CAP
    assert _account_keys() == sorted(auth_endpoint._login_failures)
    assert all(_failure_count(key) == 1 for key in _account_keys())

    # SEC-07: room came from the account keys closest to expiry
    retained = [
        email
        for email in CAP_PROBE_EMAILS
        if auth_endpoint._account_key(email) in auth_endpoint._login_failures
    ]
    assert len(retained) == PROBE_CAP


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

    # SEC-07: the attempt is refused and not counted
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

    # SEC-07: in-process storage; no cache service is provisioned. The
    # class is the one slowapi itself selects when no store is
    # configured, read here from a reference limiter.
    in_process = Limiter(key_func=get_remote_address)
    assert in_process._storage_uri is None
    assert type(limiter._storage) is type(in_process._storage)


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

    # SEC-07: the refusal is raised before the reservation; no counter
    # records a request the caller never had answered
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
    # never sees and naming the throttle, not a generic failure
    assert len(records) == 1
    assert rejection.detail in records[0]
    assert "rate limit" in records[0]
    assert LOGIN_PATH in records[0]

    # SEC-08: no submitted value reaches the record
    assert WRONG_SECRET not in records[0]
    assert CAP_PROBE_EMAILS[0] not in records[0]
