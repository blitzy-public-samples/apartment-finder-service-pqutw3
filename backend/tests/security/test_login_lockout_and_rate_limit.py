"""The credential endpoints' brute-force controls.

The unit under test is :mod:`backend.app.api.endpoints.auth`. Each case
exercises ``POST /auth/login`` or ``POST /auth/register`` and asserts
the refusal the control under test returns.

Four controls are covered:

* the per-account lockout, which counts failures on
  ``users.failed_login_attempts`` and sets ``users.locked_until`` on
  reaching ``settings.LOGIN_MAX_ATTEMPTS``
* the uniformity of every refusal ``POST /auth/login`` returns, whether
  the address names no account, the account's lock is in force, or the
  password does not match
* the per-address rate limit the two credential endpoints declare
  against ``settings.RATE_LIMIT_LOGIN`` and
  ``settings.RATE_LIMIT_REGISTER``, measured on an account carrying no
  lock and answered without any credential work or account lookup
* the password contract :mod:`backend.app.schema.user` applies -- a
  seventy-two byte ceiling and the four-class policy floor

Every request body is posted as JSON keyed on ``email`` and
``password``.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event

from backend.app.api.endpoints import auth as auth_module
from backend.app.core import security
from backend.app.core.config import settings
from backend.app.db.models import User
from backend.app.main import (
    INVALID_REQUEST_DETAIL,
    REQUEST_ID_HEADER,
    TOO_MANY_REQUESTS_DETAIL,
    app,
    limiter,
)
from backend.tests.support import VALID_TEST_PASSWORD

#: Clears the shared per-address limiter counters around every case in
#: this module.
pytestmark = pytest.mark.usefixtures("reset_rate_limits")

#: Password that matches no seeded account. It stays inside the byte
#: ceiling ``UserLogin`` applies.
WRONG_PASSWORD = "Wr0ngPassphrase!2024"

#: Address that names no stored account.
UNKNOWN_EMAIL = "no.such.account@example.com"

#: Maximum UTF-8 byte length the credential contract accepts.
PASSWORD_MAX_BYTES = 72

#: Fragment every constructed password is built from. It carries an
#: upper-case letter, a lower-case letter, a digit and a special
#: character, which is every class the policy floor names.
_POLICY_FRAGMENT = "TestPassw0rd!"

#: Password whose UTF-8 encoding is exactly
#: :data:`PASSWORD_MAX_BYTES` bytes long.
PASSWORD_AT_BYTE_CEILING = _POLICY_FRAGMENT + "y" * 59

#: Password one byte beyond the ceiling, every character encoding to a
#: single byte.
PASSWORD_OVER_CEILING_ASCII = PASSWORD_AT_BYTE_CEILING + "z"

#: Password carrying fewer characters than :data:`PASSWORD_MAX_BYTES`
#: while encoding to more bytes than it.
PASSWORD_OVER_CEILING_MULTIBYTE = _POLICY_FRAGMENT + "\u00e9" * 30

#: Headers whose value changes between two requests independently of
#: the credentials those requests carried.
VOLATILE_HEADERS = frozenset({REQUEST_ID_HEADER.lower(), "date"})


def _allowance(expression):
    """Return the request count a rate-limit expression names."""
    return int(expression.split("/", 1)[0])


def _as_utc(moment):
    """Return an instant as offset-aware UTC."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def _stored(db, user_id):
    """Return the persisted account row, discarding any cached copy."""
    db.expire_all()
    return db.query(User).filter(User.id == user_id).one()


def _account_exists(db, email):
    """Report whether a row holds the address."""
    return (
        db.query(User).filter(User.email == email).one_or_none()
        is not None
    )


def _post_login(test_client, email, password, reset=True):
    """Post one login as a JSON body.

    The shared per-address limiter counter is cleared first unless
    ``reset`` is ``False``.
    """
    if reset:
        limiter.reset()
    return test_client.post(
        "/auth/login", json={"email": email, "password": password}
    )


def _post_registration(test_client, email, password, reset=True):
    """Post one registration as a JSON body.

    The shared per-address limiter counter is cleared first unless
    ``reset`` is ``False``.
    """
    if reset:
        limiter.reset()
    return test_client.post(
        "/auth/register", json={"email": email, "password": password}
    )


def _comparable(response):
    """Return the parts of a response two refusals must share.

    The status code, the raw body bytes and every header outside
    :data:`VOLATILE_HEADERS` are returned.
    """
    headers = dict(
        (name.lower(), value)
        for name, value in response.headers.items()
        if name.lower() not in VOLATILE_HEADERS
    )
    return response.status_code, response.content, headers


def _drive_to_threshold(login_json, test_client, email):
    """Post ``settings.LOGIN_MAX_ATTEMPTS`` failed logins.

    Returns the responses in the order they were received. The
    per-address limiter counter is cleared before each request.
    """
    return [
        login_json(test_client, email, WRONG_PASSWORD)
        for _ in range(settings.LOGIN_MAX_ATTEMPTS)
    ]


def _credential_calls(monkeypatch):
    """Record the arguments the credential path is driven with.

    Returns a mapping whose ``"checks"`` list receives the stored hash
    handed to :func:`backend.app.core.security.verify_credential`, and
    whose ``"comparisons"`` list receives every hash
    :func:`backend.app.core.security.verify_password` is asked to
    compare against. Both replacements delegate to the function they
    stand in for, and ``monkeypatch`` restores both at test exit.
    """
    record = {"checks": [], "comparisons": []}
    check = auth_module.verify_credential
    compare = security.verify_password

    def recording_check(plain_password, hashed_password):
        """Record the stored hash and delegate the credential check."""
        record["checks"].append(hashed_password)
        return check(plain_password, hashed_password)

    def recording_compare(plain_password, hashed_password):
        """Record the compared hash and delegate the comparison."""
        record["comparisons"].append(hashed_password)
        return compare(plain_password, hashed_password)

    monkeypatch.setattr(
        auth_module, "verify_credential", recording_check
    )
    monkeypatch.setattr(security, "verify_password", recording_compare)
    return record


def _invalid_credentials_body():
    """Return the body every refused login carries."""
    return {"detail": auth_module.INVALID_CREDENTIALS_DETAIL}


def _throttled_body():
    """Return the body every request refused by the throttle carries."""
    return {"detail": TOO_MANY_REQUESTS_DETAIL}


@contextmanager
def _recorded_statements(session):
    """Record every statement the shared engine runs inside the block.

    ``session`` names any session on the test database; the engine
    behind it is the one the application's request-scoped sessions are
    also drawn from, so a statement any request issues is recorded. The
    yielded list receives each statement in the order it ran, and the
    listener is removed when the block ends.
    """
    statements = []
    engine = session.get_bind()

    def record(
        connection, cursor, statement, parameters, context, executemany
    ):
        """Append one executed statement to the recording."""
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        yield statements
    finally:
        event.remove(engine, "before_cursor_execute", record)


def _touching_accounts(statements):
    """Return the recorded statements naming the accounts table."""
    return [
        statement
        for statement in statements
        if User.__tablename__ in statement.lower()
    ]


def _consume_login_allowance(test_client, email):
    """Spend the login allowance on logins that succeed.

    ``settings.RATE_LIMIT_LOGIN`` names the allowance. Each request
    carries the password the account was seeded with, so each answers
    200 and each returns the failed-attempt count to zero -- leaving the
    allowance spent and the account carrying no lock. The shared
    per-address counter is not cleared between the requests.
    """
    admitted = [
        _post_login(test_client, email, VALID_TEST_PASSWORD, reset=False)
        for _ in range(_allowance(settings.RATE_LIMIT_LOGIN))
    ]
    for response in admitted:
        assert response.status_code == 200
    return admitted


def test_every_failure_up_to_the_threshold_is_refused_alike(
    client, login_json, registered_user
):
    responses = _drive_to_threshold(
        login_json, client, registered_user.email
    )

    assert len(responses) == settings.LOGIN_MAX_ATTEMPTS
    for response in responses:
        assert response.status_code == 401
        assert response.json() == _invalid_credentials_body()
        assert "access_token" not in response.json()

    first = _comparable(responses[0])
    for response in responses[1:]:
        assert _comparable(response) == first


def test_reaching_the_threshold_locks_the_account_row(
    db, client, login_json, registered_user
):
    _drive_to_threshold(login_json, client, registered_user.email)

    stored = _stored(db, registered_user.id)
    assert stored.failed_login_attempts == settings.LOGIN_MAX_ATTEMPTS
    assert stored.locked_until is not None

    locked_until = _as_utc(stored.locked_until)
    now = datetime.now(timezone.utc)
    window = timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
    assert locked_until > now
    assert locked_until <= now + window


def test_the_correct_password_is_refused_while_the_lock_holds(
    db, client, login_json, registered_user
):
    _drive_to_threshold(login_json, client, registered_user.email)

    response = login_json(client, registered_user.email)

    assert response.status_code == 401
    assert response.json() == _invalid_credentials_body()
    assert "access_token" not in response.json()
    assert _stored(db, registered_user.id).locked_until is not None


def test_a_failure_while_locked_does_not_advance_the_count(
    db, client, login_json, registered_user
):
    _drive_to_threshold(login_json, client, registered_user.email)
    at_threshold = _stored(db, registered_user.id)
    locked_until = at_threshold.locked_until

    response = login_json(
        client, registered_user.email, WRONG_PASSWORD
    )

    assert response.status_code == 401
    stored = _stored(db, registered_user.id)
    assert stored.failed_login_attempts == settings.LOGIN_MAX_ATTEMPTS
    assert stored.locked_until == locked_until


def test_the_lock_does_not_reach_a_second_account(
    db,
    client,
    login_json,
    registered_user,
    second_registered_user,
):
    _drive_to_threshold(login_json, client, registered_user.email)

    response = login_json(client, second_registered_user.email)

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["token_type"] == "bearer"

    unaffected = _stored(db, second_registered_user.id)
    assert unaffected.failed_login_attempts == 0
    assert unaffected.locked_until is None
    assert _stored(db, registered_user.id).locked_until is not None


def test_a_successful_login_clears_the_failure_count(
    db, client, login_json, registered_user
):
    below_threshold = settings.LOGIN_MAX_ATTEMPTS - 1
    for _ in range(below_threshold):
        refused = login_json(
            client, registered_user.email, WRONG_PASSWORD
        )
        assert refused.status_code == 401

    counted = _stored(db, registered_user.id)
    assert counted.failed_login_attempts == below_threshold
    assert counted.locked_until is None

    accepted = login_json(client, registered_user.email)

    assert accepted.status_code == 200
    assert accepted.json()["token_type"] == "bearer"
    cleared = _stored(db, registered_user.id)
    assert cleared.failed_login_attempts == 0
    assert cleared.locked_until is None


def test_a_lock_that_has_expired_admits_the_correct_password(
    db, client, login_json, registered_user
):
    registered_user.failed_login_attempts = settings.LOGIN_MAX_ATTEMPTS
    registered_user.locked_until = datetime.now(
        timezone.utc
    ) - timedelta(minutes=1)
    db.commit()

    response = login_json(client, registered_user.email)

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["token_type"] == "bearer"
    stored = _stored(db, registered_user.id)
    assert stored.failed_login_attempts == 0
    assert stored.locked_until is None


def test_an_unknown_address_and_a_wrong_password_answer_identically(
    client, login_json, registered_user
):
    unknown = login_json(client, UNKNOWN_EMAIL, WRONG_PASSWORD)
    mismatched = login_json(
        client, registered_user.email, WRONG_PASSWORD
    )

    assert unknown.status_code == 401
    assert mismatched.status_code == 401
    assert unknown.content == mismatched.content
    assert unknown.json() == mismatched.json()
    assert unknown.json() == _invalid_credentials_body()
    assert _comparable(unknown) == _comparable(mismatched)


def test_the_locked_refusal_matches_the_unknown_address_refusal(
    client, login_json, registered_user
):
    _drive_to_threshold(login_json, client, registered_user.email)

    locked = login_json(client, registered_user.email)
    unknown = login_json(client, UNKNOWN_EMAIL, WRONG_PASSWORD)

    assert locked.status_code == 401
    assert locked.content == unknown.content
    assert _comparable(locked) == _comparable(unknown)


def test_both_credential_branches_run_exactly_one_credential_check(
    monkeypatch, client, login_json, registered_user
):
    stored_hash = registered_user.hashed_password
    record = _credential_calls(monkeypatch)

    login_json(client, UNKNOWN_EMAIL, WRONG_PASSWORD)
    unknown_checks = list(record["checks"])
    login_json(client, registered_user.email, WRONG_PASSWORD)
    mismatched_checks = record["checks"][len(unknown_checks):]

    assert unknown_checks == [None]
    assert mismatched_checks == [stored_hash]
    assert len(unknown_checks) == len(mismatched_checks)


def test_the_unknown_address_branch_compares_against_the_decoy_hash(
    monkeypatch, client, login_json, registered_user
):
    stored_hash = registered_user.hashed_password
    record = _credential_calls(monkeypatch)

    login_json(client, UNKNOWN_EMAIL, WRONG_PASSWORD)
    unknown = list(record["comparisons"])
    login_json(client, registered_user.email, WRONG_PASSWORD)
    mismatched = record["comparisons"][len(unknown):]

    assert unknown == [security.DECOY_HASH, security.DECOY_HASH]
    assert mismatched == [stored_hash, security.DECOY_HASH]
    assert len(unknown) == len(mismatched)


def test_the_limiter_is_registered_on_the_application():
    assert getattr(app.state, "limiter", None) is not None
    assert app.state.limiter is limiter
    assert app.state.limiter is auth_module.limiter


def test_login_beyond_the_configured_rate_is_throttled(
    client, registered_user
):
    allowance = _allowance(settings.RATE_LIMIT_LOGIN)
    for _ in range(allowance):
        admitted = _post_login(
            client,
            registered_user.email,
            WRONG_PASSWORD,
            reset=False,
        )
        assert admitted.status_code == 401

    throttled = _post_login(
        client, registered_user.email, WRONG_PASSWORD, reset=False
    )

    assert throttled.status_code == 429
    assert throttled.json() == {"detail": TOO_MANY_REQUESTS_DETAIL}


def test_registration_beyond_the_configured_rate_is_throttled(client):
    allowance = _allowance(settings.RATE_LIMIT_REGISTER)
    for index in range(allowance):
        admitted = _post_registration(
            client,
            "throttle.candidate.{0}@example.com".format(index),
            VALID_TEST_PASSWORD,
            reset=False,
        )
        assert admitted.status_code == 200

    throttled = _post_registration(
        client,
        "throttle.candidate.excess@example.com",
        VALID_TEST_PASSWORD,
        reset=False,
    )

    assert throttled.status_code == 429
    assert throttled.json() == {"detail": TOO_MANY_REQUESTS_DETAIL}


def test_a_throttled_login_never_reaches_the_account(
    monkeypatch, db, client, registered_user
):
    """A login refused by the throttle runs no part of the handler.

    The allowance is spent on logins that succeed, so the account
    carries no lock and a zero failed-attempt count when the throttled
    request arrives, and the correct password is what that request
    carries. That request answers 429 carrying
    :data:`backend.app.main.TOO_MANY_REQUESTS_DETAIL` and no token, it
    issues no statement against ``users``, it drives no credential check
    and no password comparison, and it leaves the count and the lock as
    it found them.
    """
    _consume_login_allowance(client, registered_user.email)
    unlocked = _stored(db, registered_user.id)
    assert unlocked.failed_login_attempts == 0
    assert unlocked.locked_until is None

    record = _credential_calls(monkeypatch)
    with _recorded_statements(db) as statements:
        throttled = _post_login(
            client,
            registered_user.email,
            VALID_TEST_PASSWORD,
            reset=False,
        )

    assert throttled.status_code == 429
    assert throttled.json() == _throttled_body()
    assert "access_token" not in throttled.json()
    assert _touching_accounts(statements) == []
    assert statements == []
    assert record["checks"] == []
    assert record["comparisons"] == []
    unchanged = _stored(db, registered_user.id)
    assert unchanged.failed_login_attempts == 0
    assert unchanged.locked_until is None


def test_the_throttle_and_the_lock_are_told_apart(
    monkeypatch,
    db,
    client,
    login_json,
    registered_user,
    second_registered_user,
):
    """The two controls answer differently and neither stands in.

    One account is driven to its lock with the allowance cleared before
    each request, so the lock alone refuses it; a second account spends
    the allowance on logins that succeed, so the throttle alone refuses
    it. The lock's refusal answers 401 carrying
    :data:`backend.app.api.endpoints.auth.INVALID_CREDENTIALS_DETAIL`
    after reading the row and running one credential check, and the
    throttle's refusal answers 429 carrying
    :data:`backend.app.main.TOO_MANY_REQUESTS_DETAIL` having read no row
    and run no credential check. The two statuses and the two bodies
    differ.
    """
    _drive_to_threshold(login_json, client, registered_user.email)
    assert _stored(db, registered_user.id).locked_until is not None

    record = _credential_calls(monkeypatch)
    limiter.reset()
    with _recorded_statements(db) as locked_statements:
        locked = login_json(
            client, registered_user.email, reset=False
        )
    locked_checks = list(record["checks"])

    assert locked.status_code == 401
    assert locked.json() == _invalid_credentials_body()
    assert _touching_accounts(locked_statements) != []
    assert locked_checks != []

    limiter.reset()
    _consume_login_allowance(client, second_registered_user.email)
    assert _stored(db, second_registered_user.id).locked_until is None
    spent = len(record["checks"])
    with _recorded_statements(db) as throttled_statements:
        throttled = _post_login(
            client,
            second_registered_user.email,
            VALID_TEST_PASSWORD,
            reset=False,
        )

    assert throttled.status_code == 429
    assert throttled.json() == _throttled_body()
    assert _touching_accounts(throttled_statements) == []
    assert record["checks"][spent:] == []
    assert throttled.status_code != locked.status_code
    assert throttled.json() != locked.json()


@pytest.mark.parametrize(
    "password",
    [
        pytest.param(
            PASSWORD_OVER_CEILING_ASCII, id="ascii_over_the_ceiling"
        ),
        pytest.param(
            PASSWORD_OVER_CEILING_MULTIBYTE,
            id="multibyte_over_the_ceiling",
        ),
    ],
)
def test_a_registration_password_beyond_the_byte_ceiling_is_refused(
    db, client, password
):
    address = "over.the.ceiling@example.com"
    assert len(password.encode("utf-8")) > PASSWORD_MAX_BYTES

    response = _post_registration(client, address, password)

    assert response.status_code == 422
    assert response.json() == {"detail": INVALID_REQUEST_DETAIL}
    assert not _account_exists(db, address)


def test_a_login_password_beyond_the_byte_ceiling_is_refused(
    client, registered_user
):
    response = _post_login(
        client, registered_user.email, PASSWORD_OVER_CEILING_ASCII
    )

    assert response.status_code == 422
    assert response.json() == {"detail": INVALID_REQUEST_DETAIL}


def test_the_byte_ceiling_counts_bytes_and_not_characters():
    password = PASSWORD_OVER_CEILING_MULTIBYTE

    assert len(password) < PASSWORD_MAX_BYTES
    assert len(password.encode("utf-8")) > PASSWORD_MAX_BYTES
    assert len(password) >= 12
    assert any(character.isupper() for character in password)
    assert any(character.islower() for character in password)
    assert any(character.isdigit() for character in password)
    assert "!" in password


def test_a_password_at_the_byte_ceiling_is_accepted(client):
    address = "at.the.ceiling@example.com"
    assert (
        len(PASSWORD_AT_BYTE_CEILING.encode("utf-8"))
        == PASSWORD_MAX_BYTES
    )

    response = _post_registration(
        client, address, PASSWORD_AT_BYTE_CEILING
    )

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["token_type"] == "bearer"
    assert body["user"]["email"] == address


@pytest.mark.parametrize(
    "password",
    [
        pytest.param("Ab1!efghijk", id="under_twelve_characters"),
        pytest.param("testpassw0rd!", id="no_uppercase_letter"),
        pytest.param("TESTPASSW0RD!", id="no_lowercase_letter"),
        pytest.param("TestPassword!", id="no_digit"),
        pytest.param("TestPassw0rd1", id="no_special_character"),
    ],
)
def test_a_password_failing_the_policy_floor_is_refused(
    db, client, password
):
    address = "policy.candidate@example.com"
    assert len(password.encode("utf-8")) <= PASSWORD_MAX_BYTES

    response = _post_registration(client, address, password)

    assert response.status_code == 422
    assert response.json() == {"detail": INVALID_REQUEST_DETAIL}
    assert not _account_exists(db, address)
