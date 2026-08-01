"""Error-boundary tests for SEC-08.

Every error reply must carry the same envelope, withhold internal
detail, and quote a correlation identifier the server log repeats.
"""
import json
import logging
from contextlib import contextmanager

import pytest
from conftest import ALLOWED_ORIGIN
from fastapi.exceptions import StarletteHTTPException
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from backend.app.core.config import settings
from backend.app.core.security import (
    SESSION_COOKIE_NAME,
    create_access_token,
)
from backend.app.db.database import get_db
from backend.app.main import app

# SEC-08: the key set every handler registered in backend/app/main.py
# emits, whatever the status
ERROR_ENVELOPE_KEYS = {"detail", "error_id", "fields"}

GENERIC_SERVER_DETAIL = "Internal server error"

SUBMITTED_VALUE_SENTINEL = "zzz-sentinel-9137"

# SEC-08: exception text the reply withholds and the server log carries
EXCEPTION_TEXT_SENTINEL = "zzz-exception-text-4412"

# SEC-08: secrets planted inside an exception message, each in the shape
# a diagnostic record has to strip before a handler receives it
PLANTED_SIGNING_KEY = "zzz-planted-signing-key-7781-abcdefghijklmnop"
PLANTED_DSN = (
    "postgresql://svcuser:zzz-planted-dsn-2244@db.internal:5432/appdb"
)
PLANTED_DSN_CREDENTIAL = "zzz-planted-dsn-2244"
PLANTED_BEARER = "zzz-planted-bearer-5150-qrstuvwx"
REDACTION_MARKER = "[redacted]"

# SEC-04: a synthetic fixture value clearing every rule in
# backend/app/schema/user.py - at least twelve characters with one
# uppercase, one lowercase, one digit and one listed special character
POLICY_PASSWORD = "Sec08Fixture1!Value"

# SEC-08: markers of a leaked traceback, source location or SQL
# statement, matched without regard to case
_LEAK_MARKERS_ANY_CASE = (
    "traceback",
    'file "',
    ".py",
    "/backend/",
    "site-packages",
    "sqlalchemy",
    "sqlstate",
    "origin=",
    "line ",
)

# SEC-08: exception and statement names, matched with their own casing
_LEAK_MARKERS_EXACT_CASE = (
    "RuntimeError",
    "NameError",
    "SQLAlchemyError",
    "OperationalError",
    "IntegrityError",
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
)

# SEC-07: an upper bound on the login attempts the throttle case sends
_LOGIN_ATTEMPT_CEILING = 25

# SEC-08: a body no JSON parser accepts. The parser reports the position
# it stopped at, and that position measures the submitted content.
NON_JSON_BODY = b"this-is-not-json-" + b"x" * 40

# SEC-08: the cross-origin headers a reply from inside the CORS layer
# carries. A reply from outside it carries none of them.
_ALLOW_ORIGIN_HEADER = "Access-Control-Allow-Origin"
_ALLOW_CREDENTIALS_HEADER = "Access-Control-Allow-Credentials"

# SEC-08: the detail the duplicate-address guard raises. The boundary
# replaces it with the status phrase, so it must not reach the caller.
_DUPLICATE_INTERNAL_DETAIL = "Email already registered"


def _bearer(token):
    """Return the Authorization header carrying one bearer token."""
    return {"Authorization": "Bearer {0}".format(token)}


def _assert_uniform_envelope(response):
    """Return the reply body after checking the shared envelope keys."""
    body = response.json()
    assert set(body) == ERROR_ENVELOPE_KEYS
    assert isinstance(body["detail"], str)
    assert body["detail"]
    assert isinstance(body["fields"], list)
    error_id = body["error_id"]
    assert isinstance(error_id, str)
    assert error_id
    assert not any(character.isspace() for character in error_id)
    return body


def _assert_no_internal_detail(text):
    """Assert one text names no traceback, source path or statement."""
    lowered = text.lower()
    for marker in _LEAK_MARKERS_ANY_CASE:
        assert marker not in lowered, marker
    for marker in _LEAK_MARKERS_EXACT_CASE:
        assert marker not in text, marker


def _login_until_throttled(client, email):
    """Return the first 429 response from repeated failed logins."""
    rejected = 0
    for _ in range(_LOGIN_ATTEMPT_CEILING):
        response = client.post(
            "/auth/login",
            json={"email": email, "password": POLICY_PASSWORD},
        )
        if response.status_code == 401:
            rejected += 1
            continue
        assert response.status_code == 429
        assert rejected >= 1
        return response
    raise AssertionError(
        "the login route answered 401 for {0} attempts and never "
        "throttled".format(_LOGIN_ATTEMPT_CEILING)
    )


class _CommitLosesTheRace:
    """A session view whose commit reports a duplicate key.

    Every other call reaches the real session, so the route's pre-check
    query, its insert and its rollback all behave normally and only the
    commit fails - which is the shape of a lost unique-address race.
    """

    def __init__(self, session):
        self._session = session
        self.rolled_back = False

    def __getattr__(self, name):
        return getattr(self._session, name)

    def commit(self):
        raise IntegrityError(
            "INSERT INTO users", {}, Exception("duplicate key value")
        )

    def rollback(self):
        self.rolled_back = True
        self._session.rollback()


@pytest.fixture
def failing_database(client):
    """Yield a factory that makes the session dependency raise."""
    harness_override = app.dependency_overrides.get(get_db)

    def _restore():
        # SEC-08: restores the single harness override key
        if harness_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = harness_override

    @contextmanager
    def _failing(exception):
        def _raising_get_db():
            raise exception
            yield

        app.dependency_overrides[get_db] = _raising_get_db
        try:
            yield
        finally:
            _restore()

    try:
        yield _failing
    finally:
        _restore()


@pytest.fixture
def losing_the_commit_race(client):
    """Yield a factory that makes the registration commit lose a race."""
    harness_override = app.dependency_overrides[get_db]

    @contextmanager
    def _racing():
        views = []

        def _racing_get_db():
            session = next(harness_override())
            view = _CommitLosesTheRace(session)
            views.append(view)
            try:
                yield view
            finally:
                session.close()

        app.dependency_overrides[get_db] = _racing_get_db
        try:
            yield views
        finally:
            # SEC-08: restores the single harness override key
            app.dependency_overrides[get_db] = harness_override

    try:
        yield _racing
    finally:
        app.dependency_overrides[get_db] = harness_override


def test_forced_internal_error_returns_a_sanitized_500(
    client, failing_database
):
    """An unhandled failure answers 500 with no exception detail."""
    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        response = client.get("/listings/")

    assert response.status_code == 500
    body = _assert_uniform_envelope(response)
    assert body["detail"] == GENERIC_SERVER_DETAIL
    assert body["fields"] == []
    _assert_no_internal_detail(response.text)
    assert EXCEPTION_TEXT_SENTINEL not in response.text


def test_database_error_returns_the_same_sanitized_500(
    client, failing_database
):
    """A database failure answers 500 with no query or driver text."""
    with failing_database(SQLAlchemyError(EXCEPTION_TEXT_SENTINEL)):
        response = client.get("/listings/")

    assert response.status_code == 500
    body = _assert_uniform_envelope(response)
    assert body["detail"] == GENERIC_SERVER_DETAIL
    assert body["fields"] == []
    _assert_no_internal_detail(response.text)
    assert EXCEPTION_TEXT_SENTINEL not in response.text


def test_an_endpoint_failure_returns_the_sanitized_500(
    client, registered_user
):
    """A live endpoint failure reaches the same sanitized 500."""
    response = client.get(
        "/subscriptions/",
        headers=_bearer(registered_user["access_token"]),
    )

    assert response.status_code == 500
    body = _assert_uniform_envelope(response)
    assert body["detail"] == GENERIC_SERVER_DETAIL
    assert body["fields"] == []
    _assert_no_internal_detail(response.text)


def test_validation_error_names_fields_and_withholds_values(client):
    """A rejected body names its fields and repeats no submitted value."""
    response = client.post(
        "/auth/register",
        json={
            "email": SUBMITTED_VALUE_SENTINEL,
            "password": SUBMITTED_VALUE_SENTINEL,
        },
    )

    assert response.status_code == 422
    body = _assert_uniform_envelope(response)
    assert set(body["fields"]) == {"email", "password"}
    assert SUBMITTED_VALUE_SENTINEL not in response.text
    _assert_no_internal_detail(response.text)


def test_a_body_that_is_not_json_reports_no_byte_offset(client):
    """A body no parser accepts is refused without measuring it.

    The parser locates the failure by an offset into the submitted
    content, so promoting that offset into the field list would publish
    a measurement of the request body back to its sender.
    """
    response = client.post(
        "/auth/register",
        content=NON_JSON_BODY,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    body = _assert_uniform_envelope(response)
    # SEC-08: an offset is a measurement of the body, never a field name
    assert body["fields"] == []
    # SEC-08: no number reaches the caller at all. The correlation
    # identifier is excluded because it is random hex and carries no
    # information about the request.
    reportable = json.dumps(
        {key: value for key, value in body.items() if key != "error_id"}
    )
    assert not [
        character for character in reportable if character.isdigit()
    ], reportable
    # SEC-08: the submitted bytes do not return either
    assert NON_JSON_BODY.decode() not in response.text
    _assert_no_internal_detail(response.text)


def test_a_sanitized_500_reaches_an_allow_listed_origin(
    client, failing_database
):
    """A 500 carries the cross-origin headers every other status does.

    The sanitized layer is registered ahead of the cross-origin
    middleware, which nests it inside. Moving it outside would leave a
    browser reading an opaque network failure instead of the envelope
    and the correlation identifier inside it.
    """
    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        response = client.get(
            "/listings/", headers={"Origin": ALLOWED_ORIGIN}
        )

    assert response.status_code == 500
    body = _assert_uniform_envelope(response)
    assert body["detail"] == GENERIC_SERVER_DETAIL
    # SEC-08: the failure is answered from inside the cross-origin layer
    assert response.headers[_ALLOW_ORIGIN_HEADER] == ALLOWED_ORIGIN
    assert response.headers[_ALLOW_CREDENTIALS_HEADER] == "true"
    assert "origin" in response.headers.get("vary", "").lower()
    assert response.headers["content-type"].startswith("application/json")
    _assert_no_internal_detail(response.text)
    assert EXCEPTION_TEXT_SENTINEL not in response.text


def test_a_lost_unique_address_race_answers_bad_request(
    client, losing_the_commit_race, unique_email
):
    """A registration losing the unique-address race is not a 500.

    The pre-check clears because no row holds the address yet, so only
    the commit fails. The route answers with the same 400 the pre-check
    raises, and the failed transaction is rolled back.
    """
    with losing_the_commit_race() as views:
        response = client.post(
            "/auth/register",
            json={"email": unique_email, "password": POLICY_PASSWORD},
        )

    # SEC-08: a lost race is a rejected request, never a server fault
    assert response.status_code != 500, response.text
    assert response.status_code == 400, response.text
    body = _assert_uniform_envelope(response)
    assert body["fields"] == []
    # SEC-08: the raised detail is replaced by the status phrase
    assert _DUPLICATE_INTERNAL_DETAIL not in response.text
    _assert_no_internal_detail(response.text)
    # SEC-08: the open transaction is discarded rather than left behind
    assert views and views[-1].rolled_back


def test_the_error_envelope_is_uniform_across_handlers(
    client, failing_database, registered_user, unique_email
):
    """Every handler answers with the same envelope key set."""
    collected = [
        client.post(
            "/auth/register",
            json={
                "email": SUBMITTED_VALUE_SENTINEL,
                "password": SUBMITTED_VALUE_SENTINEL,
            },
        ),
        client.get("/filters/", headers=_bearer("not.a.jwt")),
        client.post(
            "/filters/",
            json={"name": "", "criteria": []},
            headers=_bearer(registered_user["access_token"]),
        ),
        _login_until_throttled(client, unique_email),
    ]
    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        collected.append(client.get("/listings/"))
    with failing_database(SQLAlchemyError(EXCEPTION_TEXT_SENTINEL)):
        collected.append(client.get("/listings/"))

    statuses = [response.status_code for response in collected]
    assert statuses == [422, 401, 400, 429, 500, 500]
    key_sets = [set(response.json()) for response in collected]
    assert key_sets == [ERROR_ENVELOPE_KEYS] * len(collected)
    for response in collected:
        _assert_uniform_envelope(response)
        _assert_no_internal_detail(response.text)


def test_the_credential_guard_answers_every_failure_alike(client):
    """One 401 shape covers each way the credential guard fails."""
    responses = {
        "token_absent": client.get("/filters/"),
        "token_malformed": client.get(
            "/filters/", headers=_bearer("not.a.jwt")
        ),
        "subject_absent": client.get(
            "/filters/",
            headers=_bearer(create_access_token({"scope": "read"})),
        ),
        "subject_not_an_id": client.get(
            "/filters/",
            headers=_bearer(
                create_access_token({"sub": "someone@example.com"})
            ),
        ),
        "subject_unresolved": client.get(
            "/filters/",
            headers=_bearer(create_access_token({"sub": "999999"})),
        ),
    }
    collected = list(responses.values())

    for name, response in responses.items():
        assert response.status_code == 401, name
        _assert_uniform_envelope(response)
        _assert_no_internal_detail(response.text)

    # SEC-08: an absent account is answered as 401, never as 404
    assert responses["subject_unresolved"].status_code != 404
    details = {response.json()["detail"] for response in collected}
    assert len(details) == 1
    challenges = {
        response.headers.get("WWW-Authenticate") for response in collected
    }
    assert challenges == {"Bearer"}
    identifiers = {response.json()["error_id"] for response in collected}
    assert len(identifiers) == len(collected)


def test_the_correlation_identifier_joins_the_response_and_the_log(
    client, failing_database, caplog
):
    """The identifier in the 500 body appears in one log record."""
    caplog.set_level(logging.ERROR)
    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        response = client.get("/listings/")

    assert response.status_code == 500
    error_id = response.json()["error_id"]
    matching = [
        record
        for record in caplog.records
        if error_id in record.getMessage()
    ]
    assert len(matching) == 1
    record = matching[0]
    assert record.levelno >= logging.ERROR
    message = record.getMessage()
    # SEC-08: diagnostics reach the log, not the caller
    assert "RuntimeError" in message
    assert "origin=" in message
    # SEC-08: the record resolves the reference into a usable diagnosis -
    # the exception text, the traceback and the raising frame
    assert EXCEPTION_TEXT_SENTINEL in message
    assert "Traceback (most recent call last)" in message
    assert "in _raising_get_db" in message
    # SEC-08: the reply carries the reference and nothing else
    assert EXCEPTION_TEXT_SENTINEL not in response.text
    _assert_no_internal_detail(response.text)


def test_the_diagnostic_record_redacts_every_planted_secret(
    client, failing_database, caplog
):
    """A traceback quoting secrets reaches the log with them removed."""
    caplog.set_level(logging.ERROR)
    minted_token = create_access_token({"sub": "1"})
    planted = RuntimeError(
        "{0} signing_key={1} dsn={2} authorization: Bearer {3}"
        " session={4}".format(
            EXCEPTION_TEXT_SENTINEL,
            PLANTED_SIGNING_KEY,
            PLANTED_DSN,
            PLANTED_BEARER,
            minted_token,
        )
    )

    with failing_database(planted):
        response = client.get("/listings/")

    assert response.status_code == 500
    error_id = response.json()["error_id"]
    matching = [
        record
        for record in caplog.records
        if error_id in record.getMessage()
    ]
    # SEC-08: redaction does not split or duplicate the single record
    assert len(matching) == 1
    message = matching[0].getMessage()

    # SEC-08: the diagnosis survives redaction
    assert EXCEPTION_TEXT_SENTINEL in message
    assert "Traceback (most recent call last)" in message
    assert REDACTION_MARKER in message

    # SEC-08: no planted secret reaches the record in any shape
    for secret in (
        PLANTED_SIGNING_KEY,
        PLANTED_DSN_CREDENTIAL,
        PLANTED_BEARER,
        minted_token,
    ):
        assert secret not in message, secret
        assert secret not in caplog.text, secret

    # SEC-08: a redacted value never returns to the caller either
    assert PLANTED_SIGNING_KEY not in response.text
    assert minted_token not in response.text
    _assert_no_internal_detail(response.text)


def test_the_diagnostic_record_redacts_a_configured_secret(
    client, failing_database, caplog, monkeypatch
):
    """A traceback quoting a held setting value reaches the log without it."""
    caplog.set_level(logging.ERROR)
    held = {
        "SECRET_KEY": "zzz-held-signing-key-3061-abcdefghijklmnopqrstuv",
        "PAYPAL_CLIENT_SECRET": "zzz-held-paypal-credential-3062",
        "SENDGRID_API_KEY": "zzz-held-sendgrid-credential-3063",
        "ZILLOW_API_KEY": "zzz-held-zillow-credential-3064",
        "DATABASE_URL": PLANTED_DSN,
    }
    for name, value in held.items():
        monkeypatch.setattr(settings, name, value)

    planted = RuntimeError(
        "{0} {1}".format(
            EXCEPTION_TEXT_SENTINEL,
            " ".join(value for value in held.values()),
        )
    )
    with failing_database(planted):
        response = client.get("/listings/")

    assert response.status_code == 500
    message = "\n".join(record.getMessage() for record in caplog.records)
    assert EXCEPTION_TEXT_SENTINEL in message
    assert REDACTION_MARKER in message

    # SEC-08: the held values are read when the record is built, so a value
    # rotated after import is still removed
    for name, value in held.items():
        if name == "DATABASE_URL":
            assert PLANTED_DSN_CREDENTIAL not in message
            continue
        assert value not in message, name
    assert EXCEPTION_TEXT_SENTINEL not in response.text


@pytest.mark.parametrize(
    "status_code,diagnostics_expected", [(503, True), (418, False)]
)
def test_a_raised_status_opens_the_diagnostic_channel_at_500(
    client, failing_database, caplog, status_code, diagnostics_expected
):
    """A raised 5xx is diagnosed in the log; a raised 4xx is not."""
    caplog.set_level(logging.WARNING)
    raised = StarletteHTTPException(
        status_code=status_code, detail=EXCEPTION_TEXT_SENTINEL
    )

    with failing_database(raised):
        response = client.get("/listings/")

    assert response.status_code == status_code
    body = _assert_uniform_envelope(response)
    # SEC-08: the raised detail is replaced by the status phrase
    assert EXCEPTION_TEXT_SENTINEL not in response.text
    _assert_no_internal_detail(response.text)

    matching = [
        record
        for record in caplog.records
        if body["error_id"] in record.getMessage()
    ]
    assert len(matching) == 1
    message = matching[0].getMessage()
    assert ("Traceback (most recent call last)" in message) is (
        diagnostics_expected
    )
    if diagnostics_expected:
        # SEC-08: a server fault is recorded at the severity a 500 alert
        # already watches
        assert matching[0].levelno >= logging.ERROR


def test_the_log_withholds_the_password_the_token_and_the_cookie(
    client, failing_database, caplog
):
    """No log record and no reply repeats a submitted secret.

    Both channels are checked against the whole serialized reply, so a
    token echoed in any envelope field fails the case.
    """
    caplog.set_level(logging.ERROR)
    cookie_token = create_access_token({"sub": "1"})
    header_token = create_access_token({"sub": "2"})
    client.cookies.set(SESSION_COOKIE_NAME, cookie_token)

    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        response = client.post(
            "/auth/register",
            json={
                "email": "boundary-probe@example.com",
                "password": POLICY_PASSWORD,
            },
            headers=_bearer(header_token),
        )

    assert response.status_code == 500
    body = _assert_uniform_envelope(response)
    assert body["detail"] == GENERIC_SERVER_DETAIL
    assert body["fields"] == []
    assert caplog.records
    assert POLICY_PASSWORD not in caplog.text
    assert cookie_token not in caplog.text
    assert header_token not in caplog.text
    assert POLICY_PASSWORD not in response.text
    assert cookie_token not in response.text
    assert header_token not in response.text


def test_each_error_carries_its_own_correlation_identifier(
    client, failing_database
):
    """Two failures of one kind carry two different identifiers."""
    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        first = client.get("/listings/")
        second = client.get("/listings/")

    assert first.status_code == 500
    assert second.status_code == 500
    assert first.json()["error_id"] != second.json()["error_id"]


def test_the_harness_session_override_survives_a_forced_failure(
    client, failing_database
):
    """A forced failure leaves the harness database override in place."""
    harness_override = app.dependency_overrides[get_db]

    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        assert client.get("/listings/").status_code == 500

    assert app.dependency_overrides[get_db] is harness_override
    restored = client.get("/listings/")
    assert restored.status_code == 200
    assert restored.json() == []
