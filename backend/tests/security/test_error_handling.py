"""Error-boundary tests for SEC-08.

Every error reply must carry the same envelope, withhold internal
detail, and quote a correlation identifier the server log repeats.

Two channels are checked. The reply is read for internal detail. The
server record is read for text the caller supplied or a provider returned:
a request path, a request method, an undeclared key name, a driver
diagnostic and a statement. The record is checked at the handler that
writes it as well as through ``caplog``. DL-379
"""
import io
import json
import logging
from contextlib import contextmanager
from datetime import datetime

import pytest
from conftest import ALLOWED_ORIGIN, test_engine
from fastapi.exceptions import StarletteHTTPException
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from backend.app.core.config import settings
from backend.app.core.security import (
    SESSION_COOKIE_NAME,
    create_access_token,
)
from backend.app.db.database import engine as application_engine
from backend.app.db.database import get_db
from backend.app.db.models import Base, User
from backend.app.main import (
    _APPLICATION_LOGGER_NAME,
    _ApplicationLogHandler,
    _DIAGNOSTIC_BURST,
    _JOINED_LINE_MARKER,
    _LOG_LEVEL,
    _MAX_DIAGNOSTIC_BYTES,
    _MAX_RENDERED_FRAMES,
    _SUPPRESSED_DIAGNOSTICS,
    _TRUNCATION_MARKER,
    _UNMATCHED_ROUTE,
    _UNSERVED_METHOD,
    _configure_application_logging,
    _redact,
    app,
    logger as application_logger,
)

# SEC-08: the key set every handler registered in backend/app/main.py
# emits, whatever the status
ERROR_ENVELOPE_KEYS = {"detail", "error_id", "fields"}

GENERIC_SERVER_DETAIL = "Internal server error"

SUBMITTED_VALUE_SENTINEL = "zzz-sentinel-9137"

# SEC-08: values bound into a real duplicate-key failure, shaped as the
# address and the stored hash a registration writes
BOUND_ADDRESS_SENTINEL = "zzz-bound-address-8827@example.test"
BOUND_HASH_SENTINEL = "$2b$12$zzzBoundHashSentinel8827abcdefghijklmno"

# SEC-08: the text SQLAlchemy substitutes for withheld bound values
PARAMETERS_WITHHELD_MARKER = "SQL parameters hidden"

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
POLICY_PASSWORD = "Sec08Fixture1!Value"  # blitzy-scan-allow: test fixture

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
# replaces it with the status phrase; it reaches no caller.
_DUPLICATE_INTERNAL_DETAIL = "Email already registered"

# SEC-08: the text a PostgreSQL driver returns when a unique constraint
# rejects a row. The diagnostic line quotes the column value, so the
# provider hands back content the caller submitted.
PLANTED_ROW_ADDRESS = "zzz-planted-row-6021@example.com"
PLANTED_ROW_SECRET = "zzz-planted-row-value-6022"
PLANTED_CONSTRAINT = "zzz_planted_unique_6023"
PLANTED_STATEMENT = (
    "INSERT INTO zzz_planted_6024 (email, hashed_password) VALUES "
    "(%(email)s, %(hashed_password)s)"
)
PLANTED_SQLSTATE = "23505"

# SEC-08: the request line a caller controls. A path segment and a query
# value are caller-supplied text, and the record names the matched route
# (CWE-117).
PLANTED_PATH = "/missing/{0}/{1}".format(
    PLANTED_BEARER, PLANTED_ROW_ADDRESS
)
PLANTED_METHOD = "ZZZMETHOD-6025"
PLANTED_QUERY_VALUE = "zzz-planted-query-6026"


class _DuplicateAddress(Exception):
    """A driver exception shaped like the one psycopg2 raises.

    The message carries the constraint name and a diagnostic line quoting
    the rejected column value, which is the shape that makes rendering a
    database exception into a disclosure.
    """

    pgcode = PLANTED_SQLSTATE

    def __str__(self):
        return (
            'duplicate key value violates unique constraint "{0}"\n'
            'DETAIL:  Key (email)=({1}) already exists.\n'.format(
                PLANTED_CONSTRAINT, PLANTED_ROW_ADDRESS
            )
        )


def _driver_rejection():
    """Return an IntegrityError carrying driver text and bound values."""
    return IntegrityError(
        PLANTED_STATEMENT,
        {
            "email": PLANTED_ROW_ADDRESS,
            "hashed_password": PLANTED_ROW_SECRET,
        },
        _DuplicateAddress(),
    )


def _rejection_caught_and_reraised():
    """Return a plain error whose context is a driver rejection.

    A driver failure caught and re-raised as an ordinary error reaches the
    generic handler, which renders the whole formatted report - including
    the context exception's own message.
    """
    try:
        raise _driver_rejection()
    except SQLAlchemyError:
        try:
            raise RuntimeError(EXCEPTION_TEXT_SENTINEL)
        except RuntimeError as reraised:
            return reraised


def _assert_no_provider_text(text):
    """Assert one text quotes no driver diagnostic and no statement."""
    for planted in (
        PLANTED_ROW_ADDRESS,
        PLANTED_ROW_SECRET,
        PLANTED_CONSTRAINT,
        PLANTED_STATEMENT,
        "DETAIL:",
        "duplicate key value",
        "INSERT INTO zzz_planted_6024",
    ):
        assert planted not in text, planted


def _owned_handler():
    """Return the single diagnostic handler this application installs."""
    owned = [
        handler
        for handler in logging.getLogger(_APPLICATION_LOGGER_NAME).handlers
        if isinstance(handler, _ApplicationLogHandler)
    ]
    assert len(owned) == 1
    return owned[0]


def _record_naming(caplog, error_id):
    """Return the single record quoting one correlation identifier."""
    matching = [
        record
        for record in caplog.records
        if error_id in record.getMessage()
    ]
    assert len(matching) == 1
    return matching[0]


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

    Every other call reaches the real session: the route's pre-check
    query, its insert and its rollback behave normally and the commit
    alone fails. DL-378
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
    """Yield a factory that makes the session dependency raise.

    Replaces the one harness override key for the span of a context and
    restores it afterwards. DL-378
    """
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
    content. The field list is asserted to carry no offset. DL-384
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
    # identifier is excluded; it is random hex carrying no information
    # about the request.
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
    middleware, which nests it inside, so the envelope and the correlation
    identifier reach the browser. DL-384
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

    No row holds the address when the pre-check runs, and the commit
    alone fails. The route answers with the same 400 the pre-check
    raises, and the failed transaction is rolled back. DL-378
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
    # SEC-08: the failed request's transaction is rolled back
    assert views and views[-1].rolled_back


def _bound_row():
    """Return one insertable user row carrying both sentinels."""
    return {
        "email": BOUND_ADDRESS_SENTINEL,
        "hashed_password": BOUND_HASH_SENTINEL,
        "created_at": datetime.utcnow(),
    }


def _duplicate_key_failure(bound_engine):
    """Return a real duplicate-key failure raised by one engine.

    Both rows carry the same address. The unique index refuses the
    statement and the raised error holds the bound values.
    """
    Base.metadata.create_all(bind=bound_engine)
    try:
        with bound_engine.begin() as connection:
            connection.execute(
                User.__table__.insert(), [_bound_row(), _bound_row()]
            )
    except IntegrityError as failure:
        return failure
    raise AssertionError("the duplicate insert was accepted")


def test_the_engine_withholds_bound_parameters_from_a_real_failure():
    """A real duplicate-key failure on the application engine carries no
    bound value.

    The suppression sits on the engine, which also covers the consumers
    that never reach an HTTP handler, such as the listing task printing
    the exception it catches. DL-384
    """
    # SEC-08: the engine-level setting, asserted directly
    assert application_engine.hide_parameters is True

    failure = _duplicate_key_failure(application_engine)
    reported = str(failure)

    assert BOUND_ADDRESS_SENTINEL not in reported
    assert BOUND_HASH_SENTINEL not in reported
    assert PARAMETERS_WITHHELD_MARKER in reported


def test_the_handler_withholds_bound_parameters_from_a_real_failure(
    client, failing_database, caplog
):
    """A parameter-bearing failure reaching the handler leaves no bound
    value in the reply or the log.

    The harness engine keeps its parameters, so the values reach the
    handler and its own suppression is the one under assertion. DL-384
    """
    caplog.set_level(logging.ERROR)
    failure = _duplicate_key_failure(test_engine)
    assert BOUND_ADDRESS_SENTINEL in str(failure)

    with failing_database(failure):
        response = client.get("/listings/")

    assert response.status_code == 500
    body = _assert_uniform_envelope(response)
    assert body["detail"] == GENERIC_SERVER_DETAIL
    # SEC-08: neither channel repeats a bound value
    assert BOUND_ADDRESS_SENTINEL not in response.text
    assert BOUND_HASH_SENTINEL not in response.text
    assert caplog.records
    assert BOUND_ADDRESS_SENTINEL not in caplog.text
    assert BOUND_HASH_SENTINEL not in caplog.text


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
    # SEC-08: the log carries the diagnostics the caller never receives
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

    # SEC-08: the held values are read when the record is built; a value
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

    Both channels are checked against the whole serialized reply, every
    envelope field included.
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


def test_a_database_error_withholds_the_driver_diagnostic(
    client, failing_database, caplog
):
    """The record diagnoses a rejected row without quoting it.

    A driver diagnostic names the column and the value that failed, and
    the statement names the table and the row it wrote. Neither is a
    server fact: both are the request, handed back by the provider.
    """
    caplog.set_level(logging.ERROR)
    with failing_database(_driver_rejection()):
        response = client.get("/listings/")

    assert response.status_code == 500
    body = _assert_uniform_envelope(response)
    assert body["detail"] == GENERIC_SERVER_DETAIL
    message = _record_naming(caplog, body["error_id"]).getMessage()

    # SEC-08: the record identifies the failure by type and SQLSTATE
    assert "sqlalchemy.exc.IntegrityError" in message
    assert "_DuplicateAddress" in message
    assert "sqlstate={0}".format(PLANTED_SQLSTATE) in message
    assert "origin=" in message

    # SEC-08: and quotes no provider text, on either channel
    _assert_no_provider_text(message)
    _assert_no_provider_text(caplog.text)
    _assert_no_provider_text(response.text)
    _assert_no_internal_detail(response.text)


def test_a_reraised_database_error_withholds_the_driver_diagnostic(
    client, failing_database, caplog
):
    """A rendered report drops the driver text its context carries.

    The generic handler formats the whole exception report, including a
    re-raised driver rejection rendered through its context exception's
    message and bound parameters. DL-384
    """
    caplog.set_level(logging.ERROR)
    with failing_database(_rejection_caught_and_reraised()):
        response = client.get("/listings/")

    assert response.status_code == 500
    body = _assert_uniform_envelope(response)
    message = _record_naming(caplog, body["error_id"]).getMessage()

    # SEC-08: the diagnosis survives - both exceptions and the traceback
    assert "Traceback (most recent call last)" in message
    assert EXCEPTION_TEXT_SENTINEL in message
    assert "sqlalchemy.exc.IntegrityError" in message

    # SEC-08: the rendered statement and parameter blocks are emptied
    assert "[SQL: {0}]".format(REDACTION_MARKER) in message
    assert "hide_parameters=True" in message

    _assert_no_provider_text(message)
    _assert_no_provider_text(caplog.text)
    _assert_no_provider_text(response.text)
    _assert_no_internal_detail(response.text)


def test_an_unmatched_route_answers_the_sanitized_404(client, caplog):
    """A path that matches nothing answers the shared envelope.

    The reply is checked for the envelope, and the record is checked for
    the path: an unmatched request line is entirely caller-supplied, so
    writing it verbatim forges log content (CWE-117).
    """
    caplog.set_level(logging.WARNING)
    response = client.get(PLANTED_PATH)

    assert response.status_code == 404
    body = _assert_uniform_envelope(response)
    assert body["detail"] == "Not Found"
    assert body["fields"] == []
    _assert_no_internal_detail(response.text)

    message = _record_naming(caplog, body["error_id"]).getMessage()
    assert "status=404" in message
    # SEC-08: no route matched, so the record names the marker
    assert _UNMATCHED_ROUTE in message
    for planted in (PLANTED_BEARER, PLANTED_ROW_ADDRESS, PLANTED_PATH):
        assert planted not in message, planted
        assert planted not in caplog.text, planted
        assert planted not in response.text, planted


def test_an_unserved_method_names_the_marker_not_the_method(client, caplog):
    """A method the route does not serve is named by a marker."""
    caplog.set_level(logging.WARNING)
    response = client.request(PLANTED_METHOD, "/listings/")

    assert response.status_code == 405
    body = _assert_uniform_envelope(response)
    assert body["detail"] == "Method Not Allowed"

    message = _record_naming(caplog, body["error_id"]).getMessage()
    assert "status=405" in message
    # SEC-08: the verb is caller-supplied text, the route is not
    assert _UNSERVED_METHOD in message
    assert "/listings/" in message
    assert PLANTED_METHOD not in message
    assert PLANTED_METHOD not in caplog.text
    assert PLANTED_METHOD not in response.text


def test_a_matched_route_names_the_template_not_the_query(client, caplog):
    """A rejected query value stays out of the record."""
    caplog.set_level(logging.WARNING)
    response = client.get(
        "/listings/", params={"limit": PLANTED_QUERY_VALUE}
    )

    assert response.status_code == 422
    body = _assert_uniform_envelope(response)
    # SEC-08: the caller is told which field was rejected
    assert body["fields"] == ["limit"]
    assert PLANTED_QUERY_VALUE not in response.text

    message = _record_naming(caplog, body["error_id"]).getMessage()
    # SEC-08: the matched route reaches the record, the query does not
    assert "/listings/" in message
    assert "fields=limit" in message
    assert PLANTED_QUERY_VALUE not in message
    assert PLANTED_QUERY_VALUE not in caplog.text


def test_the_application_logger_owns_a_configured_handler():
    """The package logger carries a handler, a level and a format.

    The case reads the handler, the level and the format string off the
    package logger (CWE-778). DL-364
    """
    package_logger = logging.getLogger(_APPLICATION_LOGGER_NAME)
    assert package_logger.level == _LOG_LEVEL

    handler = _owned_handler()
    assert handler.level == _LOG_LEVEL
    assert isinstance(handler.formatter, logging.Formatter)
    assert handler.stream is not None

    # SEC-08: every module logger resolves to it, and propagation stays
    # intact for a deployment sink above, which receives the folded
    # record; the case below drives that path
    assert application_logger.name.startswith(
        "{0}.".format(_APPLICATION_LOGGER_NAME)
    )
    assert application_logger.getEffectiveLevel() == _LOG_LEVEL

    # SEC-08: repeated configuration attaches no second handler and chains
    # no second record factory
    factory = logging.getLogRecordFactory()
    _configure_application_logging()
    assert _owned_handler() is handler
    assert logging.getLogRecordFactory() is factory


def test_the_owned_handler_records_one_line_without_a_root_handler(
    client, failing_database
):
    """A diagnosed failure reaches the owned sink as a single line."""
    handler = _owned_handler()
    root_logger = logging.getLogger()
    held_handlers = list(root_logger.handlers)
    held_stream = handler.stream
    captured = io.StringIO()

    root_logger.handlers = []
    handler.stream = captured
    try:
        with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
            response = client.get("/listings/")
    finally:
        handler.stream = held_stream
        root_logger.handlers = held_handlers

    assert response.status_code == 500
    error_id = response.json()["error_id"]
    written = captured.getvalue()

    # SEC-08: one record, one line, whatever the deployment configures
    lines = written.splitlines()
    assert len(lines) == 1
    line = lines[0]
    assert error_id in line
    assert "ERROR" in line
    assert application_logger.name in line

    # SEC-08: the traceback is joined, so a collector keeps the diagnosis
    # attached to the identifier (CWE-778)
    assert _JOINED_LINE_MARKER in line
    assert "Traceback (most recent call last)" in line
    assert EXCEPTION_TEXT_SENTINEL in line
    assert EXCEPTION_TEXT_SENTINEL not in response.text


@contextmanager
def _ancestor_sink(only=_APPLICATION_LOGGER_NAME):
    """Attach a root handler carrying the stock formatter.

    The deployment shape under assertion: a sink above the package,
    carrying no knowledge of this application's format. ``only`` admits
    one logger subtree. DL-379
    """
    captured = io.StringIO()
    sink = logging.StreamHandler(stream=captured)
    sink.setLevel(logging.NOTSET)
    sink.setFormatter(logging.Formatter())
    sink.addFilter(logging.Filter(only))
    root_logger = logging.getLogger()
    held_handlers = list(root_logger.handlers)
    held_level = root_logger.level

    root_logger.handlers = [sink]
    root_logger.setLevel(logging.NOTSET)
    try:
        yield captured
    finally:
        root_logger.handlers = held_handlers
        root_logger.setLevel(held_level)


def test_an_ancestor_handler_receives_one_line_too(client, failing_database):
    """A root sink with the stock formatter records one line.

    The record reaching this sink is asserted to be one line
    (CWE-117, CWE-778). DL-379
    """
    with _ancestor_sink() as captured:
        with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
            response = client.get("/listings/")

    assert response.status_code == 500
    error_id = response.json()["error_id"]
    written = captured.getvalue()

    # SEC-08: one record, one line, at a sink this application never
    # configured
    lines = [line for line in written.splitlines() if line]
    assert len(lines) == 1, written
    line = lines[0]
    assert error_id in line
    assert _JOINED_LINE_MARKER in line
    assert "Traceback (most recent call last)" in line
    assert EXCEPTION_TEXT_SENTINEL in line
    assert EXCEPTION_TEXT_SENTINEL not in response.text


@pytest.mark.parametrize(
    "planted",
    (
        "first\nsecond",
        "first\r\nsecond",
        "first\rsecond",
        "carried\x1b[31mescape",
        "carried\x7fdelete",
        "carried\vvertical",
    ),
    ids=(
        "newline",
        "carriage-return-newline",
        "bare-carriage-return",
        "terminal-escape",
        "delete",
        "vertical-tab",
    ),
)
def test_a_control_character_never_reaches_a_sink(planted):
    """Every control character in a record is replaced before any sink.

    The replacement covers every C0 code point and DEL, the carriage
    return and the escape included (CWE-117). DL-364
    """
    with _ancestor_sink() as captured:
        application_logger.error("planted=%s", planted)

    written = captured.getvalue()
    lines = [line for line in written.splitlines() if line]
    assert len(lines) == 1, written
    for character in "\n\r\x1b\x7f\v":
        assert character not in lines[0], repr(character)
    assert _JOINED_LINE_MARKER in lines[0]


def test_the_fold_survives_exception_information_on_the_record():
    """A record carrying exc_info reaches a sink as one line."""
    with _ancestor_sink() as captured:
        try:
            raise RuntimeError(EXCEPTION_TEXT_SENTINEL)
        except RuntimeError:
            application_logger.error("planted failure", exc_info=True)

    written = captured.getvalue()
    lines = [line for line in written.splitlines() if line]
    assert len(lines) == 1, written
    assert "Traceback (most recent call last)" in lines[0]
    assert EXCEPTION_TEXT_SENTINEL in lines[0]


def test_a_record_from_another_library_is_left_alone():
    """A record outside this package keeps its own text.

    The fold is scoped by logger name. A third-party record keeps its
    text and its exception information.
    """
    foreign = logging.getLogger("zzz_foreign_library.probe")
    with _ancestor_sink(only="zzz_foreign_library") as captured:
        foreign.error("first\nsecond")

    written = captured.getvalue()
    assert written.splitlines()[:2] == ["first", "second"]


# ---------------------------------------------------------------------
# The diagnostic channel is bounded in size and in volume
# ---------------------------------------------------------------------
def _records_naming(caplog, error_id):
    """Return every record quoting one correlation identifier."""
    return [
        record
        for record in caplog.records
        if error_id in record.getMessage()
    ]


def test_every_repeat_of_one_failure_is_still_recorded_once(
    client, failing_database, caplog
):
    """Each reply's identifier resolves to exactly one record.

    The budget below bounds what a record carries, never whether one is
    written: a reference handed to a caller that resolves to nothing is
    an unusable reference.
    """
    caplog.set_level(logging.ERROR)
    replies = []
    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        for _ in range(_DIAGNOSTIC_BURST + 3):
            replies.append(client.get("/listings/"))

    identifiers = [reply.json()["error_id"] for reply in replies]
    assert all(reply.status_code == 500 for reply in replies)
    assert len(set(identifiers)) == len(identifiers)
    for error_id in identifiers:
        assert len(_records_naming(caplog, error_id)) == 1, error_id


def test_the_diagnostic_report_is_rendered_within_a_budget(
    client, failing_database, caplog
):
    """One route and one exception type render a bounded number of
    reports.

    A client that can reach a failing route repeats it as often as it
    likes. Rendering, scrubbing and writing a full traceback for every
    occurrence turns that into an unbounded amount of work on the request
    path and an unbounded volume of log (CWE-770), so the report is
    rendered within a window's budget and every occurrence past it is
    recorded compactly.
    """
    caplog.set_level(logging.ERROR)
    messages = []
    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        for _ in range(_DIAGNOSTIC_BURST + 3):
            reply = client.get("/listings/")
            assert reply.status_code == 500
            messages.append(
                _record_naming(caplog, reply.json()["error_id"]).getMessage()
            )

    rendered = [
        message for message in messages
        if "Traceback (most recent call last)" in message
    ]
    compact = [
        message for message in messages
        if "diagnostics={0}".format(_SUPPRESSED_DIAGNOSTICS) in message
    ]

    # SEC-08: the budget is spent on the first occurrences, and the rest
    # are recorded without a rendered report
    assert len(rendered) == _DIAGNOSTIC_BURST
    assert len(compact) == len(messages) - _DIAGNOSTIC_BURST
    assert messages[:_DIAGNOSTIC_BURST] == rendered

    # SEC-08: a compact record still identifies the failure, counts the
    # occurrence it stands for, and carries no rendered report
    for position, message in enumerate(compact, start=_DIAGNOSTIC_BURST + 1):
        assert "RuntimeError" in message
        assert "occurrence={0} ".format(position) in message
        assert "Traceback (most recent call last)" not in message
        assert EXCEPTION_TEXT_SENTINEL not in message

    # SEC-08: a compact record is a fraction of a rendered one
    assert max(len(message) for message in compact) < min(
        len(message) for message in rendered
    )


def test_a_diagnostic_record_stays_within_its_size_ceiling(
    client, failing_database, caplog
):
    """A rendered record is bounded however long the failure text is.

    An exception whose own message is long would otherwise decide the
    size of a log record, so the rendered report stops at the ceiling and
    says that it did.
    """
    caplog.set_level(logging.ERROR)
    long_text = "{0}-{1}".format(
        EXCEPTION_TEXT_SENTINEL, "y" * (4 * _MAX_DIAGNOSTIC_BYTES)
    )

    with failing_database(RuntimeError(long_text)):
        response = client.get("/listings/")

    assert response.status_code == 500
    message = _record_naming(caplog, response.json()["error_id"]).getMessage()

    # SEC-08: the report is truncated and marked, and the record stays
    # within a bound the failure text cannot move
    assert _TRUNCATION_MARKER in message
    assert len(message) < 2 * _MAX_DIAGNOSTIC_BYTES

    # SEC-08: the diagnosis still identifies the failure
    assert "RuntimeError" in message
    assert EXCEPTION_TEXT_SENTINEL in message
    assert "Traceback (most recent call last)" in message

    # SEC-08: and the caller still receives the reference alone
    assert EXCEPTION_TEXT_SENTINEL not in response.text
    _assert_no_internal_detail(response.text)


def test_a_rendered_report_keeps_the_innermost_frames(
    client, failing_database, caplog
):
    """The bounded report keeps the frames that raised the failure.

    The outer frames of a request are the same server stack every time.
    The innermost ones name the code that failed, so those are the frames
    the bound keeps.
    """
    caplog.set_level(logging.ERROR)
    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        response = client.get("/listings/")

    assert response.status_code == 500
    message = _record_naming(caplog, response.json()["error_id"]).getMessage()

    # SEC-08: the frame that raised is present, and the report carries no
    # more frames than the bound allows per rendered exception
    assert "in _raising_get_db" in message
    quoted_frames = message.count('File "')
    assert 0 < quoted_frames <= _MAX_RENDERED_FRAMES * 2


def test_redaction_removes_a_credential_named_with_a_prefix():
    """A prefixed credential name is redacted with its value.

    The scrubber matches the credential word, so an identifier that ends
    with it - a signing key, a client secret, an api token - is covered
    while the identifier itself stays readable in the record (CWE-532).
    """
    planted = (
        "signing_key=zzz-prefixed-signing-7401 "
        "client_secret="  # blitzy-scan-allow: planted fixture
        "'zzz-prefixed-client-7402' "
        'api-token: "zzz-prefixed-api-7403" '
        "COOKIE=zzz-prefixed-cookie-7404 "
        "passphrase=zzz-prefixed-phrase-7405"
    )

    scrubbed = _redact(planted)

    for secret in (
        "zzz-prefixed-signing-7401",
        "zzz-prefixed-client-7402",
        "zzz-prefixed-api-7403",
        "zzz-prefixed-cookie-7404",
        "zzz-prefixed-phrase-7405",
    ):
        assert secret not in scrubbed, secret

    # SEC-08: the name is left in place, so a reader still sees which
    # value was removed
    for name in ("signing_", "client_", "api-", "COOKIE", "passphrase"):
        assert name in scrubbed, name
    assert scrubbed.count(REDACTION_MARKER) == 5
