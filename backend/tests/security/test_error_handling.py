"""Error-boundary tests for SEC-08.

Every error reply must carry the same envelope, withhold internal
detail, and quote a correlation identifier the server log repeats.
"""
import logging
from contextlib import contextmanager

import pytest
from sqlalchemy.exc import SQLAlchemyError

from backend.app.core.security import (
    SESSION_COOKIE_NAME,
    create_access_token,
)
from backend.app.db.database import get_db
from backend.app.main import app

# SEC-08: the key set every handler registered in backend/app/main.py
# emits, whatever the status
ERROR_ENVELOPE_KEYS = {"detail", "error_id", "fields"}

# SEC-08: the detail both 500 handlers return
GENERIC_SERVER_DETAIL = "Internal server error"

# SEC-08: a submitted value the 422 reply must not repeat
SUBMITTED_VALUE_SENTINEL = "zzz-sentinel-9137"

# SEC-08: exception text the reply and the log must both withhold
EXCEPTION_TEXT_SENTINEL = "zzz-exception-text-4412"

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
    """Return the first login reply the throttle answers."""
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


def test_forced_internal_error_returns_a_sanitized_500(
    client, failing_database
):
    """An unhandled failure answers 500 with no exception detail."""
    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        response = client.get("/listings/")

    assert response.status_code == 500
    body = _assert_uniform_envelope(response)
    # SEC-08: the generic detail; no exception text reaches the caller
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
    # SEC-08: the submitted value never returns to the caller
    assert SUBMITTED_VALUE_SENTINEL not in response.text
    _assert_no_internal_detail(response.text)


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
    # SEC-08: one envelope across every handler
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
    # SEC-08: one detail and one challenge header across every path
    details = {response.json()["detail"] for response in collected}
    assert len(details) == 1
    challenges = {
        response.headers.get("WWW-Authenticate") for response in collected
    }
    assert challenges == {"Bearer"}
    # SEC-08: the correlation identifier marks one occurrence
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
    # SEC-08: the correlation identifier joins response and log
    assert len(matching) == 1
    record = matching[0]
    assert record.levelno >= logging.ERROR
    message = record.getMessage()
    # SEC-08: diagnostics reach the log, not the caller
    assert "RuntimeError" in message
    assert "origin=" in message
    assert EXCEPTION_TEXT_SENTINEL not in message


def test_the_log_withholds_the_password_the_token_and_the_cookie(
    client, failing_database, caplog
):
    """No log record for a failed request repeats a submitted secret."""
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
    assert response.json()["detail"] == GENERIC_SERVER_DETAIL
    assert caplog.records
    # SEC-08: no submitted secret reaches the log
    assert POLICY_PASSWORD not in caplog.text
    assert cookie_token not in caplog.text
    assert header_token not in caplog.text
    # SEC-08: no submitted secret returns to the caller
    assert POLICY_PASSWORD not in response.text
    assert cookie_token not in response.text


def test_each_error_carries_its_own_correlation_identifier(
    client, failing_database
):
    """Two failures of one kind carry two different identifiers."""
    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        first = client.get("/listings/")
        second = client.get("/listings/")

    assert first.status_code == 500
    assert second.status_code == 500
    # SEC-08: the correlation identifier marks one occurrence
    assert first.json()["error_id"] != second.json()["error_id"]


def test_the_harness_session_override_survives_a_forced_failure(
    client, failing_database
):
    """A forced failure leaves the harness database override in place."""
    harness_override = app.dependency_overrides[get_db]

    with failing_database(RuntimeError(EXCEPTION_TEXT_SENTINEL)):
        assert client.get("/listings/").status_code == 500

    # SEC-08: the harness override is the same object again
    assert app.dependency_overrides[get_db] is harness_override
    restored = client.get("/listings/")
    assert restored.status_code == 200
    assert restored.json() == []
