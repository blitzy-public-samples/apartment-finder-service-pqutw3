"""SEC-06 regression tests for session token storage.

The session token travels in an HttpOnly cookie that page script cannot
read, and the register and login bodies keep the keys they had. Nine
tests cover the cookie attributes, both response bodies, a cookie-only
request, the bearer-header fallback and logout.
"""
from datetime import datetime, timedelta
from http import HTTPStatus
from http.cookies import SimpleCookie

from conftest import VALID_PASSWORD

from backend.app.core.config import settings
from backend.app.core.security import (
    SESSION_COOKIE_NAME,
    create_access_token,
)
from backend.app.db.models import Filter as FilterModel

REGISTER_ROUTE = "/auth/register"
LOGIN_ROUTE = "/auth/login"
LOGOUT_ROUTE = "/auth/logout"

# SEC-06: an authenticated route reached through the session cookie.
# Declared at backend/app/api/endpoints/filters.py:45 and guarded by
# get_current_user.
PROTECTED_ROUTE = "/filters/"

# SEC-06: the cookie attributes the auth routes set and clear
EXPECTED_SAMESITE = "strict"
EXPECTED_COOKIE_PATH = "/"

# Frozen response contracts, read from
# backend/app/api/endpoints/auth.py:177-184 and :220-223
REGISTER_BODY_KEYS = frozenset({"user", "access_token", "token_type"})
REGISTER_USER_KEYS = frozenset({"id", "email"})
LOGIN_BODY_KEYS = frozenset({"access_token", "token_type"})
EXPECTED_TOKEN_TYPE = "bearer"

BEARER_PREFIX = "Bearer "
EXPECTED_AUTH_CHALLENGE = "Bearer"

# SEC-08: the detail get_current_user raises; the error boundary at
# main.py:234 keeps it out of the response body
INTERNAL_401_DETAIL = "Could not validate credentials"

SEEDED_FILTER_NAME = "session-cookie-owner-probe"

# SEC-06: rows naming their owner, so a reply identifies which of two
# valid credentials the guard resolved
COOKIE_OWNER_FILTER_NAME = "cookie-owner-probe"
HEADER_OWNER_FILTER_NAME = "header-owner-probe"

# SEC-06: a cookie value the signature check cannot parse
UNPARSABLE_COOKIE = "not.a.jwt"

# SEC-06: the cookie value logout leaves behind, which the guard must
# treat as absent so a non-browser client keeps working
CLEARED_COOKIE = ""


def _session_cookie_directive(response):
    """Return the Set-Cookie morsel that names the session cookie."""
    directives = response.headers.get_list("set-cookie")
    for directive in directives:
        parsed = SimpleCookie()
        parsed.load(directive)
        if SESSION_COOKIE_NAME in parsed:
            return parsed[SESSION_COOKIE_NAME]
    raise AssertionError(
        "no Set-Cookie header names {0!r}; the response carried {1}".format(
            SESSION_COOKIE_NAME, len(directives)
        )
    )


def _assert_cookie_security_attributes(morsel):
    """Check the three attributes that keep the token away from script."""
    # SEC-06: HttpOnly puts the token beyond page script
    assert morsel["httponly"] is True, "the session cookie omits HttpOnly"
    # SEC-06: the Secure attribute follows settings.COOKIE_SECURE
    assert settings.COOKIE_SECURE, "COOKIE_SECURE is disabled under test"
    assert morsel["secure"] is True, "the session cookie omits Secure"
    # SEC-06: SameSite bounds delivery on a cross-site request
    assert str(morsel["samesite"]).lower() == EXPECTED_SAMESITE, (
        "the session cookie carries SameSite={0!r}".format(
            morsel["samesite"]
        )
    )
    assert morsel["path"] == EXPECTED_COOKIE_PATH, (
        "the session cookie carries Path={0!r}".format(morsel["path"])
    )


def _assert_cookie_lifetime(morsel):
    """Check the cookie expires with the token it carries."""
    assert morsel["max-age"] or morsel["expires"], (
        "the session cookie carries neither Max-Age nor Expires"
    )
    expected = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    assert int(morsel["max-age"]) == expected, (
        "Max-Age={0!r} does not match {1} seconds".format(
            morsel["max-age"], expected
        )
    )


def _login(client, account):
    """Log one registered account in and return the response."""
    return client.post(
        LOGIN_ROUTE,
        json={"email": account["email"], "password": account["password"]},
    )


def _seed_owned_filter(db_session, account, name=SEEDED_FILTER_NAME):
    """Insert one filter row owned by the given account."""
    db_session.add(
        FilterModel(
            user_id=account["id"],
            name=name,
            created_at=datetime.utcnow(),
        )
    )
    db_session.commit()


def _filter_names(response):
    """Return the filter names one authenticated reply carries."""
    return [row["name"] for row in response.json()]


def _send_with_one_cookie(client, cookie_value, headers):
    """Send one request carrying exactly the named cookie value.

    Replacing a value in the jar leaves the value the server set behind
    under a different domain, so both would travel and the request would
    not be the one the test describes. The jar is emptied first and the
    outgoing header is checked before the request goes out.
    """
    client.cookies.clear()
    client.cookies.set(SESSION_COOKIE_NAME, cookie_value)
    request = client.build_request("GET", PROTECTED_ROUTE, headers=headers)
    sent = request.headers.get("cookie", "")
    assert sent.count(SESSION_COOKIE_NAME + "=") == 1, sent
    assert sent.strip().endswith(cookie_value), sent
    return client.send(request)


def test_register_response_sets_the_httponly_session_cookie(
    client, unique_email
):
    """Registering issues the session cookie with all three attributes."""
    response = client.post(
        REGISTER_ROUTE,
        json={"email": unique_email, "password": VALID_PASSWORD},
    )
    assert response.status_code == 200, response.text

    morsel = _session_cookie_directive(response)
    _assert_cookie_security_attributes(morsel)
    _assert_cookie_lifetime(morsel)
    # SEC-06: the cookie and the body carry the same token
    assert morsel.value == response.json()["access_token"]


def test_login_response_sets_the_httponly_session_cookie(
    client, register_user
):
    """Logging in issues the session cookie with all three attributes."""
    account = register_user()
    response = _login(client, account)
    assert response.status_code == 200, response.text

    morsel = _session_cookie_directive(response)
    _assert_cookie_security_attributes(morsel)
    _assert_cookie_lifetime(morsel)
    # SEC-06: the cookie and the body carry the same token
    assert morsel.value == response.json()["access_token"]
    assert client.cookies.get(SESSION_COOKIE_NAME) == morsel.value


def test_register_response_body_keys_are_unchanged(client, unique_email):
    """The register body carries exactly the keys its contract names."""
    response = client.post(
        REGISTER_ROUTE,
        json={"email": unique_email, "password": VALID_PASSWORD},
    )
    assert response.status_code == 200, response.text

    body = response.json()
    assert set(body) == REGISTER_BODY_KEYS
    assert set(body["user"]) == REGISTER_USER_KEYS
    assert body["token_type"] == EXPECTED_TOKEN_TYPE
    assert body["user"]["email"] == unique_email
    assert isinstance(body["user"]["id"], int)
    assert isinstance(body["access_token"], str)
    assert body["access_token"]


def test_login_response_body_carries_no_user_key(client, register_user):
    """The login body carries exactly two keys and no user object."""
    account = register_user()
    response = _login(client, account)
    assert response.status_code == 200, response.text

    body = response.json()
    assert set(body) == LOGIN_BODY_KEYS
    assert "user" not in body
    assert body["token_type"] == EXPECTED_TOKEN_TYPE
    assert isinstance(body["access_token"], str)
    assert body["access_token"]


def test_cookie_only_request_authenticates(client, db_session, register_user):
    """A request carrying only the session cookie reads its owner's rows."""
    account = register_user()
    login = _login(client, account)
    assert login.status_code == 200, login.text
    assert client.cookies.get(SESSION_COOKIE_NAME)
    _seed_owned_filter(db_session, account)

    request = client.build_request("GET", PROTECTED_ROUTE)
    # SEC-06: no bearer header on the request
    assert "authorization" not in request.headers
    response = client.send(request)

    assert response.status_code == 200, response.text
    rows = response.json()
    assert [row["name"] for row in rows] == [SEEDED_FILTER_NAME]
    assert rows[0]["user_id"] == str(account["id"])


def test_bearer_header_authenticates_after_the_cookie_is_cleared(
    client, db_session, register_user
):
    """A non-browser client still authenticates with the bearer header."""
    account = register_user()
    login = _login(client, account)
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    _seed_owned_filter(db_session, account)

    client.cookies.delete(SESSION_COOKIE_NAME)
    assert client.cookies.get(SESSION_COOKIE_NAME) is None

    request = client.build_request(
        "GET",
        PROTECTED_ROUTE,
        headers={"Authorization": BEARER_PREFIX + token},
    )
    # SEC-06: no session cookie on the request
    assert "cookie" not in request.headers
    response = client.send(request)

    assert response.status_code == 200, response.text
    assert response.json()[0]["user_id"] == str(account["id"])


def test_cookie_and_bearer_header_together_authenticate(
    client, register_user
):
    """Sending both the cookie and the header keeps the request working."""
    account = register_user()
    login = _login(client, account)
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    assert client.cookies.get(SESSION_COOKIE_NAME) == token

    response = client.get(
        PROTECTED_ROUTE,
        headers={"Authorization": BEARER_PREFIX + token},
    )
    assert response.status_code == 200, response.text


def test_the_session_cookie_outranks_the_bearer_header(
    client, db_session, register_user
):
    """The account the cookie names is the one the guard resolves.

    Both credentials are valid and name different accounts, so the rows
    that come back say which one was read. The order is a deliberate
    choice: reading the header first would let any caller holding a
    token displace the session the browser is carrying.
    """
    cookie_owner = register_user()
    header_owner = register_user()
    _seed_owned_filter(
        db_session, cookie_owner, name=COOKIE_OWNER_FILTER_NAME
    )
    _seed_owned_filter(
        db_session, header_owner, name=HEADER_OWNER_FILTER_NAME
    )

    client.cookies.set(SESSION_COOKIE_NAME, cookie_owner["access_token"])
    response = client.get(
        PROTECTED_ROUTE,
        headers={
            "Authorization": BEARER_PREFIX + header_owner["access_token"]
        },
    )

    assert response.status_code == 200, response.text
    # SEC-06: the cookie decides; the header cannot displace it
    assert _filter_names(response) == [COOKIE_OWNER_FILTER_NAME]

    # SEC-06: swapping the two credentials swaps the answer, so the
    # order rather than the account is what decided
    client.cookies.set(SESSION_COOKIE_NAME, header_owner["access_token"])
    mirrored = client.get(
        PROTECTED_ROUTE,
        headers={
            "Authorization": BEARER_PREFIX + cookie_owner["access_token"]
        },
    )

    assert mirrored.status_code == 200, mirrored.text
    assert _filter_names(mirrored) == [HEADER_OWNER_FILTER_NAME]


def test_an_unusable_cookie_does_not_fall_back_to_the_header(
    client, register_user
):
    """A cookie the guard cannot use refuses the request outright.

    The cookie is authoritative, so a value planted on the domain is
    answered with a refusal rather than quietly discarded in favour of
    whatever header the same caller also sent. Falling back would make a
    hostile cookie a no-op and hide it from every caller.
    """
    account = register_user()
    login = _login(client, account)
    assert login.status_code == 200, login.text
    valid_header = {
        "Authorization": BEARER_PREFIX + login.json()["access_token"]
    }
    # SEC-06: a token whose lifetime has already elapsed
    expired_cookie = create_access_token(
        {"sub": str(account["id"])}, expires_delta=timedelta(seconds=-1)
    )

    for cookie_value in (UNPARSABLE_COOKIE, expired_cookie):
        response = _send_with_one_cookie(
            client, cookie_value, headers=valid_header
        )

        # SEC-06: a present but unusable cookie fails closed
        assert response.status_code == 401, response.text
        assert response.headers["WWW-Authenticate"] == (
            EXPECTED_AUTH_CHALLENGE
        )
        # SEC-08: the boundary answers with the uniform envelope
        assert response.json()["detail"] == HTTPStatus.UNAUTHORIZED.phrase
        assert INTERNAL_401_DETAIL not in response.text


def test_a_cleared_cookie_leaves_the_bearer_header_in_charge(
    client, db_session, register_user
):
    """The cookie logout leaves behind counts as no cookie at all.

    Logout clears the cookie by sending an empty value, so a
    non-browser client holding a token must keep working afterwards.
    """
    account = register_user()
    login = _login(client, account)
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    _seed_owned_filter(db_session, account)

    response = _send_with_one_cookie(
        client,
        CLEARED_COOKIE,
        headers={"Authorization": BEARER_PREFIX + token},
    )

    assert response.status_code == 200, response.text
    assert _filter_names(response) == [SEEDED_FILTER_NAME]


def test_logout_clears_the_session_cookie(client, register_user):
    """Logout instructs the browser to drop the session cookie."""
    account = register_user()
    login = _login(client, account)
    assert login.status_code == 200, login.text
    assert client.cookies.get(SESSION_COOKIE_NAME) == (
        login.json()["access_token"]
    )

    logout = client.post(LOGOUT_ROUTE)
    assert logout.status_code == 200, logout.text

    # SEC-06: logout clears the cookie server-side
    morsel = _session_cookie_directive(logout)
    assert morsel.value == ""
    assert int(morsel["max-age"]) == 0
    _assert_cookie_security_attributes(morsel)
    assert client.cookies.get(SESSION_COOKIE_NAME) is None


def test_protected_route_rejects_the_request_after_logout(
    client, register_user
):
    """After logout a cookie-only request to a protected route fails."""
    account = register_user()
    login = _login(client, account)
    assert login.status_code == 200, login.text
    before = client.send(client.build_request("GET", PROTECTED_ROUTE))
    assert before.status_code == 200, before.text

    logout = client.post(LOGOUT_ROUTE)
    assert logout.status_code == 200, logout.text

    request = client.build_request("GET", PROTECTED_ROUTE)
    assert "authorization" not in request.headers
    response = client.send(request)

    assert response.status_code == 401, response.text
    assert response.headers["WWW-Authenticate"] == EXPECTED_AUTH_CHALLENGE
    # SEC-08: the boundary answers with the uniform sanitized envelope
    body = response.json()
    assert body["detail"] == HTTPStatus.UNAUTHORIZED.phrase
    assert body["error_id"]
    assert INTERNAL_401_DETAIL not in response.text
