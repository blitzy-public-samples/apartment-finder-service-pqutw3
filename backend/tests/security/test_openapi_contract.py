"""Regression cases for the published API contract.

The acceptance gate found three defects in the schema document, all of them
a mismatch between what the document says and what the application does.
The security scheme advertised an OAuth2 password flow whose token URL
resolves to no route, so the interactive documentation offered an
authorization dialog that could not authenticate anything. The password
property published nothing but its type, so none of the enforced policy was
discoverable. And all three authentication routes published an empty 200
schema despite returning a fixed body.

Each case here asserts the document against the running application rather
than against a transcription, so the two cannot drift.

Rationale is indexed in ``documentation/security/decision-log.md`` at
DL-441, DL-442 and DL-443.
"""
import pytest

from conftest import VALID_PASSWORD

from backend.app.core.security import SESSION_COOKIE_NAME
from backend.app.schema.user import (
    PASSWORD_MAX_BYTES,
    PASSWORD_MIN_LENGTH,
    PASSWORD_SPECIAL_CHARACTERS,
)


# The document the interactive pages are rendered from
SCHEMA_DOCUMENT = "/openapi.json"

# The path the pre-fix OAuth2 declaration sent a reader to
ADVERTISED_TOKEN_PATH = "/token"

# The two credential channels the guard accepts
COOKIE_SCHEME_NAME = "SessionCookie"
BEARER_SCHEME_NAME = "BearerToken"

# The three authentication routes and the body key set each returns
AUTH_ROUTE_BODIES = {
    "/auth/register": {"user", "access_token", "token_type"},
    "/auth/login": {"access_token", "token_type"},
    "/auth/logout": {"detail"},
}

# One route behind the authentication guard
PROTECTED_ROUTE = "/filters/"

# What the published password description has to name, because no schema
# keyword can express any of it
POLICY_DESCRIPTION_MARKERS = (
    "uppercase",
    "lowercase",
    "digit",
    "NUL",
    "UTF-8 bytes",
    str(PASSWORD_MIN_LENGTH),
    str(PASSWORD_MAX_BYTES),
)


def _document(client):
    """Return the served schema document."""
    response = client.get(SCHEMA_DOCUMENT)
    assert response.status_code == 200, response.text
    return response.json()


def _resolve(document, schema):
    """Return a schema with one level of reference resolved."""
    reference = schema.get("$ref")
    if not reference:
        return schema
    assert reference.startswith("#/components/schemas/"), reference
    name = reference.rsplit("/", 1)[1]
    return document["components"]["schemas"][name]


def _success_schema(document, path):
    """Return the resolved 200 response schema one route publishes."""
    responses = document["paths"][path]["post"]["responses"]
    content = responses["200"]["content"]["application/json"]
    return _resolve(document, content["schema"])


def _register(client, email, password):
    return client.post(
        "/auth/register", json={"email": email, "password": password}
    )


# QA-04: the document advertises no credential endpoint that does not exist
def test_the_document_advertises_no_token_url(client):
    """No security scheme names a token URL."""
    document = _document(client)

    schemes = document["components"]["securitySchemes"]
    for name, scheme in schemes.items():
        assert scheme["type"] != "oauth2", (name, scheme)
        assert "flows" not in scheme, (name, scheme)
    assert "tokenUrl" not in str(document)


# QA-04: the advertised path really is absent, which is why it was wrong
def test_the_previously_advertised_token_path_is_not_a_route(client):
    """Nothing serves the path the OAuth2 declaration named."""
    declared = {route.path for route in client.app.routes}
    assert ADVERTISED_TOKEN_PATH not in declared

    for method in ("get", "post"):
        response = getattr(client, method)(ADVERTISED_TOKEN_PATH)
        assert response.status_code == 404, (method, response.text)


# QA-04: the published schemes are the two channels the guard reads
def test_the_document_publishes_the_two_real_credential_channels(client):
    """The cookie and the bearer header are published as themselves."""
    schemes = _document(client)["components"]["securitySchemes"]

    assert set(schemes) == {COOKIE_SCHEME_NAME, BEARER_SCHEME_NAME}

    cookie = schemes[COOKIE_SCHEME_NAME]
    assert cookie["type"] == "apiKey"
    assert cookie["in"] == "cookie"
    assert cookie["name"] == SESSION_COOKIE_NAME
    assert "/auth/login" in cookie["description"]

    bearer = schemes[BEARER_SCHEME_NAME]
    assert bearer["type"] == "http"
    assert bearer["scheme"] == "bearer"
    assert "access_token" in bearer["description"]
    assert "/auth/login" in bearer["description"]


# QA-04: a protected operation declares both channels
def test_a_protected_operation_declares_both_credential_channels(client):
    """The guarded route publishes the two schemes it accepts."""
    document = _document(client)
    operation = document["paths"][PROTECTED_ROUTE]["get"]

    declared = {name for entry in operation["security"] for name in entry}
    assert declared == {COOKIE_SCHEME_NAME, BEARER_SCHEME_NAME}


def _login(client, account):
    """Log one account in, leaving the session cookie on the client."""
    response = client.post(
        "/auth/login",
        json={"email": account["email"], "password": account["password"]},
    )
    assert response.status_code == 200, response.text
    return response


# QA-04: swapping the scheme changed no runtime behaviour
def test_a_cookie_only_request_still_authenticates(client, register_user):
    """The cookie alone reaches the guarded route."""
    account = register_user()
    _login(client, account)
    assert client.cookies.get(SESSION_COOKIE_NAME)

    request = client.build_request("GET", PROTECTED_ROUTE)
    assert "authorization" not in request.headers
    response = client.send(request)

    assert response.status_code == 200, response.text


def test_a_bearer_only_request_still_authenticates(client, register_user):
    """The bearer header alone reaches the guarded route."""
    account = register_user()
    client.cookies.clear()

    response = client.get(
        PROTECTED_ROUTE,
        headers={"Authorization": "Bearer " + account["access_token"]},
    )

    assert response.status_code == 200, response.text


@pytest.mark.parametrize(
    "header",
    [
        "Bearer",
        "Bearer ",
        "Token abc",
        "abc",
        "Basic dXNlcjpwYXNz",
    ],
)
def test_an_unusable_authorization_header_is_refused(client, header):
    """A header the bearer scheme cannot read answers 401, never 500."""
    client.cookies.clear()

    response = client.get(PROTECTED_ROUTE, headers={"Authorization": header})

    assert response.status_code == 401, response.text
    assert response.headers["www-authenticate"] == "Bearer"


def test_a_request_with_no_credential_is_refused(client):
    """Neither channel present answers the uniform 401."""
    client.cookies.clear()

    response = client.get(PROTECTED_ROUTE)

    assert response.status_code == 401, response.text
    assert response.headers["www-authenticate"] == "Bearer"


def test_the_cookie_still_wins_over_a_conflicting_header(
    client, register_user
):
    """The cookie is read before the header, unchanged by the swap."""
    account = register_user()
    _login(client, account)
    assert client.cookies.get(SESSION_COOKIE_NAME)

    response = client.get(
        PROTECTED_ROUTE,
        headers={"Authorization": "Bearer not-a-token"},
    )

    assert response.status_code == 200, response.text
    assert account["access_token"]


# QA-05: the password property publishes the policy
def test_the_password_property_publishes_the_policy(client):
    """The two expressible bounds and the rest as a description."""
    document = _document(client)
    published = document["components"]["schemas"]["UserCreate"]["properties"]
    password = published["password"]

    assert password["minLength"] == PASSWORD_MIN_LENGTH
    assert password["maxLength"] == PASSWORD_MAX_BYTES

    description = password["description"]
    for marker in POLICY_DESCRIPTION_MARKERS:
        assert marker in description, marker
    # the special-character set is published in full, not summarised
    assert PASSWORD_SPECIAL_CHARACTERS in description


# QA-05: the login model carries no bound, so a refusal stays a 401
def test_the_login_password_property_carries_no_bound(client):
    """A stored credential is never refused by a schema bound."""
    published = _document(client)["components"]["schemas"]["UserLogin"]
    password = published["properties"]["password"]

    assert "minLength" not in password
    assert "maxLength" not in password
    assert password["description"]


# QA-05: publishing the bounds did not weaken the runtime validator
@pytest.mark.parametrize(
    "password",
    [
        pytest.param("Ab1!" + "c" * 7, id="eleven-characters"),
        pytest.param("ab1!" + "c" * 20, id="no-uppercase"),
        pytest.param("AB1!" + "C" * 20, id="no-lowercase"),
        pytest.param("Abc!" + "d" * 20, id="no-digit"),
        pytest.param("Abc1" + "d" * 20, id="no-special"),
        pytest.param("Ab1!" + "c" * 80, id="over-the-byte-ceiling"),
        pytest.param("Ab1!" + "é" * 40, id="over-the-ceiling-in-bytes-only"),
        pytest.param("Ab1!\x00" + "c" * 20, id="contains-a-nul"),
    ],
)
def test_a_non_compliant_password_is_still_refused(
    client, unique_email, password
):
    """Every rule still refuses, with the field named and no echo."""
    response = _register(client, unique_email, password)

    assert response.status_code == 422, response.text
    assert "password" in response.json()["fields"]
    assert password not in response.text


def test_a_compliant_password_is_still_accepted(client, unique_email):
    """The policy admits a compliant password unchanged."""
    response = _register(client, unique_email, VALID_PASSWORD)

    assert response.status_code == 200, response.text


def test_a_non_string_password_is_still_refused(client, unique_email):
    """Strict typing survives the declarative bounds."""
    response = client.post(
        "/auth/register",
        json={"email": unique_email, "password": 123456789012345},
    )

    assert response.status_code == 422, response.text
    assert "password" in response.json()["fields"]


# QA-06: each authentication route publishes the body it returns
@pytest.mark.parametrize("path", sorted(AUTH_ROUTE_BODIES))
def test_each_auth_route_publishes_a_response_schema(client, path):
    """No 200 schema is empty, and each names the frozen key set."""
    document = _document(client)
    schema = _success_schema(document, path)

    assert schema, path
    assert schema["type"] == "object"
    assert set(schema["properties"]) == AUTH_ROUTE_BODIES[path], path
    assert set(schema["required"]) == AUTH_ROUTE_BODIES[path], path


# QA-06: the published key set is the one the route actually returns
def test_the_published_bodies_match_the_served_bodies(
    client, unique_email, db_session
):
    """Each published key set equals the served key set exactly."""
    document = _document(client)

    registered = _register(client, unique_email, VALID_PASSWORD)
    assert registered.status_code == 200, registered.text
    assert set(registered.json()) == set(
        _success_schema(document, "/auth/register")["properties"]
    )
    # the nested user object is published too
    nested = _resolve(
        document,
        _success_schema(document, "/auth/register")["properties"]["user"],
    )
    assert set(registered.json()["user"]) == set(nested["properties"])

    logged_in = client.post(
        "/auth/login",
        json={"email": unique_email, "password": VALID_PASSWORD},
    )
    assert logged_in.status_code == 200, logged_in.text
    assert set(logged_in.json()) == set(
        _success_schema(document, "/auth/login")["properties"]
    )

    logged_out = client.post("/auth/logout")
    assert logged_out.status_code == 200, logged_out.text
    assert set(logged_out.json()) == set(
        _success_schema(document, "/auth/logout")["properties"]
    )
    assert db_session is not None


# QA-06: documenting the body filters nothing out of it
def test_documenting_the_body_filters_no_key(client, unique_email):
    """The routes carry no response_model, so nothing is dropped."""
    for route in client.app.routes:
        if getattr(route, "path", None) in AUTH_ROUTE_BODIES:
            assert route.response_model is None, route.path

    registered = _register(client, unique_email, VALID_PASSWORD)

    body = registered.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["user"]["email"] == unique_email
    assert isinstance(body["user"]["id"], int)
