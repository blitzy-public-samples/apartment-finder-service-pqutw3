"""Regression cases for the browser-facing response headers.

The acceptance gate inspected the headers on ``/openapi.json``, ``/docs``,
``/redoc``, ``/listings/``, the three ``/auth`` routes, a protected 200 and
401, a CORS preflight and a sanitized error, and found every checked
header absent from every response class, with no ``Cache-Control:
no-store`` on the token-bearing registration answer.

The cases below drive each of those response classes and assert the
baseline set is present and exact, that the content policy is the one the
path is served under, that HSTS follows the scheme rather than being
claimed unconditionally, and that only the token-bearing routes forbid
storage. Two cases keep the documentation policy honest by reading the
sources the generated pages actually load.

Rationale is indexed in ``documentation/security/decision-log.md`` at
DL-444.
"""
import re

import pytest
from fastapi.testclient import TestClient

from conftest import ALLOWED_ORIGIN, TEST_BASE_URL, TEST_HOST, VALID_PASSWORD

from test_cors_policy import APPLICATION_ROUTE_MAP

from backend.app.db.database import get_db
from backend.app.main import (
    API_CONTENT_SECURITY_POLICY,
    BASELINE_SECURITY_HEADERS,
    CONTENT_SECURITY_POLICY_HEADER,
    DOCUMENTATION_CONTENT_SECURITY_POLICY,
    DOCUMENTATION_PATHS,
    STRICT_TRANSPORT_SECURITY,
    STRICT_TRANSPORT_SECURITY_HEADER,
    SecurityHeadersMiddleware,
    app,
    content_security_policy_for,
)


# The header the acceptance gate expects on a token-bearing answer
CACHE_CONTROL_HEADER = "Cache-Control"
NO_STORE = "no-store"
PRAGMA_HEADER = "Pragma"
NO_CACHE = "no-cache"

# The routes that mint or revoke a session, and so may not be stored
TOKEN_BEARING_PATHS = ("/auth/register", "/auth/login", "/auth/logout")

# A path served publicly, which stays cacheable
PUBLIC_READ_PATH = "/listings/"

# A protected path, for the authorized and the unauthorized answer
PROTECTED_PATH = "/filters/"

# The plain-HTTP base URL, on which HSTS must not be claimed
PLAINTEXT_BASE_URL = "http://{0}".format(TEST_HOST)

# The directives both policies share
SHARED_POLICY_DIRECTIVES = (
    "default-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'none'",
)

# Every host the documentation policy is expected to name
DOCUMENTATION_SOURCE_HOSTS = (
    "https://cdn.jsdelivr.net",
    "https://cdn.redoc.ly",
    "https://fastapi.tiangolo.com",
    "https://fonts.googleapis.com",
    "https://fonts.gstatic.com",
)

# The origin the ReDoc bundle requests its attribution glyph from. It is
# reachable only from inside the bundle, so no served HTML names it and a
# browser is what discovered the block.
BUNDLE_IMAGE_ORIGIN = "https://cdn.redoc.ly"

# What an untrusted Host is answered with
HOST_REFUSAL_STATUS = 400

# Absolute URLs a generated documentation page loads
_ABSOLUTE_URL_PATTERN = re.compile(r"(?:src|href)=\"(https://[^\"]+)\"")

# The scheme and host part of an absolute URL
_ORIGIN_PATTERN = re.compile(r"^(https://[^/]+)")


def _baseline_expectations():
    """Return the baseline headers as a name-to-value mapping."""
    return dict(BASELINE_SECURITY_HEADERS)


def _assert_baseline(response, path):
    """Assert one response carries every baseline header, exactly."""
    for name, value in _baseline_expectations().items():
        assert response.headers.get(name) == value, (path, name)


def _assert_policy(response, path):
    """Assert one response carries the policy its path is served under."""
    assert response.headers.get(
        CONTENT_SECURITY_POLICY_HEADER
    ) == content_security_policy_for(path), path


def _login(client, account):
    """Return the login response for one registered account."""
    return client.post(
        "/auth/login",
        json={"email": account["email"], "password": account["password"]},
    )


def _client_sending(host):
    """Return a client whose requests carry ``host`` in the Host header."""
    return TestClient(
        app,
        base_url="https://{0}".format(host),
        raise_server_exceptions=False,
    )


def _plaintext_client():
    """Return a client whose requests arrive over plain HTTP."""
    return TestClient(
        app,
        base_url=PLAINTEXT_BASE_URL,
        raise_server_exceptions=False,
    )


def _directives(policy):
    """Return one policy as a directive-name-to-source-set mapping."""
    parsed = {}
    for directive in policy.split(";"):
        parts = directive.split()
        if not parts:
            continue
        parsed[parts[0]] = set(parts[1:])
    return parsed


def _loaded_origins(document):
    """Return the origins one generated documentation page loads from."""
    origins = set()
    for url in _ABSOLUTE_URL_PATTERN.findall(document):
        matched = _ORIGIN_PATTERN.match(url)
        if matched:
            origins.add(matched.group(1))
    return origins


# QA-09: the baseline set reaches every response class the gate inspected
@pytest.mark.parametrize(
    "path",
    [
        "/openapi.json",
        "/docs",
        "/redoc",
        "/docs/oauth2-redirect",
        PUBLIC_READ_PATH,
    ],
)
def test_a_read_response_carries_every_baseline_header(client, path):
    """Each read path answers 200 with the baseline set and its policy."""
    response = client.get(path)

    assert response.status_code == 200, response.text
    _assert_baseline(response, path)
    _assert_policy(response, path)


# QA-09: the three token-bearing answers carry the baseline set
def test_the_authentication_responses_carry_every_baseline_header(
    client, unique_email
):
    """Register, login and logout each carry the baseline set."""
    registered = client.post(
        "/auth/register",
        json={"email": unique_email, "password": VALID_PASSWORD},
    )
    assert registered.status_code == 200, registered.text
    _assert_baseline(registered, "/auth/register")
    _assert_policy(registered, "/auth/register")

    logged_in = client.post(
        "/auth/login",
        json={"email": unique_email, "password": VALID_PASSWORD},
    )
    assert logged_in.status_code == 200, logged_in.text
    _assert_baseline(logged_in, "/auth/login")

    logged_out = client.post("/auth/logout")
    assert logged_out.status_code == 200, logged_out.text
    _assert_baseline(logged_out, "/auth/logout")


# QA-09: both answers on a protected route carry the baseline set
def test_the_protected_route_carries_the_headers_on_both_answers(
    client, registered_user
):
    """The authorized 200 and the unauthorized 401 both carry the set."""
    unauthorized = client.get(PROTECTED_PATH)
    assert unauthorized.status_code == 401, unauthorized.text
    _assert_baseline(unauthorized, PROTECTED_PATH)

    authorized = client.get(
        PROTECTED_PATH,
        headers={
            "Authorization": "Bearer {0}".format(
                registered_user["access_token"]
            )
        },
    )
    assert authorized.status_code == 200, authorized.text
    _assert_baseline(authorized, PROTECTED_PATH)


# QA-09: a CORS preflight carries the baseline set
def test_a_preflight_response_carries_every_baseline_header(client):
    """The preflight answer the CORS layer produces carries the set."""
    response = client.options(
        "/auth/login",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200, response.text
    assert response.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
    _assert_baseline(response, "/auth/login")


# QA-09: a sanitized server error carries the baseline set
def test_a_sanitized_error_carries_every_baseline_header(client):
    """The 500 the error boundary produces carries the set."""
    harness_override = app.dependency_overrides.get(get_db)

    def _raising_get_db():
        raise RuntimeError("probe")
        yield

    app.dependency_overrides[get_db] = _raising_get_db
    try:
        response = client.get(PUBLIC_READ_PATH)
    finally:
        if harness_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = harness_override

    assert response.status_code == 500, response.text
    _assert_baseline(response, PUBLIC_READ_PATH)
    _assert_policy(response, PUBLIC_READ_PATH)


# QA-09: a validation refusal carries the baseline set
def test_a_validation_refusal_carries_every_baseline_header(client):
    """The 422 the request-validation handler produces carries the set."""
    response = client.post("/auth/register", json={"email": "not-an-address"})

    assert response.status_code == 422, response.text
    _assert_baseline(response, "/auth/register")


# QA-09: an unmatched path carries the baseline set
def test_an_unmatched_path_carries_every_baseline_header(client):
    """The framework 404 carries the set, since the layer is outermost."""
    response = client.get("/no-such-path")

    assert response.status_code == 404, response.text
    _assert_baseline(response, "/no-such-path")


# QA-09: the throttle refusal carries the baseline set
def test_a_throttle_refusal_carries_every_baseline_header(
    client, registered_user
):
    """The 429 the throttle produces carries the set."""
    replies = [
        client.post(
            "/auth/login",
            json={
                "email": registered_user["email"],
                "password": "Wrong1!Passphrase",
            },
        )
        for _ in range(10)
    ]
    throttled = [reply for reply in replies if reply.status_code == 429]

    assert throttled, [reply.status_code for reply in replies]
    _assert_baseline(throttled[0], "/auth/login")


# QA-03, QA-09: the Host refusal carries the baseline set, since the
# header layer sits outside the host layer
def test_the_host_refusal_carries_every_baseline_header():
    """A refused Host is answered with the baseline set."""
    with _client_sending("attacker.example") as hostile:
        response = hostile.get("/listings")

    assert response.status_code == HOST_REFUSAL_STATUS, response.text
    _assert_baseline(response, "/listings")


# QA-09: the layer is outermost, which is what puts the headers on the
# refusals the layers below produce
def test_the_header_layer_is_the_outermost_middleware():
    """The registered stack names this layer first."""
    assert app.user_middleware[0].cls is SecurityHeadersMiddleware


# QA-09: the API surface is served under the closed policy
@pytest.mark.parametrize(
    "path",
    ["/openapi.json", PUBLIC_READ_PATH, PROTECTED_PATH, "/auth/login"],
)
def test_the_api_surface_is_served_under_the_closed_policy(path):
    """No API path is served under the documentation policy."""
    assert content_security_policy_for(path) == API_CONTENT_SECURITY_POLICY


# QA-09: the documentation pages are served under the documentation policy
@pytest.mark.parametrize("path", sorted(DOCUMENTATION_PATHS))
def test_a_documentation_path_is_served_under_the_document_policy(path):
    """Each generated page is served under the documentation policy."""
    assert content_security_policy_for(path) == (
        DOCUMENTATION_CONTENT_SECURITY_POLICY
    )


# QA-09: the documentation path set is every registered path that is
# neither an application route nor the schema document, so a documentation
# route cannot be added or moved without the policy following it
def test_the_documentation_paths_are_every_document_serving_route():
    """The path set equals the registered non-API, non-schema routes."""
    registered = {
        route.path
        for route in app.routes
        if getattr(route, "methods", None)
    }
    documents = registered - set(APPLICATION_ROUTE_MAP) - {app.openapi_url}

    assert documents == set(DOCUMENTATION_PATHS)


# QA-09: the framework's own documentation routes are switched off, so no
# stock template can reappear on a path the policy treats as a document
def test_the_framework_serves_no_documentation_route_of_its_own():
    """Every documentation path is served by this application."""
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.swagger_ui_oauth2_redirect_url is None


# QA-09: both policies deny framing, URL rebasing and form submission
@pytest.mark.parametrize(
    "policy",
    [API_CONTENT_SECURITY_POLICY, DOCUMENTATION_CONTENT_SECURITY_POLICY],
)
@pytest.mark.parametrize("directive", SHARED_POLICY_DIRECTIVES)
def test_both_policies_carry_the_shared_denials(policy, directive):
    """Neither policy relaxes a denial the other applies."""
    assert directive in policy


# QA-09: the closed policy permits nothing at all
def test_the_api_policy_permits_no_source():
    """The API policy names no host and no inline allowance."""
    assert "https://" not in API_CONTENT_SECURITY_POLICY
    assert "unsafe-inline" not in API_CONTENT_SECURITY_POLICY
    assert "unsafe-eval" not in API_CONTENT_SECURITY_POLICY


# QA-09: neither policy permits evaluated code
@pytest.mark.parametrize(
    "policy",
    [API_CONTENT_SECURITY_POLICY, DOCUMENTATION_CONTENT_SECURITY_POLICY],
)
def test_no_policy_permits_evaluated_code(policy):
    """Neither policy allows string-to-code evaluation."""
    assert "unsafe-eval" not in policy


# QA-09: the documentation policy names every host it needs and no other
def test_the_documentation_policy_names_exactly_its_sources():
    """Each expected host appears, and no unexpected host does."""
    named = set(re.findall(r"https://[^\s;]+", (
        DOCUMENTATION_CONTENT_SECURITY_POLICY
    )))

    assert named == set(DOCUMENTATION_SOURCE_HOSTS)


# QA-09: the ReDoc bundle requests its attribution glyph from an origin no
# served HTML names, so the image source is pinned here. A browser found
# this block; a document scan cannot.
def test_the_document_policy_permits_the_bundles_own_image_origin():
    """The image sources name the origin the bundle itself requests."""
    sources = _directives(DOCUMENTATION_CONTENT_SECURITY_POLICY)["img-src"]

    assert BUNDLE_IMAGE_ORIGIN in sources


# QA-09: a fetch destination cannot be meaningfully narrower than a code
# source for the same origin, so every origin trusted to execute is also
# reachable. Withholding one only suppresses a source-map request.
def test_the_document_policy_can_connect_to_every_code_source():
    """Each remote script source is also a connect source."""
    parsed = _directives(DOCUMENTATION_CONTENT_SECURITY_POLICY)
    remote_scripts = {
        source
        for source in parsed["script-src"]
        if source.startswith("https://")
    }

    assert remote_scripts
    assert remote_scripts <= parsed["connect-src"]


# QA-09: the closed policy declares no source list to widen
def test_the_api_policy_declares_only_denials():
    """Every directive in the closed policy names 'none' or nothing else."""
    parsed = _directives(API_CONTENT_SECURITY_POLICY)

    assert set(parsed) == {
        "default-src",
        "frame-ancestors",
        "base-uri",
        "form-action",
    }
    for sources in parsed.values():
        assert sources == {"'none'"}


# QA-09: the generated pages still load, and every origin they load from
# is permitted, so the policy cannot silently break the documentation
@pytest.mark.parametrize("path", ["/docs", "/redoc"])
def test_every_origin_a_generated_page_loads_is_permitted(client, path):
    """The page renders and its policy names each origin it requests."""
    response = client.get(path)

    assert response.status_code == 200, response.text
    policy = response.headers[CONTENT_SECURITY_POLICY_HEADER]
    for origin in _loaded_origins(response.text):
        assert origin in policy, (path, origin)


# QA-09: HSTS is claimed only on a request that arrived over TLS
def test_a_secure_request_carries_strict_transport_security(client):
    """The HTTPS harness client receives the HSTS header."""
    response = client.get(PUBLIC_READ_PATH)

    assert response.headers.get(
        STRICT_TRANSPORT_SECURITY_HEADER
    ) == STRICT_TRANSPORT_SECURITY


# QA-09: over plain HTTP the header would be a claim the connection does
# not support, so it is withheld
def test_a_plaintext_request_carries_no_strict_transport_security():
    """A plain-HTTP request receives the baseline set without HSTS."""
    with _plaintext_client() as plaintext:
        response = plaintext.get(PUBLIC_READ_PATH)

    assert response.status_code == 200, response.text
    _assert_baseline(response, PUBLIC_READ_PATH)
    assert STRICT_TRANSPORT_SECURITY_HEADER not in response.headers


# QA-09: HSTS names a year and every subdomain
def test_the_transport_claim_covers_a_year_and_every_subdomain():
    """The directive value is a year in seconds, subdomains included."""
    assert "max-age=31536000" in STRICT_TRANSPORT_SECURITY
    assert "includeSubDomains" in STRICT_TRANSPORT_SECURITY


# QA-09: the token-bearing answers forbid storage
@pytest.mark.parametrize("path", TOKEN_BEARING_PATHS)
def test_a_token_bearing_response_forbids_storage(
    client, unique_email, path
):
    """Register, login and logout each answer with no-store."""
    responses = {
        "/auth/register": lambda: client.post(
            "/auth/register",
            json={"email": unique_email, "password": VALID_PASSWORD},
        ),
        "/auth/logout": lambda: client.post("/auth/logout"),
    }
    if path == "/auth/login":
        client.post(
            "/auth/register",
            json={"email": unique_email, "password": VALID_PASSWORD},
        )
        response = _login(
            client, {"email": unique_email, "password": VALID_PASSWORD}
        )
    else:
        response = responses[path]()

    assert response.status_code == 200, response.text
    assert response.headers.get(CACHE_CONTROL_HEADER) == NO_STORE
    assert response.headers.get(PRAGMA_HEADER) == NO_CACHE


# QA-09: the answer that sets the session cookie is the answer that
# forbids storage, so the cookie is never written to a shared cache
def test_the_response_setting_the_session_cookie_forbids_storage(
    client, unique_email
):
    """A single response carries both the cookie and the no-store."""
    response = client.post(
        "/auth/register",
        json={"email": unique_email, "password": VALID_PASSWORD},
    )

    assert response.status_code == 200, response.text
    assert "set-cookie" in response.headers
    assert response.headers[CACHE_CONTROL_HEADER] == NO_STORE


# QA-09: the public read path is unaffected, so a cache in front of it
# still serves the listing feed
def test_the_public_read_path_is_not_marked_uncacheable(client):
    """The public read answer carries no storage prohibition."""
    response = client.get(PUBLIC_READ_PATH)

    assert response.status_code == 200, response.text
    assert NO_STORE not in response.headers.get(CACHE_CONTROL_HEADER, "")


# QA-09: a header the response already carries is left alone, which is
# what lets a route narrow its own policy
def test_a_header_a_response_already_carries_is_preserved():
    """The layer does not overwrite a value the application set."""
    chosen_policy = "default-src 'self'"

    async def application(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain"),
                    (
                        CONTENT_SECURITY_POLICY_HEADER.lower().encode(),
                        chosen_policy.encode(),
                    ),
                    (b"x-frame-options", b"SAMEORIGIN"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    # the stub serves no lifespan, so the client is used without a context
    stub = TestClient(
        SecurityHeadersMiddleware(application), base_url=TEST_BASE_URL
    )
    response = stub.get("/anything")

    assert response.headers[CONTENT_SECURITY_POLICY_HEADER] == chosen_policy
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


# QA-09: the baseline set names each header once, so no value can be
# appended twice onto one response
def test_no_baseline_header_is_declared_twice():
    """Each header appears once in the baseline declaration."""
    names = [name for name, _ in BASELINE_SECURITY_HEADERS]

    assert len(names) == len(set(names))
    assert CONTENT_SECURITY_POLICY_HEADER not in names
    assert STRICT_TRANSPORT_SECURITY_HEADER not in names


# QA-09: every baseline value is a single-line header value
@pytest.mark.parametrize("name, value", list(BASELINE_SECURITY_HEADERS))
def test_every_baseline_value_is_a_single_line(name, value):
    """No declared value carries a control character."""
    assert value == value.strip()
    assert not any(character in value for character in "\r\n")


# QA-09: a response carries one value per baseline header, not two
def test_each_baseline_header_appears_once_on_a_response(client):
    """No response repeats a baseline header."""
    response = client.get(PUBLIC_READ_PATH)
    raw_names = [name.decode().lower() for name, _ in response.headers.raw]

    for name in _baseline_expectations():
        assert raw_names.count(name.lower()) == 1, name
    assert raw_names.count(CONTENT_SECURITY_POLICY_HEADER.lower()) == 1
