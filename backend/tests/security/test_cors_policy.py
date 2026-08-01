"""SEC-03 regression tests for the cross-origin resource sharing (CORS)
policy.

An allow-listed origin comes back echoed verbatim, with credentials
enabled. An origin outside the list gets no allow-origin header at all.
An unsafe allow-list raises a validation error while ``Settings`` is
built, which stops the process at import.

The allow-list arrives from the environment in production, and that path
differs from passing a keyword: an unparsable value is refused before
any validator sees it, and the guidance an operator needs travels on the
cause rather than in the message. Both spellings are covered here, so a
rejection proved through a keyword is never mistaken for a rejection
proved through the environment.
"""
import json

import pytest
from pydantic import ValidationError
from pydantic.env_settings import SettingsError

from backend.app.core.config import Settings, settings

# SEC-03: the enumerated allow-list the running application booted with
ALLOW_LISTED_ORIGINS = tuple(settings.ALLOWED_ORIGINS)

_PRIMARY_ORIGIN = ALLOW_LISTED_ORIGINS[0]
_PRIMARY_SCHEME, _, _PRIMARY_AUTHORITY = _PRIMARY_ORIGIN.partition("://")

# SEC-03: an allow-listed origin carrying an appended suffix
_SUFFIX_EXTENDED_ORIGIN = "{0}.attacker.example.com".format(
    _PRIMARY_ORIGIN
)

# SEC-03: the allow-listed authority reached over the other scheme
_SCHEME_SWAPPED_ORIGIN = "{0}://{1}".format(
    "http" if _PRIMARY_SCHEME == "https" else "https",
    _PRIMARY_AUTHORITY,
)

# SEC-03: an origin that appears nowhere in the allow-list
_UNRELATED_ORIGIN = "https://evil.example.com"

# SEC-03: the opaque origin a sandboxed frame or a redirect sends
_OPAQUE_ORIGIN = "null"

WILDCARD = "*"

# the frozen public read path: unauthenticated, trailing slash, and no
# /api prefix
PUBLIC_READ_PATH = "/listings/"

# SEC-03: the method and request-header allow-lists registered on
# CORSMiddleware in backend/app/main.py
ADVERTISED_METHODS = ("GET", "POST", "OPTIONS")
WITHHELD_METHODS = ("PUT", "PATCH", "DELETE")
ADVERTISED_REQUEST_HEADERS = ("Content-Type", "Authorization")

_ALLOW_ORIGIN = "Access-Control-Allow-Origin"
_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials"
_ALLOW_METHODS = "Access-Control-Allow-Methods"
_ALLOW_HEADERS = "Access-Control-Allow-Headers"
_MAX_AGE = "Access-Control-Max-Age"
_VARY = "Vary"

_REFERENCE_ORIGIN = "https://reference.example.com"

# SEC-03: the name of the setting the environment carries
_ALLOW_LIST_VARIABLE = "ALLOWED_ORIGINS"

# SEC-03: the JSON array spelling .env.example documents, which is the
# only form the environment path accepts
DOCUMENTED_ENV_ORIGINS = ("https://app.example.com", "http://localhost:3000")

# SEC-03: environment values no JSON parser accepts. A bare
# comma-separated list is the spelling an operator reaches for first.
UNPARSABLE_ENV_VALUES = (
    pytest.param(
        "https://a.example.com,https://b.example.com",
        id="comma-separated-string",
    ),
    pytest.param("https://a.example.com", id="single-bare-origin"),
    pytest.param("['https://a.example.com']", id="single-quoted-array"),
    pytest.param("", id="empty-string"),
)

# SEC-03: environment values that parse as JSON and then fail the
# allow-list rules, which proves the environment path reaches the same
# validator the keyword path does
UNSAFE_ENV_VALUES = (
    pytest.param("[]", id="empty-array"),
    pytest.param('["*"]', id="wildcard"),
    pytest.param('["null"]', id="opaque-origin"),
    pytest.param('["testserver"]', id="bare-host"),
    pytest.param(
        '["https://good.example.com","*"]',
        id="wildcard-mixed-with-a-valid-origin",
    ),
)

# SEC-03: the guidance the operator-facing cause has to carry
_REQUIRED_FORM_MARKERS = ("JSON array", '"https://app.example.com"')


def _header_tokens(value):
    # SEC-03: a comma-separated header field value, case-normalized
    return {
        token.strip().lower()
        for token in value.split(",")
        if token.strip()
    }


def _reference_settings_arguments():
    # SEC-03: a complete and valid keyword mapping covering every field
    # of backend.app.core.config.Settings
    return {
        "DATABASE_URL": "sqlite:///:memory:",
        "SECRET_KEY": "x" * 32,
        "ALGORITHM": "HS256",
        "ACCESS_TOKEN_EXPIRE_MINUTES": 30,
        "ALLOWED_ORIGINS": [_REFERENCE_ORIGIN],
        "ZILLOW_API_KEY": "reference-zillow-key",
        "ZILLOW_API_URL": "https://api.zillow.invalid/v1",
        "PAYPAL_CLIENT_ID": "reference-paypal-client-id",
        "PAYPAL_CLIENT_SECRET": "reference-paypal-placeholder",
        "PAYPAL_MODE": "sandbox",
        "SENDGRID_API_KEY": "reference-sendgrid-key",
        "FROM_EMAIL": "reference@example.com",
        "SENTRY_DSN": None,
        "DB_SSLMODE": "require",
        "COOKIE_SECURE": True,
        "LOGIN_RATE_LIMIT_ATTEMPTS": 5,
        "LOGIN_RATE_LIMIT_WINDOW_MINUTES": 15,
    }


def _build_settings_with_allow_list(value):
    arguments = _reference_settings_arguments()
    arguments["ALLOWED_ORIGINS"] = value
    return Settings(**arguments)


def _rejected_field_names(error):
    return {
        str(entry["loc"][0])
        for entry in error.errors()
        if entry["loc"]
    }


def _preflight(client, origin, method="POST", request_headers=None):
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": method,
    }
    if request_headers is not None:
        headers["Access-Control-Request-Headers"] = request_headers
    return client.options(PUBLIC_READ_PATH, headers=headers)


@pytest.mark.parametrize("origin", ALLOW_LISTED_ORIGINS)
def test_allow_listed_origin_is_echoed_with_credentials(client, origin):
    """An allow-listed origin comes back as itself and the response
    turns credentials on.

    The echoed value is the full origin string, never a wildcard, and
    the response declares that it varies by origin.
    """
    response = client.get(PUBLIC_READ_PATH, headers={"Origin": origin})

    assert response.status_code == 200
    # SEC-03: exact origin equality, no prefix match, no reflection
    assert response.headers[_ALLOW_ORIGIN] == origin
    assert response.headers[_ALLOW_ORIGIN] != WILDCARD
    assert response.headers[_ALLOW_CREDENTIALS] == "true"

    # SEC-03: an explicit allow-list makes the response origin-dependent,
    # so a shared cache must key on Origin rather than serve one stored
    # copy to every caller
    assert "origin" in _header_tokens(response.headers[_VARY])


def test_preflight_from_an_allow_listed_origin_is_approved(client):
    """A preflight from an allow-listed origin is approved, echoes that
    origin, turns credentials on and caches the decision."""
    response = _preflight(client, _PRIMARY_ORIGIN)

    assert response.status_code == 200
    # SEC-03: exact origin equality, no prefix match, no reflection
    assert response.headers[_ALLOW_ORIGIN] == _PRIMARY_ORIGIN
    assert response.headers[_ALLOW_ORIGIN] != WILDCARD
    assert response.headers[_ALLOW_CREDENTIALS] == "true"
    assert response.headers[_MAX_AGE].isdigit()
    assert int(response.headers[_MAX_AGE]) > 0

    # SEC-03: the cached decision is origin-dependent, so the cache key
    # has to include the origin that earned it
    assert "origin" in _header_tokens(response.headers[_VARY])


def test_preflight_advertises_an_explicit_method_list(client):
    """A preflight advertises the three methods the routes serve, and
    names neither a wildcard nor a verb no route exposes."""
    response = _preflight(client, _PRIMARY_ORIGIN)
    advertised = _header_tokens(response.headers[_ALLOW_METHODS])

    assert response.status_code == 200
    # SEC-03: enumerated methods, not a wildcard
    assert {name.lower() for name in ADVERTISED_METHODS} <= advertised
    assert WILDCARD not in advertised
    assert response.headers[_ALLOW_METHODS] != WILDCARD
    for name in WITHHELD_METHODS:
        assert name.lower() not in advertised


@pytest.mark.parametrize("method", WITHHELD_METHODS)
def test_preflight_refuses_a_method_outside_the_list(client, method):
    """A preflight asking for a method the allow-list omits is
    refused."""
    response = _preflight(client, _PRIMARY_ORIGIN, method=method)

    assert response.status_code == 400


def test_preflight_advertises_an_explicit_request_header_list(client):
    """A preflight advertises the request headers the routes read, and
    never a wildcard."""
    response = _preflight(
        client,
        _PRIMARY_ORIGIN,
        request_headers=", ".join(ADVERTISED_REQUEST_HEADERS),
    )
    advertised = _header_tokens(response.headers[_ALLOW_HEADERS])

    assert response.status_code == 200
    # SEC-03: enumerated request headers, not a wildcard
    assert {
        name.lower() for name in ADVERTISED_REQUEST_HEADERS
    } <= advertised
    assert WILDCARD not in advertised
    assert response.headers[_ALLOW_HEADERS] != WILDCARD


def test_preflight_refuses_a_request_header_outside_the_list(client):
    """A preflight asking for a request header the allow-list omits is
    refused."""
    response = _preflight(
        client, _PRIMARY_ORIGIN, request_headers="X-Unlisted-Header"
    )

    assert response.status_code == 400


@pytest.mark.parametrize(
    "origin",
    [
        pytest.param(_UNRELATED_ORIGIN, id="unrelated-origin"),
        pytest.param(_SUFFIX_EXTENDED_ORIGIN, id="suffix-extended"),
        pytest.param(_SCHEME_SWAPPED_ORIGIN, id="scheme-swapped"),
        pytest.param(_OPAQUE_ORIGIN, id="opaque-origin"),
    ],
)
def test_unlisted_origin_receives_no_allow_origin_header(client, origin):
    """An origin the allow-list omits gets no allow-origin header, and
    the request still succeeds.

    A suffix-extended spelling and a swapped scheme are both omitted.
    Matching compares whole origin strings.
    """
    assert origin not in ALLOW_LISTED_ORIGINS

    response = client.get(PUBLIC_READ_PATH, headers={"Origin": origin})

    assert response.status_code == 200
    # SEC-03: the allow-origin header is withheld outright
    assert _ALLOW_ORIGIN not in response.headers


def test_preflight_from_an_unlisted_origin_is_refused(client):
    """A preflight from an origin the allow-list omits is refused and
    carries no allow-origin header."""
    response = _preflight(client, _UNRELATED_ORIGIN)

    assert response.status_code == 400
    # SEC-03: the allow-origin header is withheld outright
    assert _ALLOW_ORIGIN not in response.headers


def test_reference_arguments_build_valid_settings():
    """The keyword mapping every allow-list case starts from builds a
    valid ``Settings`` object.

    A rejection in a later case belongs to the one overridden key.
    """
    built = Settings(**_reference_settings_arguments())

    assert built.ALLOWED_ORIGINS == [_REFERENCE_ORIGIN]


def test_running_settings_carry_an_enumerated_allow_list():
    """The allow-list the application booted with names full origins
    and holds neither the wildcard nor the opaque origin."""
    assert ALLOW_LISTED_ORIGINS
    assert WILDCARD not in ALLOW_LISTED_ORIGINS
    assert _OPAQUE_ORIGIN not in ALLOW_LISTED_ORIGINS
    for origin in ALLOW_LISTED_ORIGINS:
        assert origin.startswith(("http://", "https://"))


@pytest.mark.parametrize(
    "unsafe_value",
    [
        pytest.param([], id="empty-list"),
        pytest.param([WILDCARD], id="wildcard"),
        pytest.param([_OPAQUE_ORIGIN], id="opaque-origin"),
        pytest.param(["testserver"], id="bare-host"),
        pytest.param(["example.com"], id="bare-dotted-host"),
        pytest.param(
            ["https://good.example.com", WILDCARD],
            id="wildcard-mixed-with-a-valid-origin",
        ),
        pytest.param(
            "https://a.example.com,https://b.example.com",
            id="comma-separated-string",
        ),
    ],
)
def test_unsafe_allow_list_prevents_startup(unsafe_value):
    """An unsafe allow-list raises a validation error naming
    ALLOWED_ORIGINS, and building ``Settings`` at import then fails.

    Each value arrives as a keyword, so these cases reach the field
    validator directly. The environment path a deployment uses is
    covered separately below, because it refuses an unparsable value
    before any validator runs.
    """
    with pytest.raises(ValidationError) as raised:
        _build_settings_with_allow_list(unsafe_value)

    # SEC-03: an unsafe allow-list prevents startup
    assert _rejected_field_names(raised.value) == {"ALLOWED_ORIGINS"}


@pytest.mark.parametrize(
    "safe_value",
    [
        pytest.param(["https://app.example.com"], id="single-origin"),
        pytest.param(
            ["https://app.example.com", "http://localhost:3000"],
            id="several-origins",
        ),
        pytest.param(["https://localhost:3000"], id="explicit-port"),
    ],
)
def test_enumerated_allow_list_is_accepted(safe_value):
    """A list of full origins is accepted unchanged, including one
    carrying an explicit port."""
    built = _build_settings_with_allow_list(safe_value)

    assert built.ALLOWED_ORIGINS == safe_value


def test_the_documented_environment_spelling_is_accepted(monkeypatch):
    """The JSON array form ``.env.example`` documents parses.

    This is the path a deployment takes, so the documented spelling has
    to work there and not only as a keyword.
    """
    monkeypatch.setenv(
        _ALLOW_LIST_VARIABLE, json.dumps(list(DOCUMENTED_ENV_ORIGINS))
    )

    built = Settings(_env_file=None)

    assert built.ALLOWED_ORIGINS == list(DOCUMENTED_ENV_ORIGINS)


@pytest.mark.parametrize("raw_value", UNPARSABLE_ENV_VALUES)
def test_an_unparsable_environment_allow_list_names_the_required_form(
    monkeypatch, raw_value
):
    """An unparsable environment value fails closed and says what to
    write.

    The library refuses the value before the field validator runs and
    reports only the lowercased variable name, so the guidance an
    operator needs survives on the cause alone. Without it a failed
    deployment reports a parser complaint about a character offset.
    """
    monkeypatch.setenv(_ALLOW_LIST_VARIABLE, raw_value)

    with pytest.raises(SettingsError) as raised:
        Settings(_env_file=None)

    # SEC-03: the process does not start on an unusable allow-list
    reported = str(raised.value)
    assert _ALLOW_LIST_VARIABLE.lower() in reported.lower()

    # SEC-03: the required form is carried by the cause, not the message
    cause = raised.value.__cause__
    assert isinstance(cause, ValueError)
    guidance = str(cause)
    assert _ALLOW_LIST_VARIABLE in guidance
    for marker in _REQUIRED_FORM_MARKERS:
        assert marker in guidance, guidance
        assert marker not in reported


@pytest.mark.parametrize("raw_value", UNSAFE_ENV_VALUES)
def test_an_unsafe_environment_allow_list_prevents_startup(
    monkeypatch, raw_value
):
    """A parsable but unsafe environment value is refused by name.

    A value that parses reaches the same field validator the keyword
    cases exercise, so the wildcard and the opaque origin cannot enter
    through the environment either.
    """
    monkeypatch.setenv(_ALLOW_LIST_VARIABLE, raw_value)

    with pytest.raises(ValidationError) as raised:
        Settings(_env_file=None)

    # SEC-03: an unsafe allow-list prevents startup
    assert _rejected_field_names(raised.value) == {_ALLOW_LIST_VARIABLE}
