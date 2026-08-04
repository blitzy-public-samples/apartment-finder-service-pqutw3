"""Regression cases for the Host allow-list.

The acceptance gate found the suppressed Starlette advisory PYSEC-2026-161
runtime-reachable: a request naming an arbitrary or malformed host in its
``Host`` header was answered with a redirect whose ``Location`` was built
from that value, so ``GET /listings`` with ``Host: attacker.example``
answered ``307`` to ``http://attacker.example/listings/``. The fix release
requires a Python version this project does not run, so the compensating
control the pinned release already ships is applied instead: an exact,
environment-driven host allow-list registered outside every other layer.

The cases below drive the two hostile values the gate used, confirm a
trusted host still redirects, and confirm an unsafe allow-list prevents
startup.

Rationale is indexed in ``documentation/security/decision-log.md`` at
DL-439 and DL-440.
"""
import json

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from pydantic.env_settings import SettingsError

from conftest import TEST_BASE_URL, TEST_HOST

from backend.app.core.config import Settings
from backend.app.main import app


# The variable the allow-list is read from
_HOST_LIST_VARIABLE = "ALLOWED_HOSTS"

# The two hostile values the acceptance gate used
HOSTILE_HOST = "attacker.example"
MALFORMED_HOST = "attacker.example/abc?x="

# The routes the gate drove, each of which redirects to its trailing-slash
# form and so reconstructs a URL from the Host header
SLASH_REDIRECTING_PATHS = ("/listings", "/filters", "/subscriptions")

# What a refused host is answered with
REFUSED_STATUS = 400

# Allow-list values that must prevent startup
UNSAFE_HOST_LISTS = (
    pytest.param([], id="empty-list"),
    pytest.param(["*"], id="wildcard"),
    pytest.param(["*.example.com"], id="subdomain-pattern"),
    pytest.param(["api.example.com", "*"], id="wildcard-among-valid"),
    pytest.param(["api.example.com:8000"], id="carries-a-port"),
    pytest.param(["https://api.example.com"], id="carries-a-scheme"),
    pytest.param(["api.example.com/path"], id="carries-a-path"),
    pytest.param(["api.example.com?q=1"], id="carries-a-query"),
    pytest.param(["api.example.com#f"], id="carries-a-fragment"),
    pytest.param(["user@api.example.com"], id="carries-userinfo"),
    pytest.param(["API.example.com"], id="uppercase"),
    pytest.param(["[::1]"], id="bracketed-ipv6"),
    pytest.param(["api example com"], id="contains-a-space"),
    pytest.param(["api..example.com"], id="empty-dns-label"),
    pytest.param(["-api.example.com"], id="label-starts-with-a-hyphen"),
    pytest.param(["api.example.com."], id="trailing-dot"),
    pytest.param(["exämple.com"], id="non-ascii"),
    pytest.param([""], id="empty-entry"),
)

# Allow-list values that must be accepted
SAFE_HOST_LISTS = (
    pytest.param(["api.example.com"], id="dns-name"),
    pytest.param(["localhost"], id="single-label"),
    pytest.param(["127.0.0.1"], id="ipv4-literal"),
    pytest.param(["localhost", "127.0.0.1", "api.example.com"], id="several"),
)


def _client_sending(host):
    """Return a client whose requests carry ``host`` in the Host header."""
    return TestClient(
        app,
        base_url="https://{0}".format(host),
        raise_server_exceptions=False,
    )


def _rejected_field_names(error):
    """Return the field names one validation error names."""
    return {
        part
        for reported in error.errors()
        for part in reported["loc"]
    }


# QA-03: an untrusted host is refused before routing reconstructs a URL
@pytest.mark.parametrize("path", SLASH_REDIRECTING_PATHS)
def test_an_untrusted_host_is_refused(path):
    """The hostile host answers 400 and no redirect."""
    with _client_sending(HOSTILE_HOST) as client:
        response = client.get(path, follow_redirects=False)

    assert response.status_code == REFUSED_STATUS, response.text
    assert "location" not in response.headers
    assert HOSTILE_HOST not in response.text


# QA-03: a malformed host cannot poison a Location header
@pytest.mark.parametrize("path", SLASH_REDIRECTING_PATHS)
def test_a_malformed_host_is_refused(path):
    """A host carrying a path and a query answers 400 and no redirect."""
    with _client_sending(MALFORMED_HOST) as client:
        response = client.get(path, follow_redirects=False)

    assert response.status_code == REFUSED_STATUS, response.text
    assert "location" not in response.headers


# QA-03: the refusal reaches every method and every path, not only the
# slash-redirecting ones
def test_an_untrusted_host_reaches_no_route():
    """A refused host is answered before any handler runs."""
    with _client_sending(HOSTILE_HOST) as client:
        for method, path in (
            ("get", "/listings/"),
            ("get", "/openapi.json"),
            ("post", "/auth/login"),
            ("post", "/auth/logout"),
            ("get", "/no-such-path"),
        ):
            response = getattr(client, method)(path)
            assert response.status_code == REFUSED_STATUS, (method, path)


# QA-03: a host whose value merely ends with an allowed host is refused,
# which is the unanchored-suffix bypass an exact match avoids
@pytest.mark.parametrize(
    "host",
    [
        "evil-{0}".format(TEST_HOST),
        "{0}.attacker.example".format(TEST_HOST),
        "not{0}".format(TEST_HOST),
    ],
)
def test_a_host_resembling_an_allowed_host_is_refused(host):
    """Matching is equality, so a lookalike host is refused."""
    with _client_sending(host) as client:
        response = client.get("/listings/")

    assert response.status_code == REFUSED_STATUS, response.text


# QA-03: an absent Host header is refused
def test_a_request_with_no_host_header_is_refused(client):
    """A request carrying no Host header matches no allowed host."""
    response = client.get("/listings/", headers={"Host": ""})

    assert response.status_code == REFUSED_STATUS, response.text


# QA-03: the trusted host is unaffected, redirect included
def test_the_trusted_host_still_redirects_to_the_slash_form(client):
    """The allowed host keeps the framework's trailing-slash redirect."""
    response = client.get("/listings", follow_redirects=False)

    assert response.status_code == 307, response.text
    assert response.headers["location"] == "{0}/listings/".format(
        TEST_BASE_URL
    )


# QA-03: the trusted host still reaches the public read path
def test_the_trusted_host_still_reads_the_public_listing_path(client):
    """The allowed host is served exactly as before."""
    response = client.get("/listings/")

    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list)


# QA-03: an unsafe allow-list prevents startup
@pytest.mark.parametrize("hosts", UNSAFE_HOST_LISTS)
def test_an_unsafe_host_allow_list_prevents_startup(hosts, monkeypatch):
    """A wildcard, a pattern, a non-host or an empty list is refused."""
    monkeypatch.setenv(_HOST_LIST_VARIABLE, json.dumps(hosts))

    with pytest.raises(ValidationError) as raised:
        Settings(_env_file=None)

    assert _rejected_field_names(raised.value) == {_HOST_LIST_VARIABLE}


# QA-03: a bare comma-separated value is refused with a usable message
@pytest.mark.parametrize(
    "raw_value", ["localhost,127.0.0.1", "localhost", "[localhost]", ""]
)
def test_a_non_json_host_list_is_refused(raw_value, monkeypatch):
    """The list-valued setting names the JSON form it needs.

    The library refuses the value ahead of the field validator, so the
    required form is asserted on the cause.
    """
    monkeypatch.setenv(_HOST_LIST_VARIABLE, raw_value)

    with pytest.raises(SettingsError) as raised:
        Settings(_env_file=None)

    assert _HOST_LIST_VARIABLE.lower() in str(raised.value).lower()
    cause = raised.value.__cause__
    assert isinstance(cause, ValueError)
    assert _HOST_LIST_VARIABLE in str(cause)
    assert "JSON array" in str(cause)


# QA-03: the setting is required, so an absent value prevents startup
def test_an_absent_host_allow_list_prevents_startup(monkeypatch):
    """The allow-list carries no default."""
    monkeypatch.delenv(_HOST_LIST_VARIABLE, raising=False)

    with pytest.raises(ValidationError) as raised:
        Settings(_env_file=None)

    assert _HOST_LIST_VARIABLE in _rejected_field_names(raised.value)


# QA-03: a well-formed allow-list is accepted
@pytest.mark.parametrize("hosts", SAFE_HOST_LISTS)
def test_a_bare_host_allow_list_is_accepted(hosts, monkeypatch):
    """A DNS name, an IPv4 literal and a mixed list all construct."""
    monkeypatch.setenv(_HOST_LIST_VARIABLE, json.dumps(hosts))

    assert Settings(_env_file=None).ALLOWED_HOSTS == hosts


# QA-03: the middleware reads the validated setting rather than a literal
def test_the_registered_allow_list_is_the_configured_one():
    """The host middleware carries exactly the configured hosts, no more."""
    from starlette.middleware.trustedhost import TrustedHostMiddleware

    from backend.app.core.config import settings

    registered = [
        middleware
        for middleware in app.user_middleware
        if middleware.cls is TrustedHostMiddleware
    ]
    assert len(registered) == 1, app.user_middleware

    options = registered[0].kwargs
    assert options["allowed_hosts"] == settings.ALLOWED_HOSTS
    assert "*" not in options["allowed_hosts"]
    # a refusal must never answer with a redirect
    assert options["www_redirect"] is False
