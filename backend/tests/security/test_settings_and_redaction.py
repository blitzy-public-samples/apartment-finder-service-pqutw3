"""Regression tests for the validated settings and the redacting logger.

Every case in this module corresponds to an input that was accepted, or a
credential that was emitted verbatim, before the hardening it now guards.

The settings tests build ``Settings`` directly inside an environment from
which every setting name has been removed, so a value present in the
developer's shell or ``.env`` file cannot change a result.
"""

import contextlib
import importlib
import io
import json
import logging
import os
from decimal import Decimal
from unittest import mock

import pytest

from backend.app.core.logging import (
    REDACTION_PLACEHOLDER,
    RedactingFilter,
    RedactingJsonFormatter,
)

# Fixed marker asserted against. It is not a credential and carries no
# meaning outside this module.
SENTINEL = "TRACE_JSON_SECRET_123"

# A password satisfying the registration policy, reused by the schema
# cases so that only the address under test can fail a model.
VALID_PASSWORD = "Str0ng!Passw0rd"

# Settings values that satisfy every check, used as the baseline each
# case mutates one field of.
BASELINE_SETTINGS = {
    "ENVIRONMENT": "local",
    "DATABASE_URL": "postgresql://user:pw@localhost:5432/apartment_finder",
    "SECRET_KEY": "u7Qx2Lm9Rb4Vt6Yn1Zc8Kd3Fg5Hj0PsW",
    "JWT_ALGORITHMS": ["HS256"],
    "ALLOWED_ORIGINS": ["http://localhost:3000"],
    "ALLOWED_HOSTS": ["localhost", "127.0.0.1"],
    "ZILLOW_API_URL": "https://zillow-api.example.com/v2/listings",
    "ZILLOW_API_KEY": "listing-provider-key",
    "PAYPAL_MODE": "sandbox",
    "PAYPAL_API_BASE": "https://api-m.sandbox.paypal.com",
    "PAYPAL_CLIENT_ID": "paypal-client-id",
    "PAYPAL_CLIENT_SECRET": "paypal-client-secret",
    "PAYPAL_WEBHOOK_ID": "paypal-webhook-id",
    "SENDGRID_API_KEY": "sendgrid-key",
}


def _import_config_module():
    """Imports the settings module with a satisfying environment.

    The module validates and instantiates its settings while it loads, so
    the required names are supplied for the duration of the import and
    removed again afterwards.
    """
    missing = {
        name: (value if isinstance(value, str) else json.dumps(value))
        for name, value in BASELINE_SETTINGS.items()
        if name not in os.environ
    }
    with mock.patch.dict(os.environ, missing):
        return importlib.import_module("backend.app.core.config")


CONFIG = _import_config_module()
Settings = CONFIG.Settings


@contextlib.contextmanager
def _environment_without_settings():
    """Removes every declared setting name from the environment."""
    with mock.patch.dict(os.environ, {}, clear=False):
        for name in Settings.__fields__:
            os.environ.pop(name, None)
        yield


def build_settings(**overrides):
    """Builds ``Settings`` from the baseline plus the given overrides."""
    values = dict(BASELINE_SETTINGS)
    values.update(overrides)
    with _environment_without_settings():
        return Settings(_env_file=None, **values)


def assert_rejected(**overrides):
    """Asserts that the overridden configuration fails to construct."""
    with pytest.raises(Exception):
        build_settings(**overrides)


def emit(build):
    """Returns the text one logger call writes through the formatter."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(RedactingJsonFormatter())
    handler.addFilter(RedactingFilter())
    logger = logging.getLogger("test.redaction.%d" % id(build))
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    build(logger)
    return stream.getvalue()


def raising(text):
    """Returns a logger call that reports an exception carrying ``text``."""

    def call(logger):
        try:
            raise ValueError(text)
        except ValueError:
            logger.exception("outbound call failed")

    return call


class TestSigningKeyValidation:
    """SECRET_KEY normalization precedes measurement."""

    def test_baseline_key_is_accepted(self):
        assert build_settings().SECRET_KEY == BASELINE_SETTINGS["SECRET_KEY"]

    @pytest.mark.parametrize(
        "key",
        [
            " " * 32,
            "\t" * 40,
            "\n" * 33,
            "a" + " " * 31,
            " " * 31 + "a",
            "  " + "b" * 40 + "  ",
            "",
        ],
    )
    def test_blank_and_padded_keys_are_rejected(self, key):
        assert_rejected(SECRET_KEY=key)

    @pytest.mark.parametrize(
        "key",
        [
            "your_secret_key_here",
            "   your_secret_key_here   " + " " * 10,
            "YOUR_SECRET_KEY_HERE",
            "changeme-changeme-changeme-changeme",
            "short",
        ],
    )
    def test_placeholder_and_short_keys_are_rejected(self, key):
        assert_rejected(SECRET_KEY=key)

    @pytest.mark.parametrize(
        "key",
        ["a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", "\u00e9" * 16 + "Zq7"],
    )
    def test_keys_meeting_the_byte_floor_are_accepted(self, key):
        assert build_settings(SECRET_KEY=key).SECRET_KEY == key


class TestJwtAlgorithmAllowlist:
    """Only the HMAC allowlist is accepted, in any letter case."""

    @pytest.mark.parametrize("algorithms", [["HS256"], ["HS384"], ["HS512"]])
    def test_allowlisted_algorithms_are_accepted(self, algorithms):
        assert build_settings(JWT_ALGORITHMS=algorithms).JWT_ALGORITHMS == (
            algorithms
        )

    @pytest.mark.parametrize(
        "algorithms",
        [
            [],
            ["none"],
            ["NONE"],
            ["NoNe"],
            ["RS256"],
            ["ES256"],
            ["PS256"],
            ["hs256"],
            ["HS256", "none"],
        ],
    )
    def test_unsafe_algorithm_lists_are_rejected(self, algorithms):
        assert_rejected(JWT_ALGORITHMS=algorithms)


class TestListingProviderDestination:
    """The listing-provider key may only travel to an allowed host."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://zillow-api.example.com/v2/listings",
            "https://zillow.com/v2/listings",
            "https://api.zillow.com/v2/listings",
        ],
    )
    def test_allowlisted_destinations_are_accepted(self, url):
        assert build_settings(ZILLOW_API_URL=url).ZILLOW_API_URL == url

    @pytest.mark.parametrize(
        "url",
        [
            "http://attacker.invalid/collect",
            "https://attacker.invalid/collect",
            "http://zillow.com/v2/listings",
            "ftp://zillow.com/v2/listings",
            "https://user:pw@zillow.com/v2/listings",
            "https://zillow.com@attacker.invalid/collect",
            "https://notzillow.com/v2/listings",
            "https://zillow.com.attacker.invalid/collect",
            "   ",
        ],
    )
    def test_other_destinations_are_rejected(self, url):
        assert_rejected(ZILLOW_API_URL=url)

    def test_service_refuses_a_destination_outside_the_allowlist(
        self, monkeypatch
    ):
        service = importlib.import_module(
            "backend.app.services.zillow_service"
        )
        attempted = []

        def unreachable(*args, **kwargs):
            attempted.append(kwargs)
            raise AssertionError("no request may be issued")

        monkeypatch.setattr(service.httpx, "get", unreachable)
        monkeypatch.setattr(
            service, "ZILLOW_API_URL", "https://attacker.invalid/collect"
        )
        assert service.fetch_listings(["94105"], {}) == []
        assert attempted == []


class TestPaymentApiBase:
    """The PayPal base is pinned to the mode in every environment."""

    @pytest.mark.parametrize(
        "mode, base",
        [
            ("sandbox", "https://api-m.sandbox.paypal.com"),
            ("live", "https://api-m.paypal.com"),
        ],
    )
    def test_matching_mode_and_base_are_accepted(self, mode, base):
        built = build_settings(PAYPAL_MODE=mode, PAYPAL_API_BASE=base)
        assert built.PAYPAL_API_BASE == base

    @pytest.mark.parametrize(
        "mode, base",
        [
            ("live", "https://api-m.sandbox.paypal.com"),
            ("sandbox", "https://api-m.paypal.com"),
            ("live", "https://attacker.invalid/collect"),
            ("sandbox", "https://attacker.invalid/collect"),
            ("sandbox", "http://api-m.sandbox.paypal.com"),
            ("sandbox", "https://api-m.sandbox.paypal.com/v1/oauth2"),
            ("sandbox", "https://api-m.sandbox.paypal.com?x=1"),
            ("sandbox", "https://api-m.sandbox.paypal.com#f"),
            ("sandbox", "https://u:pw@api-m.sandbox.paypal.com"),
            ("sandbox", "https://api-m.sandbox.paypal.com:8443"),
            ("sandbox", "https://api.sandbox.paypal.com"),
        ],
    )
    def test_mismatched_or_foreign_bases_are_rejected(self, mode, base):
        assert_rejected(PAYPAL_MODE=mode, PAYPAL_API_BASE=base)

    def test_production_refuses_sandbox_mode(self):
        assert_rejected(
            ENVIRONMENT="production",
            PAYPAL_MODE="sandbox",
            PAYPAL_API_BASE="https://api-m.sandbox.paypal.com",
        )

    def test_production_accepts_live_mode(self):
        built = build_settings(
            ENVIRONMENT="production",
            PAYPAL_MODE="live",
            PAYPAL_API_BASE="https://api-m.paypal.com",
            ZILLOW_API_URL="https://api.zillow.com/v2/listings",
            FROM_EMAIL="no-reply@apartment-finder.io",
        )
        assert built.ENVIRONMENT == "production"


class TestTrustedHostList:
    """Trusted hosts must be bare hostnames, never a wildcard."""

    @pytest.mark.parametrize(
        "hosts",
        [
            ["localhost"],
            ["127.0.0.1"],
            ["api.example.com", "10.0.0.5"],
            ["testserver"],
        ],
    )
    def test_bare_hostnames_are_accepted(self, hosts):
        assert build_settings(ALLOWED_HOSTS=hosts).ALLOWED_HOSTS == hosts

    @pytest.mark.parametrize(
        "hosts",
        [
            ["*"],
            ["*.example.com"],
            ["http://evil.example.com/x"],
            ["evil.example.com:8080"],
            ["evil example.com"],
            ["user@evil.example.com"],
            ["bad_host"],
            ["-leading-hyphen.example.com"],
            [""],
            [],
        ],
    )
    def test_wildcards_and_malformed_hosts_are_rejected(self, hosts):
        assert_rejected(ALLOWED_HOSTS=hosts)

    @pytest.mark.parametrize(
        "hosts", [["api.paypal.com"], ["api-m.sandbox.paypal.com"]]
    )
    def test_certificate_hosts_accept_paypal_hostnames(self, hosts):
        built = build_settings(PAYPAL_CERT_HOST_ALLOWLIST=hosts)
        assert built.PAYPAL_CERT_HOST_ALLOWLIST == hosts

    @pytest.mark.parametrize(
        "hosts",
        [
            ["*.paypal.com"],
            ["api.evil.invalid"],
            ["https://api.paypal.com"],
            ["api.paypal.com:443"],
            [],
        ],
    )
    def test_certificate_hosts_reject_anything_else(self, hosts):
        assert_rejected(PAYPAL_CERT_HOST_ALLOWLIST=hosts)


class TestOriginList:
    """Credentialed CORS never accepts a wildcard origin."""

    def test_explicit_origins_are_accepted(self):
        origins = ["http://localhost:3000", "http://localhost:80"]
        assert build_settings(ALLOWED_ORIGINS=origins).ALLOWED_ORIGINS == (
            origins
        )

    @pytest.mark.parametrize(
        "origins", [["*"], ["http://*.example.com"], []]
    )
    def test_wildcard_and_empty_origins_are_rejected(self, origins):
        assert_rejected(ALLOWED_ORIGINS=origins)


class TestRedactionOfCredentialShapedText:
    """Every shape that previously escaped redaction is now covered."""

    @pytest.mark.parametrize(
        "name, build",
        [
            (
                "exception text carrying a JSON mapping",
                raising('{"api_key":"%s"}' % SENTINEL),
            ),
            (
                "exception text carrying a query string",
                raising("GET https://h/x?api_key=%s failed" % SENTINEL),
            ),
            (
                "exception text carrying URL user information",
                raising(
                    "connect postgresql://svc:%s@db:5432/app failed"
                    % SENTINEL
                ),
            ),
            (
                "exception text carrying a single-quoted mapping",
                raising("{'client_secret': '%s'}" % SENTINEL),
            ),
            (
                "context value carrying a JSON mapping",
                lambda logger: logger.info(
                    "outbound call failed",
                    extra={"detail": '{"api_key": "%s"}' % SENTINEL},
                ),
            ),
            (
                "context value nested in a mapping",
                lambda logger: logger.info(
                    "context", extra={"payload": {"api_key": SENTINEL}}
                ),
            ),
            (
                "context value nested several levels deep",
                lambda logger: logger.info(
                    "context",
                    extra={
                        "a": {"b": [{"c": {"access_token": SENTINEL}}]}
                    },
                ),
            ),
            (
                "context field whose own name is credential-shaped",
                lambda logger: logger.info(
                    "context", extra={"api_key": [SENTINEL, SENTINEL]}
                ),
            ),
            (
                "context value inside a tuple",
                lambda logger: logger.info(
                    "context", extra={"items": ({"pwd": SENTINEL},)}
                ),
            ),
            (
                "context value inside a set",
                lambda logger: logger.info(
                    "context", extra={"items": {"token=%s" % SENTINEL}}
                ),
            ),
            (
                "message with a fully percent-encoded key name",
                lambda logger: logger.info(
                    "http://h/x?%61%70%69%5f%6b%65%79=" + SENTINEL
                ),
            ),
            (
                "message with a partly percent-encoded key name",
                lambda logger: logger.info(
                    "http://h/x?api%5Fkey=" + SENTINEL
                ),
            ),
            (
                "message with a doubly percent-encoded key name",
                lambda logger: logger.info(
                    "http://h/x?%2561%2570%2569%255f%256b%2565%2579="
                    + SENTINEL
                ),
            ),
            (
                "message with a backslash-escaped JSON mapping",
                lambda logger: logger.info(
                    'detail=\\"api_key\\": \\"%s\\"' % SENTINEL
                ),
            ),
            (
                "message with a plain query string",
                lambda logger: logger.info(
                    "http://h/x?api_key=" + SENTINEL
                ),
            ),
            (
                "message with a bare scheme word",
                lambda logger: logger.info("Bearer " + SENTINEL),
            ),
            (
                "message with an Authorization header",
                lambda logger: logger.info(
                    "Authorization: Bearer " + SENTINEL
                ),
            ),
            (
                "message with an API key header",
                lambda logger: logger.info("X-API-Key: " + SENTINEL),
            ),
            (
                "message with an upper-case client secret",
                lambda logger: logger.info("CLIENT_SECRET=" + SENTINEL),
            ),
            (
                "message with a refresh token mapping",
                lambda logger: logger.info(
                    '{"refresh_token":"%s"}' % SENTINEL
                ),
            ),
            (
                "positional argument carrying an assignment",
                lambda logger: logger.info(
                    "outbound %s", "api_key=" + SENTINEL
                ),
            ),
            (
                "mapping argument carrying an assignment",
                lambda logger: logger.info(
                    "outbound %(value)s",
                    {"value": "client_secret=" + SENTINEL},
                ),
            ),
            (
                "argument carrying a nested container",
                lambda logger: logger.info(
                    "outbound %s", [{"api_key": SENTINEL}]
                ),
            ),
        ],
    )
    def test_credential_never_reaches_the_stream(self, name, build):
        assert SENTINEL not in emit(build), name

    @pytest.mark.parametrize(
        "value", ["bearer", "basic", "digest", "token"]
    )
    def test_a_scheme_word_is_redacted_when_the_key_is_sensitive(
        self, value
    ):
        rendered = emit(lambda logger: logger.info("password=" + value))
        assert value not in rendered
        assert REDACTION_PLACEHOLDER in rendered


class TestRegistrationAddressContract:
    """The address contract matches the frozen client-side validator."""

    @pytest.mark.parametrize(
        "model_name", ["UserCreate", "UserLogin"]
    )
    @pytest.mark.parametrize(
        "address",
        [
            "abc",
            "not-an-email",
            "a b",
            "a\nb",
            "a@b",
            "user@@example.com",
            "user@exam ple.com",
            "user example@test.com",
            "user@example.com\r\nBcc: evil@example.net",
            "user\x00@example.com",
            "user@example.com\x1b",
            "@example.com",
            "user@",
            "user@.com",
        ],
    )
    def test_invalid_addresses_are_rejected(self, model_name, address):
        schema = importlib.import_module("backend.app.schema.user")
        model = getattr(schema, model_name)
        with pytest.raises(Exception):
            model(email=address, password=VALID_PASSWORD)

    @pytest.mark.parametrize(
        "model_name", ["UserCreate", "UserLogin"]
    )
    @pytest.mark.parametrize(
        "address, stored",
        [
            ("user@example.com", "user@example.com"),
            ("  user@example.com  ", "user@example.com"),
            ("a@b.c", "a@b.c"),
            ("first.last+tag@sub.example.co.uk", None),
        ],
    )
    def test_valid_addresses_are_accepted(
        self, model_name, address, stored
    ):
        schema = importlib.import_module("backend.app.schema.user")
        model = getattr(schema, model_name)
        built = model(email=address, password=VALID_PASSWORD)
        assert built.email == (stored if stored else address)

    def test_password_policy_and_ceiling_are_unchanged(self):
        schema = importlib.import_module("backend.app.schema.user")
        with pytest.raises(Exception):
            schema.UserCreate(email="user@example.com", password="short1!A")
        with pytest.raises(Exception):
            schema.UserCreate(
                email="user@example.com", password="a" * 73
            )
        assert schema.UserCreate(
            email="user@example.com", password=VALID_PASSWORD
        ).password == VALID_PASSWORD

    def test_response_model_excludes_the_password_hash(self):
        schema = importlib.import_module("backend.app.schema.user")
        assert "hashed_password" not in schema.User.__fields__
        assert schema.User.__fields__["id"].type_ is int
        assert schema.User.Config.orm_mode is True

    def test_extra_fields_are_rejected(self):
        schema = importlib.import_module("backend.app.schema.user")
        with pytest.raises(Exception):
            schema.UserCreate(
                email="user@example.com",
                password=VALID_PASSWORD,
                role="admin",
            )


class TestRedactionLeavesOtherOutputIntact:
    """Redaction replaces values only, and never breaks a record."""

    def test_key_name_survives_redaction(self):
        rendered = emit(
            lambda logger: logger.info("api_key=" + SENTINEL)
        )
        assert "api_key=" + REDACTION_PLACEHOLDER in rendered

    def test_plain_message_is_unchanged(self):
        rendered = emit(
            lambda logger: logger.info("listing refresh finished")
        )
        assert json.loads(rendered)["message"] == (
            "listing refresh finished"
        )

    @pytest.mark.parametrize(
        "template, argument, expected",
        [
            ("count %d", 12, "count 12"),
            ("amount %.2f", 9.5, "amount 9.50"),
            ("amount %s", Decimal("9.99"), "amount 9.99"),
        ],
    )
    def test_argument_interpolation_still_works(
        self, template, argument, expected
    ):
        rendered = emit(
            lambda logger: logger.info(template, argument)
        )
        assert json.loads(rendered)["message"] == expected

    def test_non_sensitive_context_is_preserved(self):
        rendered = emit(
            lambda logger: logger.info("context", extra={"count": 12})
        )
        assert json.loads(rendered)["context"]["count"] == 12

    def test_unserializable_context_does_not_raise(self):
        rendered = emit(
            lambda logger: logger.info("context", extra={"obj": object()})
        )
        assert json.loads(rendered)["level"] == "INFO"
