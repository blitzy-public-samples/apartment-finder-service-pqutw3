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

from backend.app.core import logging as app_logging
from backend.app.core.logging import (
    BASE_LOGGER_NAME,
    HANDLER_NAME,
    REDACTION_PLACEHOLDER,
    RedactingFilter,
    RedactingJsonFormatter,
    configure_logging,
    get_logger,
    redact,
    unredacted_handler_names,
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
        [
            "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
            "u7Qx2Lm9Rb4Vt6Yn1Zc8Kd3Fg5Hj0PsW",
            "\u00e9\u00e8\u00e7Wm4Jt7Bq2Xz9Kd5Rv8Ny3Gp6Ls1Ht",
        ],
    )
    def test_keys_meeting_every_measure_are_accepted(self, key):
        """Length is measured in bytes, and variety is measured too.

        The third key carries three two-byte characters, so it measures
        35 UTF-8 bytes across 32 characters: the floor is a byte count
        rather than a character count.
        """
        assert build_settings(SECRET_KEY=key).SECRET_KEY == key

    @pytest.mark.parametrize(
        "key",
        [
            "Ab" * 16,
            "abababababababababababababababab",
            "a" * 32,
            "0123456789" * 4,
        ],
    )
    def test_keys_of_low_variety_are_rejected(self, key):
        """A key long enough in bytes but repetitive is still refused.

        Each key here clears the 32-byte floor and would have been
        accepted while length was the only measure applied.
        """
        assert_rejected(SECRET_KEY=key)

    @pytest.mark.parametrize(
        "key",
        [
            "aaaaQx2Lm9Rb4Vt6Yn1Zc8Kd3Fg5Hj0P",
            "Qx2Lm9Rb4Vt6Yn1Zc8Kd3Fg5Hj0Pwwww",
        ],
    )
    def test_keys_repeating_one_character_too_often_are_rejected(
        self, key
    ):
        assert_rejected(SECRET_KEY=key)

    @pytest.mark.parametrize(
        "key",
        [
            "abcdeQx2Lm9Rb4Vt6Yn1Zc8Kd3Fg5Hj",
            "ZYXWVUQx2Lm9Rb4Vt6Yn1Zc8Kd3Fg5H",
            "Qx2Lm9Rb4Vt6Yn1Zc8Kd3Fg5Hj0P56789",
        ],
    )
    def test_keys_carrying_a_long_character_run_are_rejected(self, key):
        assert_rejected(SECRET_KEY=key)


class TestSigningKeyLengthPerAlgorithm:
    """The key floor follows the strongest configured algorithm.

    RFC 7518 section 3.2 requires an HMAC key at least as long as the
    hash output, so HS384 requires 48 UTF-8 bytes and HS512 requires 64
    where HS256 requires 32.
    """

    # Keys measuring exactly 32, 48 and 64 UTF-8 bytes.
    KEY_32 = "u7Qx2Lm9Rb4Vt6Yn1Zc8Kd3Fg5Hj0PsW"
    KEY_48 = KEY_32 + "q9Ez4Ta6Uo2Ib5Mv"
    KEY_64 = KEY_48 + "Xd7Wl3Cn8Ju6Rk1Y"

    def test_declared_floors_match_the_hash_output_sizes(self):
        assert CONFIG.MIN_SIGNING_KEY_BYTES_BY_ALGORITHM["HS256"] == 32
        assert CONFIG.MIN_SIGNING_KEY_BYTES_BY_ALGORITHM["HS384"] == 48
        assert CONFIG.MIN_SIGNING_KEY_BYTES_BY_ALGORITHM["HS512"] == 64

    @pytest.mark.parametrize(
        "algorithms, expected",
        [
            (["HS256"], 32),
            (["HS384"], 48),
            (["HS512"], 64),
            (["HS256", "HS384"], 48),
            (["HS256", "HS512"], 64),
            (["HS512", "HS384", "HS256"], 64),
        ],
    )
    def test_required_length_is_the_strongest_algorithm(
        self, algorithms, expected
    ):
        assert (
            CONFIG.required_signing_key_bytes(algorithms) == expected
        )

    @pytest.mark.parametrize(
        "algorithms, key",
        [
            (["HS384"], KEY_32),
            (["HS512"], KEY_32),
            (["HS512"], KEY_48),
            (["HS256", "HS384"], KEY_32),
            (["HS256", "HS512"], KEY_48),
        ],
    )
    def test_key_below_the_algorithm_floor_is_rejected(
        self, algorithms, key
    ):
        assert_rejected(JWT_ALGORITHMS=algorithms, SECRET_KEY=key)

    @pytest.mark.parametrize(
        "algorithms, key",
        [
            (["HS256"], KEY_32),
            (["HS384"], KEY_48),
            (["HS512"], KEY_64),
            (["HS256", "HS384"], KEY_48),
            (["HS256", "HS512"], KEY_64),
        ],
    )
    def test_key_meeting_the_algorithm_floor_is_accepted(
        self, algorithms, key
    ):
        settings = build_settings(
            JWT_ALGORITHMS=algorithms, SECRET_KEY=key
        )
        assert settings.SECRET_KEY == key
        assert settings.JWT_ALGORITHMS == algorithms


class TestJwtAlgorithmAllowlist:
    """Only the HMAC allowlist is accepted, in any letter case."""

    @pytest.mark.parametrize(
        "algorithms, key",
        [
            (["HS256"], TestSigningKeyLengthPerAlgorithm.KEY_32),
            (["HS384"], TestSigningKeyLengthPerAlgorithm.KEY_48),
            (["HS512"], TestSigningKeyLengthPerAlgorithm.KEY_64),
        ],
    )
    def test_allowlisted_algorithms_are_accepted(self, algorithms, key):
        settings = build_settings(
            JWT_ALGORITHMS=algorithms, SECRET_KEY=key
        )
        assert settings.JWT_ALGORITHMS == algorithms

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


class TestPaymentCallbackAddresses:
    """The payer-return and cancel addresses are their own settings."""

    def test_they_are_independent_of_the_origin_list(self):
        built = build_settings(
            ALLOWED_ORIGINS=[
                "https://attacker.example.com",
                "https://app.example.com",
            ],
            PAYPAL_RETURN_URL="https://app.example.com/s/return",
            PAYPAL_CANCEL_URL="https://app.example.com/s/cancel",
        )
        assert built.PAYPAL_RETURN_URL == (
            "https://app.example.com/s/return"
        )
        assert built.PAYPAL_CANCEL_URL == (
            "https://app.example.com/s/cancel"
        )
        assert built.ALLOWED_ORIGINS[0] not in built.PAYPAL_RETURN_URL

    def test_the_two_addresses_are_configured_separately(self):
        """Neither address is derived from the other."""
        built = build_settings(
            PAYPAL_RETURN_URL="https://app.example.com/paid",
            PAYPAL_CANCEL_URL="https://other.example.com/gave-up",
        )
        assert built.PAYPAL_RETURN_URL == "https://app.example.com/paid"
        assert built.PAYPAL_CANCEL_URL == (
            "https://other.example.com/gave-up"
        )

    def test_an_equal_pair_is_rejected(self):
        """An approving payer must be distinguishable from one who left."""
        assert_rejected(
            PAYPAL_RETURN_URL="https://app.example.com/s",
            PAYPAL_CANCEL_URL="https://app.example.com/s",
        )

    @pytest.mark.parametrize(
        "address, expected",
        [
            (
                "https://App.Example.com/Return/",
                "https://app.example.com/Return",
            ),
            ("https://app.example.com", "https://app.example.com"),
            (
                "http://localhost:3000/subscription/return",
                "http://localhost:3000/subscription/return",
            ),
            (
                "http://localhost:3000/subscription?paypal=return",
                "http://localhost:3000/subscription?paypal=return",
            ),
            (
                "https://app.example.com/return/?next=1",
                "https://app.example.com/return/?next=1",
            ),
        ],
    )
    def test_accepted_addresses_are_canonicalized(
        self, address, expected
    ):
        built = build_settings(PAYPAL_RETURN_URL=address)
        assert built.PAYPAL_RETURN_URL == expected

    @pytest.mark.parametrize(
        "address",
        [
            "",
            "   ",
            "*",
            "https://*.example.com",
            "app.example.com/return",
            "ftp://app.example.com/return",
            "https://app.example.com/return#done",
            "https://u:pw@app.example.com/return",
        ],
    )
    def test_malformed_addresses_are_rejected(self, address):
        assert_rejected(PAYPAL_RETURN_URL=address)
        assert_rejected(PAYPAL_CANCEL_URL=address)

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
            DATABASE_URL=(
                "postgresql://svc:pw@db.apartment-finder.io:5432/app"
            ),
            ALLOWED_ORIGINS=["https://apartment-finder.io"],
            ALLOWED_HOSTS=["apartment-finder.io"],
            PAYPAL_RETURN_URL=(
                "https://apartment-finder.io/subscription/return"
            ),
            PAYPAL_CANCEL_URL=(
                "https://apartment-finder.io/subscription/cancel"
            ),
            RATE_LIMIT_STORAGE_URI=(
                "redis://cache.apartment-finder.io:6379/0"
            ),
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


# Settings that together describe one deployed, non-local environment.
# Every value satisfies the checks that apply outside ENVIRONMENT=local,
# so a case may override one field and have only that field fail.
DEPLOYED_SETTINGS = {
    "ENVIRONMENT": "staging",
    "DATABASE_URL": "postgresql://svc:pw@db.corp-example.net:5432/apartment",
    "ZILLOW_API_URL": "https://zillow.com/v2/listings",
    "FROM_EMAIL": "no-reply@corp-example.net",
    "ALLOWED_ORIGINS": ["https://app.corp-example.net"],
    "ALLOWED_HOSTS": ["app.corp-example.net"],
    "PAYPAL_RETURN_URL": (
        "https://app.corp-example.net/subscription/return"
    ),
    "PAYPAL_CANCEL_URL": (
        "https://app.corp-example.net/subscription/cancel"
    ),
    "RATE_LIMIT_STORAGE_URI": "redis://cache.corp-example.net:6379/0",
}


def build_deployed(**overrides):
    """Builds settings for a deployed environment plus the overrides."""
    values = dict(DEPLOYED_SETTINGS)
    values.update(overrides)
    return build_settings(**values)


def assert_deployed_rejected(**overrides):
    """Asserts the deployed configuration fails with these overrides."""
    with pytest.raises(Exception):
        build_deployed(**overrides)


class TestPaymentCallbackUrls:
    """Each hosted-redirect callback is its own validated setting.

    The checks below cover the deployed environment, where the scheme must
    be TLS and the host must be publicly addressable.
    """

    def test_callbacks_are_not_taken_from_the_origin_list(self):
        built = build_settings(
            ALLOWED_ORIGINS=["http://localhost:3000"],
            PAYPAL_RETURN_URL="http://localhost:8080/return",
            PAYPAL_CANCEL_URL="http://localhost:8080/cancel",
        )
        assert built.PAYPAL_RETURN_URL == "http://localhost:8080/return"
        assert built.PAYPAL_RETURN_URL not in built.ALLOWED_ORIGINS
        assert built.PAYPAL_CANCEL_URL not in built.ALLOWED_ORIGINS

    @pytest.mark.parametrize(
        "address",
        [
            "http://localhost:3000/return",
            "https://app.corp-example.net/return",
        ],
    )
    def test_local_accepts_plaintext_and_loopback(self, address):
        built = build_settings(PAYPAL_RETURN_URL=address)
        assert built.PAYPAL_RETURN_URL == address

    @pytest.mark.parametrize(
        "address",
        [
            "http://app.corp-example.net/return",
            "https://localhost/return",
            "https://127.0.0.1/return",
            "https://10.0.0.7/return",
            "https://service.internal/return",
        ],
    )
    def test_deployed_rejects_plaintext_and_internal_hosts(self, address):
        assert_deployed_rejected(PAYPAL_RETURN_URL=address)
        assert_deployed_rejected(PAYPAL_CANCEL_URL=address)

    def test_deployed_accepts_public_https_callbacks(self):
        deployed = build_deployed()
        assert deployed.PAYPAL_RETURN_URL == (
            "https://app.corp-example.net/subscription/return"
        )
        assert deployed.PAYPAL_CANCEL_URL == (
            "https://app.corp-example.net/subscription/cancel"
        )

    @pytest.mark.parametrize(
        "address",
        [
            "",
            "   ",
            "/subscription",
            "app.corp-example.net",
            "https://*.corp-example.net",
            "https://user:pw@app.corp-example.net",
            "https://app.corp-example.net#frag",
            "ftp://app.corp-example.net",
        ],
    )
    def test_malformed_callbacks_are_rejected(self, address):
        assert_rejected(PAYPAL_RETURN_URL=address)
        assert_rejected(PAYPAL_CANCEL_URL=address)

    def test_scheme_and_host_are_returned_lowercased(self):
        built = build_settings(
            PAYPAL_RETURN_URL="HTTP://LocalHost:3000/Return"
        )
        assert built.PAYPAL_RETURN_URL == (
            "http://localhost:3000/Return"
        )


class TestRateLimitStorage:
    """Credential-endpoint counters must be shared once deployed."""

    @pytest.mark.parametrize(
        "uri",
        [
            "memory://",
            "async+memory://",
            CONFIG.BOUNDED_MEMORY_SCHEME + "://",
        ],
    )
    def test_local_accepts_every_process_local_store(self, uri):
        assert build_settings(
            RATE_LIMIT_STORAGE_URI=uri
        ).RATE_LIMIT_STORAGE_URI == uri

    @pytest.mark.parametrize(
        "uri",
        [
            "memory://",
            "async+memory://",
            CONFIG.BOUNDED_MEMORY_SCHEME + "://",
        ],
    )
    def test_deployed_rejects_every_process_local_store(self, uri):
        assert_deployed_rejected(RATE_LIMIT_STORAGE_URI=uri)

    def test_deployed_rejects_the_declared_default(self):
        values = dict(DEPLOYED_SETTINGS)
        values.pop("RATE_LIMIT_STORAGE_URI", None)
        with pytest.raises(Exception):
            with _environment_without_settings():
                Settings(
                    _env_file=None, **dict(BASELINE_SETTINGS, **values)
                )

    def test_local_accepts_the_declared_default(self):
        values = dict(BASELINE_SETTINGS)
        values.pop("RATE_LIMIT_STORAGE_URI", None)
        with _environment_without_settings():
            built = Settings(_env_file=None, **values)
        assert built.RATE_LIMIT_STORAGE_URI == (
            Settings.__fields__["RATE_LIMIT_STORAGE_URI"].default
        )
        assert CONFIG.rate_limit_storage_scheme(
            built.RATE_LIMIT_STORAGE_URI
        ) in CONFIG.IN_PROCESS_RATE_LIMIT_SCHEMES

    @pytest.mark.parametrize(
        "uri",
        [
            "redis://cache.corp-example.net:6379/0",
            "rediss://cache.corp-example.net:6379/0",
            "memcached://cache.corp-example.net:11211",
        ],
    )
    def test_deployed_accepts_shared_storage(self, uri):
        assert build_deployed(
            RATE_LIMIT_STORAGE_URI=uri
        ).RATE_LIMIT_STORAGE_URI == uri

    @pytest.mark.parametrize(
        "uri", ["", "sqlite:///counters.db", "file:///tmp/x", "redis"]
    )
    def test_unknown_storage_schemes_are_rejected(self, uri):
        assert_rejected(RATE_LIMIT_STORAGE_URI=uri)

    def test_the_deployable_set_is_exactly_the_shared_set(self):
        assert CONFIG.DEPLOYABLE_RATE_LIMIT_STORAGE_SCHEMES == (
            CONFIG.SHARED_RATE_LIMIT_STORAGE_SCHEMES
        )
        assert CONFIG.UNBOUNDED_RATE_LIMIT_STORAGE_SCHEMES == (
            CONFIG.IN_PROCESS_RATE_LIMIT_SCHEMES
            - {CONFIG.BOUNDED_MEMORY_SCHEME}
        )
        assert not (
            CONFIG.DEPLOYABLE_RATE_LIMIT_STORAGE_SCHEMES
            & CONFIG.IN_PROCESS_RATE_LIMIT_SCHEMES
        )
        assert CONFIG.BOUNDED_MEMORY_SCHEME not in (
            CONFIG.DEPLOYABLE_RATE_LIMIT_STORAGE_SCHEMES
        )

    def test_an_in_process_store_is_recorded_once(self):
        from backend.app.core import rate_limit

        records = []
        with mock.patch.object(
            rate_limit.settings,
            "RATE_LIMIT_STORAGE_URI",
            CONFIG.BOUNDED_MEMORY_SCHEME + "://",
        ), mock.patch.object(
            rate_limit.settings,
            "ENVIRONMENT",
            DEPLOYED_SETTINGS["ENVIRONMENT"],
        ), mock.patch.object(
            rate_limit.logger,
            "warning",
            lambda message, **kwargs: records.append((message, kwargs)),
        ):
            limiter = rate_limit.build_limiter()
        assert limiter is not None
        assert [message for message, _ in records] == [
            rate_limit.IN_PROCESS_STORE_MESSAGE
        ]
        assert records[0][1]["extra"]["setting"] == (
            "RATE_LIMIT_STORAGE_URI"
        )
        assert records[0][1]["extra"]["scheme"] == (
            CONFIG.BOUNDED_MEMORY_SCHEME
        )

    def test_webhook_rate_limit_uses_the_same_expression_check(self):
        assert build_settings(
            RATE_LIMIT_WEBHOOK="30/minute"
        ).RATE_LIMIT_WEBHOOK == "30/minute"
        assert_rejected(RATE_LIMIT_WEBHOOK="lots")
        assert_rejected(RATE_LIMIT_WEBHOOK="0/minute")


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


class TestUrlQueryStringsAreRemoved:
    """A query string is removed whole, whatever its keys are named.

    A key-based rule only covers a parameter whose name spells a
    credential stem. A search term does not, so a URL rendered into a
    record previously disclosed the values a caller searched for.
    """

    #: A value carried in a query whose key names no credential.
    SEARCH_VALUE = "90210"

    @pytest.mark.parametrize(
        "text, expected",
        [
            (
                "https://h/v2/listings?zip_codes=90210",
                "https://h/v2/listings?" + REDACTION_PLACEHOLDER,
            ),
            (
                "https://h/p?a=1&b=2",
                "https://h/p?" + REDACTION_PLACEHOLDER,
            ),
            (
                "http://h:8080/p/q?x=y",
                "http://h:8080/p/q?" + REDACTION_PLACEHOLDER,
            ),
        ],
    )
    def test_the_query_is_replaced_and_the_target_kept(
        self, text, expected
    ):
        assert redact(text) == expected

    def test_a_search_value_is_removed_from_provider_prose(self):
        """The shape the HTTP library renders discloses nothing."""
        rendered = redact(
            "Client error '404 Not Found' for url "
            "'https://h/v2/listings?zip_codes=" + self.SEARCH_VALUE
            + "&max_rent=3000'"
        )

        assert self.SEARCH_VALUE not in rendered
        assert "3000" not in rendered
        assert "https://h/v2/listings" in rendered
        assert rendered.endswith("'")

    def test_a_target_without_a_query_is_unchanged(self):
        assert redact("https://h/v2/listings") == (
            "https://h/v2/listings"
        )

    def test_user_information_is_still_replaced_alongside(self):
        rendered = redact(
            "postgresql://svc:" + SENTINEL + "@db:5432/app?sslmode=require"
        )

        assert SENTINEL not in rendered
        assert "sslmode" not in rendered
        assert REDACTION_PLACEHOLDER in rendered

    def test_replacement_is_idempotent(self):
        once = redact("https://h/p?zip_codes=" + self.SEARCH_VALUE)

        assert redact(once) == once

    def test_a_query_carried_in_a_record_is_removed(self):
        """The rule applies to a record as the process would emit it."""
        rendered = emit(
            lambda logger: logger.info(
                "provider call failed",
                extra={
                    "target": "https://h/v2/listings?zip_codes="
                    + self.SEARCH_VALUE
                },
            )
        )

        assert self.SEARCH_VALUE not in rendered
        assert REDACTION_PLACEHOLDER in rendered


def _exercise_governed_logger(logger):
    """Emits one record of every credential shape the module covers."""
    logger.warning("api_key=%s", SENTINEL)
    logger.warning(
        "token: %(access_token)s", {"access_token": SENTINEL}
    )
    try:
        raise ValueError(
            "connect to https://user:" + SENTINEL + "@host/p failed"
        )
    except ValueError:
        logger.exception("outbound call failed")
    logger.warning(
        "context record",
        extra={
            "authorization": "Bearer " + SENTINEL,
            "nested": {"client_secret": SENTINEL},
            "count": 7,
        },
    )
    logger.warning("Authorization: Bearer " + SENTINEL)
    logger.warning('{"client_secret": "' + SENTINEL + '"}')


class TestRoleResolutionDeniesByDefault:
    """Only an exact canonical stored role value grants privilege.

    Before the fix the stored value was stripped and case-folded, so a
    malformed high-privilege value such as ``" Admin "`` resolved to the
    administrator role.
    """

    @pytest.fixture(scope="class")
    def authz(self):
        return importlib.import_module(
            "backend.app.core.authorization"
        )

    def test_canonical_values_resolve(self, authz):
        for role in authz.ROLE_ORDER:
            assert authz.parse_role(role.value) is role
            assert authz.parse_role(role) is role

    @pytest.mark.parametrize(
        "stored",
        [
            " admin",
            "admin ",
            " Admin ",
            "Admin",
            "ADMIN",
            "aDmIn",
            "admin\t",
            "admin\n",
            "\u00a0admin",
            " premium",
            "Premium",
            "PREMIUM",
            "registered ",
            "Registered",
            "root",
            "superuser",
            "",
            "   ",
            None,
            3,
            True,
            ["admin"],
            {"role": "admin"},
        ],
    )
    def test_malformed_values_name_no_role(self, authz, stored):
        assert authz.parse_role(stored) is None

    @pytest.mark.parametrize(
        "stored", [" Admin ", "ADMIN", "admin ", "root", None, "", 3]
    )
    def test_a_malformed_row_names_no_role_at_all(self, authz, stored):
        """A malformed value satisfies no minimum, not even the lowest.

        Resolution returns ``None`` rather than falling back to
        :data:`LOWEST_ROLE`, so the dependency refuses the request before
        any rank comparison is made.
        """
        class Row:
            role = stored

        assert authz.resolve_role(Row()) is None
        assert not authz.role_satisfies(stored, authz.Role.ADMIN)
        assert not authz.role_satisfies(stored, authz.Role.REGISTERED)
        assert not authz.role_satisfies(stored, authz.LOWEST_ROLE)

    def test_a_row_without_a_role_names_no_role_at_all(self, authz):
        class Row:
            pass

        assert authz.resolve_role(Row()) is None
        assert authz.resolve_role(None) is None

    def test_the_ordering_still_admits_higher_roles(self, authz):
        assert authz.role_satisfies("admin", authz.Role.REGISTERED)
        assert authz.role_satisfies("premium", authz.Role.REGISTERED)
        assert not authz.role_satisfies("registered", authz.Role.ADMIN)


class TestForeignHandlersOnGovernedLoggers:
    """A handler this module did not install emits nothing at all.

    Before the fix only a handler carrying the reserved name was
    inspected, so a handler installed by another component received the
    record unchanged, including its exception text and its ``extra``
    fields. Governance now inspects **every** handler on a governed
    logger, keeps the one that dispatches to the redacting listener and
    removes the rest, reporting each removal through
    :func:`unredacted_handler_names` so the deployment can treat it as a
    startup failure.
    """

    @pytest.fixture
    def governed(self):
        """Yields the base logger and restores it afterwards."""
        base = logging.getLogger(BASE_LOGGER_NAME)
        saved = (
            list(base.handlers),
            list(base.filters),
            base.level,
            base.propagate,
        )
        try:
            yield base
        finally:
            base.handlers = saved[0]
            base.filters = saved[1]
            base.setLevel(saved[2])
            base.propagate = saved[3]

    def _foreign_handler(self):
        """Returns a plain handler rendering message and exception text."""
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.set_name("someone-elses-handler")
        handler.setFormatter(
            logging.Formatter("%(message)s %(exc_text)s")
        )
        return handler, stream

    @pytest.mark.parametrize("attach_late", [False, True])
    def test_a_foreign_handler_reached_first_emits_nothing(
        self, governed, attach_late
    ):
        handler, stream = self._foreign_handler()
        governed.filters = []
        governed.setLevel(logging.DEBUG)
        if attach_late:
            governed.handlers = []
            configure_logging()
            governed.handlers = [handler] + list(governed.handlers)
        else:
            governed.handlers = [handler]
        configure_logging()
        # Whether it was attached before or after the governed handler,
        # it is gone by the time a record is emitted.
        assert handler not in governed.handlers
        _exercise_governed_logger(
            get_logger("backend.probe.%s" % attach_late)
        )
        emitted = stream.getvalue()
        assert emitted == "", emitted
        assert SENTINEL not in emitted

    def test_a_foreign_handler_is_removed_and_reported(self, governed):
        handler, stream = self._foreign_handler()
        governed.handlers = [handler]
        governed.filters = []
        configure_logging()
        assert handler not in governed.handlers
        reported = unredacted_handler_names()
        assert any(
            "someone-elses-handler" in entry for entry in reported
        )
        get_logger("backend.probe.removed").warning("no longer wired")
        assert stream.getvalue() == ""

    def test_repeated_configuration_installs_no_duplicates(
        self, governed
    ):
        handler, _ = self._foreign_handler()
        governed.handlers = [handler]
        governed.filters = []
        for _ in range(5):
            configure_logging()
            get_logger("backend.probe.idempotent")
        named = [
            entry
            for entry in governed.handlers
            if getattr(entry, "name", None) == HANDLER_NAME
        ]
        assert len(named) == 1
        # Exactly the governed handler remains: the foreign one was taken
        # off on the first pass and never reinstated.
        assert len(governed.handlers) == 1

    def test_non_sensitive_fields_survive_the_governed_formatter(
        self, governed
    ):
        """A foreign formatter is removed, and context still survives.

        The record's non-sensitive ``extra`` fields reach the output
        through the governed handler's own formatter rather than through
        whatever formatter another component attached.
        """
        rendered = emit(
            lambda logger: logger.info(
                "done %d", 12, extra={"count": 12}
            )
        )
        payload = json.loads(rendered.strip())
        assert payload["message"] == "done 12"
        assert payload["context"]["count"] == 12

    @pytest.mark.parametrize(
        "value", ["bearer", "basic", "digest", "token"]
    )
    def test_a_scheme_word_is_redacted_when_the_key_is_sensitive(
        self, value
    ):
        rendered = emit(lambda logger: logger.info("password=" + value))
        assert value not in rendered
        assert REDACTION_PLACEHOLDER in rendered


class TestListenerShutdown:
    """Stopping the listener drains its queue and ends its thread.

    Before the fix the module reference was cleared before the running
    check read it, so the check saw nothing, the queue was never drained
    and the thread was never stopped: the records still queued were lost
    and the thread outlived every replacement.
    """

    @pytest.fixture
    def running_listener(self):
        """Yields the live listener and rebuilds one afterwards."""
        configure_logging()
        listener = app_logging._listener
        assert listener is not None
        try:
            yield listener
        finally:
            app_logging._stop_listener()
            configure_logging()

    def test_the_thread_is_stopped_not_merely_dereferenced(
        self, running_listener
    ):
        thread = running_listener._thread
        assert thread is not None
        assert thread.is_alive()

        app_logging._stop_listener()

        assert app_logging._listener is None
        assert not thread.is_alive()
        assert running_listener._thread is None

    def test_a_queued_record_is_written_before_the_thread_stops(
        self, running_listener
    ):
        record_queue = app_logging._record_queue
        handler = app_logging._stream_handler
        written = io.StringIO()
        replaced = handler.setStream(written)
        try:
            record_queue.put(
                logging.LogRecord(
                    BASE_LOGGER_NAME,
                    logging.WARNING,
                    __file__,
                    0,
                    "queued before shutdown",
                    None,
                    None,
                )
            )
            app_logging._stop_listener()
        finally:
            handler.setStream(replaced)

        assert "queued before shutdown" in written.getvalue()
        assert record_queue.unfinished_tasks == 0

    def test_stopping_twice_is_harmless(self, running_listener):
        app_logging._stop_listener()
        app_logging._stop_listener()
        assert app_logging._listener is None

    def test_a_replacement_leaves_no_second_listener_thread(
        self, running_listener
    ):
        thread = running_listener._thread
        app_logging._stop_listener()
        configure_logging()
        rebuilt = app_logging._listener

        assert rebuilt is not running_listener
        assert rebuilt._thread.is_alive()
        assert not thread.is_alive()


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
