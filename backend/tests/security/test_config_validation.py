"""Regression tests for the startup validation in the settings module.

Every case constructs :class:`backend.app.core.config.Settings` from a
complete valid baseline with one value replaced, and asserts the
outcome: a rejected value raises ``ValidationError`` naming the setting
that failed, and an accepted value resolves as supplied.

The cases cover:

* ``SECRET_KEY`` below the byte floor, exactly at it, and one byte
  under it
* the ``SECRET_KEY`` placeholder ``scripts/setup_dev_environment.sh``
  writes, both verbatim and extended past the byte floor
* ``JWT_ALGORITHMS`` naming an algorithm outside the allowlist, naming
  no algorithm at all, and naming the unsigned algorithm in five letter
  cases
* ``ENVIRONMENT`` naming production while ``PAYPAL_MODE`` names
  sandbox, the two pairings that are accepted, an unknown name for
  either setting, and a payment base that contradicts the mode
* the complete valid baseline and the values it resolves to

:func:`valid_settings` returns the baseline, :func:`build_settings`
constructs from it, and :func:`rejection_message` returns the text of
the error one construction raises. The autouse
:func:`settings_environment` fixture removes every declared setting
name from the process environment, and every construction passes
``_env_file=None``.
"""

from typing import Any, Dict

import pytest
from pydantic import ValidationError

from backend.app.core.config import (
    ALLOWED_JWT_ALGORITHMS,
    LIVE_MODE,
    MIN_SIGNING_KEY_BYTES,
    PAYPAL_API_BASES,
    PRODUCTION_ENVIRONMENT,
    SANDBOX_MODE,
    Settings,
)

#: Signing key long enough for every algorithm on the allowlist. It is a
#: fixed local test value, not a credential.
STRONG_SIGNING_KEY = (
    "local-test-signing-key-for-settings-validation-regressions-only!"
)

#: Signing key measuring exactly :data:`MIN_SIGNING_KEY_BYTES` UTF-8
#: bytes.
MINIMUM_LENGTH_SIGNING_KEY = "local-test-signing-key-32-bytes!"

#: The same key one byte shorter.
UNDERSIZED_SIGNING_KEY = MINIMUM_LENGTH_SIGNING_KEY[:-1]

#: Signing key far below :data:`MIN_SIGNING_KEY_BYTES`.
SHORT_SIGNING_KEY = "short-key"

#: The signing key ``scripts/setup_dev_environment.sh`` line 54 writes
#: into the environment file of every developer environment, verbatim.
PLACEHOLDER_SIGNING_KEY = "your_secret_key_here"

#: The same placeholder extended past :data:`MIN_SIGNING_KEY_BYTES`.
PADDED_PLACEHOLDER_SIGNING_KEY = (
    PLACEHOLDER_SIGNING_KEY + "-padded-to-the-minimum-length"
)

#: The algorithm names the allowlist holds.
ALLOWLISTED_ALGORITHMS = ("HS256", "HS384", "HS512")

#: Algorithm names absent from the allowlist. ``RS256``, ``ES256`` and
#: ``PS256`` are asymmetric; the last entry names nothing at all.
UNLISTED_ALGORITHMS = ("RS256", "ES256", "PS256", "not-an-algorithm")

#: Letter cases of the unsigned algorithm name.
UNSIGNED_ALGORITHM_SPELLINGS = (
    "none",
    "None",
    "NONE",
    "NoNe",
    "nOnE",
)

#: Environment names other than the production environment.
NON_PRODUCTION_ENVIRONMENTS = ("local", "development", "staging")

#: The PayPal REST API base that belongs to the sandbox mode.
SANDBOX_API_BASE = "https://api-m.sandbox.paypal.com"

#: The PayPal REST API base that belongs to the live mode.
LIVE_API_BASE = "https://api-m.paypal.com"


def valid_settings() -> Dict[str, Any]:
    """Returns a fresh mapping of settings that passes every check.

    The mapping is complete: every setting the class requires carries a
    value, and every setting whose default is refused outside the local
    environment carries a value accepted in all four environments. A
    caller replaces one key and asserts the outcome. Each call returns a
    new mapping.
    """
    return {
        "ENVIRONMENT": "development",
        "DATABASE_URL": (
            "postgresql://db.apartment-finder.dev:5432/apartment_finder"
        ),
        "SECRET_KEY": STRONG_SIGNING_KEY,
        "JWT_ALGORITHMS": ["HS256"],
        "ALLOWED_ORIGINS": ["https://app.apartment-finder.dev"],
        "ALLOWED_HOSTS": ["app.apartment-finder.dev"],
        "ZILLOW_API_URL": "https://api.zillow.com/v2/listings",
        "ZILLOW_API_KEY": "listing-provider-test-key",
        "PAYPAL_MODE": "sandbox",
        "PAYPAL_API_BASE": SANDBOX_API_BASE,
        "PAYPAL_CLIENT_ID": "paypal-test-client-id",
        "PAYPAL_CLIENT_SECRET": "paypal-test-client-secret",
        "PAYPAL_WEBHOOK_ID": "paypal-test-webhook-id",
        "PAYPAL_RETURN_URL": (
            "https://app.apartment-finder.dev/subscription"
            "?paypal=return"
        ),
        "PAYPAL_CANCEL_URL": (
            "https://app.apartment-finder.dev/subscription"
            "?paypal=cancel"
        ),
        "SENDGRID_API_KEY": "sendgrid-test-key",
        "FROM_EMAIL": "no-reply@apartment-finder.dev",
    }


def build_settings(**overrides: Any) -> Settings:
    """Returns the settings built from the baseline plus ``overrides``.

    The environment file is not read. The values reaching validation are
    the baseline ones with ``overrides`` applied over them.
    """
    values = valid_settings()
    values.update(overrides)
    return Settings(_env_file=None, **values)


def rejection_message(**overrides: Any) -> str:
    """Returns the text of the error ``overrides`` causes.

    Fails the calling test when the overridden baseline constructs
    instead of raising ``ValidationError``.
    """
    with pytest.raises(ValidationError) as excinfo:
        build_settings(**overrides)
    return str(excinfo.value)


@pytest.fixture(autouse=True)
def settings_environment(monkeypatch):
    """Removes every declared setting name from the environment.

    Both the declared spelling and its lower-case form are removed, and
    ``monkeypatch`` restores the environment when the test ends.
    """
    for name in Settings.__fields__:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)


# --- Positive control ------------------------------------------------


def test_the_valid_baseline_configuration_is_accepted():
    """The complete baseline constructs and resolves as supplied."""
    baseline = valid_settings()
    settings = build_settings()
    assert settings.ENVIRONMENT == baseline["ENVIRONMENT"]
    assert settings.SECRET_KEY == baseline["SECRET_KEY"]
    assert settings.JWT_ALGORITHMS == baseline["JWT_ALGORITHMS"]
    assert settings.DATABASE_URL == baseline["DATABASE_URL"]
    assert settings.ZILLOW_API_URL == baseline["ZILLOW_API_URL"]
    assert settings.PAYPAL_MODE == baseline["PAYPAL_MODE"]
    assert settings.PAYPAL_API_BASE == baseline["PAYPAL_API_BASE"]
    assert settings.FROM_EMAIL == baseline["FROM_EMAIL"]
    assert settings.SECRET_BACKEND == "env"


def test_the_baseline_normalises_delimited_and_cased_settings():
    """A delimited list resolves to a list and a name folds its case."""
    delimited = build_settings(JWT_ALGORITHMS="HS256,HS384")
    assert delimited.JWT_ALGORITHMS == ["HS256", "HS384"]
    cased = build_settings(
        ENVIRONMENT="Production",
        PAYPAL_MODE="LIVE",
        PAYPAL_API_BASE=LIVE_API_BASE,
    )
    assert cased.ENVIRONMENT == "production"
    assert cased.PAYPAL_MODE == "live"


# --- C-1: weak or placeholder signing key ----------------------------


def test_a_signing_key_below_the_minimum_length_is_rejected():
    """A signing key far below the byte floor is refused."""
    message = rejection_message(SECRET_KEY=SHORT_SIGNING_KEY)
    assert "SECRET_KEY" in message
    assert (
        "at least {0} UTF-8 bytes".format(MIN_SIGNING_KEY_BYTES)
        in message
    )


def test_a_signing_key_of_exactly_the_minimum_length_is_accepted():
    """A signing key measuring exactly the byte floor is accepted."""
    assert MIN_SIGNING_KEY_BYTES == 32
    assert (
        len(MINIMUM_LENGTH_SIGNING_KEY.encode("utf-8"))
        == MIN_SIGNING_KEY_BYTES
    )
    settings = build_settings(
        SECRET_KEY=MINIMUM_LENGTH_SIGNING_KEY,
        JWT_ALGORITHMS=["HS256"],
    )
    assert settings.SECRET_KEY == MINIMUM_LENGTH_SIGNING_KEY


def test_a_signing_key_one_byte_below_the_minimum_is_rejected():
    """A signing key one byte under the byte floor is refused."""
    assert (
        len(UNDERSIZED_SIGNING_KEY.encode("utf-8"))
        == MIN_SIGNING_KEY_BYTES - 1
    )
    assert MINIMUM_LENGTH_SIGNING_KEY.startswith(
        UNDERSIZED_SIGNING_KEY
    )
    message = rejection_message(
        SECRET_KEY=UNDERSIZED_SIGNING_KEY,
        JWT_ALGORITHMS=["HS256"],
    )
    assert "SECRET_KEY" in message
    assert (
        "at least {0} UTF-8 bytes".format(MIN_SIGNING_KEY_BYTES)
        in message
    )


def test_the_setup_script_placeholder_signing_key_is_rejected():
    """The placeholder the setup script writes is refused verbatim."""
    assert PLACEHOLDER_SIGNING_KEY == "your_secret_key_here"
    message = rejection_message(SECRET_KEY=PLACEHOLDER_SIGNING_KEY)
    assert "SECRET_KEY" in message


def test_a_padded_placeholder_signing_key_is_still_rejected():
    """A placeholder extended past the byte floor is refused."""
    assert PADDED_PLACEHOLDER_SIGNING_KEY.startswith(
        PLACEHOLDER_SIGNING_KEY
    )
    assert (
        len(PADDED_PLACEHOLDER_SIGNING_KEY.encode("utf-8"))
        >= MIN_SIGNING_KEY_BYTES
    )
    message = rejection_message(
        SECRET_KEY=PADDED_PLACEHOLDER_SIGNING_KEY
    )
    assert "SECRET_KEY" in message
    assert "must not be a placeholder value" in message


def test_a_blank_signing_key_is_rejected():
    """A signing key carrying no characters is refused."""
    message = rejection_message(SECRET_KEY="   ")
    assert "SECRET_KEY" in message
    assert "must not be blank" in message


# --- C-2: algorithm read from unvalidated configuration ---------------


def test_the_algorithm_allowlist_is_immutable_and_holds_only_hmac():
    """The allowlist is a frozen set of the three HMAC algorithms."""
    assert ALLOWLISTED_ALGORITHMS == ("HS256", "HS384", "HS512")
    assert isinstance(ALLOWED_JWT_ALGORITHMS, frozenset)
    assert ALLOWED_JWT_ALGORITHMS == frozenset(ALLOWLISTED_ALGORITHMS)


@pytest.mark.parametrize("algorithm", UNLISTED_ALGORITHMS)
def test_an_algorithm_outside_the_allowlist_is_rejected(algorithm):
    """An algorithm absent from the allowlist is refused."""
    assert algorithm not in ALLOWED_JWT_ALGORITHMS
    message = rejection_message(JWT_ALGORITHMS=[algorithm])
    assert "JWT_ALGORITHMS" in message
    assert "must name only" in message
    for accepted in ALLOWLISTED_ALGORITHMS:
        assert accepted in message


@pytest.mark.parametrize("algorithm", UNLISTED_ALGORITHMS)
def test_an_unlisted_algorithm_is_rejected_beside_a_listed_one(
    algorithm,
):
    """A list pairing an accepted algorithm with an unlisted one is
    refused."""
    message = rejection_message(
        JWT_ALGORITHMS=["HS256", algorithm]
    )
    assert "JWT_ALGORITHMS" in message
    assert "must name only" in message


@pytest.mark.parametrize("algorithm", ALLOWLISTED_ALGORITHMS)
def test_every_allowlisted_algorithm_is_accepted(algorithm):
    """Each algorithm the allowlist holds constructs."""
    settings = build_settings(JWT_ALGORITHMS=[algorithm])
    assert settings.JWT_ALGORITHMS == [algorithm]


def test_an_empty_algorithm_list_is_rejected():
    """Naming no algorithm at all is refused."""
    message = rejection_message(JWT_ALGORITHMS=[])
    assert "JWT_ALGORITHMS" in message
    assert "must not be empty" in message


def test_the_unsigned_algorithm_cases_cover_a_mixed_case_spelling():
    """The refused spellings include a mixed-case ``NoNe``."""
    assert "none" in UNSIGNED_ALGORITHM_SPELLINGS
    assert "NoNe" in UNSIGNED_ALGORITHM_SPELLINGS
    assert all(
        spelling.lower() == "none"
        for spelling in UNSIGNED_ALGORITHM_SPELLINGS
    )


@pytest.mark.parametrize("spelling", UNSIGNED_ALGORITHM_SPELLINGS)
def test_the_unsigned_algorithm_is_rejected_in_any_letter_case(
    spelling,
):
    """Every letter case of the unsigned algorithm name is refused."""
    message = rejection_message(JWT_ALGORITHMS=[spelling])
    assert "JWT_ALGORITHMS" in message
    assert "must not name an unsigned algorithm" in message


@pytest.mark.parametrize("spelling", UNSIGNED_ALGORITHM_SPELLINGS)
def test_the_unsigned_algorithm_is_rejected_beside_a_listed_one(
    spelling,
):
    """A list pairing an accepted algorithm with the unsigned one is
    refused."""
    message = rejection_message(
        JWT_ALGORITHMS=["HS256", spelling]
    )
    assert "JWT_ALGORITHMS" in message
    assert "must not name an unsigned algorithm" in message


# --- C-3: payment mode fixed by validated configuration --------------


def test_production_paired_with_sandbox_payment_mode_is_rejected():
    """Production paired with the sandbox payment mode is refused."""
    assert PRODUCTION_ENVIRONMENT == "production"
    assert SANDBOX_MODE == "sandbox"
    assert PAYPAL_API_BASES[SANDBOX_MODE] == SANDBOX_API_BASE
    baseline = valid_settings()
    assert baseline["PAYPAL_MODE"] == "sandbox"
    assert baseline["PAYPAL_API_BASE"] == SANDBOX_API_BASE
    message = rejection_message(ENVIRONMENT="production")
    assert "PAYPAL_MODE" in message
    assert "must not be sandbox" in message
    assert "ENVIRONMENT is production" in message


def test_production_paired_with_live_payment_mode_is_accepted():
    """Production paired with the live payment mode constructs."""
    assert LIVE_MODE == "live"
    assert PAYPAL_API_BASES[LIVE_MODE] == LIVE_API_BASE
    settings = build_settings(
        ENVIRONMENT="production",
        PAYPAL_MODE="live",
        PAYPAL_API_BASE=LIVE_API_BASE,
    )
    assert settings.ENVIRONMENT == "production"
    assert settings.PAYPAL_MODE == "live"
    assert settings.PAYPAL_API_BASE == LIVE_API_BASE


@pytest.mark.parametrize("environment", NON_PRODUCTION_ENVIRONMENTS)
def test_a_non_production_environment_accepts_sandbox_payment_mode(
    environment,
):
    """The sandbox payment mode constructs outside production."""
    assert environment != PRODUCTION_ENVIRONMENT
    settings = build_settings(ENVIRONMENT=environment)
    assert settings.ENVIRONMENT == environment
    assert settings.PAYPAL_MODE == "sandbox"
    assert settings.PAYPAL_API_BASE == SANDBOX_API_BASE


def test_a_payment_base_that_contradicts_the_mode_is_rejected():
    """A payment base belonging to the other mode is refused."""
    message = rejection_message(
        PAYPAL_MODE="live",
        PAYPAL_API_BASE=SANDBOX_API_BASE,
    )
    assert "PAYPAL_API_BASE" in message
    assert LIVE_API_BASE in message


def test_an_unknown_environment_name_is_rejected():
    """An environment name outside the accepted set is refused."""
    message = rejection_message(ENVIRONMENT="prod")
    assert "ENVIRONMENT" in message
    assert "must be one of" in message
    assert PRODUCTION_ENVIRONMENT in message


def test_an_unknown_payment_mode_is_rejected():
    """A payment mode outside the accepted set is refused."""
    message = rejection_message(PAYPAL_MODE="test")
    assert "PAYPAL_MODE" in message
    assert "must be one of" in message
    for mode in (SANDBOX_MODE, LIVE_MODE):
        assert mode in message
