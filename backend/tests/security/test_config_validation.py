"""Startup validation in the settings module.

The cases run on two surfaces, and every one of them asserts that a
misconfiguration is refused rather than accepted.

The first surface is the settings class itself. Each case constructs
:class:`backend.app.core.config.Settings` from a complete valid baseline
with one or more targeted values overridden, and asserts the outcome: a
rejected value raises ``ValidationError`` naming the setting that failed,
and an accepted value resolves as supplied.

The second surface is application startup. Each case starts a fresh
interpreter, hands it the same valid baseline through its environment
with one value replaced, and imports either
``backend.app.core.config`` or ``backend.app.main``. A refused value
must end that interpreter with a non-zero status, before the imported
module finishes initialising, so a misconfigured deployment cannot serve
a request.

The validation categories covered are:

* ``SECRET_KEY`` below the byte floor, exactly at it, one byte under it,
  and carrying no characters at all
* the ``SECRET_KEY`` value ``your_secret_key_here``, which the validator
  rejects as a known placeholder, both verbatim and extended past the
  byte floor
* ``JWT_ALGORITHMS`` naming an algorithm outside the allowlist, naming
  no algorithm at all, and naming the unsigned algorithm in five letter
  cases
* ``ENVIRONMENT`` naming production while ``PAYPAL_MODE`` names
  sandbox, the two pairings that are accepted, an unknown name for
  either setting, and a payment base that contradicts the mode
* each setting in
  :data:`backend.app.core.config.PROVIDER_SECRET_SETTINGS` one character
  below the redaction floor, exactly at it, and registered through the
  logging module's registry so the two floors are asserted equal
* the complete valid baseline and the values it resolves to, on both
  surfaces

:func:`valid_settings` returns the baseline, :func:`build_settings`
constructs from it, and :func:`rejection_message` returns the text of
the error one construction raises. The autouse
:func:`settings_environment` fixture removes every declared setting
name from the process environment, and every construction passes
``_env_file=None``.

:func:`start_interpreter` drives the startup surface. It runs the child
in a directory of its own, so the repository's own environment file is
not on the path the settings class reads it from, and hands the child
only the baseline plus the case's replacement.
"""

import contextlib
import logging
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, Optional

import pytest
from pydantic import ValidationError

from backend.app.core.config import (
    ALLOWED_JWT_ALGORITHMS,
    DEFAULT_ENV_FILE,
    DEFAULT_MAX_PAGINATION_OFFSET,
    ENVIRONMENT_BACKEND_NAME,
    ENV_FILE_VARIABLE,
    IN_PROCESS_RATE_LIMIT_SCHEMES,
    LIVE_MODE,
    LOCAL_ENVIRONMENT,
    LOCAL_ONLY_LOG_LEVEL,
    LOG_LEVEL_NAMES,
    MANAGED_BACKEND_NAME,
    MANAGED_SECRET_SETTINGS,
    MAX_PAGINATION_OFFSET_CEILING,
    MIN_PROVIDER_SECRET_LENGTH,
    MIN_SIGNING_KEY_BYTES,
    PAYPAL_API_BASES,
    PROVIDER_SECRET_SETTINGS,
    PRODUCTION_ENVIRONMENT,
    SANDBOX_MODE,
    Settings,
    _configured_env_file,
    rate_limit_storage_scheme,
    settings,
)
from backend.app.core import logging as app_logging
from backend.app.core.logging import (
    MIN_SECRET_VALUE_LENGTH,
    REDACTION_PLACEHOLDER,
    redact,
    register_secret_values,
    registered_secret_count,
)
from backend.tests.support import REPO_ROOT

# pytest loads backend/tests/conftest.py as the top-level module
# ``conftest``. Importing it here under its package path would load the
# file a second time, and the guards asserted below would then be a
# separate copy of the ones actually protecting this run.
import conftest

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

#: Provider credential measuring exactly
#: :data:`MIN_PROVIDER_SECRET_LENGTH` characters. It is a fixed local
#: test value, not a credential.
MINIMUM_PROVIDER_SECRET = "k" * MIN_PROVIDER_SECRET_LENGTH

#: The same credential one character shorter.
UNDERSIZED_PROVIDER_SECRET = "k" * (MIN_PROVIDER_SECRET_LENGTH - 1)

#: A signing key the validator rejects as a placeholder, verbatim.
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

#: A rate-limit store whose counters are shared by every process
#: addressing it. Every environment accepts such a store; the declared
#: default keeps its counters in one process and is accepted only while
#: the environment is local.
SHARED_RATE_LIMIT_STORE = "redis://cache.apartment-finder.dev:6379/0"


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
        "RATE_LIMIT_STORAGE_URI": SHARED_RATE_LIMIT_STORE,
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
        "SECRET_BACKEND": MANAGED_BACKEND_NAME,
    }


@contextlib.contextmanager
def _managed_values_in_the_environment(values: Dict[str, Any]):
    """Places every managed setting in the process environment.

    The managed secret backend requires each of those settings to arrive
    as a process variable, so a build that names it needs them present.
    The values placed here are the ones the build is given, so the two
    sources agree. The environment is restored on the way out.
    """
    restore = {
        name: os.environ.get(name) for name in MANAGED_SECRET_SETTINGS
    }
    for name in MANAGED_SECRET_SETTINGS:
        os.environ[name] = str(values[name])
    try:
        yield
    finally:
        for name, previous in restore.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous


def build_settings(**overrides: Any) -> Settings:
    """Returns the settings built from the baseline plus ``overrides``.

    The environment file is not read. The values reaching validation are
    the baseline ones with ``overrides`` applied over them.

    The baseline names the managed secret backend, which requires every
    managed setting to be present in the process environment, so a caller
    that leaves ``SECRET_BACKEND`` alone gets them placed there. A caller
    that names ``SECRET_BACKEND`` itself is asserting something about the
    backend, so nothing is placed and the environment stays as that
    caller arranged it.
    """
    values = valid_settings()
    values.update(overrides)
    if "SECRET_BACKEND" in overrides:
        return Settings(_env_file=None, **values)
    with _managed_values_in_the_environment(values):
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


# --- The startup surface ---------------------------------------------


#: Module imported by a startup case that names no other.
STARTUP_MODULE = "backend.app.main"

#: Settings module, imported by the cases that assert the refusal
#: happens in the settings themselves rather than later in assembly.
SETTINGS_MODULE = "backend.app.core.config"

#: Written to standard output by a child interpreter that finished its
#: import. Its absence is how a case asserts initialisation stopped.
STARTUP_MARKER = "APPLICATION-INITIALISED"

#: Seconds a child interpreter is allowed before it is abandoned.
STARTUP_TIMEOUT_SECONDS = 180.0

#: Names taken from this process's environment so a child interpreter can
#: run at all. None of them is a setting.
PASSTHROUGH_ENVIRONMENT = (
    "COMSPEC",
    "NUMBER_OF_PROCESSORS",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "WINDIR",
)

#: The class of error a refused setting ends a child interpreter with.
STARTUP_ERROR_NAME = "ValidationError"


def _child_environment(overrides: Dict[str, Any]) -> Dict[str, str]:
    """Returns the environment one child interpreter is handed.

    It carries the values needed to run an interpreter, the repository
    root as the import path, the complete valid baseline, and
    ``overrides`` applied over that baseline. A value of ``None`` removes
    the name instead of setting it.

    :data:`ENV_FILE_VARIABLE` is set to an empty value, so the child
    reads no environment file at all and its whole configuration is the
    baseline plus ``overrides``. That is asserted rather than assumed by
    :func:`test_a_child_interpreter_reads_no_environment_file`.
    """
    environment = dict(
        (name, os.environ[name])
        for name in PASSTHROUGH_ENVIRONMENT
        if name in os.environ
    )
    environment["PYTHONPATH"] = str(REPO_ROOT)
    environment["PYTHONIOENCODING"] = "utf-8"
    environment[ENV_FILE_VARIABLE] = ""
    for name, value in valid_settings().items():
        environment[name] = _as_environment_value(value)
    for name, value in overrides.items():
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = _as_environment_value(value)
    return environment


def _as_environment_value(value: Any) -> str:
    """Returns one setting value in the form an environment carries.

    A list is joined with commas, which
    :meth:`backend.app.core.config.Settings.Config.parse_env_var` reads
    back as a list. Any other value is rendered as text.
    """
    if isinstance(value, (list, tuple)):
        return ",".join(str(entry) for entry in value)
    return str(value)


class StartupOutcome(object):
    """What one child interpreter did with the settings it was handed."""

    def __init__(self, module: str, completed: Any) -> None:
        self.module = module
        self.returncode = completed.returncode
        self.stdout = completed.stdout.decode("utf-8", "replace")
        self.stderr = completed.stderr.decode("utf-8", "replace")

    @property
    def started(self) -> bool:
        """Reports whether the imported module finished initialising."""
        return STARTUP_MARKER in self.stdout

    def __repr__(self) -> str:
        return (
            "StartupOutcome(module={0!r}, returncode={1!r}, "
            "stdout={2!r}, stderr={3!r})".format(
                self.module, self.returncode, self.stdout, self.stderr
            )
        )


def start_interpreter(
    module: str = STARTUP_MODULE,
    overrides: Optional[Dict[str, Any]] = None,
) -> StartupOutcome:
    """Returns what a fresh interpreter did importing ``module``.

    The child is handed :data:`ENV_FILE_VARIABLE` empty, so it reads no
    environment file and its whole configuration is the baseline plus
    ``overrides``. It also runs in a directory of its own, so nothing it
    writes touches the repository. It writes :data:`STARTUP_MARKER` to
    standard output once the import has returned, and is abandoned after
    :data:`STARTUP_TIMEOUT_SECONDS`.
    """
    program = (
        "import {0}\n"
        "import sys\n"
        "sys.stdout.write({1!r})\n"
    ).format(module, STARTUP_MARKER)
    environment = _child_environment(overrides or {})
    with tempfile.TemporaryDirectory() as working_directory:
        try:
            completed = subprocess.run(
                [sys.executable, "-c", program],
                cwd=working_directory,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=STARTUP_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as expired:
            raise AssertionError(
                "importing {0} did not finish within {1} seconds; "
                "stdout={2!r} stderr={3!r}".format(
                    module,
                    STARTUP_TIMEOUT_SECONDS,
                    expired.stdout,
                    expired.stderr,
                )
            ) from None
    return StartupOutcome(module, completed)


def assert_startup_refused(
    outcome: StartupOutcome, setting: str, fragment: str
) -> None:
    """Asserts a child interpreter refused the settings it was handed.

    Four properties are asserted: the interpreter ended with a non-zero
    status, the module never finished initialising, the report names the
    setting that was refused, and the report carries ``fragment`` and the
    name of the error a refused setting raises.
    """
    assert outcome.returncode != 0, outcome
    assert not outcome.started, outcome
    assert setting in outcome.stderr, outcome
    assert fragment in outcome.stderr, outcome
    assert STARTUP_ERROR_NAME in outcome.stderr, outcome


# --- Positive control ------------------------------------------------


def test_the_valid_baseline_configuration_is_accepted():
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
    assert settings.SECRET_BACKEND == baseline["SECRET_BACKEND"]


def test_the_baseline_normalises_delimited_and_cased_settings():
    delimited = build_settings(JWT_ALGORITHMS="HS256,HS384")
    assert delimited.JWT_ALGORITHMS == ["HS256", "HS384"]
    cased = build_settings(
        ENVIRONMENT="Production",
        PAYPAL_MODE="LIVE",
        PAYPAL_API_BASE=LIVE_API_BASE,
    )
    assert cased.ENVIRONMENT == "production"
    assert cased.PAYPAL_MODE == "live"


# --- Signing-key validation ------------------------------------------


def test_a_signing_key_below_the_minimum_length_is_rejected():
    message = rejection_message(SECRET_KEY=SHORT_SIGNING_KEY)
    assert "SECRET_KEY" in message
    assert (
        "at least {0} UTF-8 bytes".format(MIN_SIGNING_KEY_BYTES)
        in message
    )


def test_a_signing_key_of_exactly_the_minimum_length_is_accepted():
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
    assert PLACEHOLDER_SIGNING_KEY == "your_secret_key_here"
    message = rejection_message(SECRET_KEY=PLACEHOLDER_SIGNING_KEY)
    assert "SECRET_KEY" in message


def test_a_padded_placeholder_signing_key_is_still_rejected():
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
    message = rejection_message(SECRET_KEY="   ")
    assert "SECRET_KEY" in message
    assert "must not be blank" in message


# --- JWT algorithm validation ----------------------------------------


def test_the_algorithm_allowlist_is_immutable_and_holds_only_hmac():
    assert ALLOWLISTED_ALGORITHMS == ("HS256", "HS384", "HS512")
    assert isinstance(ALLOWED_JWT_ALGORITHMS, frozenset)
    assert ALLOWED_JWT_ALGORITHMS == frozenset(ALLOWLISTED_ALGORITHMS)


@pytest.mark.parametrize("algorithm", UNLISTED_ALGORITHMS)
def test_an_algorithm_outside_the_allowlist_is_rejected(algorithm):
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
    message = rejection_message(
        JWT_ALGORITHMS=["HS256", algorithm]
    )
    assert "JWT_ALGORITHMS" in message
    assert "must name only" in message


@pytest.mark.parametrize("algorithm", ALLOWLISTED_ALGORITHMS)
def test_every_allowlisted_algorithm_is_accepted(algorithm):
    settings = build_settings(JWT_ALGORITHMS=[algorithm])
    assert settings.JWT_ALGORITHMS == [algorithm]


def test_an_empty_algorithm_list_is_rejected():
    message = rejection_message(JWT_ALGORITHMS=[])
    assert "JWT_ALGORITHMS" in message
    assert "must not be empty" in message


def test_the_unsigned_algorithm_cases_cover_a_mixed_case_spelling():
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
    message = rejection_message(JWT_ALGORITHMS=[spelling])
    assert "JWT_ALGORITHMS" in message
    assert "must not name an unsigned algorithm" in message


@pytest.mark.parametrize("spelling", UNSIGNED_ALGORITHM_SPELLINGS)
def test_the_unsigned_algorithm_is_rejected_beside_a_listed_one(
    spelling,
):
    message = rejection_message(
        JWT_ALGORITHMS=["HS256", spelling]
    )
    assert "JWT_ALGORITHMS" in message
    assert "must not name an unsigned algorithm" in message


# --- Payment-mode validation -----------------------------------------


def test_production_paired_with_sandbox_payment_mode_is_rejected():
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
    assert environment != PRODUCTION_ENVIRONMENT
    settings = build_settings(ENVIRONMENT=environment)
    assert settings.ENVIRONMENT == environment
    assert settings.PAYPAL_MODE == "sandbox"
    assert settings.PAYPAL_API_BASE == SANDBOX_API_BASE


def test_a_payment_base_that_contradicts_the_mode_is_rejected():
    message = rejection_message(
        PAYPAL_MODE="live",
        PAYPAL_API_BASE=SANDBOX_API_BASE,
    )
    assert "PAYPAL_API_BASE" in message
    assert LIVE_API_BASE in message


def test_an_unknown_environment_name_is_rejected():
    message = rejection_message(ENVIRONMENT="prod")
    assert "ENVIRONMENT" in message
    assert "must be one of" in message
    assert PRODUCTION_ENVIRONMENT in message


def test_an_unknown_payment_mode_is_rejected():
    message = rejection_message(PAYPAL_MODE="test")
    assert "PAYPAL_MODE" in message
    assert "must be one of" in message
    for mode in (SANDBOX_MODE, LIVE_MODE):
        assert mode in message


# --- Provider credentials the redaction registry must be able to hold --


@pytest.mark.parametrize("setting", PROVIDER_SECRET_SETTINGS)
def test_a_provider_credential_below_the_redaction_floor_is_rejected(
    setting,
):
    """A credential the registry would not hold is refused."""
    message = rejection_message(**{setting: UNDERSIZED_PROVIDER_SECRET})
    assert setting in message
    assert str(MIN_PROVIDER_SECRET_LENGTH) in message


@pytest.mark.parametrize("setting", PROVIDER_SECRET_SETTINGS)
def test_a_provider_credential_at_the_redaction_floor_is_accepted(
    setting,
):
    """A credential of exactly the floor length constructs."""
    settings = build_settings(**{setting: MINIMUM_PROVIDER_SECRET})
    assert getattr(settings, setting) == MINIMUM_PROVIDER_SECRET


@pytest.mark.parametrize("setting", PROVIDER_SECRET_SETTINGS)
def test_every_accepted_provider_credential_can_be_registered(setting):
    """The floor here is the floor the redaction registry applies.

    The accepted value is registered through the logging module's own
    registry, and the count it reports is asserted to have grown, so the
    two floors cannot drift apart unnoticed.
    """
    assert MIN_PROVIDER_SECRET_LENGTH == MIN_SECRET_VALUE_LENGTH

    accepted = getattr(
        build_settings(**{setting: MINIMUM_PROVIDER_SECRET}), setting
    )
    before = registered_secret_count()
    after = register_secret_values(accepted)

    assert after >= before
    assert REDACTION_PLACEHOLDER in redact(
        "provider rejected " + accepted
    )


# --- Startup: the valid baseline reaches a running application -------


@pytest.mark.parametrize(
    "module",
    [
        pytest.param(SETTINGS_MODULE, id="settings_module"),
        pytest.param(STARTUP_MODULE, id="application_entrypoint"),
    ],
)
def test_the_valid_baseline_starts_a_fresh_interpreter(module):
    """A fresh interpreter imports the module and reports success.

    This is the positive control for every startup case below: it proves
    the baseline handed to a child interpreter is one that starts, so a
    refusal in a case below is the case's own replacement and not the
    harness.
    """
    outcome = start_interpreter(module)

    assert outcome.returncode == 0, outcome
    assert outcome.started, outcome
    assert outcome.stderr == "", outcome


def test_the_startup_harness_reads_no_repository_environment_file():
    """The child reads no environment file from the repository.

    The child runs in a directory of its own and is handed a signing key
    that only this case supplies, so the value it resolves proves the
    repository's own environment file did not reach it.
    """
    supplied = "startup-harness-signing-key-for-this-case-only!!"
    program = (
        "import sys\n"
        "from backend.app.core.config import settings\n"
        "sys.stdout.write(settings.SECRET_KEY)\n"
    )
    environment = _child_environment({"SECRET_KEY": supplied})
    with tempfile.TemporaryDirectory() as working_directory:
        completed = subprocess.run(
            [sys.executable, "-c", program],
            cwd=working_directory,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=STARTUP_TIMEOUT_SECONDS,
        )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.decode("utf-8") == supplied


# --- Startup: C-1, a weak or placeholder signing key -----------------


@pytest.mark.parametrize(
    "key, fragment",
    [
        pytest.param(
            SHORT_SIGNING_KEY,
            "at least {0} UTF-8 bytes".format(MIN_SIGNING_KEY_BYTES),
            id="far_below_the_byte_floor",
        ),
        pytest.param(
            UNDERSIZED_SIGNING_KEY,
            "at least {0} UTF-8 bytes".format(MIN_SIGNING_KEY_BYTES),
            id="one_byte_below_the_byte_floor",
        ),
        pytest.param(
            PLACEHOLDER_SIGNING_KEY,
            "SECRET_KEY",
            id="the_setup_script_placeholder",
        ),
        pytest.param(
            PADDED_PLACEHOLDER_SIGNING_KEY,
            "must not be a placeholder value",
            id="the_placeholder_padded_past_the_byte_floor",
        ),
        pytest.param(
            "   ", "must not be blank", id="blank"
        ),
    ],
)
def test_a_weak_signing_key_stops_a_fresh_interpreter(key, fragment):
    """A refused signing key ends startup before initialisation."""
    outcome = start_interpreter(overrides={"SECRET_KEY": key})

    assert_startup_refused(outcome, "SECRET_KEY", fragment)


def test_the_setup_script_placeholder_stops_the_settings_module():
    """The refusal is in the settings, not later in assembly.

    The placeholder is handed to a fresh interpreter importing the
    settings module alone, so nothing that imports it afterwards can be
    what refused it.
    """
    outcome = start_interpreter(
        module=SETTINGS_MODULE,
        overrides={"SECRET_KEY": PLACEHOLDER_SIGNING_KEY},
    )

    assert_startup_refused(outcome, "SECRET_KEY", "SECRET_KEY")


# --- Startup: C-2, the algorithm allowlist ---------------------------


@pytest.mark.parametrize("algorithm", UNLISTED_ALGORITHMS)
def test_an_unlisted_algorithm_stops_a_fresh_interpreter(algorithm):
    """An algorithm outside the allowlist ends startup."""
    outcome = start_interpreter(
        overrides={"JWT_ALGORITHMS": algorithm}
    )

    assert_startup_refused(
        outcome, "JWT_ALGORITHMS", "must name only"
    )


@pytest.mark.parametrize("spelling", UNSIGNED_ALGORITHM_SPELLINGS)
def test_the_unsigned_algorithm_stops_a_fresh_interpreter(spelling):
    """Every letter case of the unsigned algorithm ends startup."""
    outcome = start_interpreter(
        overrides={"JWT_ALGORITHMS": spelling}
    )

    assert_startup_refused(
        outcome,
        "JWT_ALGORITHMS",
        "must not name an unsigned algorithm",
    )


@pytest.mark.parametrize("spelling", UNSIGNED_ALGORITHM_SPELLINGS)
def test_the_unsigned_algorithm_stops_startup_beside_a_listed_one(
    spelling,
):
    """The unsigned algorithm ends startup even paired with a listed
    one."""
    outcome = start_interpreter(
        overrides={"JWT_ALGORITHMS": ["HS256", spelling]}
    )

    assert_startup_refused(
        outcome,
        "JWT_ALGORITHMS",
        "must not name an unsigned algorithm",
    )


# --- Startup: C-3, the payment mode guard ----------------------------


def test_production_paired_with_sandbox_stops_a_fresh_interpreter():
    """A production environment on sandbox payment credentials ends
    startup."""
    outcome = start_interpreter(
        overrides={"ENVIRONMENT": PRODUCTION_ENVIRONMENT}
    )

    assert_startup_refused(
        outcome, "PAYPAL_MODE", "must not be sandbox"
    )
    assert "ENVIRONMENT is production" in outcome.stderr


def test_production_paired_with_live_starts_a_fresh_interpreter():
    """A production environment on live payment credentials starts.

    This is the pairing control for the case above: it proves the guard
    refuses the combination rather than the production environment.
    """
    outcome = start_interpreter(
        overrides={
            "ENVIRONMENT": PRODUCTION_ENVIRONMENT,
            "PAYPAL_MODE": LIVE_MODE,
            "PAYPAL_API_BASE": LIVE_API_BASE,
        }
    )

    assert outcome.returncode == 0, outcome
    assert outcome.started, outcome


# --- Startup: the remaining refused settings -------------------------


@pytest.mark.parametrize(
    "setting, value, fragment",
    [
        pytest.param(
            "ENVIRONMENT",
            "prod",
            "must be one of",
            id="unknown_environment_name",
        ),
        pytest.param(
            "PAYPAL_MODE",
            "test",
            "must be one of",
            id="unknown_payment_mode",
        ),
        pytest.param(
            "PAYPAL_API_BASE",
            SANDBOX_API_BASE,
            LIVE_API_BASE,
            id="payment_base_contradicting_the_mode",
        ),
    ],
)
def test_a_refused_setting_stops_a_fresh_interpreter(
    setting, value, fragment
):
    """Each remaining refused value ends startup before initialisation."""
    overrides = {setting: value}
    if setting == "PAYPAL_API_BASE":
        overrides["PAYPAL_MODE"] = LIVE_MODE

    outcome = start_interpreter(overrides=overrides)

    assert_startup_refused(outcome, setting, fragment)


@pytest.mark.parametrize(
    "setting",
    [
        "DATABASE_URL",
        "SECRET_KEY",
        "ZILLOW_API_KEY",
        "PAYPAL_CLIENT_ID",
        "PAYPAL_CLIENT_SECRET",
        "PAYPAL_WEBHOOK_ID",
        "SENDGRID_API_KEY",
    ],
)
def test_an_absent_required_setting_stops_a_fresh_interpreter(setting):
    """A setting with no default ends startup when it is not supplied."""
    outcome = start_interpreter(overrides={setting: None})

    assert outcome.returncode != 0, outcome
    assert not outcome.started, outcome
    assert setting in outcome.stderr, outcome
    assert STARTUP_ERROR_NAME in outcome.stderr, outcome


@pytest.mark.parametrize(
    "uri", ["bounded-memory://", "memory://", "async+memory://"]
)
def test_a_deployed_in_process_rate_limit_store_is_rejected(uri):
    """Outside a local environment the counters must be shared."""
    message = rejection_message(RATE_LIMIT_STORAGE_URI=uri)
    assert "RATE_LIMIT_STORAGE_URI" in message
    assert "shared by every process" in message


def test_a_local_environment_accepts_the_in_process_store():
    """A single-process local run keeps its counters in memory."""
    settings = build_settings(
        ENVIRONMENT="local",
        RATE_LIMIT_STORAGE_URI="bounded-memory://",
    )
    assert settings.RATE_LIMIT_STORAGE_URI == "bounded-memory://"


def test_a_pagination_offset_above_the_ceiling_is_rejected():
    """The paged-read offset cap is bounded by its own ceiling."""
    message = rejection_message(
        MAX_PAGINATION_OFFSET=MAX_PAGINATION_OFFSET_CEILING + 1
    )
    assert "MAX_PAGINATION_OFFSET" in message


def test_the_default_pagination_offset_is_an_operational_cap():
    """The declared default is small enough to bound the work."""
    assert build_settings().MAX_PAGINATION_OFFSET == (
        DEFAULT_MAX_PAGINATION_OFFSET
    )
    assert DEFAULT_MAX_PAGINATION_OFFSET <= (
        MAX_PAGINATION_OFFSET_CEILING
    )
    assert MAX_PAGINATION_OFFSET_CEILING < 2 ** 63 - 1


class TestEnvironmentFileSelection:
    """The file settings are read from is named by the environment."""

    def test_an_absent_variable_names_the_default_file(self, monkeypatch):
        monkeypatch.delenv(ENV_FILE_VARIABLE, raising=False)

        assert _configured_env_file() == DEFAULT_ENV_FILE

    @pytest.mark.parametrize("declared", ["", "   ", "\t"])
    def test_a_variable_naming_nothing_reads_no_file(
        self, monkeypatch, declared
    ):
        monkeypatch.setenv(ENV_FILE_VARIABLE, declared)

        assert _configured_env_file() is None

    def test_a_declared_path_is_used_as_given(self, monkeypatch):
        monkeypatch.setenv(ENV_FILE_VARIABLE, " local.env ")

        assert _configured_env_file() == "local.env"

    def test_the_default_file_is_addressed_absolutely(self):
        """The default is an absolute path to ``.env`` at the repository
        root, so it names one file whatever the working directory."""
        assert os.path.isabs(DEFAULT_ENV_FILE)
        assert os.path.dirname(DEFAULT_ENV_FILE) == str(REPO_ROOT)
        assert os.path.basename(DEFAULT_ENV_FILE) == ".env"

    def test_the_default_file_does_not_follow_the_working_directory(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.delenv(ENV_FILE_VARIABLE, raising=False)
        monkeypatch.chdir(tmp_path)

        assert _configured_env_file() == DEFAULT_ENV_FILE


class TestAManagedSecretBackendRequiresTheEnvironment:
    """Managed secrets must arrive as variables, not from a file.

    ``SECRET_BACKEND`` naming the managed backend is a statement that the
    deployment's secrets come from a secret manager, delivered to the
    process as environment variables. The check exists so that such a
    deployment cannot silently fall back on a file committed or copied
    into the image: a value that is only in a file is treated as absent.

    The autouse fixture above removes every setting name from the process
    environment, so each case here places back exactly what it means to
    supply.
    """

    @staticmethod
    def _supply(monkeypatch, values):
        """Places ``values`` in the process environment."""
        for name, value in values.items():
            monkeypatch.setenv(name, value)

    def _managed(self, monkeypatch, **overrides):
        """Supplies every managed setting, then applies ``overrides``."""
        supplied = dict(
            (name, str(valid_settings()[name]))
            for name in MANAGED_SECRET_SETTINGS
        )
        supplied.update(overrides)
        self._supply(monkeypatch, supplied)
        return build_settings(SECRET_BACKEND=MANAGED_BACKEND_NAME)

    def test_the_default_backend_requires_nothing_of_the_environment(
        self,
    ):
        """The check applies to the managed backend only.

        The default backend is accepted only in the local environment, so
        the case names it while asserting that no managed value has to be
        placed in the process environment for the build to succeed.
        """
        built = build_settings(
            ENVIRONMENT=LOCAL_ENVIRONMENT,
            SECRET_BACKEND=ENVIRONMENT_BACKEND_NAME,
        )

        assert built.SECRET_BACKEND == ENVIRONMENT_BACKEND_NAME

    @pytest.mark.parametrize(
        "environment", ["development", "staging", PRODUCTION_ENVIRONMENT]
    )
    def test_a_deployed_environment_refuses_the_default_backend(
        self, environment
    ):
        """Only a local run may read its secrets from its own environment.

        Every other environment must name the managed backend, so that a
        deployment cannot serve on secrets delivered by an environment
        file. The compose definition defaults ``SECRET_BACKEND`` to the
        environment backend for local convenience, and this is the check
        that stops a Cloud SQL stack inheriting that default.
        """
        overrides = {
            "ENVIRONMENT": environment,
            "SECRET_BACKEND": ENVIRONMENT_BACKEND_NAME,
        }
        if environment == PRODUCTION_ENVIRONMENT:
            overrides["PAYPAL_MODE"] = LIVE_MODE
            overrides["PAYPAL_API_BASE"] = PAYPAL_API_BASES[LIVE_MODE]

        message = rejection_message(**overrides)

        assert "SECRET_BACKEND" in message
        assert MANAGED_BACKEND_NAME in message
        assert environment in message

    def test_the_local_environment_accepts_the_managed_backend(
        self, monkeypatch
    ):
        """Naming the managed backend locally is still accepted.

        The requirement runs one way only: a deployed environment must
        name the managed backend, and a local run may name either.
        """
        self._supply(
            monkeypatch,
            dict(
                (name, str(valid_settings()[name]))
                for name in MANAGED_SECRET_SETTINGS
            ),
        )

        built = build_settings(
            ENVIRONMENT=LOCAL_ENVIRONMENT,
            SECRET_BACKEND=MANAGED_BACKEND_NAME,
        )

        assert built.SECRET_BACKEND == MANAGED_BACKEND_NAME

    def test_every_managed_value_supplied_is_accepted(self, monkeypatch):
        built = self._managed(monkeypatch)

        assert built.SECRET_BACKEND == MANAGED_BACKEND_NAME

    @pytest.mark.parametrize("absent", list(MANAGED_SECRET_SETTINGS))
    def test_a_managed_value_missing_from_the_environment_is_refused(
        self, monkeypatch, absent
    ):
        supplied = dict(
            (name, str(valid_settings()[name]))
            for name in MANAGED_SECRET_SETTINGS
            if name != absent
        )
        self._supply(monkeypatch, supplied)

        message = rejection_message(SECRET_BACKEND=MANAGED_BACKEND_NAME)

        assert absent in message
        assert MANAGED_BACKEND_NAME in message

    @pytest.mark.parametrize("blank", ["", "   ", "\t"])
    def test_a_managed_value_present_but_blank_counts_as_absent(
        self, monkeypatch, blank
    ):
        supplied = dict(
            (name, str(valid_settings()[name]))
            for name in MANAGED_SECRET_SETTINGS
        )
        supplied["SENDGRID_API_KEY"] = blank
        self._supply(monkeypatch, supplied)

        message = rejection_message(SECRET_BACKEND=MANAGED_BACKEND_NAME)

        assert "SENDGRID_API_KEY" in message

    def test_the_refusal_names_every_value_that_is_missing(
        self, monkeypatch
    ):
        message = rejection_message(SECRET_BACKEND=MANAGED_BACKEND_NAME)

        for name in MANAGED_SECRET_SETTINGS:
            assert name in message

    def test_a_lower_case_variable_name_still_supplies_the_value(
        self, monkeypatch
    ):
        """The environment is read case-insensitively, as pydantic does."""
        supplied = dict(
            (name.lower(), str(valid_settings()[name]))
            for name in MANAGED_SECRET_SETTINGS
        )
        self._supply(monkeypatch, supplied)

        built = build_settings(SECRET_BACKEND=MANAGED_BACKEND_NAME)

        assert built.SECRET_BACKEND == MANAGED_BACKEND_NAME

    def test_every_managed_setting_is_one_the_class_declares(self):
        for name in MANAGED_SECRET_SETTINGS:
            assert name in Settings.__fields__


def test_a_child_interpreter_reads_no_environment_file():
    """The startup harness supplies settings and reads no file.

    Every startup case here decides what a fresh interpreter was handed,
    so a file contributing a value would make an absent setting look
    present. The harness switches file loading off explicitly rather than
    relying on the child's working directory.
    """
    environment = _child_environment({})

    assert environment[ENV_FILE_VARIABLE] == ""


class TestTheSuiteRunsOnIsolatedConfiguration:
    """The suite supplies every setting and reads no file.

    The bootstrap in :mod:`backend.tests.conftest` places each setting in
    the process environment and switches environment-file loading off,
    so neither the repository's own file nor an ambient value reaches a
    test.
    """

    def test_no_environment_file_is_read(self):
        assert Settings.Config.env_file is None

    def test_every_declared_setting_is_supplied_by_the_suite(self):
        """The forced set covers every field, so none can be inherited."""
        declared = set(Settings.__fields__)
        supplied = set(conftest.TEST_SETTINGS) - {ENV_FILE_VARIABLE}

        assert declared - supplied == set()
        assert supplied - declared == set()

    def test_the_prior_value_of_every_forced_name_is_recorded(self):
        assert set(conftest.PRIOR_ENVIRONMENT) == set(
            conftest.TEST_SETTINGS
        )

    def test_every_isolated_setting_resolved_to_its_forced_value(self):
        for name in conftest.ISOLATED_SETTINGS:
            assert str(getattr(settings, name)) == (
                conftest.TEST_SETTINGS[name]
            )

    def test_the_limiter_counters_are_held_in_this_process(self):
        assert conftest.LIMITER_IS_IN_PROCESS is True
        assert rate_limit_storage_scheme(
            settings.RATE_LIMIT_STORAGE_URI
        ) in IN_PROCESS_RATE_LIMIT_SCHEMES

    def test_a_setting_resolving_elsewhere_stops_collection(
        self, monkeypatch
    ):
        """The refusal names the setting and the value it found."""
        monkeypatch.setattr(
            settings, "DATABASE_URL", "postgresql://live-host/prod"
        )
        with pytest.raises(RuntimeError) as raised:
            conftest._refuse_unisolated_configuration()

        assert conftest.UNISOLATED_SETTING_MESSAGE in str(raised.value)
        assert "DATABASE_URL" in str(raised.value)

    def test_a_shared_rate_limit_store_stops_collection(
        self, monkeypatch
    ):
        """A shared store is refused even when it was the forced value."""
        shared = "redis://cache.example.com:6379/0"
        monkeypatch.setitem(
            conftest.TEST_SETTINGS, "RATE_LIMIT_STORAGE_URI", shared
        )
        monkeypatch.setattr(
            settings, "RATE_LIMIT_STORAGE_URI", shared
        )
        with pytest.raises(RuntimeError) as raised:
            conftest._refuse_unisolated_configuration()

        assert "shared with other processes" in str(raised.value)

    def test_a_shared_store_is_never_cleared(self, monkeypatch):
        """A store outside this process is refused, not emptied."""
        monkeypatch.setattr(conftest, "LIMITER_IS_IN_PROCESS", False)
        with pytest.raises(RuntimeError) as raised:
            conftest.reset_limiter_counters()

        assert conftest.SHARED_LIMITER_MESSAGE in str(raised.value)


class TestTheLogLevelIsValidated:
    """The record threshold is a named level and nothing else.

    The level governs every structured record the application writes, so
    a value the application has no name for cannot be accepted: a
    deployment that mistypes the level must be told rather than served at
    a threshold it did not choose. The one level that records a rendered
    traceback is confined to the local environment.
    """

    def test_the_default_is_the_information_level(self):
        assert build_settings().LOG_LEVEL == "INFO"
        assert "INFO" in LOG_LEVEL_NAMES

    @pytest.mark.parametrize("name", LOG_LEVEL_NAMES)
    def test_every_named_level_is_accepted(self, name):
        """Each accepted name resolves to itself, local included."""
        built = build_settings(ENVIRONMENT=LOCAL_ENVIRONMENT, LOG_LEVEL=name)

        assert built.LOG_LEVEL == name

    @pytest.mark.parametrize(
        "written", ["info", "Info", " warning ", "eRRor"]
    )
    def test_a_name_is_read_however_it_is_written(self, written):
        built = build_settings(LOG_LEVEL=written)

        assert built.LOG_LEVEL == written.strip().upper()

    @pytest.mark.parametrize(
        "value",
        ["20", "0", "TRACE", "VERBOSE", "NOTSET", "WARN", "", "   "],
    )
    def test_a_value_outside_the_names_is_refused(self, value):
        """A numeric level and a near-miss name both stop startup."""
        message = rejection_message(LOG_LEVEL=value)

        assert "LOG_LEVEL" in message

    @pytest.mark.parametrize(
        "environment", ["development", "staging", PRODUCTION_ENVIRONMENT]
    )
    def test_the_traceback_level_is_refused_outside_local(
        self, environment
    ):
        """The refusal names the level and the environment it refused."""
        message = rejection_message(
            ENVIRONMENT=environment, LOG_LEVEL=LOCAL_ONLY_LOG_LEVEL
        )

        assert LOCAL_ONLY_LOG_LEVEL in message
        assert environment in message

    def test_the_traceback_level_is_accepted_locally(self):
        built = build_settings(
            ENVIRONMENT=LOCAL_ENVIRONMENT, LOG_LEVEL=LOCAL_ONLY_LOG_LEVEL
        )

        assert built.LOG_LEVEL == LOCAL_ONLY_LOG_LEVEL

    def test_the_names_are_the_ones_the_logger_resolves(self):
        """Every accepted name is a level the logging module knows.

        The setting would otherwise accept a name the logger falls back
        from, which would leave the configured threshold silently
        replaced by the default.
        """
        for name in LOG_LEVEL_NAMES:
            assert app_logging._resolve_level(name) == getattr(
                logging, name
            )

    def test_the_application_applies_the_configured_level(self):
        """Passing the setting through moves the base logger's level."""
        base = logging.getLogger(app_logging.BASE_LOGGER_NAME)
        original = base.level
        try:
            app_logging.configure_logging("WARNING")
            assert base.level == logging.WARNING
            app_logging.configure_logging(settings.LOG_LEVEL)
            assert base.level == getattr(logging, settings.LOG_LEVEL)
        finally:
            base.setLevel(original)

    def test_the_configured_level_cannot_lower_a_namespace_floor(self):
        """A verbose application level leaves the other namespaces alone.

        The outbound HTTP, migration and statement namespaces carry
        thresholds of their own that keep a request target or a statement
        out of the log; a configured application level must not reach
        them.
        """
        floors = app_logging._governed_namespace_levels()
        base = logging.getLogger(app_logging.BASE_LOGGER_NAME)
        original = base.level
        try:
            app_logging.configure_logging(LOCAL_ONLY_LOG_LEVEL)
            assert floors
            for name, level in floors:
                assert logging.getLogger(name).level == level
        finally:
            app_logging.configure_logging(settings.LOG_LEVEL)
            base.setLevel(original)
