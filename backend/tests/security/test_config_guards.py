"""Configuration guards for the payment environment, the signing key and
database transport.

Three settings decide whether the application starts in a safe state: the
payment environment, the signing key length, and the database transport
mode. Every case builds ``Settings`` directly and inspects the field named
in the validation error it raises.

The transport cases execute ``backend/app/db/database.py`` against each
database URL form and inspect the engine it builds, and the payment
cases execute ``backend/app/services/paypal_service.py`` with the
provider library replaced, so the configured environment is read by the
code that talks to the provider rather than only validated in isolation.
"""
import importlib.util
from unittest import mock

import paypalrestsdk
import pytest
from pydantic import VERSION as PYDANTIC_VERSION
from pydantic import ValidationError
from sqlalchemy import create_engine, event

from backend.app.core.config import (
    DB_SSLMODES,
    HMAC_KEY_MIN_BYTES,
    Settings,
    settings,
)
from backend.app.db import database
from backend.app.services import paypal_service

# SEC-10: URL forms reaching each branch of the database.py conditional
POSTGRES_URL = "postgresql://u:p@localhost:5432/d"
POSTGRES_DRIVER_URL = "postgresql+psycopg2://u:p@localhost:5432/d"
SQLITE_URL = "sqlite://"

# SEC-10: the transport modes the database driver defines, ascending in
# protection. The two verifying modes are accepted as configuration and
# need a root certificate distributed out of band, which this work
# deliberately defers; require encrypts without verifying the server.
LIBPQ_SSLMODES = (
    "disable",
    "allow",
    "prefer",
    "require",
    "verify-ca",
    "verify-full",
)

# SEC-10: values outside the driver's domain - a misspelling, a wrong
# case, a padded spelling, an unknown word, the wildcard and the empty
# string. A downgrade to a negotiated mode would still be inside the
# domain, so a typo is the shape that has to be caught here.
REJECTED_SSLMODES = (
    "",
    "requier",
    "REQUIRE",
    "prefer ",
    " require",
    "none",
    "*",
    "require;sslrootcert=/tmp/x",
)

# SEC-12: a lifetime of zero or less mints a token already expired
REJECTED_TOKEN_LIFETIMES = (0, -1, -30)

# SEC-07: a threshold or window below one leaves guessing unbounded
REJECTED_THROTTLE_VALUES = (0, -1, -15)

# SEC-12: RFC 7518 sec. 3.2 key-length floor
SIGNING_KEY_MIN_LENGTH = 32

# SEC-12: keys are built by repetition, never written as a literal key
KEY_CHARACTER = "a"

# SEC-12: clears the byte floor of every accepted signing algorithm
LONG_KEY = KEY_CHARACTER * 64

# SEC-01/SEC-12: the signing key field, addressed by name; no line here
# spells a key assignment
SIGNING_KEY_FIELD = "SECRET_KEY"


def valid_settings_kwargs(**overrides):
    """Return one complete, valid keyword mapping for ``Settings``."""
    values = {
        "DATABASE_URL": SQLITE_URL,
        SIGNING_KEY_FIELD: KEY_CHARACTER * SIGNING_KEY_MIN_LENGTH,
        "ALGORITHM": "HS256",
        "ACCESS_TOKEN_EXPIRE_MINUTES": 30,
        "ZILLOW_API_KEY": "guard-zillow-key",
        "PAYPAL_CLIENT_ID": "guard-paypal-client-id",
        "PAYPAL_CLIENT_SECRET": "guard-paypal-token",
        "ALLOWED_ORIGINS": ["https://app.example.com"],
        "SENDGRID_API_KEY": "guard-sendgrid-key",
        "FROM_EMAIL": "guard@example.com",
        "ZILLOW_API_URL": "https://api.example.com/v1",
    }
    values.update(overrides)
    return values


def build_settings(**overrides):
    """Construct ``Settings`` from a complete keyword mapping."""
    # SEC-12: env_file disabled; the mapping is the only source of fields
    return Settings(_env_file=None, **valid_settings_kwargs(**overrides))


def assert_rejects(field, **overrides):
    """Assert the override is rejected and that ``field`` is named."""
    with pytest.raises(ValidationError) as caught:
        build_settings(**overrides)
    reported = caught.value.errors()
    named = [error["loc"] for error in reported]
    assert (field,) in named, named
    return reported


def assert_rejected_across_fields(*quoted, **overrides):
    """Assert the override is rejected and the message quotes each term.

    A rule spanning two fields is reported against the model rather than
    against one field name, so the field is identified by the message it
    raises instead of by the error location.
    """
    with pytest.raises(ValidationError) as caught:
        build_settings(**overrides)
    reported = str(caught.value)
    for term in quoted:
        assert str(term) in reported, (term, reported)
    return reported


class ConnectIntercepted(Exception):
    """Raised from the connect hook to stop before the driver runs."""


def recorded_connect_args(engine):
    """Return the connect arguments SQLAlchemy hands the driver."""
    recorded = {}
    fired = []

    def record(dialect, connection_record, arguments, keywords):
        fired.append(True)
        recorded.update(keywords)
        raise ConnectIntercepted

    event.listen(engine, "do_connect", record)
    try:
        with engine.connect():
            pass
    except ConnectIntercepted:
        pass
    finally:
        event.remove(engine, "do_connect", record)
    # SEC-10: a pooled engine never reaches the hook
    assert fired, "the connect hook never ran on this engine"
    return recorded


def recorded_paypal_configuration(monkeypatch, mode):
    """Return the configuration the payment service hands the provider.

    The provider library is replaced outright, so the service runs its
    own configuration call and reaches no network.
    """
    recorded = []

    def record(configuration):
        recorded.append(dict(configuration))

    monkeypatch.setattr(paypalrestsdk, "configure", record)
    monkeypatch.setattr(settings, "PAYPAL_MODE", mode)
    return recorded


class StubPayment:
    """A provider payment that reports success without a request."""

    created = {"id": "PAY-stub", "state": "created"}

    def __init__(self, definition):
        self.definition = definition

    def create(self):
        return True

    def to_dict(self):
        return dict(self.created)


def load_database_module(url, sslmode):
    """Execute the application database module against one settings pair."""
    specification = importlib.util.spec_from_file_location(
        "backend_app_db_database_config_guard_probe", database.__file__
    )
    module = importlib.util.module_from_spec(specification)
    with mock.patch.object(settings, "DATABASE_URL", url), mock.patch.object(
        settings, "DB_SSLMODE", sslmode
    ):
        specification.loader.exec_module(module)
    return module


def test_pinned_validation_library_is_the_one_x_line():
    """The installed validation library is the pinned 1.x line."""
    assert PYDANTIC_VERSION.startswith("1."), PYDANTIC_VERSION


def test_baseline_kwargs_supply_every_required_field():
    """The shared mapping names every field ``Settings`` requires."""
    required = {
        name
        for name, field in Settings.__fields__.items()
        if field.required
    }
    missing = required - set(valid_settings_kwargs())
    assert not missing, missing
    build_settings()


# SEC-09: payment environment domain
@pytest.mark.parametrize("mode", ["sandbox", "live"])
def test_payment_mode_accepts_the_two_supported_environments(mode):
    """Each supported payment environment passes validation."""
    assert build_settings(PAYPAL_MODE=mode).PAYPAL_MODE == mode


# SEC-09: payment environment domain
@pytest.mark.parametrize(
    "mode",
    [
        "production",
        "",
        "Sandbox",
        "SANDBOX",
        "Live",
        " sandbox",
        "sandbox ",
        "sandbox,live",
    ],
)
def test_payment_mode_rejects_values_outside_the_domain(mode):
    """A payment environment outside the two accepted values is rejected."""
    assert_rejects("PAYPAL_MODE", PAYPAL_MODE=mode)


# SEC-09: payment environment domain
def test_payment_mode_defaults_to_sandbox(monkeypatch):
    """With no payment environment configured, the default is sandbox."""
    monkeypatch.delenv("PAYPAL_MODE", raising=False)
    assert build_settings().PAYPAL_MODE == "sandbox"


# SEC-09: the payment service reads the configured environment
@pytest.mark.parametrize("mode", ["sandbox", "live"])
def test_payment_creation_configures_the_environment_it_is_given(
    monkeypatch, mode
):
    """Creating a payment configures the provider with the setting.

    The validated setting only matters if the code that talks to the
    provider reads it; a literal restored in the service would route a
    live transaction to the wrong environment with the domain check
    still in place.
    """
    recorded = recorded_paypal_configuration(monkeypatch, mode)
    monkeypatch.setattr(paypalrestsdk, "Payment", StubPayment)

    result = paypal_service.create_payment(
        19.99, "USD", "https://app.example.com/ok",
        "https://app.example.com/cancel",
    )

    assert result == StubPayment.created
    assert len(recorded) == 1
    # SEC-09: the environment is the configured one, not a literal
    assert recorded[0]["mode"] == mode
    assert recorded[0]["mode"] == settings.PAYPAL_MODE


# SEC-09: the payment service reads the configured environment
@pytest.mark.parametrize("mode", ["sandbox", "live"])
def test_payment_lookup_configures_the_environment_it_is_given(
    monkeypatch, mode
):
    """Looking a reference up configures the provider with the setting.

    The second configuration call in the service is on the verification
    path, where a wrong environment would report a payment as
    unauthorized or authorize against the wrong ledger.
    """
    recorded = recorded_paypal_configuration(monkeypatch, mode)

    def absent(_reference):
        return None

    monkeypatch.setattr(paypalrestsdk.Payment, "find", staticmethod(absent))
    monkeypatch.setattr(
        paypalrestsdk.BillingAgreement, "find", staticmethod(absent)
    )

    assert paypal_service._find_payment_resource("PAY-absent") is None
    assert len(recorded) == 1
    # SEC-09: the environment is the configured one, not a literal
    assert recorded[0]["mode"] == mode
    assert recorded[0]["mode"] == settings.PAYPAL_MODE


# SEC-09: the payment service reads the configured environment
def test_the_payment_service_spells_no_environment_literal():
    """No source line in the payment service names an environment.

    A literal is what SEC-09 removed, and the two configuration calls
    are the sites that would carry it back.
    """
    with open(paypal_service.__file__, encoding="utf-8") as handle:
        source = handle.read()

    configured = source.count('"mode": settings.PAYPAL_MODE')
    assert configured == 2, configured
    for literal in ('"mode": "sandbox"', '"mode": "live"'):
        assert literal not in source, literal


# SEC-12: RFC 7518 sec. 3.2 key-length floor
@pytest.mark.parametrize(
    "length", [0, 1, 8, 20, SIGNING_KEY_MIN_LENGTH - 1]
)
def test_signing_key_below_the_floor_is_rejected(length):
    """A signing key shorter than the floor is rejected."""
    reported = assert_rejects(
        SIGNING_KEY_FIELD, **{SIGNING_KEY_FIELD: KEY_CHARACTER * length}
    )
    limits = [
        error.get("ctx", {}).get("limit_value")
        for error in reported
        if error["loc"] == (SIGNING_KEY_FIELD,)
    ]
    assert SIGNING_KEY_MIN_LENGTH in limits, reported


# SEC-12: RFC 7518 sec. 3.2 key-length floor
@pytest.mark.parametrize(
    "length",
    [SIGNING_KEY_MIN_LENGTH, SIGNING_KEY_MIN_LENGTH + 1, 64, 128],
)
def test_signing_key_at_or_above_the_floor_is_accepted(length):
    """A signing key at the floor or longer passes validation."""
    key = KEY_CHARACTER * length
    built = build_settings(**{SIGNING_KEY_FIELD: key})
    assert getattr(built, SIGNING_KEY_FIELD) == key


# SEC-12: token signing algorithm family
@pytest.mark.parametrize("algorithm", ["HS256", "HS384", "HS512"])
def test_signing_algorithm_accepts_the_keyed_hash_family(algorithm):
    """Each keyed-hash signing algorithm passes validation."""
    built = build_settings(
        ALGORITHM=algorithm, **{SIGNING_KEY_FIELD: LONG_KEY}
    )
    assert built.ALGORITHM == algorithm


# SEC-12: token signing algorithm family
@pytest.mark.parametrize(
    "algorithm", ["none", "None", "NONE", "RS256", "ES256", "PS256", ""]
)
def test_signing_algorithm_rejects_every_other_family(algorithm):
    """A signing algorithm outside the keyed-hash family is rejected."""
    assert_rejects(
        "ALGORITHM", ALGORITHM=algorithm, **{SIGNING_KEY_FIELD: LONG_KEY}
    )


# SEC-12: RFC 7518 sec. 3.2 floor rises with the algorithm
FLOORS_ABOVE_THE_FIELD = sorted(
    (algorithm, minimum)
    for algorithm, minimum in HMAC_KEY_MIN_BYTES.items()
    if minimum > SIGNING_KEY_MIN_LENGTH
)


# SEC-12: RFC 7518 sec. 3.2 floor rises with the algorithm
def test_the_stronger_algorithms_carry_a_higher_key_floor():
    """The floor table exceeds the field constraint for HS384 and HS512.

    A character constraint on the field is one number, so it can only
    express the weakest algorithm's floor. Were the table flattened to
    that number, a 32-byte key would sign HS512 tokens at half the
    length RFC 7518 sec. 3.2 requires.
    """
    assert HMAC_KEY_MIN_BYTES == {"HS256": 32, "HS384": 48, "HS512": 64}
    assert HMAC_KEY_MIN_BYTES["HS256"] == SIGNING_KEY_MIN_LENGTH
    assert [name for name, _ in FLOORS_ABOVE_THE_FIELD] == [
        "HS384",
        "HS512",
    ]


# SEC-12: RFC 7518 sec. 3.2 floor rises with the algorithm
@pytest.mark.parametrize("algorithm,minimum", FLOORS_ABOVE_THE_FIELD)
def test_signing_key_one_byte_below_the_algorithm_floor_is_rejected(
    algorithm, minimum
):
    """A key one byte under its algorithm's floor is rejected.

    Every key here clears the field's character constraint, so only the
    algorithm-coupled rule can refuse it, and the message it raises has
    to name the algorithm an operator must change.
    """
    short = KEY_CHARACTER * (minimum - 1)
    assert len(short) >= SIGNING_KEY_MIN_LENGTH

    assert_rejected_across_fields(
        SIGNING_KEY_FIELD,
        algorithm,
        minimum,
        minimum - 1,
        ALGORITHM=algorithm,
        **{SIGNING_KEY_FIELD: short}
    )


# SEC-12: RFC 7518 sec. 3.2 floor rises with the algorithm
@pytest.mark.parametrize(
    "algorithm,minimum", sorted(HMAC_KEY_MIN_BYTES.items())
)
def test_signing_key_at_the_algorithm_floor_is_accepted(
    algorithm, minimum
):
    """A key of exactly the algorithm's floor passes validation."""
    key = KEY_CHARACTER * minimum
    built = build_settings(ALGORITHM=algorithm, **{SIGNING_KEY_FIELD: key})

    assert built.ALGORITHM == algorithm
    assert len(getattr(built, SIGNING_KEY_FIELD).encode("utf-8")) == minimum


# SEC-12: the floor counts UTF-8 bytes, not characters
def test_a_multibyte_key_is_measured_in_bytes():
    """A key long enough in characters but short in bytes is rejected.

    Neither direction may be decided by character count: half as many
    two-byte characters clears the strongest floor, and one character
    fewer than that floor in one-byte characters does not.
    """
    strongest = max(HMAC_KEY_MIN_BYTES, key=HMAC_KEY_MIN_BYTES.get)
    floor = HMAC_KEY_MIN_BYTES[strongest]

    wide_enough = "\u00e9" * (floor // 2)
    assert len(wide_enough) < floor
    assert len(wide_enough.encode("utf-8")) == floor
    built = build_settings(
        ALGORITHM=strongest, **{SIGNING_KEY_FIELD: wide_enough}
    )
    assert built.ALGORITHM == strongest

    narrow = KEY_CHARACTER * (floor - 1)
    assert len(narrow) >= SIGNING_KEY_MIN_LENGTH
    assert_rejected_across_fields(
        SIGNING_KEY_FIELD,
        floor,
        floor - 1,
        ALGORITHM=strongest,
        **{SIGNING_KEY_FIELD: narrow}
    )


# SEC-12: a non-positive lifetime mints an already-expired token
@pytest.mark.parametrize("minutes", REJECTED_TOKEN_LIFETIMES)
def test_non_positive_token_lifetime_is_rejected(minutes):
    """A token lifetime of zero or less is rejected."""
    assert_rejects(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        ACCESS_TOKEN_EXPIRE_MINUTES=minutes,
    )


# SEC-12: a positive lifetime is the only accepted shape
@pytest.mark.parametrize("minutes", [1, 30, 1440])
def test_positive_token_lifetime_is_accepted(minutes):
    """A positive token lifetime passes validation."""
    built = build_settings(ACCESS_TOKEN_EXPIRE_MINUTES=minutes)

    assert built.ACCESS_TOKEN_EXPIRE_MINUTES == minutes


# SEC-07: a threshold or window below one leaves guessing unbounded
@pytest.mark.parametrize(
    "field",
    ["LOGIN_RATE_LIMIT_ATTEMPTS", "LOGIN_RATE_LIMIT_WINDOW_MINUTES"],
)
@pytest.mark.parametrize("value", REJECTED_THROTTLE_VALUES)
def test_non_positive_throttle_setting_is_rejected(field, value):
    """A throttle threshold or window below one is rejected.

    A threshold of zero admits every attempt, and a window of zero
    prunes every counter on the next attempt, so either value turns the
    login throttle off while leaving it configured.
    """
    assert_rejects(field, **{field: value})


# SEC-07: the configured threshold and window the throttle enforces
def test_throttle_settings_default_to_the_specified_limit(monkeypatch):
    """With nothing configured the limit is five attempts per quarter
    hour."""
    monkeypatch.delenv("LOGIN_RATE_LIMIT_ATTEMPTS", raising=False)
    monkeypatch.delenv("LOGIN_RATE_LIMIT_WINDOW_MINUTES", raising=False)
    built = build_settings()

    assert built.LOGIN_RATE_LIMIT_ATTEMPTS == 5
    assert built.LOGIN_RATE_LIMIT_WINDOW_MINUTES == 15


# SEC-10: sslmode applied for postgres, withheld for sqlite
def test_sslmode_argument_breaks_a_sqlite_connection():
    """The SQLite driver rejects an sslmode argument when it connects."""
    engine = create_engine(SQLITE_URL, connect_args={"sslmode": "require"})
    with pytest.raises(TypeError) as caught:
        engine.connect()
    assert "sslmode" in str(caught.value)


# SEC-10: sslmode applied for postgres, withheld for sqlite
def test_application_sqlite_engine_opens_a_connection():
    """The engine the application built for SQLite serves a query."""
    assert database.engine.url.get_backend_name() == "sqlite"
    with database.engine.connect() as connection:
        assert connection.exec_driver_sql("select 1").scalar() == 1


# SEC-10: sslmode applied for postgres, withheld for sqlite
@pytest.mark.parametrize("url", [POSTGRES_URL, POSTGRES_DRIVER_URL])
def test_postgres_url_applies_the_configured_sslmode(url):
    """A PostgreSQL URL carries the configured transport mode."""
    module = load_database_module(url, "require")
    assert module.engine.url.get_backend_name() == "postgresql"
    assert recorded_connect_args(module.engine)["sslmode"] == "require"


# SEC-10: sslmode applied for postgres, withheld for sqlite
@pytest.mark.parametrize("mode", LIBPQ_SSLMODES)
def test_postgres_url_carries_each_configured_mode(mode):
    """Every configured transport mode reaches the PostgreSQL driver."""
    module = load_database_module(POSTGRES_URL, mode)
    assert recorded_connect_args(module.engine)["sslmode"] == mode


# SEC-10: sslmode applied for postgres, withheld for sqlite
def test_sqlite_url_withholds_the_sslmode_argument():
    """A SQLite URL yields a connectable engine with no sslmode."""
    module = load_database_module(SQLITE_URL, "require")
    assert module.engine.url.get_backend_name() == "sqlite"
    assert "sslmode" not in recorded_connect_args(module.engine)
    with module.engine.connect() as connection:
        assert connection.exec_driver_sql("select 1").scalar() == 1


# SEC-10: sslmode applied for postgres, withheld for sqlite
def test_loading_the_database_module_leaves_shared_state_intact():
    """Probing both branches leaves the application engine unchanged."""
    original_url = settings.DATABASE_URL
    original_mode = settings.DB_SSLMODE
    load_database_module(POSTGRES_URL, "verify-full")
    assert settings.DATABASE_URL == original_url
    assert settings.DB_SSLMODE == original_mode
    assert database.engine.url.get_backend_name() == "sqlite"
    with database.engine.connect() as connection:
        assert connection.exec_driver_sql("select 1").scalar() == 1


# SEC-10: explicit transport mode replaces the driver's negotiated default
def test_transport_mode_defaults_to_require(monkeypatch):
    """With no transport mode configured, the default is require."""
    monkeypatch.delenv("DB_SSLMODE", raising=False)
    assert build_settings().DB_SSLMODE == "require"


# SEC-10: explicit transport mode replaces the driver's negotiated default
@pytest.mark.parametrize("mode", LIBPQ_SSLMODES)
def test_transport_mode_accepts_every_driver_defined_mode(mode):
    """Each transport mode the database driver defines is accepted."""
    assert build_settings(DB_SSLMODE=mode).DB_SSLMODE == mode


# SEC-10: a transport mode outside the driver's domain is refused
@pytest.mark.parametrize("mode", REJECTED_SSLMODES)
def test_transport_mode_outside_the_driver_domain_is_rejected(mode):
    """A transport mode the driver does not define is rejected.

    Without the domain check a misspelling reaches the driver, which
    rejects it only when a connection is first opened - so the failure
    surfaces on the first query rather than at startup - and a value
    carrying an appended connection parameter would reach it intact.
    """
    assert mode not in LIBPQ_SSLMODES
    assert_rejects("DB_SSLMODE", DB_SSLMODE=mode)


# SEC-10: the accepted domain is exactly the driver's own
def test_the_accepted_transport_domain_matches_the_declared_one():
    """Every declared mode is accepted and nothing else is.

    The declared tuple is what the error message quotes to an operator,
    so it and the accepted set must not drift apart.
    """
    assert tuple(DB_SSLMODES) == LIBPQ_SSLMODES
    for mode in DB_SSLMODES:
        assert build_settings(DB_SSLMODE=mode).DB_SSLMODE == mode
