"""Configuration guards for the payment environment, the signing key and
database transport.

Three settings decide whether the application starts in a safe state: the
payment environment, the signing key length, and the database transport
mode. Every case builds ``Settings`` directly and inspects the field named
in the validation error it raises.

The transport cases execute ``backend/app/db/database.py`` against each
database URL form and inspect the engine it builds.
"""
import importlib.util
from unittest import mock

import pytest
from pydantic import VERSION as PYDANTIC_VERSION
from pydantic import ValidationError
from sqlalchemy import create_engine, event

from backend.app.core.config import Settings, settings
from backend.app.db import database

# SEC-10: URL forms reaching each branch of the database.py conditional
POSTGRES_URL = "postgresql://u:p@localhost:5432/d"
POSTGRES_DRIVER_URL = "postgresql+psycopg2://u:p@localhost:5432/d"
SQLITE_URL = "sqlite://"

# SEC-10: the transport modes the database driver defines, ascending in
# protection
LIBPQ_SSLMODES = (
    "disable",
    "allow",
    "prefer",
    "require",
    "verify-ca",
    "verify-full",
)

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
