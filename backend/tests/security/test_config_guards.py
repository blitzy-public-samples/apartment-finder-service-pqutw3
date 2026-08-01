"""Configuration guards for the payment environment, the signing key and
database transport, and the authorization of a payment reference.

Three settings decide whether the application starts in a safe state: the
payment environment, the signing key length, and the database transport
mode. Every case builds ``Settings`` directly and inspects the field named
in the validation error it raises.

The transport cases execute ``backend/app/db/database.py`` against each
database URL form and inspect the engine it builds; no case establishes a
live encrypted database connection. The payment cases execute
``backend/app/services/paypal_service.py`` with the provider library
replaced, so the configured environment is read by the code that talks to
the provider rather than only validated in isolation.

The authorization cases drive ``process_payment`` against fixed provider
payloads. A reference authorizes a charge only when the state, the total,
the reported unit, the payer and, for a reusable billing agreement, the
bound plan all match, and it authorizes one charge and no more. The
consumption ledger holds per-process state, so a second worker keeps its
own; the multi-worker limitation is recorded in the decision log under
SEC-09.
"""
import asyncio
import importlib.util
import inspect
import time
from unittest import mock

import paypalrestsdk
import paypalrestsdk.api
import pytest
import requests
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
# protection; require encrypts without verifying the server certificate
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


def test_application_sqlite_engine_opens_a_connection():
    """The engine the application built for SQLite serves a query."""
    assert database.engine.url.get_backend_name() == "sqlite"
    with database.engine.connect() as connection:
        assert connection.exec_driver_sql("select 1").scalar() == 1


@pytest.mark.parametrize("url", [POSTGRES_URL, POSTGRES_DRIVER_URL])
def test_postgres_url_applies_the_configured_sslmode(url):
    """A PostgreSQL URL carries the configured transport mode."""
    module = load_database_module(url, "require")
    assert module.engine.url.get_backend_name() == "postgresql"
    assert recorded_connect_args(module.engine)["sslmode"] == "require"


@pytest.mark.parametrize("mode", LIBPQ_SSLMODES)
def test_postgres_url_carries_each_configured_mode(mode):
    """Every configured transport mode reaches the PostgreSQL driver."""
    module = load_database_module(POSTGRES_URL, mode)
    assert recorded_connect_args(module.engine)["sslmode"] == mode


def test_sqlite_url_withholds_the_sslmode_argument():
    """A SQLite URL yields a connectable engine with no sslmode."""
    module = load_database_module(SQLITE_URL, "require")
    assert module.engine.url.get_backend_name() == "sqlite"
    assert "sslmode" not in recorded_connect_args(module.engine)
    with module.engine.connect() as connection:
        assert connection.exec_driver_sql("select 1").scalar() == 1


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


# SEC-09: identities the transaction-authorization cases bind against
PAYER_IDENTITY = "PAYER-1"
BOUND_PLAN = "PLAN-A"
CHARGE_TOTAL = 10.00


def approved_payment(total="10.00", currency="USD", state="approved",
                     payer=PAYER_IDENTITY):
    """Build the payload PayPal returns for a one-off payment."""
    resource = {
        "id": "PAY-1",
        "state": state,
        "transactions": [{"amount": {"total": total, "currency": currency}}],
    }
    if payer is not None:
        resource["payer"] = {"payer_info": {"payer_id": payer}}
    return resource


def active_agreement(value="10.00", currency="USD", state="active",
                     plan=BOUND_PLAN, payer=PAYER_IDENTITY):
    """Build the payload PayPal returns for a reusable billing agreement."""
    plan_body = {"payment_definitions": [
        {"amount": {"value": value, "currency": currency}}]}
    if plan is not None:
        plan_body["id"] = plan
    resource = {"id": "I-1", "state": state, "plan": plan_body}
    if payer is not None:
        resource["payer"] = {"payer_info": {"payer_id": payer}}
    return resource


def authorize(resource, amount=CHARGE_TOTAL, reference="PAY-1", **binding):
    """Verify one charge against a fixed provider payload."""
    loop = asyncio.new_event_loop()
    try:
        with mock.patch.object(paypal_service, "_find_payment_resource",
                               return_value=resource):
            return loop.run_until_complete(paypal_service.process_payment(
                reference, amount, **binding))
    finally:
        loop.close()


def refusal(resource, amount=CHARGE_TOTAL, currency="USD", plan_id=None,
            payer_id=None):
    """Return the reason the authorization gate refuses one charge."""
    return paypal_service._resource_authorizes_charge(
        resource, amount, currency, plan_id, payer_id)


@pytest.fixture
def spent_references():
    """Give one case an empty consumption ledger and leave it empty."""
    def reset():
        paypal_service._consumed_references.clear()
        paypal_service._claimed_references.clear()
    reset()
    yield paypal_service._consumed_references
    reset()


# SEC-09: a reference matching every dimension authorizes the charge
def test_charge_authorizes_a_matching_reference(spent_references):
    """A payment matching amount, unit and payer authorizes the charge."""
    assert refusal(approved_payment()) is None
    assert authorize(approved_payment()) is True


# SEC-09: the reported unit is bound to the charge (CWE-863)
@pytest.mark.parametrize("currency", ["JPY", "EUR", "GBP", "ZWL"])
def test_charge_refuses_a_foreign_currency_total(currency, spent_references):
    """A total matching numerically in another unit does not authorize."""
    resource = approved_payment(currency=currency)
    assert refusal(resource) == "currency_mismatch"
    assert authorize(resource) is False


# SEC-09: the reported unit is bound to the charge (CWE-863)
def test_charge_refuses_a_total_carrying_no_unit(spent_references):
    """A total PayPal reports with no currency does not authorize."""
    resource = {
        "id": "PAY-1",
        "state": "approved",
        "transactions": [{"amount": {"total": "10.00"}}],
        "payer": {"payer_info": {"payer_id": PAYER_IDENTITY}},
    }
    assert refusal(resource) == "currency_mismatch"
    assert authorize(resource) is False


# SEC-09: the reported unit is bound to the charge (CWE-863)
def test_charge_refuses_a_split_total_in_mixed_units(spent_references):
    """A split total summing correctly across two units does not authorize."""
    resource = {
        "id": "PAY-1",
        "state": "approved",
        "transactions": [
            {"amount": {"total": "6.00", "currency": "USD"}},
            {"amount": {"total": "4.00", "currency": "JPY"}},
        ],
        "payer": {"payer_info": {"payer_id": PAYER_IDENTITY}},
    }
    assert refusal(resource) == "currency_mismatch"
    assert authorize(resource) is False


# SEC-09: the reported unit is bound to the charge (CWE-863)
def test_charge_admits_a_bound_unit_and_normalizes_its_spelling(
        spent_references):
    """A caller-bound unit authorizes, and its spelling is normalized."""
    assert authorize(approved_payment(currency="JPY"), reference="PAY-JPY",
                     currency="JPY") is True
    assert authorize(approved_payment(currency="usd"), reference="PAY-USD",
                     currency=" usd ") is True


# SEC-09: the provider must name the payer (CWE-863)
def test_charge_refuses_an_unidentified_payer(spent_references):
    """A reference PayPal attributes to nobody does not authorize."""
    resource = approved_payment(payer=None)
    assert refusal(resource) == "payer_unidentified"
    assert authorize(resource) is False


# SEC-09: the provider must name the payer (CWE-863)
def test_charge_refuses_a_payer_the_caller_did_not_expect(spent_references):
    """A bound payer that differs from the reported one does not authorize."""
    resource = approved_payment()
    assert refusal(resource, payer_id="SOMEONE-ELSE") == "payer_mismatch"
    assert authorize(resource, payer_id="SOMEONE-ELSE") is False
    assert authorize(resource, payer_id=PAYER_IDENTITY) is True


# SEC-09: a reusable agreement authorizes nothing until a plan is bound
def test_charge_refuses_an_unbound_reusable_agreement(spent_references):
    """An agreement reached with no plan bound does not authorize."""
    resource = active_agreement()
    assert refusal(resource) == "plan_unbound"
    assert authorize(resource) is False


# SEC-09: a reusable agreement is bound to one plan (CWE-863)
def test_charge_refuses_an_agreement_for_another_plan(spent_references):
    """An agreement carrying a different plan does not authorize."""
    resource = active_agreement(plan="PLAN-B")
    assert refusal(resource, plan_id=BOUND_PLAN) == "plan_mismatch"
    assert authorize(resource, plan_id=BOUND_PLAN) is False


# SEC-09: a reusable agreement is bound to one plan (CWE-863)
def test_charge_refuses_an_agreement_naming_no_plan(spent_references):
    """An agreement reporting no plan identifier does not authorize."""
    resource = active_agreement(plan=None)
    assert refusal(resource, plan_id=BOUND_PLAN) == "plan_mismatch"
    assert authorize(resource, plan_id=BOUND_PLAN) is False


# SEC-09: a reusable agreement is bound to one plan (CWE-863)
def test_charge_admits_an_agreement_for_the_bound_plan(spent_references):
    """An agreement carrying the bound plan authorizes the charge."""
    assert refusal(active_agreement(), plan_id=BOUND_PLAN) is None
    assert authorize(active_agreement(), plan_id=BOUND_PLAN) is True


# SEC-09: a reusable agreement is bound to one plan and one unit
def test_charge_refuses_a_bound_agreement_in_a_foreign_unit(spent_references):
    """An agreement for the bound plan in another unit does not authorize."""
    resource = active_agreement(currency="JPY")
    assert refusal(resource, plan_id=BOUND_PLAN) == "currency_mismatch"
    assert authorize(resource, plan_id=BOUND_PLAN) is False


# SEC-09: a verified reference is spent once (CWE-294)
def test_a_verified_reference_authorizes_one_charge_only(spent_references):
    """Replaying a reference that already paid does not authorize again."""
    resource = approved_payment()
    outcomes = [authorize(resource, reference="PAY-REPLAY") for _ in range(3)]
    assert outcomes == [True, False, False]
    assert authorize(resource, reference="PAY-OTHER") is True
    assert len(paypal_service._claimed_references) == 0


# SEC-09: a spent reference reaches no provider call (CWE-294)
def test_a_spent_reference_drives_no_provider_call(spent_references):
    """A replayed reference is refused ahead of any provider request."""
    lookup = mock.Mock(return_value=approved_payment())
    loop = asyncio.new_event_loop()
    try:
        with mock.patch.object(paypal_service, "_find_payment_resource",
                               lookup):
            outcomes = [
                loop.run_until_complete(paypal_service.process_payment(
                    "PAY-ONCE", CHARGE_TOTAL))
                for _ in range(4)]
    finally:
        loop.close()
    assert outcomes == [True, False, False, False]
    assert lookup.call_count == 1


# SEC-09: a verified reference is spent once (CWE-294)
def test_concurrent_attempts_on_one_reference_admit_one(spent_references):
    """Two attempts in flight on one reference authorize exactly once."""
    def lookup(reference):
        time.sleep(0.05)
        return approved_payment()

    async def both():
        return await asyncio.gather(
            paypal_service.process_payment("PAY-RACE", CHARGE_TOTAL),
            paypal_service.process_payment("PAY-RACE", CHARGE_TOTAL))

    loop = asyncio.new_event_loop()
    try:
        with mock.patch.object(paypal_service, "_find_payment_resource",
                               side_effect=lookup):
            outcomes = loop.run_until_complete(both())
    finally:
        loop.close()
    assert sorted(outcomes) == [False, True]
    assert len(paypal_service._claimed_references) == 0


# SEC-09: a verified reference is spent once (CWE-294)
def test_the_ledger_records_no_provider_reference(spent_references):
    """The ledger holds a digest, never the reference PayPal issued."""
    assert authorize(approved_payment(), reference="PAY-SECRET") is True
    assert "PAY-SECRET" not in spent_references
    assert list(spent_references) == [
        paypal_service._reference_key("PAY-SECRET")]


# SEC-09: a refused reference is not consumed
def test_a_refused_reference_stays_available(spent_references):
    """A reference refused once is still usable when the charge matches."""
    assert authorize(approved_payment(currency="JPY"),
                     reference="PAY-RETRY") is False
    assert len(paypal_service._claimed_references) == 0
    assert authorize(approved_payment(), reference="PAY-RETRY") is True


# SEC-09: a verified reference is spent once (CWE-294)
def test_the_consumption_ledger_stays_bounded(spent_references):
    """The ledger evicts its oldest entry rather than growing without end."""
    limit = paypal_service._CONSUMPTION_LIMIT
    first = paypal_service._reference_key("PAY-0")
    for index in range(limit + 1):
        paypal_service._consume_reference(
            paypal_service._reference_key("PAY-%d" % index))
    assert len(spent_references) == limit
    assert first not in spent_references


# SEC-09: every provider call is bounded in time (CWE-400)
def test_every_provider_call_carries_a_timeout():
    """The transport supplies a timeout the provider SDK never sets."""
    assert isinstance(paypalrestsdk.api.requests,
                      paypal_service._BoundedTransport)
    recorded = {}

    class Recorder:
        def request(self, *args, **kwargs):
            recorded.update(kwargs)
            raise requests.exceptions.Timeout("bounded")

    bounded = paypal_service._BoundedTransport(
        Recorder(), paypal_service._REQUEST_TIMEOUT_SECONDS)
    with mock.patch.object(paypalrestsdk.api, "requests", bounded):
        assert paypal_service._find_payment_resource("PAY-TIMEOUT") is None
    assert recorded["timeout"] == paypal_service._REQUEST_TIMEOUT_SECONDS
    assert paypal_service._REQUEST_TIMEOUT_SECONDS > 0


# SEC-09: every provider call is bounded in time (CWE-400)
def test_a_provider_timeout_refuses_the_charge(spent_references):
    """A provider call that times out refuses rather than raising."""
    class Stalled:
        def request(self, *args, **kwargs):
            raise requests.exceptions.Timeout("bounded")

    bounded = paypal_service._BoundedTransport(
        Stalled(), paypal_service._REQUEST_TIMEOUT_SECONDS)
    loop = asyncio.new_event_loop()
    try:
        with mock.patch.object(paypalrestsdk.api, "requests", bounded):
            outcome = loop.run_until_complete(
                paypal_service.process_payment("PAY-STALL", CHARGE_TOTAL))
    finally:
        loop.close()
    assert outcome is False


# SEC-09: the binding parameters leave the caller contract unchanged
def test_the_verification_call_contract_is_preserved():
    """The two positional parameters stay first; the bindings are keyword."""
    signature = inspect.signature(paypal_service.process_payment)
    parameters = list(signature.parameters.values())
    positional = [p.name for p in parameters
                  if p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD]
    keyword_only = {p.name for p in parameters
                    if p.kind is inspect.Parameter.KEYWORD_ONLY}
    assert positional == ["payment_method", "amount"]
    assert keyword_only == {"currency", "plan_id", "payer_id"}
    assert all(parameters[index].default is None
               for index in range(2, len(parameters)))
    assert inspect.iscoroutinefunction(paypal_service.process_payment)
