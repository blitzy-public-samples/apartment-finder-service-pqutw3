"""Configuration guards for the payment environment, the signing key and
database transport, and the subscription charge seam.

The validation cases build ``Settings`` directly for each guarded
setting - the payment environment, the signing key length, the signing
algorithm, the token lifetime, the login-throttle threshold and window,
and the database transport mode - and inspect the field named in the
validation error it raises.

The database transport mode carries an explicit value in place of the
driver's negotiated default; it is not restricted to a closed set of
values. The transport cases execute ``backend/app/db/database.py`` against
each database URL form and inspect the engine it builds; no case
establishes a live encrypted database connection. The payment cases execute
``backend/app/services/paypal_service.py`` with the provider library
replaced, so the configured environment reaches the code that calls the
provider.

The charge cases drive ``process_payment`` through the signature
``backend/app/api/endpoints/subscriptions.py`` calls, and drive the route
itself. The seam carries no trusted plan, price or authenticated identity,
so it authorizes nothing; the refusal and the absent local ledger are
recorded in the decision log under SEC-09.
"""
import asyncio
import importlib.util
import inspect
import logging
import os
import re
import shlex
import stat
from http import HTTPStatus
import subprocess
from pathlib import Path
from unittest import mock

import paypalrestsdk
import pytest
from pydantic import VERSION as PYDANTIC_VERSION
from pydantic import ValidationError
from sqlalchemy import create_engine, event

from backend.app.api.endpoints import subscriptions as subscription_route
from backend.app.core.config import (
    DB_SSLMODES,
    HMAC_KEY_MIN_BYTES,
    Settings,
    settings,
)
from backend.app.db import database
from backend.app.db.models import Subscription as SubscriptionModel
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

# SEC-10: values outside the driver's domain
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

# AAP 0.1.4: the eight frozen environment variable names, transcribed
FROZEN_SETTING_NAMES = (
    "DATABASE_URL",
    "SECRET_KEY",
    "ALGORITHM",
    "ACCESS_TOKEN_EXPIRE_MINUTES",
    "ZILLOW_API_KEY",
    "PAYPAL_CLIENT_ID",
    "PAYPAL_CLIENT_SECRET",
    "SENTRY_DSN",
)

FROZEN_SETTING_COUNT = 8

# The one frozen name the model does not require. An empty value is a
# valid choice for it: no error reporter is configured.
OPTIONAL_FROZEN_NAME = "SENTRY_DSN"

# Every path below is resolved from this file, so it holds whether pytest
# runs from the repository root or from backend/ as ci.yml does.
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]

# SEC-12: the template that documents every variable by name and carries
# no secret value
ENVIRONMENT_TEMPLATE = REPOSITORY_ROOT / ".env.example"

# SEC-12: the template carries two contracts; the backend parity check
# below applies to the first, and this heading divides them
FRONTEND_SECTION_HEADING = "# Frontend build variables"

# SEC-12: the two names create-react-app embeds into the client bundle at
# build time, so a value supplied at run time never reaches the browser
FRONTEND_BUILD_VARIABLE = re.compile(r"process\.env\.(REACT_APP_[A-Z0-9_]+)")
FRONTEND_SOURCE_DIR = REPOSITORY_ROOT / "frontend" / "src"
FRONTEND_IMAGE = (
    REPOSITORY_ROOT / "infrastructure" / "docker" / "Dockerfile.frontend"
)
COMPOSE_DEFINITION = (
    REPOSITORY_ROOT / "infrastructure" / "docker" / "docker-compose.yml"
)

# SEC-01/SEC-12: the workflow carrying the credential scan, and the two
# paths that scan formerly excluded
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
FORMERLY_EXCLUDED_PATHS = (".github/workflows/ci.yml", "SECURITY.md")
EXCLUSION_PATHSPEC = ":(exclude)"

# CWE-1104: the dependency advisory gate, its flags and its register size
AUDIT_STEP_NAME = "Audit Python dependencies"
AUDIT_STEP_FLAGS = ("--strict", "--no-deps")
FROZEN_CLOSURE_COMMAND = "pip freeze > /tmp/frozen.txt"
RUNNER_DEPENDENT_FREEZE_FLAG = "pip freeze --all"
EXPECTED_SUPPRESSION_COUNT = 15

# a step's own lines are indented deeper than its header
STEP_BODY_INDENT = " " * 6

# the two identifier namespaces the register uses
ADVISORY_IDENTIFIER = re.compile(
    r"PYSEC-[0-9]{4}-[0-9]+|GHSA(?:-[2-9a-hjkmnp-z]{4}){3}"
)

# One line per credential shape the scan detects. Every value is invented
# and assembled from fragments, so the scan matches none of them here.
CREDENTIAL_POSITIVE_CONTROLS = (
    pytest.param(
        "DATABASE_URL=postgresql://postgres" + ":" + "postgres@db:5432/app",
        id="default-credential-pair",
    ),
    pytest.param(
        "CREATE USER app WITH PASS" + "WORD 'seeded-role-secret';",
        id="inline-sql-password-literal",
    ),
    pytest.param(
        "SECRET_KEY=" + "seeded0signing0key0value",
        id="assigned-signing-key",
    ),
    pytest.param(
        "postgresql://svc:pass" + "word@db.internal:5432/appdb",
        id="url-embedded-password",
    ),
)

# Documented placeholders the scan must pass over
CREDENTIAL_NEGATIVE_CONTROLS = (
    pytest.param(
        "SECRET_KEY=<random-secret-min-32-chars>", id="template-key"
    ),
    pytest.param(
        "DATABASE_URL=postgresql://<db-user>:<db-password>"
        "@<db-host>:5432/<db-name>",
        id="template-url",
    ),
    pytest.param(
        "PAYPAL_CLIENT_SECRET=<paypal-client-secret>", id="template-paypal"
    ),
    pytest.param("SENTRY_DSN=", id="template-empty-value"),
)

# Rule 1: the register justifying every suppressed advisory, and the
# condition under which all are re-measured
DECISION_LOG = (
    REPOSITORY_ROOT / "documentation" / "security" / "decision-log.md"
)
REVIEW_TRIGGER = "a Python runtime upgrade"

# Rule 1: the operational document that carries the residual register
SECURITY_DOCUMENT = REPOSITORY_ROOT / "SECURITY.md"

# SEC-01/SEC-11: the developer provisioning script, read as text
PROVISIONING_SCRIPT = REPOSITORY_ROOT / "scripts" / "setup_dev_environment.sh"

# SEC-11: every privilege the application role is granted
APP_ROLE_GRANTS = (
    "GRANT CONNECT ON DATABASE dbname TO app_user;",
    "GRANT USAGE ON SCHEMA public TO app_user;",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public"
    " TO app_user;",
    "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;",
)

# SEC-11: the same data operations on tables the owner creates later, so a
# later table does not silently arrive unreachable or over-shared
APP_ROLE_DEFAULT_PRIVILEGES = (
    "ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public"
    " GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;",
    "ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public"
    " GRANT USAGE, SELECT ON SEQUENCES TO app_user;",
)

# SEC-11: the application role is created with a login and nothing else
APP_ROLE_CREATION = "CREATE ROLE app_user WITH LOGIN"

# SEC-11: schema public grants CREATE to PUBLIC by default, which would
# hand the application role the DDL the grants above withhold
REVOKED_FROM_PUBLIC = "REVOKE CREATE ON SCHEMA public FROM PUBLIC;"

# SEC-11: the owner role performs schema work
OWNER_ROLE_GRANT = "GRANT CREATE, USAGE ON SCHEMA public TO app_owner;"

# SEC-11: privileges no provisioning statement may confer
FORBIDDEN_PROVISIONING_SQL = (
    "GRANT ALL",
    "SUPERUSER",
    "CREATEDB",
    "CREATEROLE",
    "BYPASSRLS",
    "GRANT CREATE ON SCHEMA public TO app_user",
)

# SEC-11: an inline role-password literal, assembled from fragments so the
# repository credential scan does not match this expression
SQL_PASSWORD_LITERAL = re.compile("PASS" + "WORD +'")

# SEC-11: the two forms that would place a role password in an argument
# list, readable by any local process (CWE-214)
ARGUMENT_LIST_PASSWORD_FORMS = ("-v owner_pw=", "-v app_pw=")

# SEC-01: the guards that keep the generated secret file unreadable by
# another user, and keep a symlink at .env from being written through
SECRET_FILE_GUARDS = (
    pytest.param("umask 077", id="owner-only-creation-mask"),
    pytest.param("mktemp ./.env.tmp.XXXXXXXX", id="unpredictable-temp-name"),
    pytest.param("trap 'rm -f \"$env_tmp\"' EXIT", id="temp-file-cleanup"),
    pytest.param('chmod 600 "$env_tmp"', id="restricted-before-install"),
    pytest.param('mv -f "$env_tmp" .env', id="atomic-install"),
    pytest.param("secrets.token_urlsafe(48)", id="generated-signing-key"),
    pytest.param("^[A-Za-z0-9_-]+$", id="generated-password-charset"),
)

# SEC-01: the direct-write shape the guards above replace
DIRECT_SECRET_WRITE = "EOF > .env"

# SEC-01/SEC-11: the order main runs these in, each stopping the run on
# failure
PROVISIONING_ORDER = (
    "setup_virtual_env || exit 1",
    "install_dependencies || exit 1",
    "configure_env_vars || exit 1",
    "init_database || exit 1",
)

# SEC-11: the grant batch reaches psql on standard input, and a failed
# batch stops the run rather than leaving half-provisioned roles behind
PSQL_INVOCATION = "} | psql -v ON_ERROR_STOP=1 -d dbname"
GRANT_BATCH_STATUS = '[ "${PIPESTATUS[1]}" -ne 0 ]'

# SEC-01/SEC-11: every command whose failure would leave the run
# provisioning against state that does not exist (CWE-252)
GUARDED_COMMANDS = (
    "python3 -m venv venv",
    "source venv/bin/activate",
    'python3 -m pip install -r "$repo_root/backend/requirements.txt"',
    "check_schema_prerequisites",
    "createdb dbname",
    'chmod 600 "$env_tmp"',
    'mv -f "$env_tmp" .env',
    "create_schema_as_owner",
)

# SEC-01/SEC-11: the two ways a step ends the run rather than continuing
FAILURE_CONTROLS = ("return 1", "exit 1")

# SEC-11: the manifest is resolved from the script's own location, so the
# install does not depend on the directory the operator ran it from
BACKEND_MANIFEST = '-r "$repo_root/backend/requirements.txt"'
SCRIPT_RELATIVE_ROOT = (
    'repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || return 1'
)

# SEC-11: the owner role creates every schema object, so the application
# role needs no DDL privilege to reach a populated database
OWNER_BOOTSTRAP = "create_schema_as_owner"
OWNER_BOOTSTRAP_PREREQUISITES = "check_schema_prerequisites"
OWNER_CREDENTIAL_VARIABLE = "OWNER_DATABASE_URL"
OWNER_SCHEMA_CREATION = "Base.metadata.create_all(bind=engine)"

# SEC-10/SEC-11: the infrastructure declarations, read as text
TERRAFORM_DIRECTORY = REPOSITORY_ROOT / "infrastructure" / "terraform"
TERRAFORM_MAIN = TERRAFORM_DIRECTORY / "main.tf"
TERRAFORM_VARIABLES = TERRAFORM_DIRECTORY / "variables.tf"

# the resource type and local name of each gated declaration
CLOUD_SQL_INSTANCE = ("google_sql_database_instance", "main")
CLOUD_SQL_USER = ("google_sql_user", "app")

# SEC-10: the one instance transport setting that refuses an unencrypted
# connection; every other value in the domain permits one
REQUIRED_SSL_MODE = "ENCRYPTED_ONLY"
QUOTED_SSL_MODE = '"{0}"'.format(REQUIRED_SSL_MODE)

# AAP 0.5.10: the superseded argument this configuration must not use
DEPRECATED_SSL_ARGUMENT = "require_ssl"

DECLARED_DATABASE_VERSION = "POSTGRES_13"
QUOTED_DATABASE_VERSION = '"{0}"'.format(DECLARED_DATABASE_VERSION)

# SEC-11: the input variables the application role draws its identity
# from, so that no credential appears in a tracked file
APP_ROLE_NAME_VARIABLE = "db_app_user"
APP_ROLE_PASSWORD_VARIABLE = "db_app_password"
APP_ROLE_NAME_REFERENCE = "var.{0}".format(APP_ROLE_NAME_VARIABLE)
APP_ROLE_PASSWORD_REFERENCE = "var.{0}".format(APP_ROLE_PASSWORD_VARIABLE)

# SEC-12: the write-only password argument, its rotation counter, and the
# state-persisting argument that must stay absent
APP_ROLE_PASSWORD_ARGUMENT = "password_wo"
APP_ROLE_PASSWORD_VERSION_ARGUMENT = "password_wo_version"
APP_ROLE_PASSWORD_VERSION_VARIABLE = "db_app_password_version"
STATE_PERSISTING_PASSWORD_ARGUMENT = "password ="

# SEC-11: the argument and the variable the declaration must not carry
ROLE_ASSIGNMENT_ARGUMENT = "database_roles"
WITHDRAWN_ROLE_VARIABLE = "db_app_role"

# SEC-11: the input variables the declaration does reference. A variable the
# configuration never reads is a knob that changes nothing.
REFERENCED_ROLE_VARIABLES = (
    APP_ROLE_NAME_VARIABLE,
    APP_ROLE_PASSWORD_VARIABLE,
    APP_ROLE_PASSWORD_VERSION_VARIABLE,
)

# SEC-11: the role Cloud SQL grants every built-in user it creates, and the
# statements SECURITY.md carries for narrowing the account out of band
CLOUD_AUTOMATIC_ROLE = "cloudsqlsuperuser"
CLOUD_PRIVILEGE_STATEMENTS = (
    "REVOKE cloudsqlsuperuser FROM app_user;",
    "ALTER ROLE app_user NOCREATEDB NOCREATEROLE;",
    "REVOKE CREATE ON SCHEMA public FROM PUBLIC;",
    'GRANT CONNECT ON DATABASE "main-database" TO app_user;',
    "GRANT USAGE ON SCHEMA public TO app_user;",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public"
    " TO app_user;",
    "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;",
    "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT,"
    " UPDATE, DELETE ON TABLES TO app_user;",
    "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON"
    " SEQUENCES TO app_user;",
)


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


# Every engine a probe builds, registered for disposal by the fixture below
_PROBE_ENGINES = []


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
    probe_engine = getattr(module, "engine", None)
    if probe_engine is not None:
        _PROBE_ENGINES.append(probe_engine)
    return module


@pytest.fixture(autouse=True)
def dispose_probe_engines():
    """Dispose every engine a probe built in this test.

    The application engine is never registered, so it is untouched.
    """
    _PROBE_ENGINES.clear()
    try:
        yield
    finally:
        while _PROBE_ENGINES:
            _PROBE_ENGINES.pop().dispose()


def test_pinned_validation_library_is_the_one_x_line():
    """The installed validation library is the pinned 1.x line."""
    assert PYDANTIC_VERSION.startswith("1."), PYDANTIC_VERSION


def _assigned_names(source):
    """Return the variable names one template extract assigns."""
    return {
        line.split("=", 1)[0].strip()
        for line in source.splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }


def _template_sections():
    """Return the backend and frontend halves of the template."""
    assert ENVIRONMENT_TEMPLATE.is_file(), ENVIRONMENT_TEMPLATE
    source = ENVIRONMENT_TEMPLATE.read_text(encoding="utf-8")
    backend_half, marker, frontend_half = source.partition(
        FRONTEND_SECTION_HEADING
    )
    assert marker, FRONTEND_SECTION_HEADING
    return backend_half, frontend_half


def _documented_setting_names():
    """Return every backend variable name the template documents."""
    return _assigned_names(_template_sections()[0])


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


def test_the_frozen_setting_names_are_declared_unchanged():
    """``Settings`` still declares each of the eight frozen names.

    AAP 0.1.4 freezes these names, so renaming or dropping one breaks the
    deployment contract even when the field behind it survives under
    another name. The names are transcribed above this case.
    """
    declared = set(Settings.__fields__)

    for name in FROZEN_SETTING_NAMES:
        assert name in declared, name

    # a name added to the tuple is a deliberate change to the frozen set
    assert len(FROZEN_SETTING_NAMES) == FROZEN_SETTING_COUNT
    assert len(set(FROZEN_SETTING_NAMES)) == FROZEN_SETTING_COUNT

    # AAP 0.1.4: new settings are additive, so the model declares more
    assert declared > set(FROZEN_SETTING_NAMES)

    # the shared mapping supplies every frozen name the model requires,
    # and the one it does not require stays optional
    baseline = set(valid_settings_kwargs())
    assert set(FROZEN_SETTING_NAMES) - baseline == {OPTIONAL_FROZEN_NAME}
    assert not Settings.__fields__[OPTIONAL_FROZEN_NAME].required
    for name in FROZEN_SETTING_NAMES:
        if name != OPTIONAL_FROZEN_NAME:
            assert Settings.__fields__[name].required, name


def test_every_declared_setting_is_documented_by_name():
    """The environment template names every setting the code reads.

    SEC-12 requires each variable to be documented by name with no value.
    A setting the template omits reaches an operator only as a startup
    failure, and a name the template carries that the code no longer
    reads sends an operator to configure nothing, so the parity is
    asserted in both directions.
    """
    documented = _documented_setting_names()

    for name in FROZEN_SETTING_NAMES:
        assert name in documented, name

    undocumented = set(Settings.__fields__) - documented
    assert not undocumented, undocumented

    unread = documented - set(Settings.__fields__)
    assert not unread, unread


@pytest.mark.parametrize("name", FROZEN_SETTING_NAMES)
def test_each_frozen_name_is_the_variable_the_application_reads(
    name, monkeypatch
):
    """Each frozen name is decisive in the process environment.

    A field name in ``Settings`` is half the contract; what an operator
    sets is an environment variable. Removing one frozen name from the
    environment and rebuilding the settings shows which variable the
    field reads: a field bound to some other variable through an alias
    fails this case.
    """
    monkeypatch.delenv(name, raising=False)

    if name == OPTIONAL_FROZEN_NAME:
        # SEC-12: no configured error reporter is a valid state
        assert Settings(_env_file=None).SENTRY_DSN is None
        return

    with pytest.raises(ValidationError) as caught:
        Settings(_env_file=None)
    named = [error["loc"] for error in caught.value.errors()]
    assert (name,) in named, named


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
def test_the_payment_service_spells_no_environment_literal():
    """No source line in the payment service names an environment.

    A literal is what SEC-09 removed, and the configuration call is the
    site that would carry it back.
    """
    with open(paypal_service.__file__, encoding="utf-8") as handle:
        source = handle.read()

    configured = source.count('"mode": settings.PAYPAL_MODE')
    assert configured == 1, configured
    for literal in ('"mode": "sandbox"', '"mode": "live"'):
        assert literal not in source, literal


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
    """The signing-key floor is measured in bytes, not in characters.

    Both directions are checked. A key of half as many two-byte
    characters carries exactly the strongest floor in bytes and is
    accepted, even though its character count sits below that floor. A
    key one byte under the floor is rejected, even though its character
    count clears the 32-character minimum the field itself declares.
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
    try:
        with pytest.raises(TypeError) as caught:
            engine.connect()
        assert "sslmode" in str(caught.value)
    finally:
        engine.dispose()


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
def test_transport_mode_carries_every_driver_defined_mode(mode):
    """Each transport mode the database driver defines round-trips."""
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


# ---------------------------------------------------------------------
# SEC-09: the production charge seam
# ---------------------------------------------------------------------
SUBSCRIPTION_PATH = "/subscriptions/"

# SEC-09: a body SubscriptionCreate accepts, carrying a named plan
CHARGE_BODY = {
    "plan_id": "PLAN-A",
    "payment_method": "paypal",
    "amount": 10.0,
    "start_date": "2030-01-01T00:00:00",
    "end_date": "2030-02-01T00:00:00",
}

# SEC-08: the key set every error handler emits
ENVELOPE_KEYS = {"detail", "error_id", "fields"}

# SEC-09: name fragments of a reference or consumption ledger
LEDGER_NAME_FRAGMENTS = ("reference", "consum", "claim")


def _workflow_step(name):
    """Return the lines belonging to one workflow step.

    The step is its own header plus every line indented under it, so a
    comment written between two steps belongs to neither.
    """
    assert WORKFLOW.is_file(), WORKFLOW
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    header = "- name: {0}".format(name)
    matching = [index for index, line in enumerate(lines) if header in line]
    assert len(matching) == 1, matching

    collected = [lines[matching[0]]]
    for line in lines[matching[0] + 1:]:
        if line.strip() and not line.startswith(STEP_BODY_INDENT):
            break
        collected.append(line)
    return "\n".join(collected)


# CWE-1104: the dependency advisory gate keeps a passing direction
def test_the_dependency_audit_gate_keeps_its_shape():
    """The audit step fails on any advisory outside its register.

    The count is transcribed here, so a suppression added without a
    decision-log entry fails this case. Every identifier is shape-checked
    as well, since an unrecognised one suppresses nothing.
    """
    step = _workflow_step(AUDIT_STEP_NAME)

    for flag in AUDIT_STEP_FLAGS:
        assert flag in step, flag

    # CWE-1104: the audited set is the manifest closure, and the
    # runner-dependent freeze flag is absent from the step
    assert FROZEN_CLOSURE_COMMAND in step
    assert RUNNER_DEPENDENT_FREEZE_FLAG not in step

    suppressed = re.findall(r"--ignore-vuln\s+(\S+)", step)
    assert len(suppressed) == EXPECTED_SUPPRESSION_COUNT, suppressed
    assert len(set(suppressed)) == EXPECTED_SUPPRESSION_COUNT, suppressed
    for identifier in suppressed:
        assert ADVISORY_IDENTIFIER.fullmatch(identifier), identifier


# Rule 1: every suppression carries a justified entry in the register
def test_every_suppressed_advisory_is_justified_in_the_decision_log():
    """No advisory is suppressed without a register entry, and none spare.

    Suppressing an advisory is accepting a risk, and an acceptance with
    no recorded reachability assessment and no review trigger is how a
    temporary exception becomes permanent. The register and the gate are
    compared in both directions, so neither can move without the other:
    an identifier added to the workflow alone fails here, and an entry
    left in the register after its suppression is dropped fails here too.
    """
    assert DECISION_LOG.is_file(), DECISION_LOG
    log = DECISION_LOG.read_text(encoding="utf-8")

    suppressed = set(
        re.findall(r"--ignore-vuln\s+(\S+)", _workflow_step(AUDIT_STEP_NAME))
    )
    registered = {
        row[1]
        for row in re.findall(
            r"^\|\s*(\d+)\s*\|[^|]*\|\s*`(" + ADVISORY_IDENTIFIER.pattern
            + r")`\s*\|",
            log,
            re.MULTILINE,
        )
    }

    assert registered == suppressed, sorted(
        registered.symmetric_difference(suppressed)
    )

    # the register states the shared review trigger it accepts them under
    assert REVIEW_TRIGGER in log


def _credential_scan_command():
    """Return the one workflow line that runs the credential scan."""
    assert WORKFLOW.is_file(), WORKFLOW
    source = WORKFLOW.read_text(encoding="utf-8")
    running = [line for line in source.splitlines() if "git grep" in line]
    assert len(running) == 1, running
    return running[0]


def _credential_scan_pattern():
    """Return the compiled pattern the workflow scans tracked files with."""
    quoted = re.findall(r'-E\s+"([^"]+)"', _credential_scan_command())
    assert len(quoted) == 1, quoted
    return re.compile(quoted[0])


def _tracked_files():
    """Return every path the repository tracks."""
    listed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=str(REPOSITORY_ROOT),
        stdout=subprocess.PIPE,
        check=True,
    )
    return [
        REPOSITORY_ROOT / name
        for name in listed.stdout.decode("utf-8").split("\0")
        if name
    ]


# SEC-01/SEC-12: the credential scan detects each shape it claims to
@pytest.mark.parametrize("line", CREDENTIAL_POSITIVE_CONTROLS)
def test_the_credential_scan_detects_each_credential_shape(line):
    """Each credential shape the scan names is matched by it.

    The pattern under test is read out of the workflow, not copied here.
    """
    assert _credential_scan_pattern().search(line), line


# SEC-12: a documented placeholder is not a credential
@pytest.mark.parametrize("line", CREDENTIAL_NEGATIVE_CONTROLS)
def test_the_credential_scan_passes_over_documented_placeholders(line):
    """A template line naming a variable without a value is not matched.

    Each control below is a line the value-free template carries.
    """
    assert not _credential_scan_pattern().search(line), line


def test_the_credential_scan_matches_no_part_of_its_own_source():
    """The scan does not match the line that declares it.

    Every branch of the pattern is split by a one-character bracket
    expression, so it matches the same text without matching itself.
    """
    command = _credential_scan_command()
    pattern = _credential_scan_pattern()

    assert not pattern.search(command), command

    # no path is excluded, so every tracked file is scanned
    assert EXCLUSION_PATHSPEC not in command
    for path in FORMERLY_EXCLUDED_PATHS:
        assert path not in command


def test_the_credential_scan_reports_nothing_across_tracked_content():
    """No tracked file carries a credential the scan detects.

    This is the gate's passing direction, executed over the same content
    the workflow reads: every tracked file, none excluded. A document or
    a workflow added later is covered without editing this case.
    """
    pattern = _credential_scan_pattern()
    reported = []

    for path in _tracked_files():
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            # the workflow passes -I, which skips binary content likewise
            continue
        for number, line in enumerate(content.splitlines(), 1):
            if pattern.search(line):
                reported.append(
                    "{0}:{1}".format(path.relative_to(REPOSITORY_ROOT), number)
                )

    assert not reported, reported


def _hcl_block(source, header):
    """Return the body of the one block whose header is ``header``."""
    assert source.count(header) == 1, header
    opened = source.index("{", source.index(header))
    depth = 0
    index = opened
    while index < len(source):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opened + 1:index]
        index += 1
    raise AssertionError("unterminated block: {0}".format(header))


def _hcl_argument(body, name):
    """Return the value one argument is assigned inside a block body."""
    assigned = re.compile(
        r"^\s*" + re.escape(name) + r"\s*=\s*(\S.*?)\s*$", re.MULTILINE
    )
    found = assigned.findall(body)
    assert len(found) == 1, (name, found)
    return found[0]


def _terraform_resource(kind, name):
    """Return the body of one declared infrastructure resource."""
    assert TERRAFORM_MAIN.is_file(), TERRAFORM_MAIN
    source = TERRAFORM_MAIN.read_text(encoding="utf-8")
    return _hcl_block(source, 'resource "{0}" "{1}"'.format(kind, name))


def _terraform_variable(name):
    """Return the body of one declared input variable."""
    assert TERRAFORM_VARIABLES.is_file(), TERRAFORM_VARIABLES
    source = TERRAFORM_VARIABLES.read_text(encoding="utf-8")
    return _hcl_block(source, 'variable "{0}"'.format(name))


# SEC-10: the server half of transport encryption lives in infrastructure
def test_the_database_instance_refuses_unencrypted_connections():
    """The Cloud SQL instance declares encrypted-only transport.

    AAP 0.5.10 requires both ends. Every other transport case inspects the
    client half; this one reads the server half, which exists only as a
    declaration no runtime case can reach.
    """
    instance = _terraform_resource(*CLOUD_SQL_INSTANCE)
    ip_configuration = _hcl_block(
        _hcl_block(instance, "settings"), "ip_configuration"
    )

    assert _hcl_argument(ip_configuration, "ssl_mode") == QUOTED_SSL_MODE

    # AAP 0.5.10: the superseded argument is deprecated and unused, so a
    # configuration relying on it would not enforce anything
    assert DEPRECATED_SSL_ARGUMENT not in instance

    # the gated instance is the PostgreSQL one the application connects to
    assert _hcl_argument(
        instance, "database_version"
    ) == QUOTED_DATABASE_VERSION


# SEC-11: the application role is separate and carries no literal secret
def test_the_application_database_role_carries_no_literal_credential():
    """The application role is declared with its password from a variable.

    SEC-11 separates the application account from the instance admin
    account. Every identifying argument arrives from an input variable, so
    no credential and no role name sits in a tracked file. SEC-12 carries
    the password through the write-only argument, so the value reaches
    neither state nor a plan file, and the variable is sensitive and
    ephemeral with no default.
    """
    role = _terraform_resource(*CLOUD_SQL_USER)

    assert _hcl_argument(role, "name") == APP_ROLE_NAME_REFERENCE
    password = _hcl_argument(role, APP_ROLE_PASSWORD_ARGUMENT)
    assert password == APP_ROLE_PASSWORD_REFERENCE

    # SEC-12: the state-persisting argument is absent, so no apply writes
    # the password into the state file
    assert STATE_PERSISTING_PASSWORD_ARGUMENT not in role

    # SEC-12: without the counter a rotated password is never reapplied,
    # which would leave the account on the value it was created with
    assert _hcl_argument(
        role, APP_ROLE_PASSWORD_VERSION_ARGUMENT
    ) == "var.{0}".format(APP_ROLE_PASSWORD_VERSION_VARIABLE)

    # a quoted value in either argument would be a credential in the file
    assert '"' not in password
    assert '"' not in _hcl_argument(role, "name")

    # the role attaches to the instance the case above gates
    assert _hcl_argument(role, "instance") == "{0}.{1}.name".format(
        *CLOUD_SQL_INSTANCE
    )

    password_variable = _terraform_variable(APP_ROLE_PASSWORD_VARIABLE)
    assert _hcl_argument(password_variable, "sensitive") == "true"
    assert _hcl_argument(password_variable, "type") == "string"
    # SEC-12: an ephemeral value is held for the run only
    assert _hcl_argument(password_variable, "ephemeral") == "true"
    # a default would put a password in the file the variable exists to
    # keep it out of
    assert "default" not in password_variable

    name_variable = _terraform_variable(APP_ROLE_NAME_VARIABLE)
    assert _hcl_argument(name_variable, "type") == "string"


# SEC-11: the declaration a default apply can satisfy, and the residual it
# leaves for the documented out-of-band statements
def test_the_cloud_application_account_is_creatable_and_its_residual_stated():
    """The declaration assigns no role, and SECURITY.md carries the grants.

    A role assignment names a role. Nothing in this repository creates one
    or grants it anything, so an assignment leaves a default apply unable to
    create the account at all. Cloud SQL also grants an elevated role to
    every built-in user it creates, and this provider carries no grant or
    revoke resource, so the restriction has to arrive out of band. This case
    fails if the assignment returns, if the withdrawn variable returns, if a
    referenced variable stops being read, or if the document stops carrying
    any statement the account needs.
    """
    main_source = TERRAFORM_MAIN.read_text(encoding="utf-8")
    variables_source = TERRAFORM_VARIABLES.read_text(encoding="utf-8")
    role = _terraform_resource(*CLOUD_SQL_USER)

    assert ROLE_ASSIGNMENT_ARGUMENT not in role
    assert WITHDRAWN_ROLE_VARIABLE not in main_source
    assert WITHDRAWN_ROLE_VARIABLE not in variables_source

    # every variable this work declared is read by the declaration
    for name in REFERENCED_ROLE_VARIABLES:
        assert 'variable "{0}"'.format(name) in variables_source, name
        assert "var.{0}".format(name) in main_source, name

    assert SECURITY_DOCUMENT.is_file(), SECURITY_DOCUMENT
    document = SECURITY_DOCUMENT.read_text(encoding="utf-8")

    # the residual is named, not implied
    assert CLOUD_AUTOMATIC_ROLE in document
    for statement in CLOUD_PRIVILEGE_STATEMENTS:
        assert statement in document, statement


def _provisioning_source():
    """Return the developer provisioning script as text."""
    assert PROVISIONING_SCRIPT.is_file(), PROVISIONING_SCRIPT
    return PROVISIONING_SCRIPT.read_text(encoding="utf-8")


def _shell_function(name):
    """Return the body of one function the provisioning script defines."""
    source = _provisioning_source()
    header = "\n{0}() {{\n".format(name)
    assert source.count(header) == 1, name
    body = source[source.index(header) + len(header):]
    closed = body.index("\n}\n")
    return body[:closed]


def _provisioning_statements():
    """Return the SQL statements the provisioning script sends to psql.

    The batch is a quoted here-document, so the shell performs no
    expansion on it and the tracked bytes are the statements the server
    receives. Each statement is returned on one line, as shipped.
    """
    body = _shell_function("init_database")
    opened = "cat <<'SQL'\n"
    assert body.count(opened) == 1, opened
    batch = body[body.index(opened) + len(opened):]
    closed = batch.index("\nSQL\n")
    return [line for line in batch[:closed].splitlines() if line.strip()]


# SEC-11: the application role reaches table data and nothing else
def test_the_application_role_is_granted_data_access_only():
    """Every privilege the application role receives is a data operation.

    SEC-11 replaces one account holding every privilege on the database
    with two roles. The granted set is compared whole, so a privilege
    added to the application role later fails this case. Nothing here
    runs the script; it creates cluster roles, so the shipped statements
    are read.
    """
    statements = _provisioning_statements()
    granted = [line for line in statements if "app_user" in line]

    expected = set(APP_ROLE_GRANTS)
    expected.update(APP_ROLE_DEFAULT_PRIVILEGES)
    expected.add(APP_ROLE_CREATION)

    # the creation statement carries a psql variable rather than a value,
    # so it is compared by its privilege-bearing prefix
    normalised = {
        APP_ROLE_CREATION if line.startswith(APP_ROLE_CREATION) else line
        for line in granted
    }
    assert normalised == expected, sorted(normalised.symmetric_difference(
        expected
    ))


# SEC-11: the default grant on schema public would return the withheld DDL
def test_the_default_public_schema_privilege_is_revoked():
    """PUBLIC loses CREATE on schema public, and the owner keeps it.

    A PostgreSQL 13 database grants CREATE on schema public to PUBLIC,
    which every role holds. Granting the application role no DDL is
    therefore not enough on its own: without this revoke the role creates
    tables through the default grant. Revoking without granting the owner
    explicitly would leave nobody able to create, so both statements are
    required and the owner grant is the only CREATE on the schema.
    """
    statements = _provisioning_statements()

    assert REVOKED_FROM_PUBLIC in statements
    assert OWNER_ROLE_GRANT in statements

    creating = [
        line
        for line in statements
        if "SCHEMA public" in line and line.startswith("GRANT")
        and "CREATE" in line
    ]
    assert creating == [OWNER_ROLE_GRANT], creating


# SEC-11: no provisioning statement confers a broad privilege
@pytest.mark.parametrize("privilege", FORBIDDEN_PROVISIONING_SQL)
def test_the_provisioning_statements_confer_no_broad_privilege(privilege):
    """No statement grants the privileges SEC-11 exists to remove.

    The account this script used to create held every privilege on the
    database. Each name below either restores that account or gives the
    application role cluster-level authority, so each is checked against
    the shipped statements case-insensitively.
    """
    batch = "\n".join(_provisioning_statements()).upper()

    assert privilege.upper() not in batch, privilege


# SEC-01/SEC-11: a role password in a tracked file is a disclosed password
def test_the_provisioning_statements_carry_no_password_literal():
    """Both role passwords reach the server as psql variables.

    A generated value is only unexposed while it stays out of the file
    that creates it. Each creation statement names a psql variable, which
    the script assigns on standard input, so the tracked bytes carry no
    password and the repository credential scan has nothing to report
    here.
    """
    statements = _provisioning_statements()
    batch = "\n".join(statements)

    assert SQL_PASSWORD_LITERAL.search(batch) is None, batch

    # each role is created with a variable reference, not a value
    creating = [line for line in statements if line.startswith("CREATE ROLE")]
    assert len(creating) == 2, creating
    for line in creating:
        assert ":'" in line, line


# SEC-11: an argument list is readable by any local process (CWE-214)
def test_the_role_passwords_never_enter_a_process_argument_list():
    """The grant batch and its variable assignments arrive on stdin.

    Passing either value with psql's own variable flag would place it in
    an argument list, which any local process can read. The script writes
    both assignments through the printf builtin, which runs inside the
    shell and starts no process, and pipes them into psql ahead of the
    quoted batch. The pipeline status of psql itself is checked, because
    a pipeline reports only its last command by default and the batch is
    the command that can fail.
    """
    body = _shell_function("init_database")

    assert PSQL_INVOCATION in body
    assert GRANT_BATCH_STATUS in body

    for form in ARGUMENT_LIST_PASSWORD_FORMS:
        assert form not in body, form

    # both assignments are shell builtins reading from the script itself
    assigning = [
        line for line in body.splitlines() if line.strip().startswith("printf")
    ]
    assert len(assigning) == 2, assigning
    for line in assigning:
        assert "set owner_pw" in line or "set app_pw" in line, line

    # neither value is expanded on the line that invokes psql
    invocation = [
        line for line in body.splitlines() if PSQL_INVOCATION in line
    ]
    assert len(invocation) == 1, invocation
    assert "DB_OWNER_" not in invocation[0]
    assert "DB_APP_" not in invocation[0]


# SEC-01: the generated secret file is never readable by another user
@pytest.mark.parametrize("guard", SECRET_FILE_GUARDS)
def test_the_generated_secret_file_is_installed_under_a_restrictive_mask(
    guard,
):
    """Each guard on the generated secret file is present as shipped.

    Writing the values straight to the destination leaves a window in
    which the file exists under the invoking user's default mask, and it
    writes through any symlink already at that path. The script creates
    an owner-only temporary file in the same directory, restricts it,
    then renames it over the destination, which closes both.
    """
    assert guard in _shell_function("configure_env_vars"), guard


def test_the_secrets_are_never_written_straight_to_the_destination():
    """The here-document writes to the temporary file, not to .env.

    This is the shape the guards above replace, so its absence is what
    proves they are in the path rather than beside it.
    """
    body = _shell_function("configure_env_vars")

    assert DIRECT_SECRET_WRITE not in body
    assert 'cat << EOF > "$env_tmp"' in body


# SEC-11: schema objects are owned by the role that holds DDL
def test_the_schema_is_created_by_the_owner_role():
    """The owner role creates the tables, over an environment credential.

    The application role holds no DDL, so something else has to create
    the schema. The owner bootstrap does, and its credential travels in
    the environment of the interpreter it starts rather than in an
    argument list. Its imports are checked before the first database
    object exists, so a missing driver reports itself rather than leaving
    a database with roles and no tables.
    """
    body = _shell_function(OWNER_BOOTSTRAP)

    assert OWNER_CREDENTIAL_VARIABLE + "=" in body
    assert 'os.environ["{0}"]'.format(OWNER_CREDENTIAL_VARIABLE) in body
    assert OWNER_SCHEMA_CREATION in body

    initialising = _shell_function("init_database")
    assert "if ! {0}; then".format(OWNER_BOOTSTRAP) in initialising
    assert "if ! {0}; then".format(
        OWNER_BOOTSTRAP_PREREQUISITES
    ) in initialising

    # the prerequisite check runs before any database object is created
    checked = initialising.index(OWNER_BOOTSTRAP_PREREQUISITES)
    created = initialising.index("createdb dbname")
    assert checked < created, (checked, created)

    prerequisites = _shell_function(OWNER_BOOTSTRAP_PREREQUISITES)
    for module in ("sqlalchemy", "psycopg2", "backend.app.db.models"):
        assert 'importlib.import_module("{0}")'.format(module) in prerequisites


# SEC-01/SEC-11: a failed step stops the run instead of continuing (CWE-252)
def test_every_provisioning_step_stops_the_run_on_failure():
    """Each step runs in order and aborts the run when it fails.

    Order is load-bearing twice over. The interpreter is prepared and
    populated before the credential step, which needs it to generate the
    values, and the credentials exist before the roles that carry them.
    Without the failure controls a broken step would leave the run
    provisioning roles against credentials it never wrote.
    """
    body = _shell_function("main")
    positions = []

    for step in PROVISIONING_ORDER:
        assert body.count(step) == 1, step
        positions.append(body.index(step))

    assert positions == sorted(positions), positions


# SEC-01/SEC-11: a failed command aborts its step (CWE-252)
@pytest.mark.parametrize("command", GUARDED_COMMANDS)
def test_each_provisioning_command_aborts_its_step_on_failure(command):
    """Each command that can fail is tested, and a failure returns.

    Ordering alone does not make the sequence safe: an unguarded command
    lets the run continue past a step that did nothing, which is how a
    database ends up with roles and no tables, or a role created against
    a credential no file records. Every command below is wrapped in the
    same shape, and the guard returns rather than reporting success.
    """
    source = _provisioning_source()
    guard = "if ! {0}; then".format(command)

    assert source.count(guard) == 1, guard

    body = source[source.index(guard) + len(guard):]
    assert "return 1" in body[:body.index("\n    fi")], command


# SEC-01/SEC-11: no guard reports a problem and then carries on (CWE-252)
def test_no_provisioning_guard_continues_past_a_failure():
    """Every conditional guard in the script ends the run.

    The case above names the commands that exist today. This one holds
    for a guard added later: whatever the script tests, the branch it
    takes on failure returns or exits rather than printing a message and
    continuing. A guard that only prints is how the script reported
    success after provisioning nothing.
    """
    lines = _provisioning_source().splitlines()
    continuing = []

    for index, line in enumerate(lines):
        stripped = line.strip()
        if not (stripped.startswith("if ! ") or stripped.startswith("if [")):
            continue
        branch = []
        for following in lines[index + 1:]:
            if following.strip() == "fi":
                break
            branch.append(following.strip())
        if not any(statement in FAILURE_CONTROLS for statement in branch):
            continuing.append("{0}:{1}".format(index + 1, stripped))

    assert not continuing, continuing


# SEC-11: the manifest installed is the tracked one, not a relative guess
def test_the_backend_manifest_is_resolved_from_the_script_location():
    """The install targets the tracked manifest by absolute path.

    A path relative to the working directory installs nothing when the
    operator runs the script from anywhere but the repository root, and a
    silent no-install leaves the owner bootstrap without a driver. The
    script resolves its own location first, so the manifest it installs
    is the tracked one wherever it is invoked from.
    """
    body = _shell_function("install_dependencies")

    assert SCRIPT_RELATIVE_ROOT in body
    assert BACKEND_MANIFEST in body

    # the manifest the install names is the one the repository tracks
    assert (REPOSITORY_ROOT / "backend" / "requirements.txt").is_file()

    # the interpreter is the one the virtual environment put on the path
    assert "python3 -m pip install" in body


def test_the_provisioning_script_parses():
    """The script is syntactically valid for the shell that runs it.

    Every case above reads the script as text, which cannot tell a valid
    guard from one inside an unclosed quotation. The shell's own parser
    can, and it reads the file without running any statement in it.
    """
    parsed = subprocess.run(
        ["bash", "-n", str(PROVISIONING_SCRIPT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    assert parsed.returncode == 0, parsed.stdout.decode("utf-8")


# SEC-09: identities the transaction-authorization cases bind against
PAYER_IDENTITY = "PAYER-1"
BOUND_PLAN = "PLAN-A"
CHARGE_TOTAL = 10.00


def charge(payment_method, amount):
    """Call the charge seam exactly as the subscription route calls it."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            paypal_service.process_payment(payment_method, amount)
        )
    finally:
        loop.close()


def bearer(access_token):
    """Return the request header that carries one access token."""
    return {"Authorization": "Bearer " + access_token}


# SEC-09: the seam signature is the one the route calls (CWE-863)
def test_the_charge_seam_matches_the_call_the_route_makes():
    """The seam takes the two positional arguments the route passes.

    The route awaits ``process_payment(payment_method, amount)`` and
    supplies nothing else. A keyword-only parameter or a third parameter
    makes every production call raise.
    """
    signature = inspect.signature(paypal_service.process_payment)
    parameters = list(signature.parameters.values())

    positional = [
        parameter.name
        for parameter in parameters
        if parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    ]
    assert positional == ["payment_method", "amount"]
    assert len(parameters) == 2
    assert inspect.iscoroutinefunction(paypal_service.process_payment)


# SEC-09: no client-supplied plan or price authorizes a charge (CWE-863)
@pytest.mark.parametrize(
    "payment_method, amount",
    (
        ("paypal", 10.0),
        ("paypal", 0.01),
        ("paypal", 1000000.0),
        ("credit_card", 10.0),
        ("", 10.0),
    ),
    ids=(
        "declared-total",
        "smallest-total",
        "large-total",
        "other-method",
        "empty-method",
    ),
)
def test_the_charge_seam_refuses_every_attempt(payment_method, amount):
    """No argument pair the route can build authorizes a charge."""
    assert charge(payment_method, amount) is False


# SEC-09: a refused charge issues no provider call
def test_the_charge_seam_reaches_no_provider(monkeypatch):
    """The seam performs no provider configuration and no lookup."""
    reached = []

    def record(name):
        def hook(*arguments):
            reached.append(name)
        return hook

    monkeypatch.setattr(paypalrestsdk, "configure", record("configure"))
    monkeypatch.setattr(
        paypalrestsdk.Payment, "find", staticmethod(record("payment"))
    )
    monkeypatch.setattr(
        paypalrestsdk.BillingAgreement,
        "find",
        staticmethod(record("agreement")),
    )

    assert charge("paypal", 10.0) is False
    assert reached == []


# SEC-09: the service holds no local authorization ledger (CWE-367)
def test_the_payment_service_keeps_no_reference_ledger():
    """No module attribute records a claimed or consumed reference.

    A local ledger spends a reference before the caller commits its row,
    and the caller holds no way to release one.
    """
    for name in dir(paypal_service):
        lowered = name.lower()
        for fragment in LEDGER_NAME_FRAGMENTS:
            assert fragment not in lowered, name


# SEC-09: the module grew no payment flow beyond the substitution
def test_the_payment_service_declares_only_the_three_documented_callables():
    """The service module exposes create, execute and the charge seam.

    AAP 0.5.13 scopes this module to the environment substitution, the
    typing import and this wrapper. A fourth public callable would mean a
    payment flow grew here that no caller asked for.
    """
    public = sorted(
        name
        for name, value in vars(paypal_service).items()
        if not name.startswith("_") and callable(value)
        and getattr(value, "__module__", None) == paypal_service.__name__
    )

    assert public == ["create_payment", "execute_payment", "process_payment"]


# SEC-09: the route refuses the charge and writes no row
def test_the_subscription_route_refuses_the_charge(
    client, register_user, db_session
):
    """A subscription request is refused with the uniform envelope."""
    account = register_user()

    response = client.post(
        SUBSCRIPTION_PATH,
        json=CHARGE_BODY,
        headers=bearer(account["access_token"]),
    )

    assert response.status_code == 400, response.text
    body = response.json()
    assert set(body) == ENVELOPE_KEYS
    # SEC-08: the refusal names no provider and no internal detail
    assert body["detail"] == HTTPStatus(400).phrase
    assert db_session.query(SubscriptionModel).count() == 0


# SEC-09: the refusal is reached before any provider call
def test_the_subscription_route_reaches_no_provider(
    client, register_user, monkeypatch
):
    """The refused route issues no provider configuration."""
    reached = []
    monkeypatch.setattr(
        paypalrestsdk,
        "configure",
        lambda configuration: reached.append("configure"),
    )
    account = register_user()

    response = client.post(
        SUBSCRIPTION_PATH,
        json=CHARGE_BODY,
        headers=bearer(account["access_token"]),
    )

    assert response.status_code == 400, response.text
    assert reached == []


# SEC-10: a probe engine holds a connection pool until it is disposed
def test_probe_engines_are_registered_for_disposal():
    """Loading the database module registers its engine for disposal.

    An engine left undisposed keeps its pool, and the parametrized cases
    above build one per case. The registry is what the autouse fixture
    drains, so an unregistered engine would leak silently.
    """
    before = len(_PROBE_ENGINES)
    module = load_database_module(POSTGRES_URL, "require")

    assert len(_PROBE_ENGINES) == before + 1
    assert _PROBE_ENGINES[-1] is module.engine

    # the application engine is never registered, so it is never disposed
    assert all(engine is not database.engine for engine in _PROBE_ENGINES)


def test_disposing_a_probe_engine_releases_its_pool():
    """A disposed probe engine reports an empty pool.

    The pool is read after disposal, so the fixture's cleanup is shown to
    have an effect.
    """
    module = load_database_module(SQLITE_URL, "require")
    engine = module.engine
    with engine.connect() as connection:
        assert connection.exec_driver_sql("select 1").scalar() == 1

    pooled_before = engine.pool
    engine.dispose()

    # dispose() closes the pooled connections and recreates the pool, so
    # the replacement is a different object holding nothing
    assert engine.pool is not pooled_before


# ---------------------------------------------------------------------
# SEC-09: the provider client is held above the level its records use
# ---------------------------------------------------------------------
PROVIDER_LOGGER_NAME = "paypalrestsdk"


def test_the_provider_logger_withholds_records_below_warning():
    """The provider library is held above the level its records use.

    The client records the request URL at INFO, and that URL carries the
    caller-supplied reference; it records the authorization header, the
    request body and the response body at DEBUG. Capping the library
    logger is what keeps those out of the diagnostic channel (CWE-532).
    """
    assert paypal_service.PROVIDER_LOG_LEVEL == logging.WARNING
    provider_logger = logging.getLogger(PROVIDER_LOGGER_NAME)
    assert provider_logger.level == paypal_service.PROVIDER_LOG_LEVEL

    # SEC-09: the child logger the SDK actually writes to inherits the cap
    api_logger = logging.getLogger("{0}.api".format(PROVIDER_LOGGER_NAME))
    assert api_logger.level == logging.NOTSET
    assert api_logger.getEffectiveLevel() == logging.WARNING
    assert not api_logger.isEnabledFor(logging.INFO)
    assert not api_logger.isEnabledFor(logging.DEBUG)


# SEC-09: the route awaits the service seam, not a local stand-in
def test_the_subscription_route_awaits_the_service_seam():
    """The subscription route is bound to the module-level charge seam."""
    assert subscription_route.process_payment is paypal_service.process_payment


# ---------------------------------------------------------------------
# SEC-01/SEC-12: how the provisioning script writes its credentials
# ---------------------------------------------------------------------
# SEC-01: the alphabet the generated values are constrained to
CREDENTIAL_ALPHABET = re.compile(r"\A[A-Za-z0-9_-]+\Z")

# SEC-01: a permissive creation mask, so each case measures the script's
# own guarantee (CWE-732)
PERMISSIVE_UMASK = "022"

# SEC-01: what a planted name standing at .env holds before the run
PLANTED_TARGET_CONTENT = "zzz-planted-standing-name-8901\n"

# SEC-11: no-op stands-in for the two bootstrap helpers that reach a live
# cluster, so the psql batch between them executes as shipped
PROVISIONING_BOOTSTRAP_STUBS = (
    "check_schema_prerequisites() { return 0; }",
    "create_schema_as_owner() { return 0; }",
)


def _run_provisioning(work_dir, functions, expect_status=0):
    """Run named functions from the real provisioning script.

    The script is sourced with its bare ``main`` invocation removed, and
    only ``psql`` and ``createdb`` are replaced; each replacement records
    the argument vector and the standard input it received.
    """
    stub_dir = work_dir / "stub-bin"
    capture_dir = work_dir / "capture"
    stub_dir.mkdir()
    capture_dir.mkdir()

    (stub_dir / "psql").write_text(
        "#!/bin/bash\n"
        'printf "%s\\n" "$@" > "$CAPTURE_DIR/psql.argv"\n'
        'cat > "$CAPTURE_DIR/psql.stdin"\n'
    )
    (stub_dir / "createdb").write_text("#!/bin/bash\nexit 0\n")
    for name in ("psql", "createdb"):
        (stub_dir / name).chmod(0o755)

    program = "umask {0}\nsource <(grep -v '^main$' {1})\n{2}\n".format(
        PERMISSIVE_UMASK,
        shlex.quote(str(PROVISIONING_SCRIPT)),
        "\n".join(functions),
    )
    environment = dict(os.environ)
    environment["PATH"] = "{0}{1}{2}".format(
        stub_dir, os.pathsep, environment.get("PATH", "")
    )
    environment["CAPTURE_DIR"] = str(capture_dir)

    completed = subprocess.run(
        ["bash", "-c", program],
        cwd=str(work_dir),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
    )
    assert completed.returncode == expect_status, completed.stdout.decode()
    return capture_dir, completed.stdout.decode()


def _generated_values(work_dir):
    """Return the values the script wrote into its environment file."""
    written = (work_dir / ".env").read_text()
    values = {}
    for line in written.splitlines():
        if "=" in line:
            name, _, value = line.partition("=")
            values[name] = value
    return values


def _meta_command_values(captured_stdin):
    """Return the values set by the psql meta-commands on standard input.

    Each value is shipped as a quoted SQL literal, so the quoting is
    asserted here and stripped before the value is compared.
    """
    values = {}
    for line in captured_stdin.splitlines():
        if line.startswith("\\set "):
            _, name, quoted = line.split(" ", 2)
            assert quoted.startswith("'") and quoted.endswith("'"), quoted
            values[name] = quoted[1:-1]
    return values


# SEC-01/SEC-12: the generated secret file is never world-readable (CWE-732)
def test_the_generated_secret_file_is_owner_only(tmp_path):
    """The file carrying the generated credentials is owner-only."""
    _run_provisioning(tmp_path, ["configure_env_vars"])
    written = tmp_path / ".env"

    assert written.is_file()
    mode = stat.S_IMODE(written.stat().st_mode)
    # SEC-01: created under a restrictive mask and renamed into place, so no
    # interval exists in which the mode is permissive
    assert mode == 0o600, oct(mode)

    values = _generated_values(tmp_path)
    assert len(values["SECRET_KEY"]) >= 32
    assert "app_user:" in values["DATABASE_URL"]

    # SEC-01: the temporary name is removed, and it is covered by .gitignore
    assert list(tmp_path.glob(".env.tmp.*")) == []


# SEC-01/SEC-12: a planted symlink at .env is neither followed nor
# replaced; the run refuses instead (CWE-59, CWE-367)
def test_the_generated_secret_file_refuses_a_planted_symlink(tmp_path):
    """A symlink standing at .env stops the run before a key exists.

    The link is neither followed nor replaced: a name the developer did
    not create is never the destination of a freshly generated
    credential, and nothing is written anywhere.
    """
    target = tmp_path / "victim.txt"
    target.write_text(PLANTED_TARGET_CONTENT)
    target.chmod(0o644)
    (tmp_path / ".env").symlink_to(target.name)

    _, output = _run_provisioning(
        tmp_path, ["configure_env_vars"], expect_status=1
    )
    assert "already present" in output, output

    # SEC-01: the link is left standing and its target is untouched
    assert (tmp_path / ".env").is_symlink()
    assert target.read_text() == PLANTED_TARGET_CONTENT
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert "SECRET_KEY" not in target.read_text()

    # SEC-01: no temporary secret file is left behind either
    assert list(tmp_path.glob(".env.tmp.*")) == []


# SEC-01/SEC-12: a planted hard link receives no secret (CWE-59, CWE-367)
def test_the_generated_secret_file_refuses_a_planted_hard_link(tmp_path):
    """A second name for .env keeps its content and gains no secret.

    Redirecting into an existing name truncates that inode in place, so
    any other name for it - a link made earlier, while the mode was still
    permissive - would receive the secret. The pre-existence guard stops
    the run before a credential is generated, so neither name changes.
    """
    standing = tmp_path / ".env"
    standing.write_text(PLANTED_TARGET_CONTENT)
    standing.chmod(0o644)
    planted = tmp_path / "planted_link.txt"
    os.link(str(standing), str(planted))
    assert planted.stat().st_ino == standing.stat().st_ino

    _, output = _run_provisioning(
        tmp_path, ["configure_env_vars"], expect_status=1
    )
    assert "already present" in output, output

    # SEC-01: both names still describe the planted inode, unchanged
    assert standing.stat().st_ino == planted.stat().st_ino
    assert standing.read_text() == PLANTED_TARGET_CONTENT
    assert planted.read_text() == PLANTED_TARGET_CONTENT
    assert "SECRET_KEY" not in planted.read_text()
    assert stat.S_IMODE(planted.stat().st_mode) == 0o644
    assert list(tmp_path.glob(".env.tmp.*")) == []


# SEC-01/SEC-12: no role password reaches the argument vector (CWE-214)
def test_no_role_password_reaches_the_process_arguments(tmp_path):
    """Both role passwords travel on standard input, not in argv."""
    capture_dir, _output = _run_provisioning(
        tmp_path,
        ["configure_env_vars"]
        + list(PROVISIONING_BOOTSTRAP_STUBS)
        + ["init_database"],
    )
    argv = (capture_dir / "psql.argv").read_text()
    captured_stdin = (capture_dir / "psql.stdin").read_text()
    supplied = _meta_command_values(captured_stdin)

    # SEC-01: the arguments carry the failure mode and the database only
    assert argv.split() == ["-v", "ON_ERROR_STOP=1", "-d", "dbname"]
    assert set(supplied) == {"owner_pw", "app_pw"}

    for name, value in supplied.items():
        assert value, name
        # SEC-01: an argument vector is readable by any local user
        assert value not in argv, name

    # SEC-01: the value the application itself will use is the same one, and
    # it reaches neither the arguments nor any other channel
    application_url = _generated_values(tmp_path)["DATABASE_URL"]
    assert supplied["app_pw"] in application_url
    assert supplied["app_pw"] not in argv

    # SEC-11: the statements still bind the passwords through the variables,
    # so moving the channel changed no privilege
    assert captured_stdin.index("\\set owner_pw") < captured_stdin.index(
        "CREATE ROLE app_owner"
    )
    assert "PASSWORD :'owner_pw'" in captured_stdin
    assert "PASSWORD :'app_pw'" in captured_stdin
    assert "GRANT ALL" not in captured_stdin


# SEC-01: a generated value cannot end a meta-command and begin another
def test_the_generated_credentials_use_a_constrained_alphabet(tmp_path):
    """Every generated value stays inside the guarded alphabet."""
    capture_dir, _output = _run_provisioning(
        tmp_path,
        ["configure_env_vars"]
        + list(PROVISIONING_BOOTSTRAP_STUBS)
        + ["init_database"],
    )
    supplied = _meta_command_values(
        (capture_dir / "psql.stdin").read_text()
    )
    values = _generated_values(tmp_path)

    for value in list(supplied.values()) + [values["SECRET_KEY"]]:
        assert CREDENTIAL_ALPHABET.match(value), value
        assert "\n" not in value
        assert "'" not in value

    # SEC-12: and the key clears the floor of every algorithm Settings
    # accepts, not only the configured one
    assert len(values["SECRET_KEY"]) >= max(HMAC_KEY_MIN_BYTES.values())


# ---------------------------------------------------------------------
# SEC-12: docker build-context exclusions
# ---------------------------------------------------------------------
# SEC-12: both images copy their whole context, so the context-local
# ignore file is what keeps a local secret out of an image layer
# (CWE-200, CWE-522)
DOCKER_CONTEXTS = {
    ".": REPOSITORY_ROOT / ".dockerignore",
    "backend": REPOSITORY_ROOT / "backend" / ".dockerignore",
    "frontend": REPOSITORY_ROOT / "frontend" / ".dockerignore",
}

DOCKERFILES = (
    REPOSITORY_ROOT / "infrastructure" / "docker" / "Dockerfile.backend",
    REPOSITORY_ROOT / "infrastructure" / "docker" / "Dockerfile.frontend",
)

# SEC-12: one path per class of material that must never enter a layer
EXCLUDED_CONTEXT_PATHS = {
    ".": (
        ".env",
        "backend/.env",
        "frontend/.env",
        ".env.tmp.7f3a91",
        "infrastructure/docker/secrets/google-credentials.json",
        "tls/server.pem",
        "tls/server.key",
        "gcp-credentials.json",
        ".venv/bin/python",
        "backend/venv/bin/python",
        "frontend/node_modules/axios/index.js",
        "backend/app/__pycache__/main.cpython-39.pyc",
        "backend/app/main.pyc",
        "backend/.pytest_cache/CACHEDATA",
        "backend/.coverage",
        "backend/coverage.xml",
        "htmlcov/index.html",
        "frontend/build/index.html",
        "frontend/coverage/lcov.info",
        ".git/config",
    ),
    "backend": (
        ".env",
        ".env.tmp.7f3a91",
        "secrets/google-credentials.json",
        "tls/server.pem",
        "tls/server.key",
        "gcp-credentials.json",
        ".venv/bin/python",
        "venv/bin/python",
        "app/__pycache__/main.cpython-39.pyc",
        "app/main.pyc",
        ".pytest_cache/CACHEDATA",
        ".coverage",
        "coverage.xml",
        "htmlcov/index.html",
        ".git/config",
    ),
    "frontend": (
        ".env",
        ".env.tmp.7f3a91",
        "secrets/google-credentials.json",
        "tls/server.pem",
        "tls/server.key",
        "gcp-credentials.json",
        "node_modules/axios/index.js",
        "build/index.html",
        "coverage/lcov.info",
        ".git/config",
    ),
}

# SEC-12: material each build needs, so an exclusion cannot be widened
# into a broken image
REQUIRED_CONTEXT_PATHS = {
    ".": ("backend/requirements.txt", "frontend/package.json", ".env.example"),
    "backend": ("requirements.txt", "app/main.py", "tests/conftest.py"),
    "frontend": (
        "package.json",
        "package-lock.json",
        "src/index.tsx",
        "src/services/api.ts",
    ),
}


def _dockerignore_patterns(path):
    """Return the ignore patterns one context file declares."""
    assert path.is_file(), path
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _pattern_regex(pattern):
    """Compile one ignore pattern under Docker's documented matching.

    Only the constructs these files use are handled: a leading ``**/``
    or an embedded ``**`` spanning whole path segments, ``*`` and ``?``
    inside one segment, a character class, and a trailing separator
    marking a directory. A directory pattern also matches the paths
    beneath it, which the caller supplies by testing every ancestor.
    """
    directory = pattern.endswith("/")
    segments = pattern.rstrip("/").split("/")
    compiled = ""
    pending_separator = False
    for index, segment in enumerate(segments):
        if pending_separator:
            compiled += "/"
            pending_separator = False
        if segment == "**":
            # a spanning wildcard supplies its own separator, and matches
            # zero segments, so none is added after it
            last = index == len(segments) - 1
            compiled += ".*" if last else "(?:[^/]+/)*"
            continue
        position = 0
        while position < len(segment):
            character = segment[position]
            if character == "*":
                compiled += "[^/]*"
            elif character == "?":
                compiled += "[^/]"
            elif character == "[":
                closing = segment.find("]", position)
                assert closing != -1, pattern
                compiled += segment[position:closing + 1]
                position = closing
            else:
                compiled += re.escape(character)
            position += 1
        pending_separator = True
    return re.compile("(?:{0})$".format(compiled)), directory


def _is_excluded(patterns, candidate):
    """Report whether the ignore patterns exclude one context path."""
    parts = candidate.split("/")
    prefixes = ["/".join(parts[:count + 1]) for count in range(len(parts))]
    excluded = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        expression, _directory = _pattern_regex(pattern.lstrip("!"))
        if any(expression.match(prefix) for prefix in prefixes):
            excluded = not negated
    return excluded


@pytest.mark.parametrize("context", sorted(DOCKER_CONTEXTS))
def test_every_build_context_declares_an_ignore_file(context):
    """Each build context carries its own ignore file."""
    assert DOCKER_CONTEXTS[context].is_file(), DOCKER_CONTEXTS[context]
    assert _dockerignore_patterns(DOCKER_CONTEXTS[context])


@pytest.mark.parametrize("context", sorted(EXCLUDED_CONTEXT_PATHS))
def test_the_build_context_excludes_every_secret_bearing_path(context):
    """No secret, key, credential, dependency or cache path is copied.

    SEC-12 keeps secrets out of version control; an image layer is the
    other place a local secret can escape to, because both Dockerfiles
    copy the whole context.
    """
    patterns = _dockerignore_patterns(DOCKER_CONTEXTS[context])

    for candidate in EXCLUDED_CONTEXT_PATHS[context]:
        assert _is_excluded(patterns, candidate), (context, candidate)


@pytest.mark.parametrize("context", sorted(REQUIRED_CONTEXT_PATHS))
def test_the_build_context_still_carries_what_the_image_needs(context):
    """The exclusions withhold nothing the build depends on."""
    patterns = _dockerignore_patterns(DOCKER_CONTEXTS[context])

    for candidate in REQUIRED_CONTEXT_PATHS[context]:
        assert not _is_excluded(patterns, candidate), (context, candidate)


def test_the_matcher_rejects_a_pattern_that_covers_nothing():
    """The matcher fails a context whose ignore file lost a pattern."""
    weakened = [
        pattern
        for pattern in _dockerignore_patterns(DOCKER_CONTEXTS["backend"])
        if pattern != "**/.env"
    ]

    assert not _is_excluded(weakened, ".env")
    assert _is_excluded(weakened, "secrets/google-credentials.json")


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.name)
def test_each_image_copies_its_context_wholesale(dockerfile):
    """The premise the exclusions rest on is asserted, not assumed.

    An image that copied an explicit allow-list would not need the
    exclusions. Both copy the whole context, so the exclusions are the
    control, and this case fails if that stops being true.
    """
    assert dockerfile.is_file(), dockerfile
    body = dockerfile.read_text(encoding="utf-8")

    assert re.search(r"^COPY \. \.$", body, re.MULTILINE), dockerfile


# ---------------------------------------------------------------------
# SEC-12: the frontend build-variable contract
# ---------------------------------------------------------------------
def _frontend_build_variables():
    """Return every build variable the browser sources read."""
    assert FRONTEND_SOURCE_DIR.is_dir(), FRONTEND_SOURCE_DIR
    found = set()
    for path in sorted(FRONTEND_SOURCE_DIR.rglob("*")):
        if path.suffix in {".ts", ".tsx"} and path.is_file():
            found.update(
                FRONTEND_BUILD_VARIABLE.findall(
                    path.read_text(encoding="utf-8")
                )
            )
    assert found, FRONTEND_SOURCE_DIR
    return found


def test_the_template_documents_every_frontend_build_variable():
    """The template names each build variable the browser code reads.

    SEC-12 requires each variable to be documented by name, and the
    template is the authority an operator is sent to. A build variable it
    omits reaches that operator as a bundle pointing at nothing.
    """
    documented = _assigned_names(_template_sections()[1])

    assert documented == _frontend_build_variables(), documented


def test_no_backend_setting_is_documented_as_a_build_variable():
    """The two contracts stay separate, so neither absorbs the other."""
    backend_half, frontend_half = _template_sections()

    assert not _assigned_names(frontend_half) & set(Settings.__fields__)
    assert not _assigned_names(backend_half) & _frontend_build_variables()


@pytest.mark.parametrize("name", sorted(_frontend_build_variables()))
def test_the_frontend_build_declares_each_variable_it_embeds(name):
    """The image takes each build variable as an argument, not a literal."""
    assert FRONTEND_IMAGE.is_file(), FRONTEND_IMAGE
    body = FRONTEND_IMAGE.read_text(encoding="utf-8")

    argument = body.index("ARG {0}".format(name))
    assigned = body.index("ENV {0}=${0}".format(name))

    # SEC-12: both precede the build, or the substitution misses them
    assert argument < body.index("RUN npm run build")
    assert assigned < body.index("RUN npm run build")


@pytest.mark.parametrize("name", sorted(_frontend_build_variables()))
def test_the_compose_definition_forwards_each_build_variable(name):
    """Compose passes each name to the build with no inline default."""
    assert COMPOSE_DEFINITION.is_file(), COMPOSE_DEFINITION
    body = COMPOSE_DEFINITION.read_text(encoding="utf-8")

    assert "- {0}=${{{0}}}".format(name) in body, name


def test_no_build_variable_is_supplied_only_at_run_time():
    """No build variable is offered to the running container instead.

    A value the bundle needs at build time does nothing in a runtime
    environment block, and offering it there reads as though it works.
    """
    body = COMPOSE_DEFINITION.read_text(encoding="utf-8")
    runtime_lines = [
        line
        for line in body.splitlines()
        if "REACT_APP" in line and "${" not in line and "#" not in line
    ]

    assert runtime_lines == [], runtime_lines
