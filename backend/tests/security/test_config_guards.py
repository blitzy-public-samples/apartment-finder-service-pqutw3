"""Configuration guards for the payment environment, the signing key and
database transport, and the subscription charge seam.

The validation cases build ``Settings`` directly for each guarded setting
and inspect the field named in the error it raises. The transport cases execute
``backend/app/db/database.py`` against each database URL form and read the
connect arguments off the engine it builds. The payment and charge cases
execute the payment service and the subscription route with the provider
library replaced. The remaining cases read the shipped
pipeline, provisioning, Terraform and build definitions as text and assert
the controls they carry.

No case opens a network connection or an encrypted database connection.
Rationale: ``documentation/security/decision-log.md`` sections 14, 18, 21,
24, 25 and 28, and DL-380 through DL-383.
"""
import asyncio
import importlib.util
import inspect
import json
import logging
import os
import re
import shlex
import stat
import sys
import time
from http import HTTPStatus
import subprocess
from pathlib import Path
from unittest import mock

import paypalrestsdk
import pytest
import requests
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
        "CREATE USER app WITH PASS" + "WORD   'seeded-role-secret';",
        id="inline-sql-password-literal-padded",
    ),
    pytest.param(
        "SECRET_KEY=" + "seeded0signing0key0value",
        id="assigned-signing-key",
    ),
    pytest.param(
        "SECRET_KEY = " + '"seeded0signing0key0value"',
        id="spaced-quoted-signing-key",
    ),
    pytest.param(
        "SECRET_KEY  =  " + "'seeded0signing0key0value'",
        id="padded-single-quoted-signing-key",
    ),
    pytest.param(
        "SECRET_KEY_VALUE = " + '"seeded0signing0key0value"',
        id="suffixed-signing-key",
    ),
    pytest.param(
        "postgresql://svc:pass" + "word@db.internal:5432/appdb",
        id="url-embedded-password",
    ),
    pytest.param(
        "DB_PASS" + "WORD = " + '"seeded0role0secret"',
        id="spaced-quoted-role-password",
    ),
    pytest.param(
        "PAYPAL_CLIENT_SECRET = " + '"seeded0client0secret"',
        id="spaced-quoted-client-secret",
    ),
    pytest.param(
        "AWS_ACCESS_KEY_ID = " + '"AKIASEEDEDKEYVALUE1"',
        id="spaced-quoted-access-key",
    ),
    pytest.param(
        "ZILLOW_API_KEY=" + '"zw-seeded-listing-key"',
        id="quoted-provider-key",
    ),
    pytest.param(
        "client_" + "secret = " + '"seeded0client0secret"',
        id="lower-case-client-secret",
    ),
    pytest.param(
        "pass" + "word = " + '"seeded0role0secret"',
        id="lower-case-password",
    ),
    pytest.param(
        "-----BEGIN RSA " + "PRIVATE KEY-----", id="private-key-header"
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
    pytest.param(
        "      - SECRET_KEY=${SECRET_KEY:?message}", id="compose-indirection"
    ),
    pytest.param(
        "    SECRET_KEY: str = Field(..., min_length=32)",
        id="annotated-declaration",
    ),
    pytest.param(
        "ACCESS_TOKEN_EXPIRE_MINUTES=30", id="numeric-setting"
    ),
)

# The marker admitting one reviewed line, and how many lines carry it
ALLOW_LIST_MARKER = "blitzy-scan" + "-allow"
EXPECTED_ALLOW_LIST_COUNT = 4

# One line per class the reviewed allow-list admits. Each is matched by the
# scan and then dropped, so both halves of the gate are exercised.
ALLOW_LISTED_CONTROLS = (
    pytest.param(
        "SENDGRID_API_KEY = settings.SENDGRID_API_KEY",
        id="value-read-from-configuration",
    ),
    pytest.param(
        "PASS" + "WORD_MIN_LENGTH = 12", id="policy-bound"
    ),
    pytest.param(
        "PASS" + "WORD_UPPERCASE = " + '"ABCDEFGHIJKLMNOPQRSTUVWXYZ"',
        id="policy-alphabet",
    ),
    pytest.param(
        "api_" + "key = " + '"YOUR_ZILLOW_API_KEY"',
        id="placeholder-token",
    ),
    pytest.param(
        "APP_ROLE_PASS" + "WORD_VARIABLE = " + '"db_app_password"',
        id="named-variable",
    ),
    pytest.param(
        "VALID_PASS" + "WORD = " + '"Harness1!Passphrase"'
        + "  # " + ALLOW_LIST_MARKER + ": harness fixture",
        id="marked-harness-fixture",
    ),
)

# Rule 1: the register justifying every suppressed advisory, and the
# condition under which all are re-measured
DECISION_LOG = (
    REPOSITORY_ROOT / "documentation" / "security" / "decision-log.md"
)
REVIEW_TRIGGER = "a Python runtime upgrade"

# Rule 1: the date every suppression entry carries. DL-387
ACCEPTANCE_DATE = "2026-07-31"

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

# SEC-11: schema public grants CREATE to PUBLIC by default, reaching the
# application role past the grants above. DL-370
REVOKED_FROM_PUBLIC = "REVOKE CREATE ON SCHEMA public FROM PUBLIC;"

# SEC-11: a database grants CONNECT and TEMPORARY to PUBLIC by default, so
# every cluster role can reach it and create temporary objects until both
# are revoked (CWE-269)
DATABASE_REVOKED_FROM_PUBLIC = (
    "REVOKE CONNECT, TEMPORARY ON DATABASE dbname FROM PUBLIC;"
)

# SEC-11: the effective-ACL probes the batch ends with. Explicit GRANT text
# describes intent; these read what the catalog actually holds, and each
# raise aborts the batch under ON_ERROR_STOP
EFFECTIVE_PRIVILEGE_BLOCK = "DO $$"
EFFECTIVE_PRIVILEGE_PROBES = (
    # PUBLIC's effective database privileges, with the default ACL
    # substituted when the column is still null
    "aclexplode(coalesce(d.datacl, acldefault('d', d.datdba)))",
    "aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner)))",
    # grantee zero is the PUBLIC pseudo-role
    "a.grantee = 0",
    "has_database_privilege('app_user', current_database(), 'CONNECT')",
    "has_database_privilege('app_user', current_database(), 'TEMPORARY')",
    "has_schema_privilege('app_user', 'public', 'CREATE')",
    "has_schema_privilege('app_user', 'public', 'USAGE')",
)

# SEC-11: the refusal statements the batch carries; each probe raises when
# it finds an unexpected privilege, stopping the run
EFFECTIVE_PRIVILEGE_FAILURES = (
    "RAISE EXCEPTION 'PUBLIC still holds % on database %'",
    "RAISE EXCEPTION 'PUBLIC still holds % on schema public'",
    "RAISE EXCEPTION 'app_user cannot connect to %'",
    "RAISE EXCEPTION 'app_user retains TEMPORARY on %'",
    "RAISE EXCEPTION 'app_user retains CREATE on schema public'",
    "RAISE EXCEPTION 'app_user cannot use schema public'",
)

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

# SEC-11: the two forms that place a role password in an argument list,
# readable by any local process (CWE-214). DL-370
ARGUMENT_LIST_PASSWORD_FORMS = ("-v owner_pw=", "-v app_pw=")

# SEC-01: the guards that keep the generated secret file unreadable by
# another user, and keep a symlink at .env from being written through
SECRET_FILE_GUARDS = (
    pytest.param("umask 077", id="owner-only-creation-mask"),
    pytest.param("mktemp ./.env.tmp.XXXXXXXX", id="unpredictable-temp-name"),
    pytest.param("trap 'rm -f \"$env_tmp\"' EXIT", id="temp-file-cleanup"),
    pytest.param('chmod 600 "$env_tmp"', id="restricted-before-install"),
    pytest.param('publish_env_file "$env_tmp" .env', id="no-clobber-install"),
    pytest.param("secrets.token_urlsafe(48)", id="generated-signing-key"),
    pytest.param("^[A-Za-z0-9_-]+$", id="generated-password-charset"),
)

# SEC-01: the publish primitive and the two forms it replaces. link(2)
# fails when the destination exists in any form, so no check precedes it
# and no window exists in which the destination can change (CWE-367)
PUBLISH_FUNCTION = "publish_env_file"
PUBLISH_PRIMITIVE = "os.link("
REPLACED_PUBLISH_FORMS = ('mv -f "$env_tmp" .env', "mv -n ")
PUBLISH_VERIFICATION = (
    '[ ! -f "$destination" ]',
    '[ -L "$destination" ]',
    '[ ! -s "$destination" ]',
)

# SEC-01: what a planted destination holds, and the content a publish
# that wrote through it delivers. DL-370
PLANTED_DESTINATION_CONTENT = "zzz-planted-destination-4471\n"
PUBLISHED_MARKER = "PROBE_KEY=probe-published-value"

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
# batch stops the run. DL-370
PSQL_INVOCATION = "} | psql -v ON_ERROR_STOP=1 -d dbname"
GRANT_BATCH_STATUS = '[ "${PIPESTATUS[1]}" -ne 0 ]'

# SEC-01/SEC-11: every command whose failure leaves the run provisioning
# against absent state (CWE-252). DL-370
GUARDED_COMMANDS = (
    "python3 -m venv venv",
    "source venv/bin/activate",
    'python3 -m pip install -r "$repo_root/backend/requirements.txt"',
    "check_schema_prerequisites",
    "createdb dbname",
    'chmod 600 "$env_tmp"',
    'publish_env_file "$env_tmp" .env',
    "create_schema_as_owner",
)

# SEC-01/SEC-11: the two ways a step ends the run
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
# from; no credential appears in a tracked file. DL-368
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
    # SEC-11: the default database privileges PUBLIC holds until revoked
    'REVOKE CONNECT, TEMPORARY ON DATABASE "main-database" FROM PUBLIC;',
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

# SEC-11: the cloud block reads the effective access lists and states what
# each query must return. DL-368
CLOUD_PRIVILEGE_VERIFICATION = (
    "aclexplode(coalesce(d.datacl, acldefault('d', d.datdba)))",
    "a.grantee = 0",
    "has_database_privilege('app_user', current_database(), 'CONNECT')",
    "has_database_privilege('app_user', current_database(), 'TEMPORARY')",
    "has_schema_privilege('app_user', 'public', 'USAGE')",
    "has_schema_privilege('app_user', 'public', 'CREATE')",
)

# SEC-10/SEC-11/SEC-12: the provider delivery contract. Every argument
# below is a provider feature (CWE-1104). DL-368
TERRAFORM_LOCK = TERRAFORM_DIRECTORY / ".terraform.lock.hcl"
TERRAFORM_SETTINGS_HEADER = "\nterraform {"
PROVIDER_LOCAL_NAME = "google"
PROVIDER_DECLARATION = "{0} = ".format(PROVIDER_LOCAL_NAME)
PROVIDER_SOURCE = "hashicorp/{0}".format(PROVIDER_LOCAL_NAME)
PROVIDER_ADDRESS = "registry.terraform.io/{0}".format(PROVIDER_SOURCE)
PROVIDER_GATED_ARGUMENTS = (
    "ssl_mode",
    APP_ROLE_PASSWORD_ARGUMENT,
    APP_ROLE_PASSWORD_VERSION_ARGUMENT,
)

# SEC-12: the command-line release the write-only argument arrived in,
# which is the declared floor. DL-368
TERRAFORM_VERSION_FLOOR = (1, 11, 0)

# the platforms an operator or the pipeline installs from; the lock carries
# one directory hash for each, so a checkout on any of them verifies
LOCKED_PLATFORMS = (
    "linux_amd64",
    "linux_arm64",
    "darwin_amd64",
    "darwin_arm64",
)
PLATFORM_HASH_PREFIX = '"h1:'
REGISTRY_HASH_PREFIX = '"zh:'

# SEC-12: the operator document and the pipeline describe the same run, so
# a documented command that no longer matches is a claim, not a record
DOCUMENTED_SUITE_STEP = "Run backend unit tests"
DOCUMENTED_SECURITY_STEP = "Run backend security tests"
COLLECTION_ERROR_FLAG = "--continue-on-collection-errors"
ASSESSMENT_FINDINGS = tuple("SQ-{0:02d}".format(number) for number in
                            range(1, 16))

# SEC-12: the input channels a sensitive variable may recommend, and the
# flag it may only warn against. -var puts the value in the process
# arguments any local user can read, and in shell history
# (CWE-214, CWE-532)
SECRET_ENVIRONMENT_PREFIX = "TF_VAR_"
SECRET_FILE_CHANNEL = "-var-file"
COMMAND_LINE_FLAG = re.compile(r"-var(?!-file)\b")
PROHIBITION_MARKER = "never"
IGNORED_VARIABLE_FILE = "infrastructure/terraform/secret.tfvars"
ADMITTED_VARIABLE_TEMPLATE = "infrastructure/terraform/secret.tfvars.example"


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

    A rule spanning two fields is reported against the model, so the field
    is identified from the message text. DL-384
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
    """Return the connect arguments SQLAlchemy hands the driver.

    A ``do_connect`` listener records the keywords and raises, so no
    connection is opened. DL-380
    """
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

    The provider library is replaced outright: the service runs its own
    configuration call and opens no connection. DL-383
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
    """Execute the application database module against one settings pair.

    ``spec_from_file_location`` loads the shipped file as a fresh module
    under a probe name, leaving the application engine untouched. DL-381
    """
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

    The application engine is never registered. DL-381
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

    AAP 0.1.4 freezes these names. They are transcribed above this case and
    compared against the declared fields. DL-384
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
    The parity is asserted in both directions. DL-372
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

    Each frozen name is removed from the environment in turn and the
    settings rebuilt, which names the variable the field reads. DL-384
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

    The configuration the service hands the provider is recorded and
    compared against the setting. DL-383
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

    Both configuration call sites are read from the shipped source.
    """
    with open(paypal_service.__file__, encoding="utf-8") as handle:
        source = handle.read()

    configured = source.count('"mode": settings.PAYPAL_MODE')
    assert configured == 2, configured
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

    The field's character constraint carries one number, the weakest
    algorithm's floor. The per-algorithm table is asserted to exceed it
    for HS384 and HS512, as RFC 7518 sec. 3.2 requires. DL-384
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

    Every key here clears the field's character constraint, leaving the
    algorithm-coupled rule to refuse it. The message is asserted to name
    the algorithm. DL-384
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

    Both directions are checked. A key of two-byte characters carrying the
    strongest floor in bytes is accepted below that floor in characters. A
    key one byte under the floor is rejected above the 32-character
    minimum. DL-384
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

    A threshold of zero admits every attempt and a window of zero prunes
    every counter on the next attempt. Both are refused. DL-384
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

    The domain check refuses a misspelling, and a value carrying an
    appended connection parameter, at settings construction. DL-384
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


def _workflow_step(name):
    """Return the lines belonging to one workflow step.

    The step is its own header plus every line indented under it.
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

    The count is transcribed here and every identifier is shape-checked.
    DL-373
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


# CWE-1104: the staleness check reads both identifier namespaces
def test_the_staleness_check_compares_both_namespaces():
    """The check reads the report's own identifiers and its aliases.

    One accepted advisory is published only under the GitHub namespace, and
    the check is asserted to read both namespaces out of the report.
    DL-373
    """
    step = _workflow_step(AUDIT_STEP_NAME)

    for required in ("PYSEC-", "GHSA-", "aliases", "dependencies", "vulns"):
        assert required in step, required

    declared = set(re.findall(r"--ignore-vuln\s+(\S+)", step))
    namespaces = {
        "PYSEC" if identifier.startswith("PYSEC") else "GHSA"
        for identifier in declared
    }
    # both namespaces are in use across the register. DL-373
    assert namespaces == {"PYSEC", "GHSA"}, sorted(declared)


def _staleness_check(tmp_path, report, declared_line):
    """Run the workflow's own staleness check over one synthetic report.

    The check is copied out of the workflow with two substitutions, each
    asserted to apply once: the report it reads, and the workflow it reads
    its declarations from. The logic under test is the shipped one.
    DL-382
    """
    step = _workflow_step(AUDIT_STEP_NAME)
    opened = step.index("python - <<'PY'")
    closed = step.index("        PY\n", opened)
    body = step[opened:closed].splitlines()[1:]
    indent = min(
        len(line) - len(line.lstrip()) for line in body if line.strip()
    )
    script = "\n".join(line[indent:] for line in body)

    for original, replacement in (
        ('".github/workflows/ci.yml"', '"declared.txt"'),
        ('"/tmp/audit-report.json"', '"report.json"'),
    ):
        assert script.count(original) == 1, original
        script = script.replace(original, replacement)

    (tmp_path / "check.py").write_text(script, encoding="utf-8")
    (tmp_path / "declared.txt").write_text(declared_line, encoding="utf-8")
    (tmp_path / "report.json").write_text(
        json.dumps(report), encoding="utf-8"
    )
    return subprocess.run(
        [sys.executable, "check.py"],
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def _advisory_report(*advisories):
    """Return a report in the shape the audit tool publishes."""
    return {
        "dependencies": [
            {"name": "probe", "version": "1.0", "vulns": list(advisories)}
        ]
    }


# CWE-1104: a suppression the audit still reports is not stale
def test_the_staleness_check_admits_a_reported_suppression(tmp_path):
    """A declared identifier the report names passes the check."""
    completed = _staleness_check(
        tmp_path,
        _advisory_report({"id": "PYSEC-2026-161", "aliases": []}),
        "--ignore-vuln PYSEC-2026-161\n",
    )

    assert completed.returncode == 0, completed.stdout.decode("utf-8")


# CWE-1104: an identifier reported only as an alias is not stale either
def test_the_staleness_check_admits_an_alias_only_suppression(tmp_path):
    """A declaration matching only the report's alias passes the check.

    This is the msgpack shape: no identifier in the Python namespace, and a
    suppression naming the GitHub alias. DL-373
    """
    completed = _staleness_check(
        tmp_path,
        _advisory_report(
            {"id": "PYSEC-2026-9999", "aliases": ["GHSA-6v7p-g79w-8964"]}
        ),
        "--ignore-vuln GHSA-6v7p-g79w-8964\n",
    )

    assert completed.returncode == 0, completed.stdout.decode("utf-8")


# CWE-1104: a suppression nothing reports fails the build
@pytest.mark.parametrize(
    "declared",
    ("PYSEC-2026-161", "GHSA-6v7p-g79w-8964"),
    ids=("python-namespace", "github-namespace"),
)
def test_the_staleness_check_refuses_an_unreported_suppression(
    tmp_path, declared
):
    """A declared identifier the report does not name fails the check."""
    completed = _staleness_check(
        tmp_path,
        _advisory_report({"id": "PYSEC-2026-1325", "aliases": ["CVE-1-1"]}),
        "--ignore-vuln {0}\n".format(declared),
    )

    assert completed.returncode == 1, completed.stdout.decode("utf-8")
    assert declared in completed.stdout.decode("utf-8")


# Rule 1: every suppression carries a justified entry in the register
def test_every_suppressed_advisory_is_justified_in_the_decision_log():
    """No advisory is suppressed without a register entry, and none spare.

    The register and the gate are compared in both directions: every
    suppressed identifier carries a register entry, and every entry carries
    a suppression. DL-387
    """
    assert DECISION_LOG.is_file(), DECISION_LOG
    log = DECISION_LOG.read_text(encoding="utf-8")

    suppressed = set(
        re.findall(r"--ignore-vuln\s+(\S+)", _workflow_step(AUDIT_STEP_NAME))
    )
    registered = {
        row[1]
        for row in re.findall(
            r"^- \*\*Row (\d+), `(" + ADVISORY_IDENTIFIER.pattern
            + r")` in ",
            log,
            re.MULTILINE,
        )
    }

    assert registered == suppressed, sorted(
        registered.symmetric_difference(suppressed)
    )

    # the register states the shared review trigger it accepts them under
    assert REVIEW_TRIGGER in log

    # SEC-12: each entry is dated where it is accepted. DL-387
    dated = set(
        re.findall(
            r"^- \*\*Row \d+, `(" + ADVISORY_IDENTIFIER.pattern
            + r")` in [^\n]*\*\* Accepted " + ACCEPTANCE_DATE,
            log,
            re.MULTILINE,
        )
    )
    assert dated == registered, sorted(registered.difference(dated))


def _credential_scan_command():
    """Return the one workflow line that runs the credential scan."""
    assert WORKFLOW.is_file(), WORKFLOW
    source = WORKFLOW.read_text(encoding="utf-8")
    running = [line for line in source.splitlines() if "git grep" in line]
    assert len(running) == 1, running
    return running[0]


def _credential_allow_list_command():
    """Return the one workflow line that applies the reviewed allow-list."""
    source = WORKFLOW.read_text(encoding="utf-8")
    running = [line for line in source.splitlines() if "grep -vE" in line]
    assert len(running) == 1, running
    return running[0]


def _expression_argument(command):
    """Return the expression one grep invocation in the workflow carries.

    The command is split the way the shell splits it, so the expression is
    read as ``grep`` receives it. DL-382
    """
    arguments = shlex.split(command)
    expressions = [
        arguments[index + 1]
        for index, argument in enumerate(arguments)
        if argument in ("-E", "-vE") and index + 1 < len(arguments)
    ]
    assert len(expressions) == 1, expressions
    return expressions[0]


def _credential_scan_pattern():
    """Return the compiled pattern the workflow scans tracked files with."""
    return re.compile(_expression_argument(_credential_scan_command()))


def _credential_allow_list_pattern():
    """Return the compiled expression the reviewed allow-list applies."""
    return re.compile(
        _expression_argument(_credential_allow_list_command())
    )


def _reported_credential_lines():
    """Return the lines the gate reports across tracked content."""
    pattern = _credential_scan_pattern()
    allowed = _credential_allow_list_pattern()
    reported = []

    for path in _tracked_files():
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            # the workflow passes -I, which skips binary content likewise
            continue
        for number, line in enumerate(content.splitlines(), 1):
            if pattern.search(line) and not allowed.search(line):
                reported.append(
                    "{0}:{1}".format(path.relative_to(REPOSITORY_ROOT), number)
                )
    return reported


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

    Each control below is a placeholder-only line the template carries.
    """
    assert not _credential_scan_pattern().search(line), line


def test_the_credential_scan_matches_no_part_of_its_own_source():
    """The scan does not match the line that declares it.

    Every branch of the pattern is split by a one-character bracket
    expression. DL-373
    """
    command = _credential_scan_command()
    pattern = _credential_scan_pattern()

    assert not pattern.search(command), command

    # no path is excluded, so every tracked file is scanned
    assert EXCLUSION_PATHSPEC not in command
    for path in FORMERLY_EXCLUDED_PATHS:
        assert path not in command


def test_the_credential_scan_reports_nothing_across_tracked_content():
    """No tracked file carries a credential the scan reports.

    This is the gate's passing direction, executed over the same content
    the workflow reads: every tracked file, none excluded, then the
    reviewed allow-list. A document or a workflow added later is covered
    without editing this case.
    """
    assert not _reported_credential_lines()


# SEC-01: the reviewed allow-list stays small and stays out of the source
def test_the_reviewed_allow_list_marker_is_bounded_and_placed():
    """Every marked line is a harness fixture, and the count is pinned.

    The marker admits a reviewed non-credential. Its count is pinned, every
    marked line is under ``backend/tests/`` and carries a reason, and no
    line of application source carries it. DL-373
    """
    marked = []
    for path in _tracked_files():
        if path == WORKFLOW:
            # the workflow declares the marker in the allow-list itself
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        for number, line in enumerate(content.splitlines(), 1):
            if ALLOW_LIST_MARKER in line:
                marked.append(
                    (str(path.relative_to(REPOSITORY_ROOT)), number, line)
                )

    assert len(marked) == EXPECTED_ALLOW_LIST_COUNT, marked

    pattern = _credential_scan_pattern()
    for relative, _number, line in marked:
        # a marker on a line the scan does not match hides nothing and
        # only misleads a reader
        assert pattern.search(line), (relative, line)
        # SEC-01: no marker stands in shipped application code
        assert relative.startswith("backend/tests/"), relative
        # the marker states what was reviewed
        assert line.split(ALLOW_LIST_MARKER, 1)[1].strip(": ").strip(), line


# SEC-01: the allow-list admits only the classes it names
@pytest.mark.parametrize("line", ALLOW_LISTED_CONTROLS)
def test_the_allow_list_admits_each_class_it_names(line):
    """Each reviewed class is matched by the scan and then admitted."""
    assert _credential_scan_pattern().search(line), line
    assert _credential_allow_list_pattern().search(line), line


# SEC-01: the allow-list admits nothing beyond those classes
@pytest.mark.parametrize("line", CREDENTIAL_POSITIVE_CONTROLS)
def test_the_allow_list_admits_no_credential_shape(line):
    """No credential shape the scan detects is admitted by the
    allow-list."""
    assert not _credential_allow_list_pattern().search(line), line


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

    # AAP 0.5.10: the superseded argument is deprecated and unused
    assert DEPRECATED_SSL_ARGUMENT not in instance

    # the gated instance is the PostgreSQL one the application connects to
    assert _hcl_argument(
        instance, "database_version"
    ) == QUOTED_DATABASE_VERSION


# SEC-11: the application role is separate and carries no literal secret
def test_the_application_database_role_carries_no_literal_credential():
    """The application role is declared with its password from a variable.

    SEC-11 separates the application account from the instance admin
    account. Every identifying argument arrives from an input variable, the
    password through the write-only argument, and the variable is
    sensitive and ephemeral with no default. DL-368, DL-369
    """
    role = _terraform_resource(*CLOUD_SQL_USER)

    assert _hcl_argument(role, "name") == APP_ROLE_NAME_REFERENCE
    password = _hcl_argument(role, APP_ROLE_PASSWORD_ARGUMENT)
    assert password == APP_ROLE_PASSWORD_REFERENCE

    # SEC-12: the state-persisting argument is absent, so no apply writes
    # the password into the state file
    assert STATE_PERSISTING_PASSWORD_ARGUMENT not in role

    # SEC-12: the counter the provider reapplies a rotated password on.
    # DL-368
    assert _hcl_argument(
        role, APP_ROLE_PASSWORD_VERSION_ARGUMENT
    ) == "var.{0}".format(APP_ROLE_PASSWORD_VERSION_VARIABLE)

    # neither argument carries a quoted value. DL-368
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
    # the variable declares no default. DL-369
    assert "default" not in password_variable

    name_variable = _terraform_variable(APP_ROLE_NAME_VARIABLE)
    assert _hcl_argument(name_variable, "type") == "string"


# SEC-11: the declaration a default apply can satisfy, and the residual it
# leaves for the documented out-of-band statements
def test_the_cloud_application_account_is_creatable_and_its_residual_stated():
    """The declaration assigns no role, and SECURITY.md carries the grants.

    The declaration is asserted to carry no role assignment and no
    withdrawn variable, every referenced variable to be read, and
    SECURITY.md to carry every statement the account needs. DL-368
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

    # SEC-11: and the block verifies what the statements actually produced
    for probe in CLOUD_PRIVILEGE_VERIFICATION:
        assert probe in document, probe


def _terraform_settings():
    """Return the body of the root ``terraform`` settings block."""
    assert TERRAFORM_MAIN.is_file(), TERRAFORM_MAIN
    source = TERRAFORM_MAIN.read_text(encoding="utf-8")
    return _hcl_block(source, TERRAFORM_SETTINGS_HEADER)


def _version_parts(text):
    """Return the leading numeric components of a version string."""
    digits = re.findall(r"\d+", text)
    assert digits, text
    return tuple(int(digit) for digit in digits)


def _constraint_terms(constraint):
    """Return one entry per comma-separated version constraint term."""
    assert constraint.startswith('"') and constraint.endswith('"'), constraint
    terms = [term.strip() for term in constraint[1:-1].split(",")]
    assert all(terms), constraint
    return terms


def _bounds_the_next_major(terms):
    """Report whether any term bars the next major release."""
    return any(
        term.startswith("~>") or term.startswith("<") for term in terms
    )


def _git_succeeds(*arguments):
    """Report whether one git query exits successfully."""
    return subprocess.run(
        ["git"] + list(arguments),
        cwd=str(REPOSITORY_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


# SEC-10/SEC-11/SEC-12: the arguments those controls rely on are provider
# features, so the provider is part of their delivery
def test_the_configuration_bounds_the_provider_its_controls_rely_on():
    """The root block bounds both the command line and the provider.

    Encrypted-only transport, the write-only password and its rotation
    counter are all provider features. Both declared ranges are read off
    the root block. DL-368
    """
    settings_block = _terraform_settings()
    main_source = TERRAFORM_MAIN.read_text(encoding="utf-8")

    # every argument the constraint exists to protect is actually used
    for argument in PROVIDER_GATED_ARGUMENTS:
        assert argument in main_source, argument

    command_line = _constraint_terms(
        _hcl_argument(settings_block, "required_version")
    )
    floor = [term for term in command_line if term.startswith(">=")]
    assert len(floor) == 1, command_line
    assert _version_parts(floor[0]) >= TERRAFORM_VERSION_FLOOR, floor
    assert _bounds_the_next_major(command_line), command_line

    providers = _hcl_block(settings_block, "required_providers")
    declared = _hcl_block(providers, PROVIDER_DECLARATION)

    assert _hcl_argument(declared, "source") == '"{0}"'.format(
        PROVIDER_SOURCE
    )

    provider_terms = _constraint_terms(_hcl_argument(declared, "version"))
    assert _bounds_the_next_major(provider_terms), provider_terms

    # a bound that admits nothing installable is a bound in name only
    assert TERRAFORM_LOCK.is_file(), TERRAFORM_LOCK
    lock = _hcl_block(
        TERRAFORM_LOCK.read_text(encoding="utf-8"),
        'provider "{0}"'.format(PROVIDER_ADDRESS),
    )
    locked = _version_parts(_hcl_argument(lock, "version"))
    for term in provider_terms:
        bound = _version_parts(term)
        if term.startswith("~>"):
            assert locked[0] == bound[0], (locked, term)
            assert locked[:len(bound)] >= bound, (locked, term)
        elif term.startswith(">="):
            assert locked >= bound, (locked, term)
        elif term.startswith("<"):
            assert locked < bound, (locked, term)


# SEC-12: a constraint chooses a range; the lock chooses the build
def test_the_provider_lock_is_tracked_and_covers_every_platform_named():
    """The lock is committable, committed, and hashed for each platform.

    The lock is asserted to carry one directory hash per platform an
    operator or the pipeline installs from, the registry checksum set, and
    the same constraint the configuration declares. DL-368
    """
    assert TERRAFORM_LOCK.is_file(), TERRAFORM_LOCK
    lock_path = TERRAFORM_LOCK.relative_to(REPOSITORY_ROOT).as_posix()

    # committable: no ignore rule excludes it
    assert not _git_succeeds("check-ignore", "-q", lock_path), lock_path
    # committed: present in the index, not only on disk
    assert _git_succeeds("ls-files", "--error-unmatch", lock_path), lock_path

    source = TERRAFORM_LOCK.read_text(encoding="utf-8")
    lock = _hcl_block(source, 'provider "{0}"'.format(PROVIDER_ADDRESS))

    declared = _hcl_argument(
        _hcl_block(
            _hcl_block(_terraform_settings(), "required_providers"),
            PROVIDER_DECLARATION,
        ),
        "version",
    )
    assert _hcl_argument(lock, "constraints") == declared

    platform_hashes = re.findall(PLATFORM_HASH_PREFIX + r'[^"]+"', lock)
    registry_hashes = re.findall(REGISTRY_HASH_PREFIX + r'[^"]+"', lock)

    assert len(platform_hashes) >= len(LOCKED_PLATFORMS), platform_hashes
    assert len(set(platform_hashes)) == len(platform_hashes), platform_hashes
    # the registry checksum set covers the archives the hashes verify
    assert registry_hashes, source
    assert len(set(registry_hashes)) == len(registry_hashes), registry_hashes

    # every platform the lock claims to cover is named where an operator
    # reads it, so a missing hash is attributable
    document = SECURITY_DOCUMENT.read_text(encoding="utf-8")
    for platform in LOCKED_PLATFORMS:
        assert platform in document, platform


# SEC-12: a documented command that no longer runs what it claims
def test_the_documented_commands_match_the_pipeline():
    """Both documented test invocations match the steps that run them.

    Three pre-existing modules fail to import, so the full-suite command
    needs the collection-error flag to run anything at all. The flag is
    asserted in the document and in the workflow. DL-384
    """
    assert SECURITY_DOCUMENT.is_file(), SECURITY_DOCUMENT
    document = SECURITY_DOCUMENT.read_text(encoding="utf-8")

    suite_step = _workflow_step(DOCUMENTED_SUITE_STEP)
    assert COLLECTION_ERROR_FLAG in suite_step, suite_step
    assert COLLECTION_ERROR_FLAG in document

    # the security suite collects cleanly and runs without it
    security_step = _workflow_step(DOCUMENTED_SECURITY_STEP)
    assert "python -m pytest tests/security -q" in security_step
    assert COLLECTION_ERROR_FLAG not in security_step, security_step
    assert "cd backend && python -m pytest tests/security -q" in document

    # every finding the assessment raised is stated where posture is read
    for finding in ASSESSMENT_FINDINGS:
        assert finding in document, finding


# SEC-12: the secret's input channel. DL-369
def test_no_variable_description_recommends_a_command_line_secret():
    """A sensitive variable names safe channels and warns against argv.

    The description is asserted to name the environment variable and the
    ignored variable file, and to mention the command-line flag only to
    prohibit it. DL-369
    """
    source = TERRAFORM_VARIABLES.read_text(encoding="utf-8")
    names = re.findall(r'^variable "([^"]+)"', source, re.MULTILINE)
    assert names, source

    sensitive = []
    for name in names:
        body = _terraform_variable(name)
        if re.search(r"^\s*sensitive\s*=\s*true", body, re.MULTILINE):
            sensitive.append((name, body))

    # the password variable is the one this case exists for
    assert APP_ROLE_PASSWORD_VARIABLE in [name for name, _ in sensitive]

    for name, body in sensitive:
        description = _hcl_argument(body, "description")

        # the environment channel, named for this variable specifically
        assert SECRET_ENVIRONMENT_PREFIX + name in description, name
        # the protected-file channel
        assert SECRET_FILE_CHANNEL in description, name

        prohibitions = 0
        for sentence in re.split(r"(?<=\.) ", description):
            if not COMMAND_LINE_FLAG.search(sentence):
                continue
            assert PROHIBITION_MARKER in sentence.lower(), (name, sentence)
            prohibitions += 1
        assert prohibitions, name

    # the recommended file channel is genuinely protected, and its
    # template form stays committable
    assert _git_succeeds("check-ignore", "-q", IGNORED_VARIABLE_FILE)
    assert not _git_succeeds(
        "check-ignore", "-q", ADMITTED_VARIABLE_TEMPLATE
    )


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


def _provisioning_batch():
    """Return the whole SQL batch the provisioning script sends to psql.

    The batch is a quoted here-document: the shell performs no expansion,
    and the tracked bytes are the statements the server receives.
    """
    body = _shell_function("init_database")
    opened = "cat <<'SQL'\n"
    assert body.count(opened) == 1, opened
    batch = body[body.index(opened) + len(opened):]
    return batch[:batch.index("\nSQL\n")]


def _provisioning_statements():
    """Return the role and privilege statements, one per line.

    The verification block that closes the batch is returned separately
    from the privilege statements. DL-382
    """
    batch = _provisioning_batch()
    assert EFFECTIVE_PRIVILEGE_BLOCK in batch, EFFECTIVE_PRIVILEGE_BLOCK
    opened = batch.index(EFFECTIVE_PRIVILEGE_BLOCK)
    return [
        line for line in batch[:opened].splitlines() if line.strip()
    ]


def _provisioning_verification():
    """Return the effective-privilege block that closes the batch."""
    batch = _provisioning_batch()
    assert EFFECTIVE_PRIVILEGE_BLOCK in batch, EFFECTIVE_PRIVILEGE_BLOCK
    return batch[batch.index(EFFECTIVE_PRIVILEGE_BLOCK):]


# SEC-11: the application role reaches table data and nothing else
def test_the_application_role_is_granted_data_access_only():
    """Every privilege the application role receives is a data operation.

    SEC-11 replaces one account holding every privilege on the database
    with two roles. The granted set is compared whole, read from the
    shipped statements. DL-383
    """
    statements = _provisioning_statements()
    granted = [line for line in statements if "app_user" in line]

    expected = set(APP_ROLE_GRANTS)
    expected.update(APP_ROLE_DEFAULT_PRIVILEGES)
    expected.add(APP_ROLE_CREATION)

    # the creation statement carries a psql variable, compared by its
    # privilege-bearing prefix
    normalised = {
        APP_ROLE_CREATION if line.startswith(APP_ROLE_CREATION) else line
        for line in granted
    }
    assert normalised == expected, sorted(normalised.symmetric_difference(
        expected
    ))


# SEC-11: the default grant on schema public, which carries DDL. DL-370
def test_the_default_public_schema_privilege_is_revoked():
    """PUBLIC loses CREATE on schema public, and the owner keeps it.

    A PostgreSQL 13 database grants CREATE on schema public to PUBLIC,
    which every role holds. Both statements are asserted present, and the
    owner grant is asserted to be the only CREATE on the schema. DL-370
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


# SEC-11: a database grants CONNECT and TEMPORARY to PUBLIC by default
def test_the_default_public_database_privileges_are_revoked():
    """PUBLIC loses CONNECT and TEMPORARY on the database.

    PostgreSQL grants CONNECT and TEMPORARY on every database to PUBLIC.
    Both revokes are asserted present, and the revoke is asserted to
    precede the explicit grant. DL-370
    """
    statements = _provisioning_statements()

    assert DATABASE_REVOKED_FROM_PUBLIC in statements
    assert statements.index(
        DATABASE_REVOKED_FROM_PUBLIC
    ) < statements.index(APP_ROLE_GRANTS[0])

    # PUBLIC is never granted anything back
    granted_to_public = [
        line
        for line in statements
        if line.startswith("GRANT") and "PUBLIC" in line
    ]
    assert granted_to_public == [], granted_to_public

    # TEMPORARY is withheld from the application role as well as PUBLIC
    assert not [line for line in statements if "TEMPORARY ON DATABASE dbname"
                " TO " in line]


# SEC-11: the batch reads back what it granted. DL-370
def test_the_provisioning_batch_verifies_the_effective_privileges():
    """The batch ends by reading the catalog, and aborts on a surprise.

    The closing block probes the effective privileges in the catalog, and
    every probe that finds the wrong answer raises under the stop-on-error
    setting. DL-370
    """
    verification = _provisioning_verification()

    for probe in EFFECTIVE_PRIVILEGE_PROBES:
        assert probe in verification, probe
    for failure in EFFECTIVE_PRIVILEGE_FAILURES:
        assert failure in verification, failure

    # the block closes, so the batch is syntactically complete
    assert verification.rstrip().endswith("$$;"), verification[-80:]

    # verification runs last, after every statement it reads back
    assert _provisioning_batch().index(
        EFFECTIVE_PRIVILEGE_BLOCK
    ) > _provisioning_batch().index(DATABASE_REVOKED_FROM_PUBLIC)

    # the invocation stops on error, the behaviour a raise relies on
    body = _shell_function("init_database")
    assert PSQL_INVOCATION in body
    assert GRANT_BATCH_STATUS in body


# SEC-11: no provisioning statement confers a broad privilege
@pytest.mark.parametrize("privilege", FORBIDDEN_PROVISIONING_SQL)
def test_the_provisioning_statements_confer_no_broad_privilege(privilege):
    """No statement grants the privileges SEC-11 exists to remove.

    Each name below either restores the original all-privileges account or
    confers cluster-level authority. Each is checked against the whole
    shipped batch case-insensitively, verification block included.
    """
    batch = _provisioning_batch().upper()

    assert privilege.upper() not in batch, privilege


# SEC-01/SEC-11: a role password in a tracked file is a disclosed password
def test_the_provisioning_statements_carry_no_password_literal():
    """Both role passwords reach the server as psql variables.

    Each creation statement names a psql variable that the script assigns
    on standard input, so the tracked bytes carry no password. DL-370
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

    The script writes both assignments through the printf builtin, which
    runs inside the shell and starts no process, and pipes them into psql
    ahead of the quoted batch. The pipeline status of psql itself is
    checked. DL-370
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

    The script creates an owner-only temporary file in the same directory,
    restricts it, links it to the destination and drops the temporary name.
    Each step is asserted present. DL-370
    """
    assert guard in _shell_function("configure_env_vars"), guard


def test_the_secrets_are_never_written_straight_to_the_destination():
    """The here-document writes to the temporary file, not to .env.

    The direct-write shape is asserted absent from the shipped script.
    DL-370
    """
    body = _shell_function("configure_env_vars")

    assert DIRECT_SECRET_WRITE not in body
    assert 'cat << EOF > "$env_tmp"' in body


# SEC-11: schema objects are owned by the role that holds DDL
def test_the_schema_is_created_by_the_owner_role():
    """The owner role creates the tables, over an environment credential.

    The owner bootstrap creates the schema, and its credential travels in
    the environment of the interpreter it starts. Its imports are checked
    ahead of the first database object. DL-370
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


# SEC-01/SEC-11: a failed step stops the run (CWE-252)
def test_every_provisioning_step_stops_the_run_on_failure():
    """Each step runs in order and aborts the run when it fails.

    The interpreter is prepared and populated before the credential step,
    and the credentials exist before the roles that carry them. Each step
    is asserted to abort the run on failure. DL-370
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

    Every command below is asserted to be wrapped in the same guard shape,
    and every guard to return on failure. DL-370
    """
    source = _provisioning_source()
    guard = "if ! {0}; then".format(command)

    assert source.count(guard) == 1, guard

    body = source[source.index(guard) + len(guard):]
    assert "return 1" in body[:body.index("\n    fi")], command


# SEC-01/SEC-11: no guard reports a problem and then carries on (CWE-252)
def test_no_provisioning_guard_continues_past_a_failure():
    """Every conditional guard in the script ends the run.

    The case above names the commands that exist today. This one reads
    every conditional guard in the script and asserts each failure branch
    returns or exits. DL-370
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

    The script resolves its own location first, so the manifest it installs
    is the tracked one from any working directory. DL-370
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

    The shell's own parser reads the file without running any statement in
    it. DL-370
    """
    parsed = subprocess.run(
        ["bash", "-n", str(PROVISIONING_SCRIPT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    assert parsed.returncode == 0, parsed.stdout.decode("utf-8")


# ---------------------------------------------------------------------
# SEC-09: the transaction-authorization gate
# ---------------------------------------------------------------------
# SEC-09: identities the transaction-authorization cases bind against
PAYER_IDENTITY = "PAYER-1"
BOUND_PLAN = "PLAN-A"
CHARGE_TOTAL = 10.00


def bearer(access_token):
    """Return the request header that carries one access token."""
    return {"Authorization": "Bearer " + access_token}


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
    """Return the refusal the authorization gate returns for one charge."""
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


# SEC-09: an unverified reference authorizes nothing (CWE-863)
@pytest.mark.parametrize(
    "resource, reason",
    (
        ({"id": "PAY-1", "state": "created"}, "state_or_amount_mismatch"),
        ({"id": "PAY-1", "state": "failed"}, "state_or_amount_mismatch"),
        ({}, "state_or_amount_mismatch"),
    ),
    ids=("unapproved", "failed", "empty-payload"),
)
def test_charge_refuses_an_unauthorized_state(resource, reason,
                                              spent_references):
    """A reference the provider has not authorized does not authorize."""
    assert refusal(resource) == reason
    assert authorize(resource) is False


# SEC-09: the charged total is the one the provider reports (CWE-863)
@pytest.mark.parametrize(
    "reported", ("9.99", "10.01", "1.00", "1000.00"),
)
def test_charge_refuses_a_total_that_is_not_the_amount(reported,
                                                       spent_references):
    """A reported total other than the charged amount does not authorize."""
    resource = approved_payment(total=reported)
    assert refusal(resource) == "state_or_amount_mismatch"
    assert authorize(resource) is False


# SEC-09: the reported unit is bound to the charge (CWE-863)
@pytest.mark.parametrize("currency", ["JPY", "EUR", "GBP", "ZWL"])
def test_charge_refuses_a_foreign_currency_total(currency, spent_references):
    """A total matching numerically in another unit does not authorize."""
    resource = approved_payment(currency=currency)
    assert refusal(resource) == "currency_mismatch"
    assert authorize(resource) is False


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


def test_charge_refuses_a_split_total_in_mixed_units(spent_references):
    """A split total summing correctly across two units does not
    authorize."""
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


def test_charge_refuses_a_payer_the_caller_did_not_expect(spent_references):
    """A bound payer that differs from the reported one does not
    authorize."""
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


def test_charge_refuses_an_agreement_naming_no_plan(spent_references):
    """An agreement reporting no plan identifier does not authorize."""
    resource = active_agreement(plan=None)
    assert refusal(resource, plan_id=BOUND_PLAN) == "plan_mismatch"
    assert authorize(resource, plan_id=BOUND_PLAN) is False


def test_charge_admits_an_agreement_for_the_bound_plan(spent_references):
    """An agreement carrying the bound plan authorizes the charge."""
    assert refusal(active_agreement(), plan_id=BOUND_PLAN) is None
    assert authorize(active_agreement(), plan_id=BOUND_PLAN) is True


# SEC-09: a reusable agreement is bound to one plan and one unit
def test_charge_refuses_a_bound_agreement_in_a_foreign_unit(spent_references):
    """An agreement for the bound plan in another unit does not
    authorize."""
    resource = active_agreement(currency="JPY")
    assert refusal(resource, plan_id=BOUND_PLAN) == "currency_mismatch"
    assert authorize(resource, plan_id=BOUND_PLAN) is False


# SEC-09: an argument the route cannot build authorizes nothing
@pytest.mark.parametrize(
    "payment_method, amount",
    (
        ("", CHARGE_TOTAL),
        ("   ", CHARGE_TOTAL),
        ("PAY-1", 0),
        ("PAY-1", -CHARGE_TOTAL),
        ("PAY-1", True),
    ),
    ids=(
        "empty-reference",
        "blank-reference",
        "zero-amount",
        "negative-amount",
        "boolean-amount",
    ),
)
def test_charge_refuses_a_malformed_argument(payment_method, amount,
                                             spent_references):
    """A malformed reference or amount is refused before any lookup."""
    lookup = mock.Mock(return_value=approved_payment())
    loop = asyncio.new_event_loop()
    try:
        with mock.patch.object(paypal_service, "_find_payment_resource",
                               lookup):
            outcome = loop.run_until_complete(
                paypal_service.process_payment(payment_method, amount))
    finally:
        loop.close()
    assert outcome is False
    assert lookup.call_count == 0


# SEC-09: a reference the provider cannot return authorizes nothing
def test_charge_refuses_a_reference_the_provider_does_not_return(
        spent_references):
    """A reference no provider lookup resolves does not authorize."""
    loop = asyncio.new_event_loop()
    try:
        with mock.patch.object(paypal_service, "_find_payment_resource",
                               return_value=None):
            outcome = loop.run_until_complete(
                paypal_service.process_payment("PAY-ABSENT", CHARGE_TOTAL))
    finally:
        loop.close()
    assert outcome is False
    assert len(paypal_service._claimed_references) == 0


# SEC-09: a lookup that raises returns a refusal
def test_charge_refuses_when_the_provider_lookup_raises(spent_references):
    """A provider lookup that raises is answered with a refusal."""
    loop = asyncio.new_event_loop()
    try:
        with mock.patch.object(paypal_service, "_find_payment_resource",
                               side_effect=RuntimeError("provider down")):
            outcome = loop.run_until_complete(
                paypal_service.process_payment("PAY-RAISE", CHARGE_TOTAL))
    finally:
        loop.close()
    assert outcome is False
    assert len(paypal_service._claimed_references) == 0


# SEC-09: a reference retained in the ledger authorizes no second charge
# (CWE-294)
def test_a_verified_reference_authorizes_one_charge_only(spent_references):
    """A reference retained in the ledger does not authorize again."""
    resource = approved_payment()
    outcomes = [authorize(resource, reference="PAY-REPLAY") for _ in range(3)]
    assert outcomes == [True, False, False]
    assert authorize(resource, reference="PAY-OTHER") is True
    assert len(paypal_service._claimed_references) == 0


# SEC-09: a reference retained in the ledger reaches no provider call
# (CWE-294)
def test_a_spent_reference_drives_no_provider_call(spent_references):
    """A retained replay is refused ahead of any provider request."""
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


def test_the_consumption_ledger_stays_bounded(spent_references):
    """The ledger evicts its oldest entry once it reaches its cap."""
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


def test_a_provider_timeout_refuses_the_charge(spent_references):
    """A provider call that times out returns a refusal."""
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
    """The two positional parameters stay first; the bindings are
    keyword."""
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


# SEC-09: the route the browser reaches and the plan it names
REQUESTED_PLAN = "P-REQUESTED"
UNREQUESTED_PLAN = "P-OTHER"
AGREEMENT_REFERENCE = "I-AGREEMENT"

# SEC-09: the status the route answers when the charge does not authorize
PAYMENT_REFUSED_STATUS = 400

TERM_START = "2026-01-01T00:00:00"
TERM_END = "2027-01-01T00:00:00"


def subscription_body(plan_id=REQUESTED_PLAN, reference=AGREEMENT_REFERENCE,
                      amount=CHARGE_TOTAL):
    """Build the body a subscribing client posts."""
    return {
        "plan_id": plan_id,
        "payment_method": reference,
        "amount": amount,
        "start_date": TERM_START,
        "end_date": TERM_END,
    }


def post_subscription(client, token, body):
    """Post one subscription request as an authenticated caller."""
    return client.post(SUBSCRIPTION_PATH, json=body, headers=bearer(token))


def spent(reference):
    """Report whether the ledger holds the reference as spent."""
    return paypal_service._reference_key(
        reference) in paypal_service._consumed_references


# SEC-09: the route supplies the plan the authorization gate binds against
def test_the_subscription_route_binds_the_requested_plan(
        client, registered_user):
    """The route hands the verifier the plan the request names.

    The recorded call is inspected directly, keyword included. DL-383
    """
    recorded = {}

    async def record(payment_method, amount, **binding):
        recorded["positional"] = (payment_method, amount)
        recorded["binding"] = binding
        return True

    body = subscription_body()
    with mock.patch.object(subscription_route, "process_payment", record):
        response = post_subscription(
            client, registered_user["access_token"], body)

    assert recorded["positional"] == (body["payment_method"], body["amount"])
    assert set(recorded["binding"]) == {"plan_id"}
    assert recorded["binding"]["plan_id"] == body["plan_id"]
    assert response.status_code != PAYMENT_REFUSED_STATUS


# SEC-09: a reusable agreement for the requested plan authorizes the charge
def test_the_route_authorizes_an_agreement_for_the_requested_plan(
        client, registered_user, spent_references):
    """An agreement carrying the requested plan clears the payment gate."""
    body = subscription_body()
    resource = active_agreement(plan=body["plan_id"])

    with mock.patch.object(paypal_service, "_find_payment_resource",
                           return_value=resource):
        response = post_subscription(
            client, registered_user["access_token"], body)

    assert response.status_code != PAYMENT_REFUSED_STATUS
    assert spent(body["payment_method"])


# SEC-09: a reusable agreement for another plan authorizes nothing (CWE-863)
def test_the_route_refuses_an_agreement_for_another_plan(
        client, registered_user, spent_references):
    """An agreement carrying a different plan is refused at the route."""
    body = subscription_body()
    resource = active_agreement(plan=UNREQUESTED_PLAN)

    with mock.patch.object(paypal_service, "_find_payment_resource",
                           return_value=resource):
        response = post_subscription(
            client, registered_user["access_token"], body)

    assert response.status_code == PAYMENT_REFUSED_STATUS
    # SEC-08: the refusal names no provider and no internal detail
    body_json = response.json()
    assert set(body_json) == ENVELOPE_KEYS
    assert body_json["detail"] == HTTPStatus(400).phrase
    assert not spent(body["payment_method"])


# SEC-09: an unverifiable reference is refused and writes no row
def test_the_subscription_route_refuses_an_unverifiable_reference(
        client, registered_user, db_session, spent_references):
    """A reference no provider lookup resolves is refused at the route."""
    body = subscription_body()

    with mock.patch.object(paypal_service, "_find_payment_resource",
                           return_value=None):
        response = post_subscription(
            client, registered_user["access_token"], body)

    assert response.status_code == PAYMENT_REFUSED_STATUS, response.text
    assert set(response.json()) == ENVELOPE_KEYS
    assert db_session.query(SubscriptionModel).count() == 0
    assert not spent(body["payment_method"])


# SEC-09: the route reaches no provider call without a credential
def test_an_unauthenticated_subscription_reaches_no_provider_call(
        client, spent_references):
    """A request carrying no credential drives no provider lookup."""
    lookup = mock.Mock(return_value=active_agreement())
    body = subscription_body()

    with mock.patch.object(paypal_service, "_find_payment_resource", lookup):
        response = client.post(SUBSCRIPTION_PATH, json=body)

    assert response.status_code == 401
    assert lookup.call_count == 0
    assert not spent(body["payment_method"])


# SEC-09: the route awaits the module seam
def test_the_subscription_route_calls_the_service_seam(client,
                                                       registered_user):
    """The route's provider call reaches the service module's own seam."""
    reached = []

    def lookup(reference):
        reached.append(reference)
        return active_agreement(plan=REQUESTED_PLAN)

    body = subscription_body()
    with mock.patch.object(paypal_service, "_find_payment_resource", lookup):
        post_subscription(client, registered_user["access_token"], body)

    assert reached == [body["payment_method"]]


# SEC-10: a probe engine holds a connection pool until it is disposed
def test_probe_engines_are_registered_for_disposal():
    """Loading the database module registers its engine for disposal.

    The parametrized cases above build one engine each, and the autouse
    fixture drains the registry they are added to. DL-381
    """
    before = len(_PROBE_ENGINES)
    module = load_database_module(POSTGRES_URL, "require")

    assert len(_PROBE_ENGINES) == before + 1
    assert _PROBE_ENGINES[-1] is module.engine

    # the application engine is never registered, so it is never disposed
    assert all(engine is not database.engine for engine in _PROBE_ENGINES)


def test_disposing_a_probe_engine_releases_its_pool():
    """A disposed probe engine reports an empty pool.

    The pool is read after disposal. DL-381
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

    The client records the request URL at INFO, and the authorization
    header with both bodies at DEBUG. The level cap on the library logger
    is read and asserted (CWE-532). DL-364
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

# SEC-11: no-op stand-ins for the two bootstrap helpers that reach a live
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

    Each value is shipped as a quoted SQL literal. The quoting is asserted
    here and stripped before the value is compared. DL-370
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
    # SEC-01: created under a restrictive mask and published by linking the
    # same inode, so no interval exists in which the mode is permissive
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

    The pre-existence guard stops the run ahead of any credential
    generation, and both names are asserted unchanged. DL-370
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


def _run_publish(work_dir, plant, expect_status):
    """Publish a prepared file with the script's own primitive.

    ``plant`` places whatever stands at the destination, after the source
    file exists. The real ``publish_env_file`` is sourced from the shipped
    script and called directly, with no earlier existence check in the
    path. DL-383
    """
    source = work_dir / ".env.tmp.probe"
    source.write_text(PUBLISHED_MARKER + "\n")
    source.chmod(0o600)
    plant(work_dir)
    standing = sorted(path.name for path in work_dir.iterdir())

    program = (
        "umask {0}\nsource <(grep -v '^main$' {1})\n"
        "{2} .env.tmp.probe .env\n".format(
            PERMISSIVE_UMASK,
            shlex.quote(str(PROVISIONING_SCRIPT)),
            PUBLISH_FUNCTION,
        )
    )
    completed = subprocess.run(
        ["bash", "-c", program],
        cwd=str(work_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
    )
    assert completed.returncode == expect_status, completed.stdout.decode()
    return completed.stdout.decode(), standing


def _plant_nothing(work_dir):
    """Leave the destination free."""


def _plant_directory(work_dir):
    """Stand a directory where the destination goes."""
    (work_dir / ".env").mkdir()


def _plant_symlink(work_dir):
    """Stand a symlink to a victim file where the destination goes."""
    victim = work_dir / "victim.txt"
    victim.write_text(PLANTED_DESTINATION_CONTENT)
    victim.chmod(0o644)
    (work_dir / ".env").symlink_to(victim.name)


def _plant_regular_file(work_dir):
    """Stand a regular file where the destination goes."""
    standing = work_dir / ".env"
    standing.write_text(PLANTED_DESTINATION_CONTENT)
    standing.chmod(0o644)


LATE_DESTINATIONS = (
    pytest.param(_plant_directory, id="directory"),
    pytest.param(_plant_symlink, id="symlink"),
    pytest.param(_plant_regular_file, id="regular-file"),
)


# SEC-01: the publish itself refuses, with no check in front of it
@pytest.mark.parametrize("plant", LATE_DESTINATIONS)
def test_the_publish_refuses_a_destination_that_appears_late(
    plant, tmp_path
):
    """A destination standing at publish time is never written through.

    The publish is a single link call, which fails when the destination
    exists in any form. Three destination forms are planted after the
    source exists. DL-370
    """
    output, before = _run_publish(tmp_path, plant, expect_status=1)
    assert "Refusing to publish" in output, output

    destination = tmp_path / ".env"
    source = tmp_path / ".env.tmp.probe"

    # the source is neither consumed nor absorbed as a child entry
    assert source.is_file()
    assert source.read_text().startswith(PUBLISHED_MARKER)
    if destination.is_dir() and not destination.is_symlink():
        assert list(destination.iterdir()) == []

    # whatever stood there is unchanged, and holds no part of the secret
    assert sorted(path.name for path in tmp_path.iterdir()) == before
    if destination.is_symlink():
        assert destination.readlink().name == "victim.txt"
        victim = tmp_path / "victim.txt"
        assert victim.read_text() == PLANTED_DESTINATION_CONTENT
        assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    elif destination.is_file():
        assert destination.read_text() == PLANTED_DESTINATION_CONTENT
        assert stat.S_IMODE(destination.stat().st_mode) == 0o644


# SEC-01: and it does publish, owner-only, when the destination is free
def test_the_publish_installs_an_owner_only_file_and_drops_the_source(
    tmp_path,
):
    """A free destination receives the file, owner-only, once.

    The source and the destination are the same inode until the source name
    is dropped, so the published mode is the mode the file was created
    under. The run is performed under a permissive mask. DL-370
    """
    _run_publish(tmp_path, _plant_nothing, expect_status=0)

    published = tmp_path / ".env"
    assert published.is_file()
    assert not published.is_symlink()
    assert published.read_text().startswith(PUBLISHED_MARKER)
    assert stat.S_IMODE(published.stat().st_mode) == 0o600
    assert published.stat().st_nlink == 1

    # the temporary name is gone, so nothing committable is left behind
    assert list(tmp_path.glob(".env.tmp.*")) == []


# SEC-01: the primitive is a link call, and the replaced forms are absent
def test_the_publish_uses_a_no_clobber_primitive():
    """The publish is one link call, verified after the fact.

    A move overwrites, and a move into a directory succeeds while
    publishing nothing. Neither form appears; the function links, drops
    the source, and then confirms the destination is the regular non-empty
    file it just created.
    """
    body = _shell_function(PUBLISH_FUNCTION)

    assert PUBLISH_PRIMITIVE in body
    for replaced in REPLACED_PUBLISH_FORMS:
        assert replaced not in body, replaced
    for check in PUBLISH_VERIFICATION:
        assert check in body, check

    # the caller stops the run when the publish refuses
    caller = _shell_function("configure_env_vars")
    assert 'if ! {0} "$env_tmp" .env; then'.format(
        PUBLISH_FUNCTION
    ) in caller
    for replaced in REPLACED_PUBLISH_FORMS:
        assert replaced not in caller, replaced


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

    Handles the constructs these files use. A leading ``**/`` or an
    embedded ``**`` spanning whole path segments, ``*`` and ``?`` inside
    one segment, a character class, and a trailing separator marking a
    directory. The caller supplies every ancestor path. DL-382
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

    SEC-12 keeps secrets out of version control, and an image layer is the
    other place a local secret can reach. Both Dockerfiles copy the whole
    context. DL-374, DL-375
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

    Both image definitions are read and asserted to copy the whole
    context, which is the premise the exclusions rest on. DL-374
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
    """No backend setting appears in the frontend build section."""
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
    """Compose passes each name to the build, failing when it is unset.

    Each build argument is asserted to carry the ``:?`` form. DL-367
    """
    assert COMPOSE_DEFINITION.is_file(), COMPOSE_DEFINITION
    body = COMPOSE_DEFINITION.read_text(encoding="utf-8")

    forwarded = re.search(
        r"- {0}=\$\{{{0}(:[?-][^}}]*)?\}}".format(re.escape(name)), body
    )
    assert forwarded, name
    assert forwarded.group(1), (name, "no inline default and no :? guard")
    assert forwarded.group(1).startswith(":?"), forwarded.group(1)


# ---------------------------------------------------------------------
# SEC-01/SEC-12: the declared build path a clean checkout has to consume
# ---------------------------------------------------------------------
def _compose_service_blocks():
    """Return each service name mapped to the lines beneath it."""
    assert COMPOSE_DEFINITION.is_file(), COMPOSE_DEFINITION
    lines = COMPOSE_DEFINITION.read_text(encoding="utf-8").splitlines()
    start = [
        index for index, line in enumerate(lines) if line == "services:"
    ]
    assert len(start) == 1, start

    services = {}
    current = None
    for line in lines[start[0] + 1:]:
        if line.strip() and not line.startswith(" "):
            break
        header = re.fullmatch(r"  ([a-z][a-z0-9_-]*):", line)
        if header:
            current = header.group(1)
            services[current] = []
        elif current is not None:
            services[current].append(line)
    assert services, lines
    return services


def _compose_interpolations(block):
    """Return every variable reference one service block carries."""
    return re.findall(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)([^}]*)\}", "\n".join(block)
    )


def _build_reference(block):
    """Return the context and dockerfile one service builds from."""
    joined = "\n".join(block)
    context = re.search(r"^      context: (\S+)$", joined, re.MULTILINE)
    dockerfile = re.search(r"^      dockerfile: (\S+)$", joined, re.MULTILINE)
    if context is None:
        return None
    assert dockerfile is not None, joined
    return context.group(1), dockerfile.group(1)


@pytest.mark.parametrize("service", sorted(_compose_service_blocks()))
def test_each_declared_build_names_a_dockerfile_that_exists(service):
    """The image definition each service names is present in the tree.

    Compose resolves the dockerfile path against the build context, and
    each resolved path is asserted to exist in the tree. DL-367
    """
    reference = _build_reference(_compose_service_blocks()[service])
    if reference is None:
        # a service built from a published image declares no dockerfile
        return

    context, dockerfile = reference
    root = (COMPOSE_DEFINITION.parent / context).resolve()
    assert root.is_dir(), (service, context)
    resolved = (root / dockerfile).resolve()
    assert resolved.is_file(), (service, context, dockerfile)


@pytest.mark.parametrize("service", sorted(_compose_service_blocks()))
def test_no_declared_value_interpolates_to_empty(service):
    """Every variable the definition reads fails closed when unset.

    Compose substitutes an unset variable with the empty string. Every
    reference is asserted to carry a default or the ``:?`` guard. DL-367
    """
    for name, modifier in _compose_interpolations(
        _compose_service_blocks()[service]
    ):
        assert modifier.startswith(":?") or modifier.startswith(":-"), (
            service, name, modifier
        )


def test_the_backend_service_supplies_every_required_setting():
    """The container receives every setting the application demands.

    Every setting ``Settings`` declares without a default is asserted
    present in the service environment. DL-367
    """
    block = _compose_service_blocks()["backend"]
    supplied = set(re.findall(r"^      - ([A-Z_]+)=", "\n".join(block), re.M))

    required = {
        name for name, field in Settings.__fields__.items() if field.required
    }
    assert required, Settings.__fields__
    assert not required - supplied, sorted(required - supplied)

    # SEC-10: the proxy topology's documented local exception, supplied as
    # a literal. DL-367
    assert "      - DB_SSLMODE=disable" in block


def _dockerfile_for(service):
    """Return the image definition one service builds."""
    context, dockerfile = _build_reference(_compose_service_blocks()[service])
    return (
        (COMPOSE_DEFINITION.parent / context / dockerfile)
        .resolve()
        .read_text(encoding="utf-8")
    )


def test_the_backend_image_serves_the_port_the_definition_publishes():
    """The exposed port, the served port and the published port agree.

    A healthcheck or a published port naming a port nothing listens on
    reports an unhealthy container for a healthy application, which is
    how a deployment learns to ignore the signal.
    """
    body = _dockerfile_for("backend")
    block = "\n".join(_compose_service_blocks()["backend"])

    exposed = re.findall(r"^EXPOSE (\d+)$", body, re.MULTILINE)
    assert exposed == ["8000"], exposed
    served = re.search(r'"--port", "(\d+)"', body)
    assert served and served.group(1) == exposed[0], body
    published = re.findall(r'^      - "(\d+):(\d+)"$', block, re.MULTILINE)
    assert published == [(exposed[0], exposed[0])], published
    assert ":{0}/".format(exposed[0]) in block, block


def test_the_backend_image_starts_the_module_the_application_declares():
    """The entry point names the module path the package resolves.

    Every application module imports itself as ``backend.app.*``, and the
    entry point is asserted to name that path. DL-374
    """
    body = _dockerfile_for("backend")

    started = re.search(r'"uvicorn", "([^"]+)"', body)
    assert started, body
    module, _colon, attribute = started.group(1).partition(":")
    assert module == "backend.app.main", started.group(1)
    assert attribute == "app", started.group(1)

    # the context lands where that module path resolves from
    assert "WORKDIR /app/backend" in body, body
    assert re.search(r"^WORKDIR /app$", body, re.MULTILINE), body


@pytest.mark.parametrize("service", ("backend", "frontend"))
def test_each_healthcheck_names_a_program_its_image_carries(service):
    """No healthcheck invokes a program its base image does not ship.

    Neither base image carries curl. Each healthcheck program is asserted
    against its own base image. DL-367
    """
    block = "\n".join(_compose_service_blocks()[service])
    probe = re.search(r"^      test: \[(.+)\]$", block, re.MULTILINE)
    assert probe, block

    invoked = [
        token.strip().strip('"') for token in probe.group(1).split(",")
    ]
    assert invoked[0] == "CMD", invoked
    assert "curl" not in invoked, invoked
    assert invoked[1] in ("python", "wget"), invoked


def test_the_frontend_image_needs_no_file_the_repository_omits():
    """The install step resolves from the tracked manifest alone.

    No lock file is tracked, and the install step is asserted to resolve
    from the manifest alone. DL-375
    """
    body = _dockerfile_for("frontend")

    copied = re.findall(r"^COPY (\S+(?: \S+)*) \./?$", body, re.MULTILINE)
    for group in copied:
        for name in group.split():
            if name == ".":
                continue
            tracked = (FRONTEND_SOURCE_DIR.parent / name)
            assert tracked.is_file(), name
            listed = subprocess.run(
                ["git", "ls-files", "--error-unmatch", "frontend/" + name],
                cwd=str(REPOSITORY_ROOT),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            assert listed.returncode == 0, name

    assert "npm ci" not in body, body
    assert "npm install" in body, body


def test_the_pipeline_installs_the_frontend_the_same_way_the_image_does():
    """The workflow and the image resolve dependencies identically."""
    step = _workflow_step("Install Node.js dependencies")

    assert "npm ci" not in step, step
    assert "npm install" in step, step


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
