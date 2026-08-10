"""Regression tests for the three Alembic revisions.

The units under test are
``backend/migrations/versions/0001_add_rbac_and_subscription_columns.py``,
``backend/migrations/versions/0002_seed_single_admin.py`` and
``backend/migrations/versions/0003_add_workload_indexes.py``. Every case
applies a revision through ``alembic.command`` against an isolated
database and reads the result back with SQL, so each assertion is about
what a revision did to a database rather than about what the model
declares.

The database most cases run against is built by the
``pre_revision_database`` fixture: the six tables the application
declared before this remediation, carrying only the columns it declared
then. A case needing a database with no table at all uses
``empty_migration_database``. Every value a case asserts against --
addresses, role names, currency, uniqueness names -- is read from the
revision modules themselves through :func:`revision_module`.

The properties covered are:

* ``0001`` adds ``role``, ``failed_login_attempts`` and ``locked_until``
  to ``users``, and every account already stored reads the role
  ``registered`` and a zero failed-attempt count
* ``0001`` adds ``plan_id``, ``amount``, ``currency`` and
  ``paypal_order_id`` to ``subscriptions``, and every row already stored
  reads the currency ``USD``
* ``0001`` adds the uniqueness over ``subscriptions.paypal_order_id``
  and the ``webhook_events`` table whose ``transmission_id`` is unique,
  each proven by a rejected duplicate insert, and adds no uniqueness
  over ``listings.zillow_url``, proven by an accepted duplicate insert
* the ``listings`` table ``0001`` leaves behind is the same table
  whichever lineage produced it -- the schema that precedes the
  revision, either database the revision migrated, and the mapped
  metadata all agree on its columns and on its uniqueness
* ``0001`` grants no administrator, applies to a database holding no
  table, and re-applies over its own shape without changing it
* ``0002`` promotes the single address the revision names and no other,
  leaves exactly one administrator stored, is idempotent, and records
  the grant on the ``alembic`` logger
* ``0002`` provisions its target address when no row for it is stored and
  grants the role to the row it inserted -- so the address it names holds
  the role whether it was already present or not, and no other stored
  account is promoted -- and it refuses to complete when more
  administrators are stored than it permits
* each revision reverses independently of the other, and the reversal of
  ``0001`` removes only what it added
* ``0002`` grants no administrator when its target is not stored, and
  refuses to complete when more administrators are stored than it
  permits
* ``0003`` creates each index it declares, over the columns it declares
  and never unique, declares the same index set the mapped metadata
  declares, leaves ``listings.zillow_url`` repeatable, re-applies over
  its own result without changing it, and reverses by removing exactly
  those indexes while the columns, the uniqueness and the administrator
  below it stay in place
* each revision reverses independently of the others, and the reversal
  of ``0001`` removes only what it added

Design rationale is recorded in ``docs/security/DECISION_LOG.md``.
"""

import ast
import contextlib
import importlib.util
import io
import json
import os
import types
from unittest import mock

import alembic
import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from backend.app.core.authorization import Role

from pathlib import Path  # noqa: F401
from typing import Any

from alembic.config import Config
from sqlalchemy import UniqueConstraint, create_engine

from backend.app.core.logging import flush_log_queue, redirect_log_stream
from backend.app.db import database as database_module
from backend.app.db.models import (
    Base,
    Listing,
    WORKLOAD_INDEX_NAMES,
)
from backend.tests.support import (
    MIGRATION_LOGGER_NAMESPACE,
    REPO_ROOT,
    enforce_sqlite_foreign_keys,
)


#: Revision identifier of the additive schema change.
SCHEMA_REVISION = "0001"

#: Revision identifier of the administrator grant.
ADMIN_REVISION = "0002"

#: Revision identifier of the workload-index change, the head of the
#: chain.
INDEX_REVISION = "0003"

#: Logger the administrator grant records its outcome on.
#: Logger the administrator grant records its outcome on. It sits inside
#: the governed migration namespace, which is where the assertions read
#: the records from.
MIGRATION_LOGGER = "alembic.runtime.migration"

#: Path of the migration environment module.
ENVIRONMENT_PATH = REPO_ROOT / "backend" / "migrations" / "env.py"

#: The one setting the migration environment reads, and the variable that
#: switches its environment-file fallback off.
#: ``test_the_environment_declares_the_names_the_suite_uses`` asserts both
#: against the module itself.
DATABASE_URL_SETTING = "DATABASE_URL"
ENV_FILE_VARIABLE = "ENV_FILE"

#: Settings the migration environment must not require. Each has no
#: default in the settings class, so importing that class without it
#: fails -- which is what a migration process must not depend on.
APPLICATION_ONLY_SETTINGS = (
    "SECRET_KEY",
    "ZILLOW_API_KEY",
    "PAYPAL_CLIENT_ID",
    "PAYPAL_CLIENT_SECRET",
    "PAYPAL_WEBHOOK_ID",
    "SENDGRID_API_KEY",
)

#: Columns ``0001`` adds to ``users``.
ADDED_USER_COLUMNS = ("role", "failed_login_attempts", "locked_until")

#: Columns ``0001`` adds to ``subscriptions``.
ADDED_SUBSCRIPTION_COLUMNS = (
    "plan_id",
    "amount",
    "currency",
    "paypal_order_id",
)

#: Columns ``users`` carries before ``0001``.
PRE_REVISION_USER_COLUMNS = (
    "id",
    "email",
    "hashed_password",
    "created_at",
    "last_login",
)

#: Columns ``subscriptions`` carries before ``0001``.
PRE_REVISION_SUBSCRIPTION_COLUMNS = (
    "id",
    "user_id",
    "start_date",
    "end_date",
    "status",
)

#: Tables that precede ``0001`` and must survive its reversal.
PRE_REVISION_TABLES = (
    "users",
    "listings",
    "filters",
    "zip_codes",
    "criteria",
    "subscriptions",
)

#: Addresses seeded alongside the one the grant names.
OTHER_EMAILS = ("first.other@example.com", "second.other@example.com")

#: Stored hash every seeded account carries. It is never verified here.
STORED_HASH = "$2b$12$0123456789012345678901.abcdefghijklmnopqrstuvwxyz01"

#: Creation timestamp every seeded account carries.
STORED_CREATED_AT = "2026-01-01 00:00:00"

#: Status every seeded subscription row carries.
STORED_STATUS = "pending"

#: Start date every seeded subscription row carries.
STORED_START_DATE = "2026-01-02 00:00:00"

#: Provider order identifier the uniqueness cases submit twice.
DUPLICATE_ORDER_ID = "ORDER-MIGRATION-DUPLICATE"

#: Delivery identifier the uniqueness cases submit twice.
DUPLICATE_TRANSMISSION_ID = "TRANSMISSION-MIGRATION-DUPLICATE"

#: Listing target the case covering the absent listing uniqueness
#: submits twice.
DUPLICATE_LISTING_URL = "https://www.zillow.com/homedetails/duplicate"


def revision_module(config, revision):
    """Return the loaded module of one revision in this repository."""
    return ScriptDirectory.from_config(config).get_revision(
        revision
    ).module


def revision_heads(config):
    """Return the revision identifiers with nothing after them."""
    return tuple(ScriptDirectory.from_config(config).get_heads())


def stamped_revision(engine):
    """Return the revision the database records, or ``None``."""
    with engine.connect() as connection:
        if not inspect(connection).has_table("alembic_version"):
            return None
        return connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar()


def execute(engine, statement, **parameters):
    """Run one statement in its own transaction."""
    with engine.begin() as connection:
        return connection.execute(text(statement), parameters)


def query(engine, statement, **parameters):
    """Return every row one statement selects, as tuples."""
    with engine.connect() as connection:
        return [
            tuple(row)
            for row in connection.execute(
                text(statement), parameters
            ).fetchall()
        ]


def seed_account(engine, email):
    """Store one pre-revision ``users`` row."""
    execute(
        engine,
        "INSERT INTO users (email, hashed_password, created_at)"
        " VALUES (:email, :hashed, :created_at)",
        email=email,
        hashed=STORED_HASH,
        created_at=STORED_CREATED_AT,
    )


def seed_subscription(engine, user_id):
    """Store one pre-revision ``subscriptions`` row."""
    execute(
        engine,
        "INSERT INTO subscriptions (user_id, start_date, status)"
        " VALUES (:user_id, :start_date, :status)",
        user_id=user_id,
        start_date=STORED_START_DATE,
        status=STORED_STATUS,
    )


def seed_listing(engine, url):
    """Store one pre-revision ``listings`` row."""
    execute(
        engine,
        "INSERT INTO listings"
        " (created_at, updated_at, rent, zillow_url)"
        " VALUES (:created_at, :created_at, :rent, :url)",
        created_at=STORED_CREATED_AT,
        rent=2400.0,
        url=url,
    )


def column_names(engine, table):
    """Return the column names ``table`` currently carries."""
    with engine.connect() as connection:
        return tuple(
            column["name"]
            for column in inspect(connection).get_columns(table)
        )


def table_names(engine):
    """Return every table the database currently holds."""
    with engine.connect() as connection:
        return tuple(sorted(inspect(connection).get_table_names()))


def index_names(engine):
    """Return every index name the database holds, across its tables."""
    with engine.connect() as connection:
        inspector = inspect(connection)
        names = set()
        for table in inspector.get_table_names():
            for index in inspector.get_indexes(table):
                if index.get("name"):
                    names.add(index["name"])
        return names


def index_definition(engine, table, name):
    """Return one index as ``(column names, unique)``, or ``None``."""
    with engine.connect() as connection:
        for index in inspect(connection).get_indexes(table):
            if index.get("name") == name:
                return (
                    tuple(index.get("column_names") or []),
                    bool(index.get("unique")),
                )
    return None


def carries_uniqueness_over(engine, table, columns):
    """Report whether a uniqueness covers exactly ``columns``.

    Both the uniqueness constraints and the unique indexes reported for
    ``table`` are examined, because a backend may record either.
    """
    wanted = list(columns)
    with engine.connect() as connection:
        inspector = inspect(connection)
        for constraint in inspector.get_unique_constraints(table):
            if list(constraint.get("column_names") or []) == wanted:
                return True
        for index in inspector.get_indexes(table):
            if not index.get("unique"):
                continue
            if list(index.get("column_names") or []) == wanted:
                return True
    return False


def uniqueness_column_sets(engine, table):
    """Return every column set ``table`` holds a uniqueness over.

    Both the uniqueness constraints and the unique indexes reported for
    ``table`` are collected: a backend may record either.
    """
    covered = set()
    with engine.connect() as connection:
        inspector = inspect(connection)
        for constraint in inspector.get_unique_constraints(table):
            covered.add(tuple(constraint.get("column_names") or []))
        for index in inspector.get_indexes(table):
            if index.get("unique"):
                covered.add(tuple(index.get("column_names") or []))
    return covered


def listing_shape(engine, table):
    """Return the stored shape of ``table`` as columns and uniqueness."""
    return (
        tuple(sorted(column_names(engine, table))),
        frozenset(uniqueness_column_sets(engine, table)),
    )


def mapped_listing_shape():
    """Return the same shape for the table the application declares."""
    mapped = Listing.__table__
    covered = set(
        tuple(column.name for column in constraint.columns)
        for constraint in mapped.constraints
        if isinstance(constraint, UniqueConstraint)
    )
    covered.update(
        tuple(column.name for column in index.columns)
        for index in mapped.indexes
        if index.unique
    )
    covered.update(
        (column.name,) for column in mapped.columns if column.unique
    )
    return (
        tuple(sorted(column.name for column in mapped.columns)),
        frozenset(covered),
    )


def roles_by_email(engine):
    """Return the stored role of every account, keyed by address."""
    return dict(
        query(engine, "SELECT email, role FROM users ORDER BY email")
    )


def administrator_emails(engine, admin_role):
    """Return the address of every account holding ``admin_role``."""
    return [
        row[0]
        for row in query(
            engine,
            "SELECT email FROM users WHERE role = :role ORDER BY email",
            role=admin_role,
        )
    ]


#: The schema that precedes revision ``0001``: the six tables the
#: application declared before this remediation, each carrying only the
#: columns it declared then. :func:`pre_revision_database` builds a
#: database from these statements.
PRE_REVISION_SCHEMA = (
    """
    CREATE TABLE users (
        id INTEGER NOT NULL PRIMARY KEY,
        email VARCHAR NOT NULL UNIQUE,
        hashed_password VARCHAR NOT NULL,
        created_at DATETIME NOT NULL,
        last_login DATETIME
    )
    """,
    """
    CREATE TABLE listings (
        id INTEGER NOT NULL PRIMARY KEY,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        rent FLOAT NOT NULL,
        broker_fee FLOAT,
        square_footage FLOAT,
        bedrooms INTEGER,
        bathrooms INTEGER,
        available_date DATETIME,
        street_address VARCHAR,
        zillow_url VARCHAR
    )
    """,
    """
    CREATE TABLE filters (
        id INTEGER NOT NULL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        name VARCHAR NOT NULL,
        created_at DATETIME NOT NULL,
        last_used DATETIME,
        FOREIGN KEY(user_id) REFERENCES users (id)
    )
    """,
    """
    CREATE TABLE zip_codes (
        id INTEGER NOT NULL PRIMARY KEY,
        filter_id INTEGER NOT NULL,
        code VARCHAR NOT NULL,
        FOREIGN KEY(filter_id) REFERENCES filters (id)
    )
    """,
    """
    CREATE TABLE criteria (
        id INTEGER NOT NULL PRIMARY KEY,
        filter_id INTEGER NOT NULL,
        field VARCHAR NOT NULL,
        operator VARCHAR NOT NULL,
        value VARCHAR NOT NULL,
        FOREIGN KEY(filter_id) REFERENCES filters (id)
    )
    """,
    """
    CREATE TABLE subscriptions (
        id INTEGER NOT NULL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        start_date DATETIME NOT NULL,
        end_date DATETIME,
        status VARCHAR NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users (id)
    )
    """,
)


@contextlib.contextmanager
def governed_records():
    """Collect the records the governed handler writes in the block.

    Every test here that records anything drives Alembic, and the Alembic
    environment installs the governed handlers itself and removes every
    foreign handler it finds -- a capture handler attached to the
    namespace included. The records are therefore read where they are
    written: the governed handler is given a buffer of its own for the
    duration, the queue is drained before the buffer is read, and each
    line is decoded, so what the block yields is the list the assertions
    read after it closes. A line that is not a JSON object raises, which
    is how a bare write is told apart from a record.
    """
    flush_log_queue()
    buffer = io.StringIO()
    previous = redirect_log_stream(buffer)
    collected = []  # type: list
    try:
        yield collected
    finally:
        flush_log_queue()
        if previous is not None:
            redirect_log_stream(previous)
        for line in buffer.getvalue().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise AssertionError(
                    "emitted line is not a record: {0!r}".format(line)
                )
            collected.append(entry)


def recorded_messages(entries, logger_prefix=MIGRATION_LOGGER_NAMESPACE):
    """Return the rendered message of each entry from ``logger_prefix``."""
    return [
        str(entry.get("message", ""))
        for entry in entries
        if str(entry.get("logger", "")).split(".")[0] == logger_prefix
    ]


@pytest.fixture
def pre_revision_database(tmp_path):
    """Yield an engine on a database carrying the pre-revision schema.

    The database is a file of its own under ``tmp_path``, holding the six
    tables and only the columns that ``backend/migrations/versions/
    0001_add_rbac_and_subscription_columns.py`` was written to add to.
    It carries no ``alembic_version`` table, no ``webhook_events`` table,
    and none of the columns either revision adds, so a revision applied
    to it performs the work it would perform against a deployment that
    predates it. Foreign keys are enforced on every connection, and a
    row naming a parent that is not stored is refused.
    """
    engine = enforce_sqlite_foreign_keys(
        create_engine(
            "sqlite+pysqlite:///{0}".format(
                (tmp_path / "pre_revision.db").as_posix()
            ),
            connect_args={"check_same_thread": False},
        )
    )
    try:
        with engine.begin() as connection:
            for statement in PRE_REVISION_SCHEMA:
                connection.execute(text(statement))
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def empty_migration_database(tmp_path):
    """Yield an engine on a database holding no table at all.

    Foreign keys are enforced on every connection, and the tables the
    revision builds from nothing refuse a row naming a parent that is
    not stored.
    """
    engine = enforce_sqlite_foreign_keys(
        create_engine(
            "sqlite+pysqlite:///{0}".format(
                (tmp_path / "empty.db").as_posix()
            ),
            connect_args={"check_same_thread": False},
        )
    )
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def alembic_config():
    """Return the Alembic configuration aimed at this repository.

    Only ``script_location`` is set, so ``config.config_file_name`` is
    ``None`` and ``backend/migrations/env.py`` applies no logging
    configuration of its own. The revisions are read from
    ``backend/migrations/versions``.
    """
    config = Config()
    config.set_main_option(
        "script_location",
        str(REPO_ROOT / "backend" / "migrations"),
    )
    return config


@pytest.fixture
def migration_target(monkeypatch):
    """Return a callable aiming the Alembic environment at an engine.

    ``backend/migrations/env.py`` resolves ``DATABASE_URL`` itself and
    builds its own engine from it, reading no other setting. The returned
    callable places the engine's URL under that name and switches
    environment-file loading off, so the environment reaches the same
    database through the resolution path a deployment uses.
    ``monkeypatch`` restores both variables when the test ends.
    """

    def aim(engine: Any) -> Any:
        monkeypatch.setenv(ENV_FILE_VARIABLE, "")
        monkeypatch.setenv(DATABASE_URL_SETTING, str(engine.url))
        return engine

    return aim


@pytest.fixture
def seeded_pre_revision(pre_revision_database, alembic_config):
    """Return a pre-revision database holding accounts and a row each.

    Three accounts are stored: the address ``0002`` names and the two in
    :data:`OTHER_EMAILS`. One subscription row belongs to the first
    account, and one listing row carries
    :data:`DUPLICATE_LISTING_URL`.
    """
    grant = revision_module(alembic_config, ADMIN_REVISION)
    seed_account(pre_revision_database, grant.ADMIN_EMAIL)
    for email in OTHER_EMAILS:
        seed_account(pre_revision_database, email)
    seed_subscription(pre_revision_database, 1)
    seed_listing(pre_revision_database, DUPLICATE_LISTING_URL)
    return pre_revision_database


# --- The revision chain ----------------------------------------------


def test_the_repository_holds_exactly_the_three_expected_revisions(
    alembic_config,
):
    """The chain is the schema change, the grant, the indexes, and ends."""
    assert revision_heads(alembic_config) == (INDEX_REVISION,)

    schema = revision_module(alembic_config, SCHEMA_REVISION)
    grant = revision_module(alembic_config, ADMIN_REVISION)
    indexes = revision_module(alembic_config, INDEX_REVISION)

    assert schema.down_revision is None
    assert grant.down_revision == SCHEMA_REVISION
    assert indexes.down_revision == ADMIN_REVISION


def test_the_revision_role_names_are_the_application_role_names(
    alembic_config,
):
    """The roles the revisions write are the roles the model defines."""
    schema = revision_module(alembic_config, SCHEMA_REVISION)
    grant = revision_module(alembic_config, ADMIN_REVISION)

    assert schema.ROLE_DEFAULT == Role.REGISTERED.value
    assert grant.REGISTERED_ROLE == Role.REGISTERED.value
    assert grant.ADMIN_ROLE == Role.ADMIN.value
    assert grant.ADMIN_ROLE != grant.REGISTERED_ROLE


# --- 0001: additive schema change ------------------------------------


def test_0001_defaults_every_stored_account_to_the_registered_role(
    seeded_pre_revision, alembic_config, migration_target
):
    """Each account stored before the revision reads the default role.

    The added columns are asserted present, and every account is read
    back carrying the default role, a zero failed-attempt count and no
    lock.
    """
    schema = revision_module(alembic_config, SCHEMA_REVISION)
    migration_target(seeded_pre_revision)

    command.upgrade(alembic_config, SCHEMA_REVISION)

    columns = column_names(seeded_pre_revision, "users")
    for added in ADDED_USER_COLUMNS:
        assert added in columns

    stored = query(
        seeded_pre_revision,
        "SELECT email, role, failed_login_attempts, locked_until"
        " FROM users ORDER BY email",
    )
    assert len(stored) == 1 + len(OTHER_EMAILS)
    for _email, role, attempts, locked_until in stored:
        assert role == schema.ROLE_DEFAULT
        assert attempts == 0
        assert locked_until is None


def test_0001_defaults_every_stored_subscription_to_the_currency(
    seeded_pre_revision, alembic_config, migration_target
):
    """The subscription row stored before the revision reads ``USD``.

    The three columns that carry no value for a row that predates the
    revision are asserted absent rather than invented.
    """
    schema = revision_module(alembic_config, SCHEMA_REVISION)
    migration_target(seeded_pre_revision)

    command.upgrade(alembic_config, SCHEMA_REVISION)

    columns = column_names(seeded_pre_revision, "subscriptions")
    for added in ADDED_SUBSCRIPTION_COLUMNS:
        assert added in columns

    stored = query(
        seeded_pre_revision,
        "SELECT currency, plan_id, amount, paypal_order_id"
        " FROM subscriptions ORDER BY id",
    )
    assert stored == [(schema.CURRENCY_DEFAULT, None, None, None)]
    assert schema.CURRENCY_DEFAULT == "USD"


def test_0001_grants_no_administrator(
    seeded_pre_revision, alembic_config, migration_target
):
    """The additive revision promotes no account, not even its target.

    The address the grant revision names is already stored, and holds
    the default role once the additive revision alone has been applied.
    """
    schema = revision_module(alembic_config, SCHEMA_REVISION)
    grant = revision_module(alembic_config, ADMIN_REVISION)
    migration_target(seeded_pre_revision)

    command.upgrade(alembic_config, SCHEMA_REVISION)

    assert administrator_emails(
        seeded_pre_revision, grant.ADMIN_ROLE
    ) == []
    roles = roles_by_email(seeded_pre_revision)
    assert roles[grant.ADMIN_EMAIL] == schema.ROLE_DEFAULT


def test_0001_adds_the_uniqueness_the_replay_defence_relies_on(
    seeded_pre_revision, alembic_config, migration_target
):
    """The delivery table exists and refuses a repeated identifier.

    The uniqueness is asserted twice: once as reported by the schema,
    and once by the database refusing a second row carrying the same
    delivery identifier.
    """
    schema = revision_module(alembic_config, SCHEMA_REVISION)
    migration_target(seeded_pre_revision)

    command.upgrade(alembic_config, SCHEMA_REVISION)

    assert schema.WEBHOOK_EVENTS in table_names(seeded_pre_revision)
    assert carries_uniqueness_over(
        seeded_pre_revision, schema.WEBHOOK_EVENTS, ["transmission_id"]
    )

    statement = (
        "INSERT INTO webhook_events (transmission_id, event_type)"
        " VALUES (:transmission_id, :event_type)"
    )
    execute(
        seeded_pre_revision,
        statement,
        transmission_id=DUPLICATE_TRANSMISSION_ID,
        event_type="PAYMENT.CAPTURE.COMPLETED",
    )
    with pytest.raises(IntegrityError):
        execute(
            seeded_pre_revision,
            statement,
            transmission_id=DUPLICATE_TRANSMISSION_ID,
            event_type="PAYMENT.CAPTURE.COMPLETED",
        )

    assert query(
        seeded_pre_revision,
        "SELECT COUNT(*) FROM webhook_events"
        " WHERE transmission_id = :transmission_id",
        transmission_id=DUPLICATE_TRANSMISSION_ID,
    ) == [(1,)]


def test_0001_adds_the_uniqueness_over_the_provider_order_identifier(
    seeded_pre_revision, alembic_config, migration_target
):
    """A second subscription row cannot carry one order identifier."""
    schema = revision_module(alembic_config, SCHEMA_REVISION)
    migration_target(seeded_pre_revision)

    command.upgrade(alembic_config, SCHEMA_REVISION)

    assert carries_uniqueness_over(
        seeded_pre_revision,
        schema.SUBSCRIPTIONS,
        ["paypal_order_id"],
    )

    execute(
        seeded_pre_revision,
        "UPDATE subscriptions SET paypal_order_id = :order_id"
        " WHERE id = 1",
        order_id=DUPLICATE_ORDER_ID,
    )
    with pytest.raises(IntegrityError):
        execute(
            seeded_pre_revision,
            "INSERT INTO subscriptions"
            " (user_id, start_date, status, paypal_order_id)"
            " VALUES (:user_id, :start_date, :status, :order_id)",
            user_id=1,
            start_date=STORED_START_DATE,
            status=STORED_STATUS,
            order_id=DUPLICATE_ORDER_ID,
        )


def test_0001_adds_no_uniqueness_over_the_listing_target(
    seeded_pre_revision, alembic_config, migration_target
):
    """Two listing rows may carry one provider target.

    The revision adds no uniqueness over ``listings.zillow_url``, so a
    corpus already holding a repeated provider address migrates, and a
    repeated address may still be stored afterwards. Ingestion
    reconciles on that column by query rather than by constraint.
    """
    schema = revision_module(alembic_config, SCHEMA_REVISION)
    migration_target(seeded_pre_revision)

    command.upgrade(alembic_config, SCHEMA_REVISION)

    assert not carries_uniqueness_over(
        seeded_pre_revision, schema.LISTINGS, ["zillow_url"]
    )
    seed_listing(seeded_pre_revision, DUPLICATE_LISTING_URL)


def test_the_listing_table_is_the_same_whichever_lineage_built_it(
    seeded_pre_revision,
    empty_migration_database,
    alembic_config,
    migration_target,
):
    """One listing shape, across every route a database can arrive by.

    Four shapes are compared: the schema that precedes the revision, that
    same database after the revision migrated it, a database the revision
    built from nothing, and the mapped metadata the application declares.
    Each is read as its column names and the sets of columns a uniqueness
    covers, and the four readings are required to be equal. An addition
    or a removal on any one route fails this case.
    """
    schema = revision_module(alembic_config, SCHEMA_REVISION)

    preceding = listing_shape(seeded_pre_revision, schema.LISTINGS)

    migration_target(seeded_pre_revision)
    command.upgrade(alembic_config, "head")
    migrated_in_place = listing_shape(seeded_pre_revision, schema.LISTINGS)

    migration_target(empty_migration_database)
    command.upgrade(alembic_config, "head")
    built_from_nothing = listing_shape(
        empty_migration_database, schema.LISTINGS
    )

    assert migrated_in_place == preceding
    assert built_from_nothing == preceding
    assert mapped_listing_shape() == preceding


def test_0001_applies_to_a_database_holding_no_table(
    empty_migration_database, alembic_config, migration_target
):
    """The revision builds every table when none is present.

    The tables built from nothing carry the same added columns and the
    same two uniqueness constraints as the tables it alters, and no
    uniqueness over the listing target, so a database created by this
    path and one migrated into it agree.
    """
    schema = revision_module(alembic_config, SCHEMA_REVISION)
    migration_target(empty_migration_database)
    assert table_names(empty_migration_database) == ()

    command.upgrade(alembic_config, SCHEMA_REVISION)

    built = table_names(empty_migration_database)
    for table in PRE_REVISION_TABLES + (schema.WEBHOOK_EVENTS,):
        assert table in built

    users = column_names(empty_migration_database, "users")
    for added in ADDED_USER_COLUMNS:
        assert added in users

    subscriptions = column_names(
        empty_migration_database, "subscriptions"
    )
    for added in ADDED_SUBSCRIPTION_COLUMNS:
        assert added in subscriptions

    for table, columns in (
        (schema.WEBHOOK_EVENTS, ["transmission_id"]),
        (schema.SUBSCRIPTIONS, ["paypal_order_id"]),
    ):
        assert carries_uniqueness_over(
            empty_migration_database, table, columns
        )
    assert not carries_uniqueness_over(
        empty_migration_database, schema.LISTINGS, ["zillow_url"]
    )


def test_0001_re_applied_over_its_own_shape_refuses_and_changes_nothing(
    seeded_pre_revision, alembic_config, migration_target
):
    """Re-applying the revision over its own result alters nothing.

    The version record is removed between the two applications, so the
    second one runs its whole body against a database that already
    carries the shape it adds. It refuses rather than reapplying, and
    names the objects already present along with the remedy, so a
    later reversal removes only objects the revision created.
    """
    migration_target(seeded_pre_revision)
    command.upgrade(alembic_config, SCHEMA_REVISION)

    before_tables = table_names(seeded_pre_revision)
    before_users = column_names(seeded_pre_revision, "users")
    before_subscriptions = column_names(
        seeded_pre_revision, "subscriptions"
    )
    before_roles = roles_by_email(seeded_pre_revision)

    execute(seeded_pre_revision, "DROP TABLE alembic_version")
    assert stamped_revision(seeded_pre_revision) is None

    with pytest.raises(RuntimeError) as refused:
        command.upgrade(alembic_config, SCHEMA_REVISION)

    message = str(refused.value)
    assert "already carries" in message
    assert "Stamp this revision" in message

    assert table_names(seeded_pre_revision) == before_tables
    assert column_names(seeded_pre_revision, "users") == before_users
    assert column_names(
        seeded_pre_revision, "subscriptions"
    ) == before_subscriptions
    assert roles_by_email(seeded_pre_revision) == before_roles


# --- 0002: the audited administrator grant ---------------------------


def test_0002_promotes_only_the_account_the_revision_names(
    seeded_pre_revision, alembic_config, migration_target
):
    """Exactly one administrator is stored, and it is the named one.

    Every other account is read back holding the default role.
    """
    grant = revision_module(alembic_config, ADMIN_REVISION)
    migration_target(seeded_pre_revision)

    command.upgrade(alembic_config, "head")

    assert administrator_emails(
        seeded_pre_revision, grant.ADMIN_ROLE
    ) == [grant.ADMIN_EMAIL]
    roles = roles_by_email(seeded_pre_revision)
    assert roles[grant.ADMIN_EMAIL] == grant.ADMIN_ROLE
    for email in OTHER_EMAILS:
        assert roles[email] == grant.REGISTERED_ROLE


def test_0002_names_the_account_the_requirement_names(alembic_config):
    """The promoted address is the one the requirement fixes."""
    grant = revision_module(alembic_config, ADMIN_REVISION)

    assert grant.ADMIN_EMAIL == "test@blitzy.com"


def test_0002_records_the_grant_on_the_migration_logger(
    seeded_pre_revision, alembic_config, migration_target
):
    """The grant names the account reference and the role it wrote.

    The reference stands in for the address, so the record correlates
    with every other run of the revision without disclosing whose
    account it is. The records are read from the stream the governed
    handler writes, which is where a deployment reads them.
    """
    grant = revision_module(alembic_config, ADMIN_REVISION)
    migration_target(seeded_pre_revision)

    with governed_records() as entries:
        command.upgrade(alembic_config, "head")

    recorded = recorded_messages(entries)
    granted = [
        message
        for message in recorded
        if grant.ADMIN_REFERENCE in message
    ]
    assert granted
    assert any(grant.ADMIN_ROLE in message for message in granted)
    for entry in entries:
        assert grant.ADMIN_EMAIL not in json.dumps(entry)


def test_0002_re_applied_grants_no_second_administrator(
    seeded_pre_revision, alembic_config, migration_target
):
    """Applying the grant twice leaves one administrator stored.

    The version record is moved back to the additive revision between
    the two applications, so the second one runs its whole body against
    an account that already holds the role.
    """
    grant = revision_module(alembic_config, ADMIN_REVISION)
    migration_target(seeded_pre_revision)

    command.upgrade(alembic_config, "head")
    first = roles_by_email(seeded_pre_revision)

    command.stamp(alembic_config, SCHEMA_REVISION)
    assert stamped_revision(seeded_pre_revision) == SCHEMA_REVISION

    command.upgrade(alembic_config, "head")

    assert roles_by_email(seeded_pre_revision) == first
    assert administrator_emails(
        seeded_pre_revision, grant.ADMIN_ROLE
    ) == [grant.ADMIN_EMAIL]


def test_0002_promotes_no_account_other_than_the_one_it_names(
    pre_revision_database, alembic_config, migration_target
):
    """Only the named address holds the role, however it arrived.

    The two accounts stored are neither of them the named address. The
    revision stores that address itself and promotes it, and neither
    stored account is touched.
    """
    grant = revision_module(alembic_config, ADMIN_REVISION)
    for email in OTHER_EMAILS:
        seed_account(pre_revision_database, email)
    migration_target(pre_revision_database)

    with governed_records() as entries:
        command.upgrade(alembic_config, "head")

    assert administrator_emails(
        pre_revision_database, grant.ADMIN_ROLE
    ) == [grant.ADMIN_EMAIL]
    roles = roles_by_email(pre_revision_database)
    assert set(roles) == set(OTHER_EMAILS) | {grant.ADMIN_EMAIL}
    for email in OTHER_EMAILS:
        assert roles[email] == grant.REGISTERED_ROLE

    reported = [
        message
        for message in recorded_messages(entries)
        if grant.ADMIN_REFERENCE in message
    ]
    assert reported
    assert any(
        "inserted the account and granted it the role" in message
        for message in reported
    )
    for entry in entries:
        assert grant.ADMIN_EMAIL not in json.dumps(entry)


def test_0002_refuses_to_complete_when_the_count_would_exceed_one(
    seeded_pre_revision, alembic_config, migration_target
):
    """The grant raises rather than leave two administrators stored.

    Two accounts other than the named one are promoted first, so the
    revision's own promotion would take the count to three. The refusal
    is asserted to be the count guard rather than any later check, the
    version record still names the additive revision, and the promotion
    the revision attempted was not kept.
    """
    grant = revision_module(alembic_config, ADMIN_REVISION)
    migration_target(seeded_pre_revision)
    command.upgrade(alembic_config, SCHEMA_REVISION)

    for email in OTHER_EMAILS:
        execute(
            seeded_pre_revision,
            "UPDATE users SET role = :role WHERE email = :email",
            role=grant.ADMIN_ROLE,
            email=email,
        )

    with pytest.raises(RuntimeError) as excinfo:
        command.upgrade(alembic_config, "head")

    message = str(excinfo.value)
    assert "post-condition failed" in message
    assert "at most one is permitted" in message
    assert stamped_revision(seeded_pre_revision) == SCHEMA_REVISION
    assert sorted(
        administrator_emails(seeded_pre_revision, grant.ADMIN_ROLE)
    ) == sorted(OTHER_EMAILS)


# --- Independent reversal --------------------------------------------


def test_0002_reverses_without_reversing_0001(
    seeded_pre_revision, alembic_config, migration_target
):
    """Reversing the grant demotes one account and nothing else.

    The columns the additive revision added are asserted still present,
    which is what makes the revisions independently reversible. The
    workload-index revision sits above the grant, so it is reversed
    first by naming the grant as the target.
    """
    grant = revision_module(alembic_config, ADMIN_REVISION)
    migration_target(seeded_pre_revision)
    command.upgrade(alembic_config, "head")
    command.downgrade(alembic_config, ADMIN_REVISION)

    command.downgrade(alembic_config, "-1")

    assert stamped_revision(seeded_pre_revision) == SCHEMA_REVISION
    assert administrator_emails(
        seeded_pre_revision, grant.ADMIN_ROLE
    ) == []
    roles = roles_by_email(seeded_pre_revision)
    assert roles[grant.ADMIN_EMAIL] == grant.REGISTERED_ROLE
    for email in OTHER_EMAILS:
        assert roles[email] == grant.REGISTERED_ROLE

    columns = column_names(seeded_pre_revision, "users")
    for added in ADDED_USER_COLUMNS:
        assert added in columns


def test_0001_reverses_to_the_schema_that_preceded_it(
    seeded_pre_revision, alembic_config, migration_target
):
    """Reversing the additive revision removes only what it added.

    The two tables it altered are read back carrying exactly their
    pre-revision columns, the delivery table it created is gone, the six
    tables that precede it remain, and the rows stored before it are
    still stored with the values they carried.
    """
    schema = revision_module(alembic_config, SCHEMA_REVISION)
    migration_target(seeded_pre_revision)
    command.upgrade(alembic_config, "head")

    command.downgrade(alembic_config, "base")

    assert stamped_revision(seeded_pre_revision) is None
    assert column_names(
        seeded_pre_revision, "users"
    ) == PRE_REVISION_USER_COLUMNS
    assert column_names(
        seeded_pre_revision, "subscriptions"
    ) == PRE_REVISION_SUBSCRIPTION_COLUMNS

    remaining = table_names(seeded_pre_revision)
    assert schema.WEBHOOK_EVENTS not in remaining
    for table in PRE_REVISION_TABLES:
        assert table in remaining

    assert not carries_uniqueness_over(
        seeded_pre_revision, schema.LISTINGS, ["zillow_url"]
    )
    assert query(
        seeded_pre_revision,
        "SELECT email, hashed_password FROM users ORDER BY email",
    ) == sorted(
        (email, STORED_HASH)
        for email in OTHER_EMAILS
        + (
            revision_module(
                alembic_config, ADMIN_REVISION
            ).ADMIN_EMAIL,
        )
    )
    assert query(
        seeded_pre_revision,
        "SELECT user_id, status FROM subscriptions ORDER BY id",
    ) == [(1, STORED_STATUS)]


# --- 0003: workload indexes ------------------------------------------


def test_0003_creates_every_index_it_declares_non_unique(
    seeded_pre_revision, alembic_config, migration_target
):
    """Each declared index exists at the head, and none is unique."""
    indexes = revision_module(alembic_config, INDEX_REVISION)
    migration_target(seeded_pre_revision)

    command.upgrade(alembic_config, "head")

    for name, table, columns in indexes.WORKLOAD_INDEXES:
        assert index_definition(seeded_pre_revision, table, name) == (
            tuple(columns),
            False,
        )


def test_0003_declares_the_indexes_the_models_declare(alembic_config):
    """The revision and the mapped metadata name the same index set."""
    indexes = revision_module(alembic_config, INDEX_REVISION)

    declared = set(name for name, _table, _columns in (
        indexes.WORKLOAD_INDEXES
    ))

    assert declared == set(WORKLOAD_INDEX_NAMES)
    assert declared == set(
        index.name
        for table in Base.metadata.sorted_tables
        for index in table.indexes
    )
    for _name, _table, columns in indexes.WORKLOAD_INDEXES:
        assert columns, "every declared index covers at least one column"


def test_0003_adds_no_uniqueness_over_the_listing_target(
    seeded_pre_revision, alembic_config, migration_target
):
    """The provider address stays repeatable once the index exists.

    The index over ``listings.zillow_url`` supports the reconciliation
    lookup, and a second row carrying one address is still accepted.
    """
    schema = revision_module(alembic_config, SCHEMA_REVISION)
    migration_target(seeded_pre_revision)

    command.upgrade(alembic_config, "head")

    assert not carries_uniqueness_over(
        seeded_pre_revision, schema.LISTINGS, ["zillow_url"]
    )
    counted = "SELECT COUNT(*) FROM listings WHERE zillow_url = :url"
    before = query(
        seeded_pre_revision, counted, url=DUPLICATE_LISTING_URL
    )[0][0]
    seed_listing(seeded_pre_revision, DUPLICATE_LISTING_URL)
    seed_listing(seeded_pre_revision, DUPLICATE_LISTING_URL)
    assert query(
        seeded_pre_revision, counted, url=DUPLICATE_LISTING_URL
    ) == [(before + 2,)]


def test_0003_re_applied_over_its_own_result_changes_nothing(
    seeded_pre_revision, alembic_config, migration_target
):
    """Re-running the revision leaves the index set as it found it."""
    migration_target(seeded_pre_revision)
    command.upgrade(alembic_config, "head")
    before = index_names(seeded_pre_revision)

    command.stamp(alembic_config, ADMIN_REVISION)
    command.upgrade(alembic_config, "head")

    assert index_names(seeded_pre_revision) == before


def test_0003_reverses_without_reversing_the_revisions_below_it(
    seeded_pre_revision, alembic_config, migration_target
):
    """Reversing the indexes removes those indexes and nothing else.

    The uniqueness the earlier revision created, the columns it added and
    the administrator the grant promoted are all asserted still in place,
    which is what makes this revision independently reversible.
    """
    schema = revision_module(alembic_config, SCHEMA_REVISION)
    grant = revision_module(alembic_config, ADMIN_REVISION)
    indexes = revision_module(alembic_config, INDEX_REVISION)
    migration_target(seeded_pre_revision)
    command.upgrade(alembic_config, "head")
    before = index_names(seeded_pre_revision)

    command.downgrade(alembic_config, "-1")

    assert stamped_revision(seeded_pre_revision) == ADMIN_REVISION
    declared = set(
        name for name, _table, _columns in indexes.WORKLOAD_INDEXES
    )
    remaining = index_names(seeded_pre_revision)
    assert remaining & declared == set()
    assert remaining == before - declared

    assert carries_uniqueness_over(
        seeded_pre_revision, schema.SUBSCRIPTIONS, [schema.ORDER_COLUMN]
    )
    columns = column_names(seeded_pre_revision, "users")
    for added in ADDED_USER_COLUMNS:
        assert added in columns
    assert administrator_emails(
        seeded_pre_revision, grant.ADMIN_ROLE
    ) == [grant.ADMIN_EMAIL]


def test_the_documented_round_trip_applies_and_reverses_in_order(
    seeded_pre_revision, alembic_config, migration_target
):
    """The documented gate leaves the recorded revision at each step.

    The sequence is one upgrade to the head followed by three reversals,
    and the recorded revision is read after each step.
    """
    migration_target(seeded_pre_revision)

    command.upgrade(alembic_config, "head")
    assert stamped_revision(seeded_pre_revision) == INDEX_REVISION

    command.downgrade(alembic_config, "-1")
    assert stamped_revision(seeded_pre_revision) == ADMIN_REVISION

    command.downgrade(alembic_config, "-1")
    assert stamped_revision(seeded_pre_revision) == SCHEMA_REVISION

    command.downgrade(alembic_config, "-1")
    assert stamped_revision(seeded_pre_revision) is None

    command.upgrade(alembic_config, "head")
    assert stamped_revision(seeded_pre_revision) == INDEX_REVISION
    grant = revision_module(alembic_config, ADMIN_REVISION)
    assert administrator_emails(
        seeded_pre_revision, grant.ADMIN_ROLE
    ) == [grant.ADMIN_EMAIL]


# --- The migration environment ----------------------------------------


def load_migration_environment():
    """Return ``backend/migrations/env.py`` as an executed module.

    Alembic executes that file with an environment context in place
    rather than importing it, so it is loaded here against a stand-in
    context that reports an online run, supplies a connection and
    switches the logging configuration off. Every call the file makes on
    that context is answered without touching a database, so the module
    body runs to completion and its declarations can be read.
    """
    context = types.SimpleNamespace()
    context.config = types.SimpleNamespace(
        attributes={"connection": object(), "configure_logger": False},
        config_file_name=None,
    )
    context.is_offline_mode = lambda: False
    context.configure = lambda **_: None
    context.begin_transaction = contextlib.nullcontext
    context.run_migrations = lambda: None

    with mock.patch.object(alembic, "context", context):
        specification = importlib.util.spec_from_file_location(
            "blitzy_migration_environment", str(ENVIRONMENT_PATH)
        )
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
    return module


@pytest.fixture
def migration_environment():
    """Yield the migration environment module."""
    return load_migration_environment()


def test_the_environment_declares_the_names_the_suite_uses(
    migration_environment
):
    """Assert the names this module aims the environment with are its own.

    The fixtures above place the database URL under one name and switch
    the environment file off under another. Both are asserted against the
    module rather than assumed, so a rename there fails here rather than
    silently aiming the revisions at the wrong database.
    """
    assert migration_environment.DATABASE_URL_SETTING == (
        DATABASE_URL_SETTING
    )
    assert migration_environment.ENV_FILE_VARIABLE == ENV_FILE_VARIABLE


def _imported_modules(path):
    """Return every module name the file at ``path`` imports."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    return imported


def _literal_strings(path):
    """Return every string literal the file at ``path`` evaluates.

    Docstrings are excluded, so prose describing what the module does not
    do is not mistaken for a value it uses.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    documented = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                   ast.ClassDef)
        ):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(
                first.value, ast.Constant
            ):
                documented.add(id(first.value))
    return set(
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in documented
    )


def test_the_environment_reads_no_application_setting(
    migration_environment
):
    """Assert the environment resolves the database URL and nothing else.

    A migration process may therefore be given the database credential
    alone. The module's imports and its evaluated string literals are
    both read: an import of the settings module, or a literal naming a
    setting that has no default, would make the process depend on a
    credential it has no use for.
    """
    imported = _imported_modules(ENVIRONMENT_PATH)
    literals = _literal_strings(ENVIRONMENT_PATH)

    assert "backend.app.core.config" not in imported
    assert "backend.app.db.database" not in imported
    assert "backend.app.db.models" in imported
    for setting in APPLICATION_ONLY_SETTINGS:
        assert setting not in literals, setting
    assert migration_environment.DATABASE_URL_SETTING in literals


def test_the_environment_connects_on_the_same_terms_as_the_application(
    migration_environment
):
    """Assert the environment's connect arguments match the application's.

    The environment builds its own engine so that it needs no application
    setting, which means the mapping exists in two places. This case is
    what keeps them in step: a change to either side without the other
    fails here.
    """
    urls = (
        "postgresql://user:pw@localhost:5432/apartment_finder",
        "postgresql+psycopg2://user:pw@localhost:5432/apartment_finder",
        "sqlite://",
        "sqlite+pysqlite:///./local.db",
        "mysql://user:pw@localhost/apartment_finder",
    )

    for url in urls:
        assert migration_environment.connect_args(url) == (
            database_module._connect_args(url)
        ), url


def test_the_environment_refuses_an_absent_url_without_naming_a_value(
    migration_environment, monkeypatch
):
    """Assert the refusal names the sources and no value."""
    monkeypatch.setenv(ENV_FILE_VARIABLE, "")
    monkeypatch.delenv(DATABASE_URL_SETTING, raising=False)

    with pytest.raises(RuntimeError) as refused:
        migration_environment.database_url()

    message = str(refused.value)
    assert message == migration_environment.MISSING_URL_MESSAGE
    assert "://" not in message
    assert "@" not in message


@pytest.mark.parametrize("supplied", ["", "   ", "\t"])
def test_the_environment_refuses_a_blank_url(
    migration_environment, monkeypatch, supplied
):
    """Assert a blank value is refused rather than used."""
    monkeypatch.setenv(ENV_FILE_VARIABLE, "")
    monkeypatch.setenv(DATABASE_URL_SETTING, supplied)

    with pytest.raises(RuntimeError):
        migration_environment.database_url()


def test_the_environment_reads_the_url_from_the_named_file(
    migration_environment, monkeypatch, tmp_path
):
    """Assert the environment-file fallback supplies the one setting."""
    named = tmp_path / "migration.env"
    named.write_text(
        "DATABASE_URL=sqlite+pysqlite:///./from-file.db\n"
        "SECRET_KEY=not-read-by-the-environment\n",
        encoding="utf-8",
    )
    monkeypatch.setenv(ENV_FILE_VARIABLE, str(named))
    monkeypatch.delenv(DATABASE_URL_SETTING, raising=False)

    assert migration_environment.database_url() == (
        "sqlite+pysqlite:///./from-file.db"
    )


def test_the_process_environment_takes_precedence_over_the_file(
    migration_environment, monkeypatch, tmp_path
):
    """Assert a supplied value is used ahead of any file."""
    named = tmp_path / "migration.env"
    named.write_text(
        "DATABASE_URL=sqlite+pysqlite:///./from-file.db\n", encoding="utf-8"
    )
    monkeypatch.setenv(ENV_FILE_VARIABLE, str(named))
    monkeypatch.setenv(
        DATABASE_URL_SETTING, "sqlite+pysqlite:///./from-environment.db"
    )

    assert migration_environment.database_url() == (
        "sqlite+pysqlite:///./from-environment.db"
    )


def test_the_offline_stream_is_marked_as_carrying_its_values(
    migration_environment
):
    """Assert the banner states what an inline-value stream implies."""
    banner = migration_environment.OFFLINE_BANNER

    assert banner.startswith("--")
    for line in banner.splitlines():
        assert line.startswith("--") or not line.strip()
    assert "sensitive" in banner.lower()
    assert "listings" not in banner


def test_an_offline_stream_file_is_created_owner_only(
    migration_environment, monkeypatch, tmp_path
):
    """Assert the named stream file is opened with restricted bits.

    The permission bits are asserted only where the platform carries
    them: Windows reports a fixed mode whatever a creating process asks
    for, so the requested mode is asserted there and the resulting bits
    on POSIX.
    """
    target = tmp_path / "stream.sql"
    monkeypatch.setenv(
        migration_environment.SQL_OUTPUT_VARIABLE, str(target)
    )

    buffer = migration_environment._offline_output_buffer()
    try:
        assert buffer is not None
        buffer.write("SELECT 1;\n")
    finally:
        buffer.close()

    assert target.read_text(encoding="utf-8") == "SELECT 1;\n"
    assert migration_environment.SQL_OUTPUT_MODE == 0o600
    if os.name == "posix":
        assert (
            os.stat(str(target)).st_mode & 0o777
        ) & ~migration_environment.SQL_OUTPUT_MODE == 0


@pytest.mark.parametrize("named", ["", "   "])
def test_no_stream_file_is_opened_when_none_is_named(
    migration_environment, monkeypatch, named
):
    """Assert a blank value leaves the stream on standard output."""
    monkeypatch.setenv(migration_environment.SQL_OUTPUT_VARIABLE, named)

    assert migration_environment._offline_output_buffer() is None
