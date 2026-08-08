"""Regression tests for the two Alembic revisions.

The units under test are
``backend/migrations/versions/0001_add_rbac_and_subscription_columns.py``
and ``backend/migrations/versions/0002_seed_single_admin.py``. Every case
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
* ``0001`` adds the uniqueness over ``subscriptions.paypal_order_id``,
  the uniqueness over ``listings.zillow_url``, and the
  ``webhook_events`` table whose ``transmission_id`` is unique, each
  proven by a rejected duplicate insert
* ``0001`` grants no administrator, applies to a database holding no
  table, and re-applies over its own shape without changing it
* ``0002`` promotes the single address the revision names and no other,
  leaves exactly one administrator stored, is idempotent, and records
  the grant on the ``alembic`` logger
* ``0002`` grants no administrator when its target is not stored, and
  refuses to complete when more administrators are stored than it
  permits
* each revision reverses independently of the other, and the reversal of
  ``0001`` removes only what it added

Design rationale is recorded in ``docs/security/DECISION_LOG.md``.
"""

import logging

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from backend.app.core.authorization import Role

from pathlib import Path  # noqa: F401
from typing import Any

from alembic.config import Config
from sqlalchemy import create_engine

from backend.app.db import database as database_module
from backend.tests.support import REPO_ROOT


#: Revision identifier of the additive schema change.
SCHEMA_REVISION = "0001"

#: Revision identifier of the administrator grant.
ADMIN_REVISION = "0002"

#: Logger the administrator grant records its outcome on.
MIGRATION_LOGGER = "alembic.runtime.migration"

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

#: Listing target the uniqueness cases submit twice.
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


@pytest.fixture
def pre_revision_database(tmp_path):
    """Yield an engine on a database carrying the pre-revision schema.

    The database is a file of its own under ``tmp_path``, holding the six
    tables and only the columns that ``backend/migrations/versions/
    0001_add_rbac_and_subscription_columns.py`` was written to add to.
    It carries no ``alembic_version`` table, no ``webhook_events`` table,
    and none of the columns either revision adds, so a revision applied
    to it performs the work it would perform against a deployment that
    predates it.
    """
    engine = create_engine(
        "sqlite+pysqlite:///{0}".format(
            (tmp_path / "pre_revision.db").as_posix()
        ),
        connect_args={"check_same_thread": False},
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
    """Yield an engine on a database holding no table at all."""
    engine = create_engine(
        "sqlite+pysqlite:///{0}".format(
            (tmp_path / "empty.db").as_posix()
        ),
        connect_args={"check_same_thread": False},
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

    ``backend/migrations/env.py`` binds its connection from
    ``backend.app.db.database.engine``. The returned callable replaces
    that attribute, and ``monkeypatch`` restores the application engine
    when the test ends.
    """

    def aim(engine: Any) -> Any:
        monkeypatch.setattr(database_module, "engine", engine)
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


def test_the_repository_holds_exactly_the_two_expected_revisions(
    alembic_config,
):
    """The chain is the schema change followed by the grant, and ends."""
    assert revision_heads(alembic_config) == (ADMIN_REVISION,)

    schema = revision_module(alembic_config, SCHEMA_REVISION)
    grant = revision_module(alembic_config, ADMIN_REVISION)

    assert schema.down_revision is None
    assert grant.down_revision == SCHEMA_REVISION


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
    seeded_pre_revision, alembic_config, migration_target, caplog
):
    """The grant is recorded with the address and the role it wrote."""
    grant = revision_module(alembic_config, ADMIN_REVISION)
    migration_target(seeded_pre_revision)

    with caplog.at_level(logging.INFO, logger=MIGRATION_LOGGER):
        command.upgrade(alembic_config, "head")

    granted = [
        record.getMessage()
        for record in caplog.records
        if record.name == MIGRATION_LOGGER
        and grant.ADMIN_EMAIL in record.getMessage()
    ]
    assert granted
    assert any(grant.ADMIN_ROLE in message for message in granted)


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
    pre_revision_database, alembic_config, migration_target, caplog
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

    with caplog.at_level(logging.INFO, logger=MIGRATION_LOGGER):
        command.upgrade(alembic_config, "head")

    assert administrator_emails(
        pre_revision_database, grant.ADMIN_ROLE
    ) == [grant.ADMIN_EMAIL]
    roles = roles_by_email(pre_revision_database)
    assert set(roles) == set(OTHER_EMAILS) | {grant.ADMIN_EMAIL}
    for email in OTHER_EMAILS:
        assert roles[email] == grant.REGISTERED_ROLE

    reported = [
        record
        for record in caplog.records
        if record.name == MIGRATION_LOGGER
        and grant.ADMIN_EMAIL in record.getMessage()
    ]
    assert reported
    assert any(
        "inserted the account and granted it the role"
        in record.getMessage()
        for record in reported
    )


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
    which is what makes the two revisions independently reversible.
    """
    grant = revision_module(alembic_config, ADMIN_REVISION)
    migration_target(seeded_pre_revision)
    command.upgrade(alembic_config, "head")

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

    command.downgrade(alembic_config, "-1")
    command.downgrade(alembic_config, "-1")

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


def test_the_documented_round_trip_applies_and_reverses_in_order(
    seeded_pre_revision, alembic_config, migration_target
):
    """The documented gate leaves the recorded revision at each step.

    The sequence is one upgrade to the head followed by two reversals,
    and the recorded revision is read after each step.
    """
    migration_target(seeded_pre_revision)

    command.upgrade(alembic_config, "head")
    assert stamped_revision(seeded_pre_revision) == ADMIN_REVISION

    command.downgrade(alembic_config, "-1")
    assert stamped_revision(seeded_pre_revision) == SCHEMA_REVISION

    command.downgrade(alembic_config, "-1")
    assert stamped_revision(seeded_pre_revision) is None

    command.upgrade(alembic_config, "head")
    assert stamped_revision(seeded_pre_revision) == ADMIN_REVISION
    grant = revision_module(alembic_config, ADMIN_REVISION)
    assert administrator_emails(
        seeded_pre_revision, grant.ADMIN_ROLE
    ) == [grant.ADMIN_EMAIL]
