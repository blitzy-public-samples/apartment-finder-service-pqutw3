"""Execution tests for the two Alembic revisions.

Every case here drives Alembic itself -- ``alembic.command.upgrade`` and
``alembic.command.downgrade`` through
:mod:`backend.migrations.env`'s online path -- against an isolated
database, rather than building the schema from ``Base.metadata``. The
revisions under test are
:mod:`backend.migrations.versions.0001_add_rbac_and_subscription_columns`
and :mod:`backend.migrations.versions.0002_seed_single_admin`.

What is asserted:

* both revisions apply to an empty database, and to a database already
  carrying the six tables that precede revision 0001
* the columns, uniqueness constraints and table revision 0001 adds are
  present afterwards, and an account and a subscription row stored before
  the upgrade read the server defaults
* a repeated upgrade changes no row and no column
* each revision downgrades on its own: revision 0002 returns the seeded
  address to the default role and revision 0001 removes exactly what it
  added, leaving the tables and columns that precede it
* after every successful upgrade exactly one account holds the
  administrative role and its address is
  ``backend.migrations.versions.0002_seed_single_admin.ADMIN_EMAIL`` --
  the post-condition the administrative grant rests on
* the administrative grant emits its audit record
* the seeded account's stored password verifies against no candidate
* an upgrade finding a second administrative account raises and writes
  nothing

Usage::

    def test_head_leaves_one_administrator(
        migration_connection, alembic_config
    ):
        command.upgrade(alembic_config(migration_connection), "head")
"""

import logging

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

from backend.app.core.security import verify_credential, verify_password
from conftest import ALEMBIC_INI

#: Address revision 0002 leaves holding the administrative role.
ADMIN_EMAIL = "test@blitzy.com"

#: Role revision 0002 grants that address.
ADMIN_ROLE = "admin"

#: Role every other account holds, and the role revision 0002's
#: downgrade returns the seeded address to.
REGISTERED_ROLE = "registered"

#: Value revision 0002 stores in ``users.hashed_password`` for the
#: account it inserts.
LOCKED_PASSWORD = "!locked-no-password-set"

#: Revision identifier of the additive schema revision.
SCHEMA_REVISION = "0001"

#: Revision identifier of the administrative-grant revision.
GRANT_REVISION = "0002"

#: Logger the administrative grant records its outcome on.
GRANT_LOGGER = "alembic.runtime.migration"

#: Columns revision 0001 adds to ``users``.
USERS_ADDED_COLUMNS = ("role", "failed_login_attempts", "locked_until")

#: Columns revision 0001 adds to ``subscriptions``.
SUBSCRIPTIONS_ADDED_COLUMNS = (
    "plan_id",
    "amount",
    "currency",
    "paypal_order_id",
)

#: Table revision 0001 creates.
WEBHOOK_EVENTS_TABLE = "webhook_events"

#: Tables that precede revision 0001.
PRE_REVISION_TABLE_NAMES = (
    "users",
    "listings",
    "filters",
    "zip_codes",
    "criteria",
    "subscriptions",
)

#: Currency a subscription row stored before the upgrade reads.
CURRENCY_DEFAULT = "USD"

#: Failed-attempt count an account stored before the upgrade reads.
FAILED_ATTEMPTS_DEFAULT = 0

#: Address of the account stored before an upgrade in the cases that
#: assert the server defaults and the promotion path.
STORED_EMAIL = "stored-before-upgrade@example.com"

#: Stored password of that account. It is not a bcrypt hash, and no case
#: here presents it as a credential.
STORED_PASSWORD = "stored-hash-placeholder"

#: Creation timestamp written for a row inserted by a case here.
STORED_CREATED_AT = "2026-01-01 00:00:00"


def _insert_account(connection, email, role=None):
    """Insert one account, naming ``role`` only when it is given."""
    if role is None:
        connection.execute(
            text(
                "INSERT INTO users (email, hashed_password, created_at)"
                " VALUES (:email, :password, :created_at)"
            ),
            {
                "email": email,
                "password": STORED_PASSWORD,
                "created_at": STORED_CREATED_AT,
            },
        )
        return
    connection.execute(
        text(
            "INSERT INTO users"
            " (email, hashed_password, created_at, role,"
            " failed_login_attempts)"
            " VALUES (:email, :password, :created_at, :role, 0)"
        ),
        {
            "email": email,
            "password": STORED_PASSWORD,
            "created_at": STORED_CREATED_AT,
            "role": role,
        },
    )


def _insert_subscription(connection, user_id):
    """Insert one subscription row naming none of the added columns."""
    connection.execute(
        text(
            "INSERT INTO subscriptions"
            " (user_id, start_date, status)"
            " VALUES (:user_id, :start_date, :status)"
        ),
        {
            "user_id": user_id,
            "start_date": STORED_CREATED_AT,
            "status": "pending",
        },
    )


def _account_id(connection, email):
    """Return the primary key of the account stored under ``email``."""
    return connection.execute(
        text("SELECT id FROM users WHERE email = :email"),
        {"email": email},
    ).scalar()


def _administrators(connection):
    """Return the addresses of every account holding the admin role."""
    return [
        row[0]
        for row in connection.execute(
            text(
                "SELECT email FROM users WHERE role = :role"
                " ORDER BY email"
            ),
            {"role": ADMIN_ROLE},
        ).fetchall()
    ]


def _role_of(connection, email):
    """Return the role stored under ``email``."""
    return connection.execute(
        text("SELECT role FROM users WHERE email = :email"),
        {"email": email},
    ).scalar()


def _stored_password(connection, email):
    """Return the stored password of the account under ``email``."""
    return connection.execute(
        text("SELECT hashed_password FROM users WHERE email = :email"),
        {"email": email},
    ).scalar()


def _column_names(connection, table):
    """Return the column names ``table`` carries on ``connection``."""
    return set(
        column["name"]
        for column in inspect(connection).get_columns(table)
    )


def _unique_columns(connection, table):
    """Return every column tuple ``table`` holds a uniqueness over."""
    inspector = inspect(connection)
    covered = set()
    for constraint in inspector.get_unique_constraints(table):
        covered.add(tuple(constraint.get("column_names") or []))
    for index in inspector.get_indexes(table):
        if index.get("unique"):
            covered.add(tuple(index.get("column_names") or []))
    return covered


def test_the_revision_chain_is_the_schema_revision_then_the_grant():
    """Assert the two revisions are ordered additive-then-grant."""
    directory = ScriptDirectory.from_config(Config(str(ALEMBIC_INI)))
    revisions = list(directory.walk_revisions())

    assert [revision.revision for revision in revisions] == [
        GRANT_REVISION,
        SCHEMA_REVISION,
    ]
    assert directory.get_revision(GRANT_REVISION).down_revision == (
        SCHEMA_REVISION
    )
    assert directory.get_revision(SCHEMA_REVISION).down_revision is None


def test_upgrade_head_builds_the_schema_on_an_empty_database(
    migration_connection, alembic_config
):
    """Assert both revisions apply to a database carrying no table."""
    assert inspect(migration_connection).get_table_names() == []

    command.upgrade(alembic_config(migration_connection), "head")

    tables = set(inspect(migration_connection).get_table_names())
    for name in PRE_REVISION_TABLE_NAMES:
        assert name in tables
    assert WEBHOOK_EVENTS_TABLE in tables

    users = _column_names(migration_connection, "users")
    for column in USERS_ADDED_COLUMNS:
        assert column in users
    subscriptions = _column_names(migration_connection, "subscriptions")
    for column in SUBSCRIPTIONS_ADDED_COLUMNS:
        assert column in subscriptions


def test_upgrade_head_leaves_exactly_one_seeded_administrator(
    migration_connection, alembic_config
):
    """Assert the post-condition the administrative grant rests on."""
    command.upgrade(alembic_config(migration_connection), "head")

    assert _administrators(migration_connection) == [ADMIN_EMAIL]
    assert _role_of(migration_connection, ADMIN_EMAIL) == ADMIN_ROLE


def test_the_seeded_administrator_holds_no_usable_credential(
    migration_connection, alembic_config
):
    """Assert no candidate password verifies against the seeded row."""
    command.upgrade(alembic_config(migration_connection), "head")

    stored = _stored_password(migration_connection, ADMIN_EMAIL)
    assert stored == LOCKED_PASSWORD
    assert verify_password(LOCKED_PASSWORD, stored) is False
    assert verify_password("", stored) is False
    assert verify_credential(LOCKED_PASSWORD, stored) is False


def test_the_grant_records_its_outcome(
    migration_connection, alembic_config, caplog
):
    """Assert the administrative grant emits its audit record."""
    with caplog.at_level(logging.INFO, logger=GRANT_LOGGER):
        command.upgrade(alembic_config(migration_connection), "head")

    records = [
        record.getMessage()
        for record in caplog.records
        if record.name == GRANT_LOGGER
        and ADMIN_EMAIL in record.getMessage()
    ]
    assert records
    assert any(ADMIN_ROLE in message for message in records)


def test_upgrade_promotes_an_account_already_stored(
    migration_connection, alembic_config, pre_revision_schema
):
    """Assert a stored seed address is promoted rather than duplicated."""
    pre_revision_schema(migration_connection)
    _insert_account(migration_connection, ADMIN_EMAIL)

    command.upgrade(alembic_config(migration_connection), "head")

    assert _administrators(migration_connection) == [ADMIN_EMAIL]
    assert (
        _stored_password(migration_connection, ADMIN_EMAIL)
        == STORED_PASSWORD
    )
    assert migration_connection.execute(
        text("SELECT COUNT(*) FROM users WHERE email = :email"),
        {"email": ADMIN_EMAIL},
    ).scalar() == 1


def test_upgrade_applies_over_the_schema_preceding_it(
    migration_connection, alembic_config, pre_revision_schema
):
    """Assert the revisions alter the six tables that precede them."""
    pre_revision_schema(migration_connection)
    _insert_account(migration_connection, STORED_EMAIL)
    _insert_subscription(
        migration_connection,
        _account_id(migration_connection, STORED_EMAIL),
    )

    command.upgrade(alembic_config(migration_connection), "head")

    users = _column_names(migration_connection, "users")
    for column in USERS_ADDED_COLUMNS:
        assert column in users
    subscriptions = _column_names(migration_connection, "subscriptions")
    for column in SUBSCRIPTIONS_ADDED_COLUMNS:
        assert column in subscriptions
    assert WEBHOOK_EVENTS_TABLE in set(
        inspect(migration_connection).get_table_names()
    )


def test_a_row_stored_before_the_upgrade_reads_the_server_defaults(
    migration_connection, alembic_config, pre_revision_schema
):
    """Assert an existing account and subscription take the defaults."""
    pre_revision_schema(migration_connection)
    _insert_account(migration_connection, STORED_EMAIL)
    _insert_subscription(
        migration_connection,
        _account_id(migration_connection, STORED_EMAIL),
    )

    command.upgrade(alembic_config(migration_connection), "head")

    account = migration_connection.execute(
        text(
            "SELECT role, failed_login_attempts, locked_until"
            " FROM users WHERE email = :email"
        ),
        {"email": STORED_EMAIL},
    ).fetchone()
    assert account[0] == REGISTERED_ROLE
    assert int(account[1]) == FAILED_ATTEMPTS_DEFAULT
    assert account[2] is None

    subscription = migration_connection.execute(
        text(
            "SELECT plan_id, amount, currency, paypal_order_id"
            " FROM subscriptions"
        )
    ).fetchone()
    assert subscription[0] is None
    assert subscription[1] is None
    assert subscription[2] == CURRENCY_DEFAULT
    assert subscription[3] is None


def test_the_upgrade_installs_the_two_uniqueness_constraints(
    migration_connection, alembic_config, pre_revision_schema
):
    """Assert each uniqueness the schema revision adds is in place.

    The revision adds no uniqueness over ``listings.zillow_url``, so its
    absence is asserted beside the two it does add.
    """
    pre_revision_schema(migration_connection)

    command.upgrade(alembic_config(migration_connection), "head")

    assert ("paypal_order_id",) in _unique_columns(
        migration_connection, "subscriptions"
    )
    assert ("transmission_id",) in _unique_columns(
        migration_connection, WEBHOOK_EVENTS_TABLE
    )
    assert ("zillow_url",) not in _unique_columns(
        migration_connection, "listings"
    )


def test_a_repeated_upgrade_changes_nothing(
    migration_connection, alembic_config
):
    """Assert re-applying the revisions is a no-op."""
    config = alembic_config(migration_connection)
    command.upgrade(config, "head")
    before = (
        set(inspect(migration_connection).get_table_names()),
        _column_names(migration_connection, "users"),
        _column_names(migration_connection, "subscriptions"),
        _administrators(migration_connection),
    )

    command.upgrade(config, "head")

    assert (
        set(inspect(migration_connection).get_table_names()),
        _column_names(migration_connection, "users"),
        _column_names(migration_connection, "subscriptions"),
        _administrators(migration_connection),
    ) == before


def test_the_grant_revision_downgrades_to_the_default_role(
    migration_connection, alembic_config
):
    """Assert the grant reverses without touching the added columns."""
    config = alembic_config(migration_connection)
    command.upgrade(config, "head")

    command.downgrade(config, "-1")

    assert _administrators(migration_connection) == []
    assert _role_of(migration_connection, ADMIN_EMAIL) == (
        REGISTERED_ROLE
    )
    users = _column_names(migration_connection, "users")
    for column in USERS_ADDED_COLUMNS:
        assert column in users


def test_the_schema_revision_downgrades_to_the_preceding_shape(
    migration_connection, alembic_config, pre_revision_schema
):
    """Assert the schema revision removes only what it added."""
    pre_revision_schema(migration_connection)
    _insert_account(migration_connection, STORED_EMAIL)
    config = alembic_config(migration_connection)
    command.upgrade(config, "head")

    command.downgrade(config, "-1")
    command.downgrade(config, "-1")

    users = _column_names(migration_connection, "users")
    for column in USERS_ADDED_COLUMNS:
        assert column not in users
    assert {"id", "email", "hashed_password", "created_at"} <= users
    subscriptions = _column_names(migration_connection, "subscriptions")
    for column in SUBSCRIPTIONS_ADDED_COLUMNS:
        assert column not in subscriptions
    tables = set(inspect(migration_connection).get_table_names())
    assert WEBHOOK_EVENTS_TABLE not in tables
    for name in PRE_REVISION_TABLE_NAMES:
        assert name in tables
    assert (
        _account_id(migration_connection, STORED_EMAIL) is not None
    )


def test_the_chain_upgrades_again_after_a_full_downgrade(
    migration_connection, alembic_config
):
    """Assert the documented upgrade, twice-down, upgrade cycle holds."""
    config = alembic_config(migration_connection)
    command.upgrade(config, "head")
    command.downgrade(config, "-1")
    command.downgrade(config, "-1")

    command.upgrade(config, "head")

    assert _administrators(migration_connection) == [ADMIN_EMAIL]
    users = _column_names(migration_connection, "users")
    for column in USERS_ADDED_COLUMNS:
        assert column in users


def test_a_second_administrator_fails_the_upgrade(
    migration_connection, alembic_config, pre_revision_schema
):
    """Assert an upgrade finding another administrator raises."""
    pre_revision_schema(migration_connection)
    config = alembic_config(migration_connection)
    command.upgrade(config, SCHEMA_REVISION)
    _insert_account(
        migration_connection, "other-admin@example.com", ADMIN_ROLE
    )

    with pytest.raises(RuntimeError) as refusal:
        command.upgrade(config, "head")

    assert ADMIN_EMAIL in str(refusal.value)
    assert ADMIN_ROLE in str(refusal.value)


def test_every_account_other_than_the_seed_holds_the_default_role(
    migration_connection, alembic_config, pre_revision_schema
):
    """Assert the grant promotes the seed address and nothing else."""
    pre_revision_schema(migration_connection)
    for index in range(3):
        _insert_account(
            migration_connection,
            "account-{0}@example.com".format(index),
        )

    command.upgrade(alembic_config(migration_connection), "head")

    roles = migration_connection.execute(
        text(
            "SELECT email, role FROM users"
            " WHERE email <> :email ORDER BY email"
        ),
        {"email": ADMIN_EMAIL},
    ).fetchall()
    assert len(roles) == 3
    for _, role in roles:
        assert role == REGISTERED_ROLE
    assert _administrators(migration_connection) == [ADMIN_EMAIL]
