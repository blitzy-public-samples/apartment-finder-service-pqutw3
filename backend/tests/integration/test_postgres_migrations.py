"""PostgreSQL 13 migration and persistence cases.

The rest of the suite builds its schema on in-memory SQLite, which keeps
a unit-test failure and an unavailable database server distinguishable.
The cases here run against the dialect the service is deployed on, so the
behaviour SQLite cannot show is asserted rather than assumed: the DDL the
revisions emit, the transaction the grant revision rolls back, the
row lock the login lockout depends on, the fixed-scale numeric the
subscription amount is stored as, the timezone-aware instant the lock
expiry is stored as, and the two named uniqueness constraints.

The database is named by ``POSTGRES_TEST_DATABASE_URL``. Every case here
is skipped while that variable names nothing, so this module is inert in
an environment without PostgreSQL and the suite's collected count is
unchanged by it.

``.github/workflows/ci.yml`` runs this module in a job carrying a
``postgres:13`` service, and ``.github/workflows/cd.yml`` gates its deploy
on that whole workflow, so the production dialect is verified before
anything is deployed.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from alembic import command
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError

from backend.tests.support import REVISION_IDS


#: Revision the additive schema change is recorded under.
SCHEMA_REVISION = "0001"

#: Revision the administrative grant is recorded under.
GRANT_REVISION = "0002"

#: Revision the workload indexes are recorded under.
INDEX_REVISION = "0003"

#: Revision at the top of the chain, read from the chain rather than
#: restated, so a revision added above the indexes one moves this with
#: it instead of leaving a stale identifier asserted here.
HEAD_REVISION = REVISION_IDS[-1]

#: The indexes revision 0003 creates, none of them unique.
WORKLOAD_INDEXES = (
    "ix_filters_user_id_id",
    "ix_zip_codes_filter_id",
    "ix_criteria_filter_id",
    "ix_subscriptions_user_id_status_end_date",
    "ix_subscriptions_user_id_plan_id_status",
    "ix_listings_zillow_url",
)

#: Address revision 0002 leaves holding the administrative role.
ADMIN_EMAIL = "test@blitzy.com"

#: Role revision 0002 grants that address.
ADMIN_ROLE = "admin"

#: Role every other account holds after the additive revision.
REGISTERED_ROLE = "registered"

#: Credential revision 0002 stores for the account it inserts. No
#: password produces it.
LOCKED_CREDENTIAL = "!locked-no-password-set"

#: The seven tables the revisions leave behind.
APPLICATION_TABLES = (
    "users",
    "listings",
    "filters",
    "zip_codes",
    "criteria",
    "subscriptions",
    "webhook_events",
)

#: The table Alembic records the applied revision in.
VERSION_TABLE = "alembic_version"

#: Columns revision 0001 adds to ``users``.
USERS_ADDED_COLUMNS = ("role", "failed_login_attempts", "locked_until")

#: Columns revision 0001 adds to ``subscriptions``.
SUBSCRIPTIONS_ADDED_COLUMNS = (
    "plan_id",
    "amount",
    "currency",
    "paypal_order_id",
)

#: The uniqueness constraints revision 0001 adds, by table and name.
NAMED_UNIQUENESS = {
    "subscriptions": "uq_subscriptions_paypal_order_id",
    "webhook_events": "uq_webhook_events_transmission_id",
}

#: Stored credential the cases here write for an account of their own.
STORED_CREDENTIAL = "$2b$12$" + "a" * 53

#: Status a subscription row the cases here write carries.
STORED_STATUS = "active"

#: Amount asserted to survive a round trip at two decimal places.
STORED_AMOUNT = Decimal("19.99")


def _table_names(connection):
    """Return the table names the connected schema holds."""
    return set(inspect(connection).get_table_names())


def _column_names(connection, table):
    """Return the column names ``table`` carries."""
    return set(
        column["name"]
        for column in inspect(connection).get_columns(table)
    )


def _uniqueness_names(connection, table):
    """Return the names of the uniqueness constraints over ``table``."""
    inspector = inspect(connection)
    names = set(
        constraint.get("name")
        for constraint in inspector.get_unique_constraints(table)
    )
    names.update(
        index.get("name")
        for index in inspector.get_indexes(table)
        if index.get("unique")
    )
    return names


def _index_names(connection):
    """Return every index name the connected schema holds."""
    inspector = inspect(connection)
    names = set()
    for table in inspector.get_table_names():
        names.update(
            index.get("name") for index in inspector.get_indexes(table)
        )
    return names


def _stamped_revision(connection):
    """Return the revision Alembic records, or ``None`` when none is."""
    if VERSION_TABLE not in _table_names(connection):
        return None
    row = connection.execute(
        text("SELECT version_num FROM {0}".format(VERSION_TABLE))
    ).fetchone()
    return None if row is None else row[0]


def _administrators(connection):
    """Return the addresses holding the administrative role, sorted."""
    rows = connection.execute(
        text("SELECT email FROM users WHERE role = :role ORDER BY email"),
        {"role": ADMIN_ROLE},
    ).fetchall()
    return [row[0] for row in rows]


def _role_of(connection, email):
    """Return the role stored for ``email``, or ``None``."""
    row = connection.execute(
        text("SELECT role FROM users WHERE email = :email"),
        {"email": email},
    ).fetchone()
    return None if row is None else row[0]


def _insert_account(connection, email, role=None):
    """Store one account, optionally at ``role``."""
    if role is None:
        connection.execute(
            text(
                "INSERT INTO users (email, hashed_password, created_at)"
                " VALUES (:email, :credential, CURRENT_TIMESTAMP)"
            ),
            {"email": email, "credential": STORED_CREDENTIAL},
        )
        return
    connection.execute(
        text(
            "INSERT INTO users (email, hashed_password, created_at, role)"
            " VALUES (:email, :credential, CURRENT_TIMESTAMP, :role)"
        ),
        {
            "email": email,
            "credential": STORED_CREDENTIAL,
            "role": role,
        },
    )


def _account_id(connection, email):
    """Return the identifier stored for ``email``, or ``None``."""
    row = connection.execute(
        text("SELECT id FROM users WHERE email = :email"),
        {"email": email},
    ).fetchone()
    return None if row is None else row[0]


def test_upgrade_head_builds_the_mapped_schema(
    postgres_migration_connection, alembic_config
):
    """The revisions build every table, column and constraint on PostgreSQL.

    This is the DDL the deployed database receives. The uniqueness
    constraints are asserted by the names the models declare, because a
    reversal drops them by name.
    """
    connection = postgres_migration_connection
    assert _table_names(connection) == set()

    command.upgrade(alembic_config(connection), "head")

    tables = _table_names(connection)
    for table in APPLICATION_TABLES + (VERSION_TABLE,):
        assert table in tables, table

    users = _column_names(connection, "users")
    for column in USERS_ADDED_COLUMNS:
        assert column in users, column

    subscriptions = _column_names(connection, "subscriptions")
    for column in SUBSCRIPTIONS_ADDED_COLUMNS:
        assert column in subscriptions, column

    for table, name in NAMED_UNIQUENESS.items():
        assert name in _uniqueness_names(connection, table), (table, name)

    assert _administrators(connection) == [ADMIN_EMAIL]


def test_the_documented_round_trip_settles_on_postgresql(
    postgres_migration_connection, alembic_config
):
    """Upgrade, reversal to the base and a re-upgrade leave one admin.

    This is the gate the project's own verification table names, run
    against the deployed dialect. Each reversal names the revision it
    reverses down to rather than counting steps back from the head, so
    every assertion states the schema state it means and stays true as
    revisions are added above it. The reversals are asserted to leave
    the schema empty, so the additive revision is symmetric on the path
    a first deployment takes.
    """
    connection = postgres_migration_connection
    config = alembic_config(connection)

    command.upgrade(config, "head")
    assert _stamped_revision(connection) == HEAD_REVISION
    assert _administrators(connection) == [ADMIN_EMAIL]
    assert set(WORKLOAD_INDEXES) <= _index_names(connection)

    command.downgrade(config, SCHEMA_REVISION)
    assert _administrators(connection) == []
    assert _role_of(connection, ADMIN_EMAIL) == REGISTERED_ROLE
    assert "role" in _column_names(connection, "users")

    command.downgrade(config, "base")
    remaining = _table_names(connection)
    for table in APPLICATION_TABLES:
        assert table not in remaining, table

    command.upgrade(config, "head")
    assert _stamped_revision(connection) == HEAD_REVISION
    assert _administrators(connection) == [ADMIN_EMAIL]
    assert "webhook_events" in _table_names(connection)
    assert set(WORKLOAD_INDEXES) <= _index_names(connection)


def test_the_added_columns_take_their_server_defaults(
    postgres_migration_connection, alembic_config, postgres_legacy_schema
):
    """A row stored before the revision reads the server defaults.

    The defaults are evaluated by PostgreSQL itself here, which is what
    makes an existing account land on the default role without the
    revision writing a value into it.
    """
    connection = postgres_migration_connection
    postgres_legacy_schema(connection)
    _insert_account(connection, "existing@example.com")
    identifier = _account_id(connection, "existing@example.com")
    connection.execute(
        text(
            "INSERT INTO subscriptions (user_id, start_date, status)"
            " VALUES (:user_id, CURRENT_TIMESTAMP, :status)"
        ),
        {"user_id": identifier, "status": STORED_STATUS},
    )

    command.upgrade(alembic_config(connection), "head")

    row = connection.execute(
        text(
            "SELECT role, failed_login_attempts, locked_until"
            " FROM users WHERE email = :email"
        ),
        {"email": "existing@example.com"},
    ).fetchone()
    assert row[0] == REGISTERED_ROLE
    assert row[1] == 0
    assert row[2] is None

    subscription = connection.execute(
        text(
            "SELECT currency, plan_id, amount, paypal_order_id"
            " FROM subscriptions WHERE user_id = :user_id"
        ),
        {"user_id": identifier},
    ).fetchone()
    assert subscription[0] == "USD"
    assert subscription[1] is None
    assert subscription[2] is None
    assert subscription[3] is None


def test_the_reversal_leaves_the_legacy_baseline_as_it_found_it(
    postgres_migration_connection, alembic_config, postgres_legacy_schema
):
    """Reversing over a legacy baseline removes only what was added.

    The six tables that precede the revision remain, carrying exactly
    their preceding columns, and the row stored before it is still
    stored. The reversal names ``base`` rather than counting steps, so
    it reverses the whole chain however long the chain becomes; the
    legacy tables survive because no revision created them.
    """
    connection = postgres_migration_connection
    postgres_legacy_schema(connection)
    _insert_account(connection, "kept@example.com")
    config = alembic_config(connection)
    command.upgrade(config, "head")

    command.downgrade(config, "base")

    assert _stamped_revision(connection) is None
    tables = _table_names(connection)
    for table in APPLICATION_TABLES[:-1]:
        assert table in tables, table
    assert "webhook_events" not in tables
    assert set(WORKLOAD_INDEXES) & _index_names(connection) == set()

    users = _column_names(connection, "users")
    for column in USERS_ADDED_COLUMNS:
        assert column not in users, column
    subscriptions = _column_names(connection, "subscriptions")
    for column in SUBSCRIPTIONS_ADDED_COLUMNS:
        assert column not in subscriptions, column

    assert _account_id(connection, "kept@example.com") is not None


def test_a_second_administrator_rolls_the_grant_back(
    postgres_migration_connection, alembic_config, postgres_legacy_schema
):
    """The grant refuses a second administrator and changes nothing.

    The refusal and the rollback are asserted on PostgreSQL because the
    transaction the revision is wrapped in is the database's own. The
    recorded revision stays at the additive one and no role changes.
    """
    connection = postgres_migration_connection
    postgres_legacy_schema(connection)
    config = alembic_config(connection)
    command.upgrade(config, SCHEMA_REVISION)
    _insert_account(connection, "first@example.com")
    _insert_account(connection, "second@example.com")
    connection.execute(
        text("UPDATE users SET role = :role"), {"role": ADMIN_ROLE}
    )

    with pytest.raises(RuntimeError) as failure:
        command.upgrade(config, "head")

    assert "post-condition failed" in str(failure.value)
    assert sorted(_administrators(connection)) == [
        "first@example.com",
        "second@example.com",
    ]
    assert _role_of(connection, ADMIN_EMAIL) is None


def test_the_seeded_administrator_holds_no_usable_credential(
    postgres_migration_connection, alembic_config
):
    """The account the grant inserts carries the locked marker.

    The marker is not a hash any password produces, so the account holds
    the role and no means of authenticating until an operator provisions
    one through ``python -m backend.app.core.admin_provisioning``.
    """
    connection = postgres_migration_connection
    command.upgrade(alembic_config(connection), "head")

    stored = connection.execute(
        text("SELECT hashed_password FROM users WHERE email = :email"),
        {"email": ADMIN_EMAIL},
    ).fetchone()
    assert stored[0] == LOCKED_CREDENTIAL


def test_the_order_uniqueness_refuses_a_repeat(
    postgres_migration_connection, alembic_config
):
    """Two subscriptions cannot share one payment order identifier."""
    connection = postgres_migration_connection
    command.upgrade(alembic_config(connection), "head")
    identifier = _account_id(connection, ADMIN_EMAIL)

    connection.execute(
        text(
            "INSERT INTO subscriptions"
            " (user_id, start_date, status, paypal_order_id)"
            " VALUES (:user_id, CURRENT_TIMESTAMP, :status, :order)"
        ),
        {
            "user_id": identifier,
            "status": STORED_STATUS,
            "order": "ORDER-1",
        },
    )

    with pytest.raises(IntegrityError):
        connection.execute(
            text(
                "INSERT INTO subscriptions"
                " (user_id, start_date, status, paypal_order_id)"
                " VALUES (:user_id, CURRENT_TIMESTAMP, :status, :order)"
            ),
            {
                "user_id": identifier,
                "status": STORED_STATUS,
                "order": "ORDER-1",
            },
        )


def test_the_transmission_uniqueness_refuses_a_replay(
    postgres_migration_connection, alembic_config
):
    """One delivery identifier cannot be recorded twice.

    This is the constraint the webhook route reads as a replay, so it is
    asserted on the dialect the route runs against.
    """
    connection = postgres_migration_connection
    command.upgrade(alembic_config(connection), "head")

    connection.execute(
        text(
            "INSERT INTO webhook_events (transmission_id, event_type)"
            " VALUES (:transmission, :event)"
        ),
        {"transmission": "TRANSMISSION-1", "event": "PAYMENT.CAPTURED"},
    )

    with pytest.raises(IntegrityError):
        connection.execute(
            text(
                "INSERT INTO webhook_events (transmission_id, event_type)"
                " VALUES (:transmission, :event)"
            ),
            {
                "transmission": "TRANSMISSION-1",
                "event": "PAYMENT.CAPTURED",
            },
        )


def test_the_amount_keeps_its_scale(
    postgres_migration_connection, alembic_config
):
    """The subscription amount round-trips at two decimal places.

    The column is a fixed-scale numeric, so the value read back is the
    exact decimal that was written. SQLite converts through a float and
    cannot show this.
    """
    connection = postgres_migration_connection
    command.upgrade(alembic_config(connection), "head")
    identifier = _account_id(connection, ADMIN_EMAIL)

    connection.execute(
        text(
            "INSERT INTO subscriptions"
            " (user_id, start_date, status, amount, currency)"
            " VALUES (:user_id, CURRENT_TIMESTAMP, :status, :amount,"
            " :currency)"
        ),
        {
            "user_id": identifier,
            "status": STORED_STATUS,
            "amount": STORED_AMOUNT,
            "currency": "USD",
        },
    )

    stored = connection.execute(
        text(
            "SELECT amount FROM subscriptions WHERE user_id = :user_id"
        ),
        {"user_id": identifier},
    ).fetchone()
    assert isinstance(stored[0], Decimal)
    assert stored[0] == STORED_AMOUNT
    assert str(stored[0]) == "19.99"


def test_the_lock_expiry_keeps_its_offset(
    postgres_migration_connection, alembic_config
):
    """The lock expiry round-trips as a timezone-aware instant.

    The login lockout compares that column against an aware instant, so a
    value read back without an offset would compare wrongly.
    """
    connection = postgres_migration_connection
    command.upgrade(alembic_config(connection), "head")
    expiry = datetime(2026, 8, 9, 12, 30, tzinfo=timezone.utc)

    connection.execute(
        text("UPDATE users SET locked_until = :expiry WHERE email = :email"),
        {"expiry": expiry, "email": ADMIN_EMAIL},
    )

    stored = connection.execute(
        text("SELECT locked_until FROM users WHERE email = :email"),
        {"email": ADMIN_EMAIL},
    ).fetchone()
    assert stored[0].tzinfo is not None
    assert stored[0] == expiry
    assert stored[0] - expiry == timedelta(0)


def test_a_row_lock_holds_against_a_second_reader(
    postgres_engine, postgres_migration_connection, alembic_config
):
    """A locked account row is not readable for update by another session.

    The login lockout reads the account row for update so that two
    simultaneous failures cannot both write the same attempt count. The
    lock is the database's own, so it is asserted here: a second session
    asking for the same row without waiting is refused while the first
    holds it, and succeeds once the first has ended.

    The two sessions are separate connections from the same engine, so the
    row the migration stored has to be committed for either to see it,
    which the first assertion below states.
    """
    command.upgrade(alembic_config(postgres_migration_connection), "head")

    holder = postgres_engine.connect()
    waiter = postgres_engine.connect()
    try:
        assert (
            holder.execute(
                text("SELECT COUNT(*) FROM users WHERE email = :email"),
                {"email": ADMIN_EMAIL},
            ).scalar()
            == 1
        )

        # The lock is held only for the life of a transaction, so each
        # session opens one explicitly.
        holder_transaction = holder.begin()
        holder.execute(
            text(
                "SELECT id FROM users WHERE email = :email FOR UPDATE"
            ),
            {"email": ADMIN_EMAIL},
        ).fetchone()

        refused_transaction = waiter.begin()
        with pytest.raises((OperationalError, DBAPIError)):
            waiter.execute(
                text(
                    "SELECT id FROM users WHERE email = :email"
                    " FOR UPDATE NOWAIT"
                ),
                {"email": ADMIN_EMAIL},
            ).fetchone()
        refused_transaction.rollback()

        holder_transaction.rollback()

        granted_transaction = waiter.begin()
        granted = waiter.execute(
            text(
                "SELECT id FROM users WHERE email = :email"
                " FOR UPDATE NOWAIT"
            ),
            {"email": ADMIN_EMAIL},
        ).fetchone()
        assert granted is not None
        granted_transaction.rollback()
    finally:
        holder.close()
        waiter.close()
