"""Regression coverage for the two schema revisions.

Both revisions are driven directly against a temporary SQLite database
through an Alembic operations context, so no case depends on the
application database or on the ``alembic`` command line.

Covered here:

* revision 0001 adds the three ``users`` columns, the four
  ``subscriptions`` columns with their uniqueness constraint and the
  ``webhook_events`` table, and adds nothing to ``listings``
* revision 0001 refuses to run against a database already carrying any
  of those objects, and its reversal removes only what it created
* revision 0002 promotes exactly one administrator, refuses to complete
  when the authorized address is not stored, and is idempotent
* revision 0002 reversal returns that account to the default role and
  leaves no administrator
"""

import importlib.util
import pathlib

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

from backend.tests.support import enforce_sqlite_foreign_keys

#: Directory holding the revision modules.
VERSIONS_DIR = (
    pathlib.Path(__file__).resolve().parents[2]
    / "migrations"
    / "versions"
)

#: File name of each revision module.
RBAC_REVISION_FILE = "0001_add_rbac_and_subscription_columns.py"
ADMIN_REVISION_FILE = "0002_seed_single_admin.py"

#: Columns revision 0001 adds to ``users``.
USERS_ADDED = ("role", "failed_login_attempts", "locked_until")

#: Columns revision 0001 adds to ``subscriptions``.
SUBSCRIPTIONS_ADDED = ("plan_id", "amount", "currency", "paypal_order_id")

#: Columns the ``users`` table carries before revision 0001.
USERS_BASELINE = (
    "id",
    "email",
    "hashed_password",
    "created_at",
    "last_login",
)

#: Statement creating ``users`` as the schema preceding 0001 has it.
CREATE_USERS_BASELINE = (
    "CREATE TABLE users ("
    " id INTEGER NOT NULL PRIMARY KEY,"
    " email VARCHAR NOT NULL UNIQUE,"
    " hashed_password VARCHAR NOT NULL,"
    " created_at DATETIME NOT NULL,"
    " last_login DATETIME"
    ")"
)

#: Statement creating ``listings`` as the schema preceding 0001 has it.
CREATE_LISTINGS_BASELINE = (
    "CREATE TABLE listings ("
    " id INTEGER NOT NULL PRIMARY KEY,"
    " created_at DATETIME NOT NULL,"
    " updated_at DATETIME NOT NULL,"
    " rent FLOAT NOT NULL,"
    " broker_fee FLOAT,"
    " square_footage FLOAT,"
    " bedrooms INTEGER,"
    " bathrooms INTEGER,"
    " available_date DATETIME,"
    " street_address VARCHAR,"
    " zillow_url VARCHAR"
    ")"
)

#: Statement creating ``subscriptions`` as the schema preceding 0001 has
#: it.
CREATE_SUBSCRIPTIONS_BASELINE = (
    "CREATE TABLE subscriptions ("
    " id INTEGER NOT NULL PRIMARY KEY,"
    " user_id INTEGER NOT NULL REFERENCES users (id),"
    " start_date DATETIME NOT NULL,"
    " end_date DATETIME,"
    " status VARCHAR NOT NULL"
    ")"
)

#: Statements creating the schema preceding revision 0001, in an order
#: that satisfies the foreign keys.
BASELINE_SCHEMA = (
    CREATE_USERS_BASELINE,
    CREATE_LISTINGS_BASELINE,
    (
        "CREATE TABLE filters ("
        " id INTEGER NOT NULL PRIMARY KEY,"
        " user_id INTEGER NOT NULL REFERENCES users (id),"
        " name VARCHAR NOT NULL,"
        " created_at DATETIME NOT NULL,"
        " last_used DATETIME"
        ")"
    ),
    (
        "CREATE TABLE zip_codes ("
        " id INTEGER NOT NULL PRIMARY KEY,"
        " filter_id INTEGER NOT NULL REFERENCES filters (id),"
        " code VARCHAR NOT NULL"
        ")"
    ),
    (
        "CREATE TABLE criteria ("
        " id INTEGER NOT NULL PRIMARY KEY,"
        " filter_id INTEGER NOT NULL REFERENCES filters (id),"
        " field VARCHAR NOT NULL,"
        " operator VARCHAR NOT NULL,"
        " value VARCHAR NOT NULL"
        ")"
    ),
    CREATE_SUBSCRIPTIONS_BASELINE,
)

#: Address revision 0002 promotes.
ADMIN_EMAIL = "test@blitzy.com"

#: Address of an account revision 0002 never promotes.
OTHER_EMAIL = "member@example.com"


def _load(file_name):
    """Returns the revision module loaded from ``file_name``."""
    path = VERSIONS_DIR / file_name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RBAC = _load(RBAC_REVISION_FILE)
ADMIN = _load(ADMIN_REVISION_FILE)


def _run(connection, operation):
    """Runs one revision function against ``connection``."""
    context = MigrationContext.configure(connection)
    with Operations.context(context):
        operation()


def _columns(connection, table):
    """Returns the column names ``table`` carries."""
    return set(
        column["name"]
        for column in sa.inspect(connection).get_columns(table)
    )


def _tables(connection):
    """Returns the table names the database carries."""
    return set(sa.inspect(connection).get_table_names())


def _unique_column_sets(connection, table):
    """Returns every column set a uniqueness covers on ``table``."""
    inspector = sa.inspect(connection)
    covered = [
        tuple(constraint.get("column_names") or ())
        for constraint in inspector.get_unique_constraints(table)
    ]
    covered.extend(
        tuple(index.get("column_names") or ())
        for index in inspector.get_indexes(table)
        if index.get("unique")
    )
    return set(covered)


def _add_account(connection, email, role=None):
    """Stores one account, optionally carrying ``role``.

    Only columns the ``users`` table currently carries are named, so the
    helper works before and after revision 0001.
    """
    columns = ["email", "hashed_password", "created_at"]
    values = [":email", "'x'", "'2026-01-01 00:00:00'"]
    parameters = {"email": email}
    present = _columns(connection, "users")
    if role is not None:
        columns.append("role")
        values.append(":role")
        parameters["role"] = role
    if "failed_login_attempts" in present:
        columns.append("failed_login_attempts")
        values.append("0")
    connection.execute(
        sa.text(
            "INSERT INTO users ({0}) VALUES ({1})".format(
                ", ".join(columns), ", ".join(values)
            )
        ),
        parameters,
    )


def _role_of(connection, email):
    """Returns the role stored for ``email``."""
    return connection.execute(
        sa.text("SELECT role FROM users WHERE email = :email"),
        {"email": email},
    ).scalar()


def _administrator_count(connection):
    """Returns how many accounts hold the administrator role."""
    return connection.execute(
        sa.text("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    ).scalar()


@pytest.fixture
def connection():
    """Yields a connection to an empty temporary SQLite database.

    Foreign keys are enforced on the connection, and a row naming a
    parent that is not stored is refused.
    """
    engine = enforce_sqlite_foreign_keys(sa.create_engine("sqlite://"))
    conn = engine.connect()
    try:
        yield conn
    finally:
        conn.close()
        engine.dispose()


@pytest.fixture
def baseline(connection):
    """Yields a connection to the schema preceding revision 0001."""
    for statement in BASELINE_SCHEMA:
        connection.execute(sa.text(statement))
    return connection


class TestRbacRevision:
    """Revision 0001 adds its own objects and reverses exactly those."""

    def test_it_adds_only_its_own_columns_and_table(self, baseline):
        _run(baseline, RBAC.upgrade)

        assert _columns(baseline, "users") == set(
            USERS_BASELINE + USERS_ADDED
        )
        assert SUBSCRIPTIONS_ADDED[0] in _columns(
            baseline, "subscriptions"
        )
        assert set(SUBSCRIPTIONS_ADDED) <= _columns(
            baseline, "subscriptions"
        )
        assert "webhook_events" in _tables(baseline)

    def test_every_stored_account_reads_the_default_role(self, baseline):
        _add_account(baseline, OTHER_EMAIL)

        _run(baseline, RBAC.upgrade)

        assert _role_of(baseline, OTHER_EMAIL) == "registered"
        assert _administrator_count(baseline) == 0

    def test_it_adds_no_uniqueness_to_listings(self, baseline):
        before = _unique_column_sets(baseline, "listings")

        _run(baseline, RBAC.upgrade)

        assert _unique_column_sets(baseline, "listings") == before
        assert ("zillow_url",) not in _unique_column_sets(
            baseline, "listings"
        )

    def test_a_duplicate_provider_address_does_not_abort_it(
        self, baseline
    ):
        address = "https://www.zillow.com/homedetails/duplicated"
        for _ in range(2):
            baseline.execute(
                sa.text(
                    "INSERT INTO listings"
                    " (created_at, updated_at, rent, zillow_url)"
                    " VALUES ('2026-01-01', '2026-01-01', 1.0, :url)"
                ),
                {"url": address},
            )

        _run(baseline, RBAC.upgrade)

        assert baseline.execute(
            sa.text("SELECT COUNT(*) FROM listings")
        ).scalar() == 2

    def test_it_constrains_the_stored_order_identifier(self, baseline):
        _run(baseline, RBAC.upgrade)

        assert ("paypal_order_id",) in _unique_column_sets(
            baseline, "subscriptions"
        )

    def test_it_applies_to_an_empty_database(self, connection):
        _run(connection, RBAC.upgrade)

        assert {
            "users",
            "listings",
            "filters",
            "zip_codes",
            "criteria",
            "subscriptions",
            "webhook_events",
        } <= _tables(connection)
        assert set(USERS_ADDED) <= _columns(connection, "users")

    @pytest.mark.parametrize(
        "statement, named",
        [
            (
                "ALTER TABLE users ADD COLUMN role VARCHAR"
                " NOT NULL DEFAULT 'registered'",
                "users.role",
            ),
            (
                "ALTER TABLE subscriptions ADD COLUMN plan_id VARCHAR",
                "subscriptions.plan_id",
            ),
            (
                "CREATE TABLE webhook_events ("
                " id INTEGER NOT NULL PRIMARY KEY,"
                " transmission_id VARCHAR NOT NULL UNIQUE,"
                " event_type VARCHAR NOT NULL,"
                " received_at DATETIME NOT NULL"
                ")",
                "webhook_events",
            ),
        ],
    )
    def test_it_refuses_a_database_already_carrying_its_shape(
        self, baseline, statement, named
    ):
        baseline.execute(sa.text(statement))

        with pytest.raises(RuntimeError) as refused:
            _run(baseline, RBAC.upgrade)

        assert named in str(refused.value)

    def test_a_pre_existing_column_survives_the_refusal(self, baseline):
        baseline.execute(
            sa.text(
                "ALTER TABLE users ADD COLUMN role VARCHAR"
                " NOT NULL DEFAULT 'admin'"
            )
        )
        _add_account(baseline, ADMIN_EMAIL, "admin")

        with pytest.raises(RuntimeError):
            _run(baseline, RBAC.upgrade)

        assert "role" in _columns(baseline, "users")
        assert _role_of(baseline, ADMIN_EMAIL) == "admin"
        assert "webhook_events" not in _tables(baseline)

    def test_reversal_removes_only_what_it_created(self, baseline):
        _add_account(baseline, OTHER_EMAIL)

        _run(baseline, RBAC.upgrade)
        _run(baseline, RBAC.downgrade)

        assert _columns(baseline, "users") == set(USERS_BASELINE)
        assert not set(SUBSCRIPTIONS_ADDED) & _columns(
            baseline, "subscriptions"
        )
        assert "webhook_events" not in _tables(baseline)
        assert {
            "users",
            "listings",
            "filters",
            "zip_codes",
            "criteria",
            "subscriptions",
        } <= _tables(baseline)
        assert baseline.execute(
            sa.text("SELECT COUNT(*) FROM users WHERE email = :email"),
            {"email": OTHER_EMAIL},
        ).scalar() == 1

    def test_reversal_leaves_the_listings_corpus_intact(self, baseline):
        baseline.execute(
            sa.text(
                "INSERT INTO listings"
                " (created_at, updated_at, rent, zillow_url)"
                " VALUES ('2026-01-01', '2026-01-01', 1.0, 'https://z/1')"
            )
        )

        _run(baseline, RBAC.upgrade)
        _run(baseline, RBAC.downgrade)

        assert _columns(baseline, "listings") == {
            "id",
            "created_at",
            "updated_at",
            "rent",
            "broker_fee",
            "square_footage",
            "bedrooms",
            "bathrooms",
            "available_date",
            "street_address",
            "zillow_url",
        }
        assert baseline.execute(
            sa.text("SELECT COUNT(*) FROM listings")
        ).scalar() == 1


class TestAdministratorSeedRevision:
    """Revision 0002 leaves exactly one administrator, or it raises."""

    @pytest.fixture
    def migrated(self, baseline):
        """Returns a connection carrying revision 0001."""
        _run(baseline, RBAC.upgrade)
        return baseline

    def test_it_promotes_exactly_one_administrator(self, migrated):
        _add_account(migrated, ADMIN_EMAIL)
        _add_account(migrated, OTHER_EMAIL)

        _run(migrated, ADMIN.upgrade)

        assert _administrator_count(migrated) == 1
        assert _role_of(migrated, ADMIN_EMAIL) == "admin"
        assert _role_of(migrated, OTHER_EMAIL) == "registered"

    def test_it_stores_the_authorized_target_when_it_is_absent(
        self, migrated
    ):
        _add_account(migrated, OTHER_EMAIL)

        _run(migrated, ADMIN.upgrade)

        assert _administrator_count(migrated) == 1
        assert _role_of(migrated, ADMIN_EMAIL) == "admin"
        assert _role_of(migrated, OTHER_EMAIL) == "registered"

    def test_it_refuses_when_another_account_already_holds_the_role(
        self, migrated
    ):
        _add_account(migrated, ADMIN_EMAIL)
        _add_account(migrated, OTHER_EMAIL, "admin")

        with pytest.raises(RuntimeError) as refused:
            _run(migrated, ADMIN.upgrade)

        assert "exactly one is required" in str(refused.value)

    def test_re_applying_it_changes_nothing(self, migrated):
        _add_account(migrated, ADMIN_EMAIL)

        _run(migrated, ADMIN.upgrade)
        _run(migrated, ADMIN.upgrade)

        assert _administrator_count(migrated) == 1
        assert _role_of(migrated, ADMIN_EMAIL) == "admin"

    def test_reversal_leaves_no_administrator(self, migrated):
        _add_account(migrated, ADMIN_EMAIL)
        _add_account(migrated, OTHER_EMAIL)

        _run(migrated, ADMIN.upgrade)
        _run(migrated, ADMIN.downgrade)

        assert _administrator_count(migrated) == 0
        assert _role_of(migrated, ADMIN_EMAIL) == "registered"
        assert _role_of(migrated, OTHER_EMAIL) == "registered"

    def test_reversal_leaves_another_administrator_as_it_stands(
        self, migrated
    ):
        _add_account(migrated, ADMIN_EMAIL)
        _run(migrated, ADMIN.upgrade)
        _add_account(migrated, OTHER_EMAIL, "admin")

        _run(migrated, ADMIN.downgrade)

        assert _role_of(migrated, ADMIN_EMAIL) == "registered"
        assert _role_of(migrated, OTHER_EMAIL) == "admin"

    def test_reversal_over_an_unpromoted_account_changes_nothing(
        self, migrated
    ):
        _add_account(migrated, ADMIN_EMAIL)

        _run(migrated, ADMIN.downgrade)

        assert _administrator_count(migrated) == 0
        assert _role_of(migrated, ADMIN_EMAIL) == "registered"

    def test_it_grants_no_role_the_revision_does_not_name(
        self, migrated
    ):
        _add_account(migrated, ADMIN_EMAIL)

        _run(migrated, ADMIN.upgrade)

        stored = migrated.execute(
            sa.text("SELECT DISTINCT role FROM users")
        ).scalars().all()
        assert set(stored) == {"admin"}
