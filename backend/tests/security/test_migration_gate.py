"""Gate over the Alembic revisions that own the deployed schema.

Every other module in this suite builds its schema from
``Base.metadata`` and seeds its own rows, so none of them executes
``backend/migrations/versions/0001_add_rbac_and_subscription_columns.py``
or ``backend/migrations/versions/0002_seed_single_admin.py``. In
particular the ``admin_user`` fixture is a row this suite writes under
``admin@example.com``; it is not revision 0002's grant to
``test@blitzy.com``, and a test asserting on that fixture says nothing
about the revision. This module is what covers the revisions: it drives
the real Alembic command line in a subprocess against a database of its
own and asserts on the schema and rows that come out.

The fixtures here stay separate from the ones in
``backend/tests/conftest.py``: no fixture in that file runs Alembic, and
nothing in this module uses the in-memory database those fixtures build.

What is asserted:

* a fresh database reaches the mapped schema, including both named
  uniqueness constraints and the absence of any uniqueness over
  ``listings.zillow_url``
* exactly one account holds the administrative role afterwards, it is
  the address revision 0002 names, and every other account holds the
  default role
* the account revision 0002 stores carries no credential any password
  produces
* re-running the upgrade writes nothing further
* each revision reverses on its own, and the chain re-applies afterwards
* the reversal also succeeds against a schema built by
  ``Base.metadata.create_all``, whose uniqueness over the order column
  the migration did not create
* the offline statement stream is complete in both directions
* the schema this suite's own fixtures build enforces the foreign keys
  the models declare

A second group runs the same revisions against a real PostgreSQL 13
schema, through the same command line, and is marked ``postgres``. SQLite
reports a column's name and its constraints; it does not report the type,
precision, nullability or server default the deployed database will
carry, and it holds a numeric column as a floating-point value. What that
group asserts:

* a fresh PostgreSQL schema reaches the same mapped shape
* every column the revisions add carries the type, precision,
  nullability and server default the models declare, with the
  expectation derived from ``Base.metadata`` rather than written out
* the priced amount round-trips exactly, as ``NUMERIC(10, 2)`` and not
  as a float
* the order uniqueness is refused by the index PostgreSQL builds
* every revision in the chain reverses on PostgreSQL, one step per
  revision, and the chain re-applies afterwards leaving exactly one
  administrator
"""

import os
import re
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError

from backend.app.core.security import verify_password
from backend.app.db.models import Base, Filter, User
from backend.tests.support import REVISION_COUNT

#: Repository root, four directories above this file.
REPO_ROOT = Path(__file__).resolve().parents[3]

#: Alembic configuration the subprocesses are pointed at.
ALEMBIC_INI = REPO_ROOT / "backend" / "alembic.ini"

#: Address revision 0002 names. It is deliberately spelled out here
#: rather than imported, so a change to the revision fails this gate.
SEEDED_ADMIN_EMAIL = "test@blitzy.com"

#: Role revision 0002 grants that address.
ADMIN_ROLE = "admin"

#: Role every other account holds after the revisions apply.
DEFAULT_ROLE = "registered"

#: Address seeded before the revisions run, to stand for an account the
#: deployed database already holds.
EXISTING_EMAIL = "already.stored@example.com"

#: Stored credential of the account seeded before the revisions run.
EXISTING_CREDENTIAL = "legacy-stored-hash"

#: URL the offline statement stream is written for. No connection is
#: opened to it.
OFFLINE_URL = "postgresql://offline:offline@offline-host:5432/offline"

#: Seconds one Alembic subprocess is allowed before it is abandoned.
ALEMBIC_TIMEOUT_SECONDS = 300.0

#: Tables the revisions leave behind, beside Alembic's own.
EXPECTED_TABLES = frozenset(
    {
        "users",
        "listings",
        "filters",
        "zip_codes",
        "criteria",
        "subscriptions",
        "webhook_events",
    }
)

#: Columns revision 0001 adds to ``users``.
USERS_ADDED = ("role", "failed_login_attempts", "locked_until")

#: Columns revision 0001 adds to ``subscriptions``.
SUBSCRIPTIONS_ADDED = ("plan_id", "amount", "currency", "paypal_order_id")

#: Columns ``users`` holds before revision 0001.
USERS_PRECEDING = (
    "id",
    "email",
    "hashed_password",
    "created_at",
    "last_login",
)

#: Columns ``subscriptions`` holds before revision 0001.
SUBSCRIPTIONS_PRECEDING = (
    "id",
    "user_id",
    "start_date",
    "end_date",
    "status",
)

#: Non-unique indexes revision 0003 creates. Each is asserted present at
#: the head and absent once that revision is reversed.
WORKLOAD_INDEXES = (
    "ix_filters_user_id_id",
    "ix_zip_codes_filter_id",
    "ix_criteria_filter_id",
    "ix_subscriptions_user_id_status_end_date",
    "ix_subscriptions_user_id_plan_id_status",
    "ix_listings_zillow_url",
)

#: Partial unique index revision 0004 creates. It is asserted present at
#: the head and absent once that revision is reversed.
OPEN_INTENT_INDEX = "uq_subscriptions_open_intent_per_plan"

#: Table revision 0005 creates. It is asserted present at the head and
#: absent once that revision is reversed.
SLOT_TABLE = "login_attempt_slots"

#: Uniqueness constraints the revisions name, mapped to the columns each
#: covers.
NAMED_UNIQUENESS = {
    "subscriptions": (
        "uq_subscriptions_paypal_order_id",
        ("paypal_order_id",),
    ),
    "webhook_events": (
        "uq_webhook_events_transmission_id",
        ("transmission_id",),
    ),
}

#: Statements the offline upgrade stream must carry.
OFFLINE_UPGRADE_STATEMENTS = (
    "ALTER TABLE users ADD COLUMN role VARCHAR DEFAULT 'registered'",
    "ADD COLUMN failed_login_attempts INTEGER DEFAULT '0' NOT NULL",
    "ADD COLUMN locked_until",
    "ADD COLUMN plan_id",
    "ADD COLUMN amount NUMERIC(10, 2)",
    "ADD COLUMN currency VARCHAR DEFAULT 'USD' NOT NULL",
    "ADD COLUMN paypal_order_id",
    "ADD CONSTRAINT uq_subscriptions_paypal_order_id UNIQUE",
    "CREATE TABLE webhook_events",
    "CONSTRAINT uq_webhook_events_transmission_id UNIQUE",
    "INSERT INTO users",
    "UPDATE users SET role = 'admin'",
    SEEDED_ADMIN_EMAIL,
    "CREATE INDEX ix_filters_user_id_id ON filters (user_id, id)",
    "CREATE INDEX ix_zip_codes_filter_id ON zip_codes (filter_id)",
    "CREATE INDEX ix_criteria_filter_id ON criteria (filter_id)",
    "CREATE INDEX ix_subscriptions_user_id_status_end_date",
    "CREATE INDEX ix_subscriptions_user_id_plan_id_status",
    "CREATE INDEX ix_listings_zillow_url ON listings (zillow_url)",
    "CREATE UNIQUE INDEX uq_subscriptions_open_intent_per_plan",
    "WHERE status IN ('pending', 'failed') AND end_date IS NULL",
    "CREATE TABLE login_attempt_slots",
    "INSERT INTO login_attempt_slots",
)

#: Statements the offline downgrade stream must carry.
OFFLINE_DOWNGRADE_STATEMENTS = (
    "DROP TABLE login_attempt_slots",
    "DROP INDEX uq_subscriptions_open_intent_per_plan",
    "DROP INDEX ix_listings_zillow_url",
    "DROP INDEX ix_subscriptions_user_id_plan_id_status",
    "DROP INDEX ix_subscriptions_user_id_status_end_date",
    "DROP INDEX ix_criteria_filter_id",
    "DROP INDEX ix_zip_codes_filter_id",
    "DROP INDEX ix_filters_user_id_id",
    "UPDATE users SET role = 'registered'",
    "DROP TABLE webhook_events",
    "DROP CONSTRAINT uq_subscriptions_paypal_order_id",
    "DROP COLUMN paypal_order_id",
    "DROP COLUMN currency",
    "DROP COLUMN amount",
    "DROP COLUMN plan_id",
    "DROP COLUMN locked_until",
    "DROP COLUMN failed_login_attempts",
    "DROP COLUMN role",
)

#: Statements creating the schema that precedes revision 0001.
PRECEDING_SCHEMA = (
    """CREATE TABLE users (
        id INTEGER NOT NULL PRIMARY KEY,
        email VARCHAR NOT NULL UNIQUE,
        hashed_password VARCHAR NOT NULL,
        created_at TIMESTAMP NOT NULL,
        last_login TIMESTAMP
    )""",
    """CREATE TABLE listings (
        id INTEGER NOT NULL PRIMARY KEY,
        created_at TIMESTAMP NOT NULL,
        updated_at TIMESTAMP NOT NULL,
        rent FLOAT NOT NULL,
        broker_fee FLOAT,
        square_footage FLOAT,
        bedrooms INTEGER,
        bathrooms INTEGER,
        available_date TIMESTAMP,
        street_address VARCHAR,
        zillow_url VARCHAR
    )""",
    """CREATE TABLE filters (
        id INTEGER NOT NULL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users (id),
        name VARCHAR NOT NULL,
        created_at TIMESTAMP NOT NULL,
        last_used TIMESTAMP
    )""",
    """CREATE TABLE zip_codes (
        id INTEGER NOT NULL PRIMARY KEY,
        filter_id INTEGER NOT NULL REFERENCES filters (id),
        code VARCHAR NOT NULL
    )""",
    """CREATE TABLE criteria (
        id INTEGER NOT NULL PRIMARY KEY,
        filter_id INTEGER NOT NULL REFERENCES filters (id),
        field VARCHAR NOT NULL,
        operator VARCHAR NOT NULL,
        value VARCHAR NOT NULL
    )""",
    """CREATE TABLE subscriptions (
        id INTEGER NOT NULL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users (id),
        start_date TIMESTAMP NOT NULL,
        end_date TIMESTAMP,
        status VARCHAR NOT NULL
    )""",
)


def _sqlite_url(path):
    """Return the SQLite URL addressing ``path``."""
    return "sqlite:///{0}".format(str(path).replace("\\", "/"))


def _alembic(database_url, arguments, working_directory):
    """Run one Alembic command against ``database_url``.

    The command runs in a subprocess so that the revisions execute
    through the same entry point a deployment uses, with their own
    process, their own settings and their own engine. ``working_
    directory`` is a directory holding no environment file, so every
    setting reaches the subprocess through its environment.

    The subprocess is abandoned after :data:`ALEMBIC_TIMEOUT_SECONDS`
    and whatever it had written is reported, so a revision waiting on a
    lock ends the case rather than the run.
    """
    environment = dict(os.environ)
    environment["DATABASE_URL"] = database_url
    environment["PYTHONIOENCODING"] = "utf-8"
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                str(ALEMBIC_INI),
            ]
            + list(arguments),
            capture_output=True,
            text=True,
            env=environment,
            cwd=str(working_directory),
            timeout=ALEMBIC_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as expired:
        raise AssertionError(
            "alembic {0} did not finish within {1} seconds:\n"
            "stdout={2!r}\nstderr={3!r}".format(
                " ".join(arguments),
                ALEMBIC_TIMEOUT_SECONDS,
                expired.stdout,
                expired.stderr,
            )
        ) from None
    assert completed.returncode == 0, (
        "alembic {0} failed:\n{1}".format(
            " ".join(arguments), completed.stdout + completed.stderr
        )
    )
    return completed.stdout + completed.stderr


def _reflect(database_url):
    """Return the schema shape ``database_url`` currently carries."""
    engine = sa.create_engine(database_url)
    try:
        inspector = sa.inspect(engine)
        shape = {"tables": set(inspector.get_table_names())}
        for table in sorted(shape["tables"]):
            shape[table] = {
                "columns": set(
                    column["name"]
                    for column in inspector.get_columns(table)
                ),
                "uniqueness": set(
                    (
                        constraint.get("name"),
                        tuple(constraint.get("column_names") or []),
                    )
                    for constraint in inspector.get_unique_constraints(
                        table
                    )
                )
                | set(
                    (index.get("name"), tuple(index["column_names"]))
                    for index in inspector.get_indexes(table)
                    if index.get("unique")
                ),
            }
        return shape
    finally:
        engine.dispose()


def _index_names(database_url):
    """Return every index name the database carries, across its tables."""
    engine = sa.create_engine(database_url)
    try:
        inspector = sa.inspect(engine)
        names = set()
        for table in inspector.get_table_names():
            for index in inspector.get_indexes(table):
                if index.get("name"):
                    names.add(index["name"])
        return names
    finally:
        engine.dispose()


def _accounts(database_url):
    """Return every stored account as ``(email, role, credential)``."""
    engine = sa.create_engine(database_url)
    try:
        with engine.connect() as connection:
            rows = connection.execute(
                sa.text(
                    "SELECT email, role, hashed_password FROM users"
                    " ORDER BY email"
                )
            ).fetchall()
        return [tuple(row) for row in rows]
    finally:
        engine.dispose()


def _administrators(accounts):
    """Return the accounts holding the administrative role."""
    return [account for account in accounts if account[1] == ADMIN_ROLE]


def _write_preceding_schema(database_url, emails=()):
    """Build the schema preceding revision 0001 and seed ``emails``."""
    engine = sa.create_engine(database_url)
    try:
        with engine.begin() as connection:
            for statement in PRECEDING_SCHEMA:
                connection.execute(sa.text(statement))
            for identifier, email in enumerate(emails, start=1):
                connection.execute(
                    sa.text(
                        "INSERT INTO users"
                        " (id, email, hashed_password, created_at)"
                        " VALUES (:id, :email, :credential,"
                        " CURRENT_TIMESTAMP)"
                    ),
                    {
                        "id": identifier,
                        "email": email,
                        "credential": EXISTING_CREDENTIAL,
                    },
                )
    finally:
        engine.dispose()


def _assert_mapped_shape(shape):
    """Assert ``shape`` is the schema the revisions produce."""
    assert EXPECTED_TABLES <= shape["tables"], shape["tables"]
    for column in USERS_ADDED:
        assert column in shape["users"]["columns"]
    for column in SUBSCRIPTIONS_ADDED:
        assert column in shape["subscriptions"]["columns"]
    for table, expected in NAMED_UNIQUENESS.items():
        assert expected in shape[table]["uniqueness"], (
            table,
            shape[table]["uniqueness"],
        )
    covering_the_url = [
        entry
        for entry in shape["listings"]["uniqueness"]
        if entry[1] == ("zillow_url",)
    ]
    assert not covering_the_url, covering_the_url


def _assert_no_revision_objects(shape):
    """Assert ``shape`` holds nothing the revisions created.

    Revision 0001 creates the tables it needs when it is applied to a
    database that carries none, and records which ones it created, so
    reversing the whole chain on that database drops them again and leaves
    Alembic's own version table by itself. This is the other branch of the
    reversal from :func:`_assert_reversed_shape`, which is the branch a
    database that already held the tables takes.
    """
    assert shape["tables"] == {"alembic_version"}, shape["tables"]


def _assert_reversed_shape(shape):
    """Assert ``shape`` is the schema that precedes revision 0001."""
    assert "webhook_events" not in shape["tables"], shape["tables"]
    assert shape["users"]["columns"] == set(USERS_PRECEDING)
    assert shape["subscriptions"]["columns"] == set(
        SUBSCRIPTIONS_PRECEDING
    )
    assert "zillow_url" in shape["listings"]["columns"]


@pytest.fixture(scope="module")
def migrated_database(tmp_path_factory):
    """Return the URL of a database the revisions were applied to.

    One database serves every assertion that only reads, so the
    revisions run once for the group.
    """
    directory = tmp_path_factory.mktemp("migration_gate_head")
    url = _sqlite_url(directory / "migrated.db")
    _alembic(url, ["upgrade", "head"], directory)
    return url


def test_a_fresh_database_reaches_the_mapped_schema(migrated_database):
    """Assert ``upgrade head`` produces the schema the models declare.

    Both named uniqueness constraints are asserted by name and by
    covered column, and ``listings`` is asserted to carry no uniqueness
    over the provider address.
    """
    _assert_mapped_shape(_reflect(migrated_database))


def test_exactly_one_account_holds_the_administrative_role(
    migrated_database,
):
    """Assert the administrator count and the address that holds it.

    This is the assertion no fixture-seeded test can make: the row read
    here was written by revision 0002.
    """
    accounts = _accounts(migrated_database)
    administrators = _administrators(accounts)

    assert len(administrators) == 1, accounts
    assert administrators[0][0] == SEEDED_ADMIN_EMAIL
    assert all(
        account[1] == DEFAULT_ROLE
        for account in accounts
        if account[0] != SEEDED_ADMIN_EMAIL
    ), accounts


def test_the_seeded_administrator_has_no_usable_credential(
    migrated_database,
):
    """Assert no password verifies against the stored credential."""
    administrators = _administrators(_accounts(migrated_database))
    stored = administrators[0][2]

    for candidate in (stored, "", "TestPassw0rd!2024", ADMIN_ROLE):
        assert verify_password(candidate, stored) is False, candidate


def test_an_account_already_stored_is_promoted_in_place(tmp_path):
    """Assert the revisions promote a stored account without rewriting
    its credential.

    The address revision 0002 names is stored before the revisions run,
    alongside another account, and both are read back afterwards.
    """
    url = _sqlite_url(tmp_path / "already_stored.db")
    _write_preceding_schema(url, (EXISTING_EMAIL, SEEDED_ADMIN_EMAIL))

    _alembic(url, ["upgrade", "head"], tmp_path)

    accounts = _accounts(url)
    administrators = _administrators(accounts)
    assert len(administrators) == 1, accounts
    assert administrators[0][0] == SEEDED_ADMIN_EMAIL
    assert administrators[0][2] == EXISTING_CREDENTIAL
    assert (EXISTING_EMAIL, DEFAULT_ROLE, EXISTING_CREDENTIAL) in accounts


def test_re_applying_the_administrator_seed_writes_nothing_further(
    tmp_path,
):
    """Assert the seed is idempotent when the revision runs again.

    The version marker is moved back without reversing anything, so
    revision 0002 executes a second time over the state it produced.
    """
    url = _sqlite_url(tmp_path / "idempotent.db")
    _alembic(url, ["upgrade", "head"], tmp_path)
    first = _accounts(url)

    _alembic(url, ["stamp", "0001"], tmp_path)
    _alembic(url, ["upgrade", "head"], tmp_path)

    assert _accounts(url) == first
    assert len(_administrators(_accounts(url))) == 1


def test_each_revision_reverses_and_the_chain_re_applies(tmp_path):
    """Assert all five revisions reverse one at a time and re-apply.

    The first reversal drops the login-throttling slots and leaves the
    open-intent uniqueness, the workload indexes, the columns and the
    administrator in place; the second removes the uniqueness and leaves
    the workload indexes; the third removes the workload indexes and
    leaves both the columns and the administrator in place; the fourth
    returns the administrator to the default role and still leaves the
    columns in place; the fifth removes what revision 0001 added and
    nothing that precedes it.

    Each reversal is taken one step at a time deliberately: a named
    target would reach the base in one call and would stop asserting
    that every revision reverses on its own.
    """
    url = _sqlite_url(tmp_path / "round_trip.db")
    _write_preceding_schema(url, (EXISTING_EMAIL,))
    _alembic(url, ["upgrade", "head"], tmp_path)
    assert len(_administrators(_accounts(url))) == 1
    assert _index_names(url) >= set(WORKLOAD_INDEXES)
    assert OPEN_INTENT_INDEX in _index_names(url)
    assert SLOT_TABLE in _reflect(url)["tables"]

    _alembic(url, ["downgrade", "-1"], tmp_path)
    assert len(_administrators(_accounts(url))) == 1
    assert SLOT_TABLE not in _reflect(url)["tables"]
    assert OPEN_INTENT_INDEX in _index_names(url)
    assert _index_names(url) >= set(WORKLOAD_INDEXES)

    _alembic(url, ["downgrade", "-1"], tmp_path)
    assert len(_administrators(_accounts(url))) == 1
    assert OPEN_INTENT_INDEX not in _index_names(url)
    assert _index_names(url) >= set(WORKLOAD_INDEXES)

    _alembic(url, ["downgrade", "-1"], tmp_path)
    assert len(_administrators(_accounts(url))) == 1
    assert _index_names(url) & set(WORKLOAD_INDEXES) == set()
    _assert_mapped_shape(_reflect(url))

    _alembic(url, ["downgrade", "-1"], tmp_path)
    assert _administrators(_accounts(url)) == []
    _assert_mapped_shape(_reflect(url))

    _alembic(url, ["downgrade", "-1"], tmp_path)
    _assert_reversed_shape(_reflect(url))

    _alembic(url, ["upgrade", "head"], tmp_path)
    _assert_mapped_shape(_reflect(url))
    assert len(_administrators(_accounts(url))) == 1
    assert _index_names(url) >= set(WORKLOAD_INDEXES)
    assert OPEN_INTENT_INDEX in _index_names(url)
    assert SLOT_TABLE in _reflect(url)["tables"]


def test_the_reversal_succeeds_against_a_schema_built_from_the_models(
    tmp_path,
):
    """Assert the reversal handles a schema the revisions did not build.

    ``Base.metadata.create_all`` writes the uniqueness over the order
    column as part of the table definition, which the reversal must
    remove along with the column even though it did not create it.
    """
    url = _sqlite_url(tmp_path / "from_models.db")
    engine = sa.create_engine(url)
    try:
        Base.metadata.create_all(bind=engine)
    finally:
        engine.dispose()

    _alembic(url, ["stamp", "head"], tmp_path)
    _alembic(url, ["downgrade", "base"], tmp_path)

    _assert_reversed_shape(_reflect(url))


def test_the_offline_statement_stream_is_complete(tmp_path):
    """Assert ``--sql`` emits every statement, in both directions.

    No database is attached, so this also asserts the revisions inspect
    nothing and read no result.
    """
    emitted = _alembic(
        OFFLINE_URL, ["upgrade", "head", "--sql"], tmp_path
    )
    for statement in OFFLINE_UPGRADE_STATEMENTS:
        assert statement in emitted, statement
    assert "CREATE TABLE listings" not in emitted

    reversed_stream = _alembic(
        OFFLINE_URL, ["downgrade", "head:base", "--sql"], tmp_path
    )
    for statement in OFFLINE_DOWNGRADE_STATEMENTS:
        assert statement in reversed_stream, statement
    assert reversed_stream.index(
        "DROP CONSTRAINT uq_subscriptions_paypal_order_id"
    ) < reversed_stream.index("DROP COLUMN paypal_order_id")
    assert reversed_stream.index(
        "DROP INDEX ix_listings_zillow_url"
    ) < reversed_stream.index("DROP TABLE webhook_events")
    assert "DROP TABLE listings" not in reversed_stream


def test_the_suite_schema_enforces_the_declared_foreign_keys(
    db, registered_user
):
    """Assert a row naming no stored parent is refused.

    The schema this suite builds is SQLite, which enforces a foreign key
    only while the connection asks it to, so this asserts the fixtures
    ask.
    """
    absent_user_id = registered_user.id + 10_000
    assert (
        db.query(User).filter(User.id == absent_user_id).first() is None
    )

    db.add(
        Filter(
            user_id=absent_user_id,
            name="names an account that is not stored",
            created_at=registered_user.created_at,
        )
    )

    with pytest.raises(IntegrityError):
        db.flush()

    db.rollback()


# ---------------------------------------------------------------------
# The same revisions on PostgreSQL 13, the deployed dialect
#
# The cases above run on SQLite, which reports a column's name and its
# constraints but not the type, precision, nullability and server default
# the deployed database will carry. These cases apply the same revisions
# through the same command line to a real PostgreSQL 13 schema and
# compare each column the revisions install against the declaration in
# the models.
# ---------------------------------------------------------------------

#: Columns whose exact shape is compared against the mapped declaration.
#: Each is added or created by revision 0001. ``webhook_events.id`` is
#: excluded: it is a generated key whose server default is the sequence
#: PostgreSQL creates for it, which the models do not declare and the
#: primary-key assertions already cover.
COMPARED_COLUMNS = (
    ("users", "role"),
    ("users", "failed_login_attempts"),
    ("users", "locked_until"),
    ("subscriptions", "plan_id"),
    ("subscriptions", "amount"),
    ("subscriptions", "currency"),
    ("subscriptions", "paypal_order_id"),
    ("webhook_events", "transmission_id"),
    ("webhook_events", "event_type"),
    ("webhook_events", "received_at"),
)

#: Shape of the cast PostgreSQL appends to a reported server default.
DEFAULT_CAST = re.compile(r"::[A-Za-z0-9_ ]+(\(\d+(,\s*\d+)?\))?$")

#: Spellings of a default that stores nothing.
ABSENT_DEFAULTS = ("", "NULL")

#: Amount stored and read back to prove the numeric column keeps every
#: cent it was given. SQLite holds this column as a float and warns that
#: it cannot; PostgreSQL holds it as NUMERIC(10, 2).
EXACT_AMOUNT = Decimal("19.99")

#: Order identifier the uniqueness case stores twice.
CONTENDED_ORDER_ID = "ORDER-MIGRATION-GATE-UNIQUE"


def _normalised_default(reported):
    """Return one server default in a form both sides can be read in.

    PostgreSQL reports a default with its type cast appended and a string
    default in quotes, and reports a default of ``NULL`` as no default at
    all. Both spellings of "stores nothing" become ``None`` here.
    """
    if reported is None:
        return None
    value = DEFAULT_CAST.sub("", str(reported).strip()).strip()
    if len(value) > 1 and value.startswith("'") and value.endswith("'"):
        value = value[1:-1]
    if value.upper() in ABSENT_DEFAULTS:
        return None
    return value


def _mapped_shape(table, column):
    """Return the shape the models declare for one column."""
    declared = Base.metadata.tables[table].columns[column]
    default = declared.server_default
    return {
        "type": declared.type.compile(dialect=postgresql.dialect()),
        "nullable": declared.nullable,
        "default": _normalised_default(
            None if default is None else default.arg
        ),
    }


def _stored_shape(url, table, column):
    """Return the shape one column carries in a migrated schema."""
    engine = sa.create_engine(url)
    try:
        for reported in sa.inspect(engine).get_columns(table):
            if reported["name"] != column:
                continue
            return {
                "type": reported["type"].compile(
                    dialect=postgresql.dialect()
                ),
                "nullable": reported["nullable"],
                "default": _normalised_default(reported.get("default")),
            }
    finally:
        engine.dispose()
    return None


@pytest.fixture
def migrated_postgres_database(postgres_url, tmp_path):
    """Return the URL of the database the whole chain was applied to.

    The revisions run through the Alembic command line in a subprocess,
    exactly as the SQLite cases above drive them, against the database
    created for this case.
    """
    _alembic(postgres_url, ["upgrade", "head"], tmp_path)
    return postgres_url


@pytest.mark.postgres
def test_a_fresh_postgres_database_reaches_the_mapped_schema(
    migrated_postgres_database,
):
    """Asserts ``upgrade head`` produces the mapped schema on PostgreSQL.

    The same shape assertion the SQLite case makes, against the dialect
    the service is deployed on.
    """
    url = migrated_postgres_database
    _assert_mapped_shape(_reflect(url))


@pytest.mark.postgres
@pytest.mark.parametrize(
    "table,column",
    COMPARED_COLUMNS,
    ids=["{0}.{1}".format(*pair) for pair in COMPARED_COLUMNS],
)
def test_every_added_column_carries_the_declared_shape(
    migrated_postgres_database, table, column
):
    """Asserts type, precision, nullability and default all agree.

    The expectation is derived from ``Base.metadata`` rather than written
    out, so a change to a model that the revision does not follow -- or
    the reverse -- fails here.
    """
    url = migrated_postgres_database
    stored = _stored_shape(url, table, column)

    assert stored is not None, (table, column)
    assert stored == _mapped_shape(table, column), (table, column)


@pytest.mark.postgres
def test_the_amount_column_keeps_every_cent_on_postgres(
    migrated_postgres_database,
):
    """Asserts the priced amount round-trips exactly.

    The column is declared ``NUMERIC(10, 2)``. A dialect holding it as a
    floating-point value cannot promise this, which is why the assertion
    is made here.
    """
    url = migrated_postgres_database
    engine = sa.create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "INSERT INTO users"
                    " (email, hashed_password, created_at)"
                    " VALUES (:email, :credential, CURRENT_TIMESTAMP)"
                ),
                {
                    "email": "amount.holder@example.com",
                    "credential": EXISTING_CREDENTIAL,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO subscriptions"
                    " (user_id, start_date, status, amount, currency)"
                    " SELECT id, CURRENT_TIMESTAMP, 'active', :amount,"
                    " 'USD' FROM users WHERE email = :email"
                ),
                {"amount": EXACT_AMOUNT, "email": "amount.holder@example.com"},
            )
            stored = connection.execute(
                sa.text("SELECT amount FROM subscriptions")
            ).scalar()
    finally:
        engine.dispose()

    assert isinstance(stored, Decimal), type(stored)
    assert stored == EXACT_AMOUNT, stored


@pytest.mark.postgres
def test_the_order_uniqueness_is_enforced_by_postgres(
    migrated_postgres_database,
):
    """Asserts the order constraint refuses a second row on PostgreSQL.

    The constraint is what binds one payment order to one subscription,
    so it is asserted against the index the deployed database builds
    rather than against SQLite's.
    """
    url = migrated_postgres_database
    engine = sa.create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "INSERT INTO users"
                    " (email, hashed_password, created_at)"
                    " VALUES (:email, :credential, CURRENT_TIMESTAMP)"
                ),
                {
                    "email": "order.holder@example.com",
                    "credential": EXISTING_CREDENTIAL,
                },
            )
        statement = sa.text(
            "INSERT INTO subscriptions"
            " (user_id, start_date, status, paypal_order_id)"
            " SELECT id, CURRENT_TIMESTAMP, 'pending', :order"
            " FROM users WHERE email = :email"
        )
        parameters = {
            "order": CONTENDED_ORDER_ID,
            "email": "order.holder@example.com",
        }
        with engine.begin() as connection:
            connection.execute(statement, parameters)
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(statement, parameters)
    finally:
        engine.dispose()


@pytest.mark.postgres
def test_each_revision_reverses_on_postgres(
    migrated_postgres_database, tmp_path
):
    """Asserts every revision reverses and re-applies on PostgreSQL.

    Each added column carries a server default and each added index is
    dropped by the revision that created it, which is what makes the chain
    reversible from the code; this asserts the reversal against the
    deployed dialect rather than against SQLite's table rewrite. One
    reversal per revision is issued, counted from the chain, so a revision
    added later is reversed here too.

    The revisions were applied to a database carrying no table, so
    revision 0001 created them and the reversal drops them: what remains is
    Alembic's own version table. The other branch -- a database that
    already held the tables, where the reversal removes only what 0001
    added -- is asserted by
    ``backend/tests/integration/test_postgres_migrations.py``.
    """
    url = migrated_postgres_database

    for _ in range(REVISION_COUNT):
        _alembic(url, ["downgrade", "-1"], tmp_path)
    _assert_no_revision_objects(_reflect(url))

    _alembic(url, ["upgrade", "head"], tmp_path)
    _assert_mapped_shape(_reflect(url))
    assert len(_administrators(_accounts(url))) == 1
