"""Regression tests for the administrative seed revision.

Every case here drives the revision
``backend/migrations/versions/0002_seed_single_admin.py`` itself, on an
isolated database the case owns, and asserts the stored ``users`` rows
afterwards. Nothing is asserted through a fixture that stands in for the
revision, and no case builds the application.

The properties covered are:

* ``upgrade`` against a database carrying no row for
  :data:`REVISION.ADMIN_EMAIL` provisions that address and grants it
  :data:`REVISION.ADMIN_ROLE`, so the sole administrator afterwards is
  that address
* the credential the provisioning stores matches no password, is a
  bcrypt hash of the cost the application configures, and appears in no
  log record
* ``upgrade`` against a database already carrying that address promotes
  it, leaves its stored credential byte-identical, and leaves every
  other account on the role it already held
* ``upgrade`` re-applied inserts no second row, rewrites no column and
  still leaves exactly one administrator
* ``upgrade`` refuses to complete when any other account holds
  :data:`REVISION.ADMIN_ROLE`, whether the target address is stored or
  not, and the refused run leaves the stored rows exactly as it found
  them
* the refusal names the administrator count and the target address, and
  no other account's address
* the provisioning, the grant and the demotion are each recorded on the
  ``alembic`` logger at INFO
* ``downgrade`` returns that one address to
  :data:`REVISION.REGISTERED_ROLE`, deletes no row, and touches no other
  account; a following ``upgrade`` promotes it again
* the revision is the head of the chain, revises the additive revision,
  and imports no module of the application

The schema each case starts from is built from ``Base.metadata``, and
only revision ``0002`` is driven against it. The chain itself is
asserted structurally by
:func:`test_the_revision_is_the_head_and_revises_the_additive_revision`.

Design rationale is recorded in ``docs/security/DECISION_LOG.md``.
"""

import logging
import types
from datetime import datetime, timezone

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from conftest import REPO_ROOT, VALID_TEST_PASSWORD
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from backend.app.core.security import verify_password
from backend.app.db.models import Base

#: Alembic configuration of the backend, resolved from this file rather
#: than from the working directory so both invocations of the suite
#: reach it.
ALEMBIC_CONFIG = Config(str(REPO_ROOT / "backend" / "alembic.ini"))

#: Directory the revision files are read from.
SCRIPT_DIRECTORY = ScriptDirectory.from_config(ALEMBIC_CONFIG)

#: Identifier of the revision under test.
REVISION_ID = "0002"

#: Identifier of the additive revision it follows.
ADDITIVE_REVISION_ID = "0001"

#: The revision module under test, loaded through Alembic so the
#: identifier, the filename and the chain are the ones
#: ``alembic upgrade head`` would use.
REVISION = SCRIPT_DIRECTORY.get_revision(REVISION_ID).module

#: Address the revision provisions and promotes.
TARGET_EMAIL = REVISION.ADMIN_EMAIL

#: Role it grants that address.
ADMIN_ROLE = REVISION.ADMIN_ROLE

#: Role its downgrade returns that address to.
REGISTERED_ROLE = REVISION.REGISTERED_ROLE

#: Cost factor the application configures for stored credentials, and
#: the prefix a hash carrying it begins with.
EXPECTED_HASH_PREFIX = "$2b$12$"

#: Addresses the cases seed alongside the target.
BYSTANDER_EMAIL = "bystander@example.com"
INTRUDER_EMAIL = "intruder@example.com"

#: A stored hash seeded rows carry. It is a well-formed bcrypt hash of
#: a value no case supplies.
SEEDED_HASH = "$2b$12$" + "a" * 53

#: Candidate passwords asserted against the provisioned credential. The
#: last entry is the password every fixture-seeded account uses.
CREDENTIAL_CANDIDATES = (
    "",
    " ",
    "admin",
    "password",
    "changeme",
    TARGET_EMAIL,
    TARGET_EMAIL.split("@")[0],
    ADMIN_ROLE,
    VALID_TEST_PASSWORD,
)

#: The ``users`` columns the seeding helper names.
SEED_TABLE = sa.table(
    "users",
    sa.column("email", sa.String),
    sa.column("hashed_password", sa.String),
    sa.column("created_at", sa.DateTime),
    sa.column("role", sa.String),
)

#: Every column of ``users``, in the order a state snapshot carries
#: them. Both the snapshot query and the mapping it is read into are
#: built from this one construct.
SNAPSHOT_TABLE = sa.table(
    "users",
    sa.column("id", sa.Integer),
    sa.column("email", sa.String),
    sa.column("hashed_password", sa.String),
    sa.column("created_at", sa.DateTime),
    sa.column("last_login", sa.DateTime),
    sa.column("role", sa.String),
    sa.column("failed_login_attempts", sa.Integer),
    sa.column("locked_until", sa.DateTime),
)

#: The names of those columns, in the same order.
SNAPSHOT_COLUMNS = tuple(
    column.name for column in SNAPSHOT_TABLE.columns
)


@pytest.fixture
def migration_connection():
    """Yield one connection to a database holding an empty schema.

    The schema is built from ``Base.metadata`` on an in-memory database
    held open by a single connection, and is dropped when the case ends.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    connection = engine.connect()
    try:
        yield connection
    finally:
        connection.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def seed_account(connection, email, role=None):
    """Store one ``users`` row, and return the hash it carries.

    ``role`` defaults to the role the schema applies when an insert
    names none.
    """
    values = {
        "email": email,
        "hashed_password": SEEDED_HASH,
        "created_at": datetime.now(timezone.utc),
    }
    if role is not None:
        values["role"] = role
    connection.execute(SEED_TABLE.insert().values(**values))
    return SEEDED_HASH


def _run(connection, revision_callable):
    """Run one revision callable inside a transaction of its own.

    The transaction is committed when the callable returns and rolled
    back when it raises, matching the transaction Alembic opens around
    one revision.
    """
    transaction = connection.begin()
    try:
        with Operations.context(
            MigrationContext.configure(connection)
        ):
            revision_callable()
    except Exception:
        transaction.rollback()
        raise
    transaction.commit()


def run_upgrade(connection):
    """Apply the revision under test."""
    _run(connection, REVISION.upgrade)


def run_downgrade(connection):
    """Reverse the revision under test."""
    _run(connection, REVISION.downgrade)


def snapshot(connection):
    """Return every ``users`` row, ordered, as a list of tuples."""
    rows = connection.execute(
        sa.select(*SNAPSHOT_TABLE.columns).order_by(
            SNAPSHOT_TABLE.c.email
        )
    ).fetchall()
    return [tuple(row) for row in rows]


def roles_by_email(connection):
    """Return the stored role of every account, keyed by address."""
    rows = connection.execute(
        sa.text("SELECT email, role FROM users")
    ).fetchall()
    return dict((row[0], row[1]) for row in rows)


def administrators(connection):
    """Return the addresses holding :data:`ADMIN_ROLE`, ordered."""
    rows = connection.execute(
        sa.text(
            "SELECT email FROM users WHERE role = :role ORDER BY email"
        ),
        {"role": ADMIN_ROLE},
    ).fetchall()
    return [row[0] for row in rows]


def stored_account(connection, email):
    """Return one account's stored columns as a mapping, or ``None``."""
    row = connection.execute(
        sa.select(*SNAPSHOT_TABLE.columns).where(
            SNAPSHOT_TABLE.c.email == email
        )
    ).fetchone()
    if row is None:
        return None
    return dict(zip(SNAPSHOT_COLUMNS, tuple(row)))


def revision_records(caplog):
    """Return the messages the revision recorded, rendered."""
    return [
        record.getMessage()
        for record in caplog.records
        if record.name.startswith("alembic")
    ]


def test_the_target_is_provisioned_when_no_account_carries_it(
    migration_connection
):
    """Assert an empty database ends with the target as sole admin.

    Every stored column of the provisioned row is read back, including
    the role it took from the additive revision's default and the
    failed-attempt counter.
    """
    run_upgrade(migration_connection)

    assert administrators(migration_connection) == [TARGET_EMAIL]

    stored = stored_account(migration_connection, TARGET_EMAIL)
    assert stored is not None
    assert stored["role"] == ADMIN_ROLE
    assert stored["created_at"] is not None
    assert stored["failed_login_attempts"] == 0
    assert stored["locked_until"] is None
    assert stored["last_login"] is None
    assert len(snapshot(migration_connection)) == 1


@pytest.mark.parametrize("candidate", CREDENTIAL_CANDIDATES)
def test_the_provisioned_credential_matches_no_password(
    migration_connection, candidate
):
    """Assert no plausible password verifies against the credential.

    The verification is performed by
    :func:`backend.app.core.security.verify_password`, the function
    every login path compares a candidate with.
    """
    run_upgrade(migration_connection)

    stored = stored_account(migration_connection, TARGET_EMAIL)
    assert verify_password(candidate, stored["hashed_password"]) is False


def test_the_provisioned_credential_is_the_locked_sentinel(
    migration_connection
):
    """Assert the stored credential is the revision's sentinel.

    The value is deliberately not a bcrypt hash: no candidate can
    ever match it, and
    :func:`backend.app.core.security.verify_password` reads an
    unparseable stored value as a failed comparison. Storing a real
    hash instead would make the property rest on a random input
    having been discarded rather than on the stored value itself.
    """
    run_upgrade(migration_connection)

    stored = stored_account(migration_connection, TARGET_EMAIL)
    assert stored["hashed_password"] == REVISION.LOCKED_CREDENTIAL
    assert not stored["hashed_password"].startswith(
        EXPECTED_HASH_PREFIX
    )


def test_a_stored_target_is_promoted_without_its_credential_changing(
    migration_connection
):
    """Assert a stored account is promoted and not re-provisioned.

    The credential the account was stored with, its identifier, its
    creation time and the number of stored rows are all read back after
    the run.
    """
    seeded = seed_account(migration_connection, TARGET_EMAIL)
    before = stored_account(migration_connection, TARGET_EMAIL)

    run_upgrade(migration_connection)

    after = stored_account(migration_connection, TARGET_EMAIL)
    assert administrators(migration_connection) == [TARGET_EMAIL]
    assert after["hashed_password"] == seeded
    assert after["id"] == before["id"]
    assert after["created_at"] == before["created_at"]
    assert len(snapshot(migration_connection)) == 1


def test_no_other_account_changes_role(migration_connection):
    """Assert only the target's role moves.

    Three accounts are seeded at three different roles alongside the
    target, and each is read back afterwards.
    """
    seed_account(migration_connection, TARGET_EMAIL)
    seed_account(migration_connection, BYSTANDER_EMAIL, "premium")
    seed_account(migration_connection, "guest@example.com", "guest")
    seed_account(migration_connection, "member@example.com")

    run_upgrade(migration_connection)

    roles = roles_by_email(migration_connection)
    assert roles == {
        TARGET_EMAIL: ADMIN_ROLE,
        BYSTANDER_EMAIL: "premium",
        "guest@example.com": "guest",
        "member@example.com": REGISTERED_ROLE,
    }


def test_every_other_account_keeps_the_default_role(
    migration_connection
):
    """Assert the seed leaves ordinary accounts on the default role.

    This is the inventory the migration gate reads: exactly one
    administrator, and every remaining account at the default.
    """
    seed_account(migration_connection, BYSTANDER_EMAIL)
    seed_account(migration_connection, "member@example.com")

    run_upgrade(migration_connection)

    roles = roles_by_email(migration_connection)
    assert administrators(migration_connection) == [TARGET_EMAIL]
    assert [
        email
        for email, role in roles.items()
        if role != REGISTERED_ROLE
    ] == [TARGET_EMAIL]


def test_reapplying_the_upgrade_changes_nothing(migration_connection):
    """Assert a second run inserts, updates and rewrites nothing.

    Every stored column of every row is compared across the two runs,
    and so is the number of rows.
    """
    run_upgrade(migration_connection)
    first = snapshot(migration_connection)

    run_upgrade(migration_connection)
    second = snapshot(migration_connection)

    assert second == first
    assert administrators(migration_connection) == [TARGET_EMAIL]
    assert len(second) == 1


def test_reapplying_the_upgrade_over_a_stored_target_changes_nothing(
    migration_connection
):
    """Assert the same holds when the target was already stored."""
    seed_account(migration_connection, TARGET_EMAIL)
    seed_account(migration_connection, BYSTANDER_EMAIL)

    run_upgrade(migration_connection)
    first = snapshot(migration_connection)

    run_upgrade(migration_connection)

    assert snapshot(migration_connection) == first
    assert administrators(migration_connection) == [TARGET_EMAIL]


def test_a_conflicting_administrator_refuses_a_stored_target(
    migration_connection
):
    """Assert a second administrator makes the run refuse.

    The stored rows are snapshotted before the run and compared after
    it, so the refusal is asserted to have changed nothing.
    """
    seed_account(migration_connection, TARGET_EMAIL)
    seed_account(migration_connection, INTRUDER_EMAIL, ADMIN_ROLE)
    before = snapshot(migration_connection)

    with pytest.raises(RuntimeError):
        run_upgrade(migration_connection)

    assert snapshot(migration_connection) == before
    assert administrators(migration_connection) == [INTRUDER_EMAIL]
    assert roles_by_email(migration_connection)[TARGET_EMAIL] == (
        REGISTERED_ROLE
    )


def test_a_conflicting_administrator_refuses_an_absent_target(
    migration_connection
):
    """Assert the refusal also rolls back the provisioning.

    No row for the target address survives the refused run.
    """
    seed_account(migration_connection, INTRUDER_EMAIL, ADMIN_ROLE)
    before = snapshot(migration_connection)

    with pytest.raises(RuntimeError):
        run_upgrade(migration_connection)

    assert snapshot(migration_connection) == before
    assert stored_account(migration_connection, TARGET_EMAIL) is None
    assert administrators(migration_connection) == [INTRUDER_EMAIL]


def test_the_refusal_names_the_count_and_the_target_only(
    migration_connection
):
    """Assert the refusal discloses no other account's address."""
    seed_account(migration_connection, TARGET_EMAIL)
    seed_account(migration_connection, INTRUDER_EMAIL, ADMIN_ROLE)

    with pytest.raises(RuntimeError) as raised:
        run_upgrade(migration_connection)

    message = str(raised.value)
    assert TARGET_EMAIL in message
    assert ADMIN_ROLE in message
    assert "2" in message
    assert INTRUDER_EMAIL not in message


def test_the_provisioning_and_the_grant_are_recorded(
    migration_connection, caplog
):
    """Assert both records reach the ``alembic`` logger at INFO.

    The rendered messages are asserted to name the address, the role and
    the resulting count, and to carry no part of the stored credential.
    """
    with caplog.at_level(logging.INFO, logger="alembic"):
        run_upgrade(migration_connection)

    messages = revision_records(caplog)
    provisioning = [
        message for message in messages if "Provisioned" in message
    ]
    grant = [message for message in messages if "Seeded" in message]

    assert len(provisioning) == 1
    assert TARGET_EMAIL in provisioning[0]
    assert REGISTERED_ROLE in provisioning[0]

    assert len(grant) == 1
    assert TARGET_EMAIL in grant[0]
    assert ADMIN_ROLE in grant[0]
    assert "administrator count is 1" in grant[0]

    stored = stored_account(migration_connection, TARGET_EMAIL)
    for message in messages:
        assert stored["hashed_password"] not in message
        assert EXPECTED_HASH_PREFIX not in message


def test_a_promotion_without_provisioning_is_recorded(
    migration_connection, caplog
):
    """Assert a stored target produces the grant record alone."""
    seed_account(migration_connection, TARGET_EMAIL)

    with caplog.at_level(logging.INFO, logger="alembic"):
        run_upgrade(migration_connection)

    messages = revision_records(caplog)
    assert [
        message for message in messages if "Provisioned" in message
    ] == []
    assert len(
        [message for message in messages if "Seeded" in message]
    ) == 1


def test_the_downgrade_returns_the_target_to_the_default_role(
    migration_connection
):
    """Assert the demotion is the exact reverse of the grant.

    The row count, the identifier, the credential and the other
    account's role are all read back afterwards.
    """
    seed_account(migration_connection, BYSTANDER_EMAIL, "premium")
    run_upgrade(migration_connection)
    promoted = stored_account(migration_connection, TARGET_EMAIL)

    run_downgrade(migration_connection)

    demoted = stored_account(migration_connection, TARGET_EMAIL)
    assert administrators(migration_connection) == []
    assert demoted is not None
    assert demoted["role"] == REGISTERED_ROLE
    assert demoted["id"] == promoted["id"]
    assert demoted["hashed_password"] == promoted["hashed_password"]
    assert len(snapshot(migration_connection)) == 2
    assert roles_by_email(migration_connection)[BYSTANDER_EMAIL] == (
        "premium"
    )


def test_the_downgrade_leaves_another_administrator_alone(
    migration_connection
):
    """Assert the demotion is scoped to the target address."""
    seed_account(migration_connection, TARGET_EMAIL, ADMIN_ROLE)
    seed_account(migration_connection, INTRUDER_EMAIL, ADMIN_ROLE)

    run_downgrade(migration_connection)

    assert administrators(migration_connection) == [INTRUDER_EMAIL]
    assert roles_by_email(migration_connection)[TARGET_EMAIL] == (
        REGISTERED_ROLE
    )


def test_the_downgrade_is_recorded(migration_connection, caplog):
    """Assert the demotion names the address, role and count."""
    run_upgrade(migration_connection)

    with caplog.at_level(logging.INFO, logger="alembic"):
        run_downgrade(migration_connection)

    messages = revision_records(caplog)
    demotion = [
        message for message in messages if "Returned" in message
    ]
    assert len(demotion) == 1
    assert TARGET_EMAIL in demotion[0]
    assert REGISTERED_ROLE in demotion[0]
    assert "administrator count is 0" in demotion[0]


def test_the_round_trip_promotes_the_target_again(
    migration_connection
):
    """Assert upgrade, downgrade and upgrade end with one admin.

    The second upgrade finds the row already stored, so it promotes
    without provisioning and the row keeps its identifier.
    """
    run_upgrade(migration_connection)
    provisioned = stored_account(migration_connection, TARGET_EMAIL)

    run_downgrade(migration_connection)
    run_upgrade(migration_connection)

    restored = stored_account(migration_connection, TARGET_EMAIL)
    assert administrators(migration_connection) == [TARGET_EMAIL]
    assert restored["id"] == provisioned["id"]
    assert restored["hashed_password"] == (
        provisioned["hashed_password"]
    )
    assert len(snapshot(migration_connection)) == 1


def test_the_revision_is_the_head_and_revises_the_additive_revision():
    """Assert the chain that puts this revision in ``upgrade head``."""
    assert SCRIPT_DIRECTORY.get_heads() == [REVISION_ID]
    assert (
        SCRIPT_DIRECTORY.get_revision(REVISION_ID).down_revision
        == ADDITIVE_REVISION_ID
    )
    assert REVISION.revision == REVISION_ID
    assert REVISION.down_revision == ADDITIVE_REVISION_ID
    assert REVISION.branch_labels is None
    assert REVISION.depends_on is None


def test_the_revision_targets_one_fixed_address():
    """Assert the address and both roles are the fixed literals."""
    assert TARGET_EMAIL == "test@blitzy.com"
    assert ADMIN_ROLE == "admin"
    assert REGISTERED_ROLE == "registered"


def test_the_revision_imports_no_application_module():
    """Assert nothing under ``backend`` is bound in the revision.

    A bound module is named by its own name and every other bound value
    by the module it was defined in, so an imported module and an
    imported function are both reported.
    """
    origins = []
    for value in vars(REVISION).values():
        if isinstance(value, types.ModuleType):
            origins.append(value.__name__)
            continue
        origin = getattr(value, "__module__", None)
        if origin is not None:
            origins.append(str(origin))

    assert origins
    assert [
        origin for origin in origins if origin.startswith("backend")
    ] == []
