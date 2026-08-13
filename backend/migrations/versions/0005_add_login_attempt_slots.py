"""Add login attempt slots

Creates ``login_attempt_slots`` and seeds one row per bucket in
``range(SLOT_COUNT)``. No existing column, constraint, table or row is
added to, altered or removed, so every account and every subscription is
left exactly as it was found.

The table exists so that every refused login performs the same database
work. The refusal branch for a wrong password takes a write lock on the
account row, updates the failed-attempt count and commits; the branch for
an address holding no account, and the branch for an account already
locked, previously issued no statement at all. The elapsed time therefore
distinguished an address that holds an account from one that does not
whenever the account row was contended, because a wait on a row lock is
unbounded and the fixed refusal budget can only add time, never remove
it. Those two branches now take a write lock on one of these rows,
update it and commit, which is the same shape and the same number of
statements.

The table is a fixed size and is fully seeded here, so no request ever
inserts a row: a bucket the application computes always names a row that
already exists, and an address cannot cause the table to grow.

What a row holds and what it deliberately does not: ``bucket`` is the
index, ``attempts`` counts the refusals that landed on it and
``observed_at`` records when the last one did. No address, no credential,
no account identifier and no submitted value is stored. The bucket is a
keyed digest computed by
:func:`backend.app.core.security.login_attempt_slot`, and several
addresses share one bucket, so a row identifies no account.

``SLOT_COUNT`` mirrors
:data:`backend.app.db.models.LOGIN_ATTEMPT_SLOT_COUNT`. It is stated here
rather than imported, so that what this revision seeded stays fixed for a
database that has already applied it; a contract test pins the two values
to each other, so raising the model's count without adding a revision to
seed the new buckets fails.

``upgrade`` creates the table only when it is absent, and seeds only the
buckets that are missing, so a database already carrying the table or
some of its rows applies this revision unchanged. ``downgrade`` drops the
table and nothing else.

Offline, no database is present to inspect, so ``--sql`` emits the
``CREATE TABLE`` and every ``INSERT`` unconditionally, and ``--sql`` of
the reverse emits the ``DROP TABLE`` unconditionally.

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-10 10:12:38.552104

"""
from alembic import context
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


#: Table this revision creates.
TABLE_NAME = "login_attempt_slots"

#: Number of rows seeded, one per bucket. This is the count this revision
#: seeds and it is fixed for any database that has applied it. It mirrors
#: ``LOGIN_ATTEMPT_SLOT_COUNT`` in ``backend.app.db.models``, and a
#: contract test asserts the two values are equal, so raising the model's
#: count without adding a revision to seed the added buckets fails.
SLOT_COUNT = 1024

#: Rows inserted per statement while seeding.
_SEED_BATCH = 256


def _emitting_statements() -> bool:
    """Report whether this run emits SQL rather than executing it.

    ``alembic upgrade --sql`` configures an environment context that
    answers this. A revision driven directly against a connection
    configures the operations proxy alone, and executes.
    """
    try:
        return bool(context.is_offline_mode())
    except (AttributeError, NameError):
        return False


def _inspector():
    """Reflect the bind this revision is running against."""
    return sa.inspect(op.get_bind())


def _table_present(table):
    """Report whether ``table`` exists on the bind."""
    return _inspector().has_table(table)


def _slot_table() -> sa.Table:
    """Return the table definition this revision creates and seeds."""
    return sa.Table(
        TABLE_NAME,
        sa.MetaData(),
        sa.Column(
            "bucket", sa.Integer, primary_key=True, autoincrement=False
        ),
        sa.Column(
            "attempts",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            nullable=True,
            server_default=sa.text("NULL"),
        ),
    )


def _seeded_buckets(table: sa.Table):
    """Collect the buckets the table already carries."""
    return set(
        row[0]
        for row in op.get_bind().execute(sa.select(table.c.bucket))
    )


def _seed(table: sa.Table, buckets) -> None:
    """Insert one row per bucket in ``buckets``, in batches."""
    ordered = sorted(buckets)
    for start in range(0, len(ordered), _SEED_BATCH):
        batch = ordered[start:start + _SEED_BATCH]
        op.bulk_insert(
            table,
            [{"bucket": bucket, "attempts": 0} for bucket in batch],
        )


def upgrade() -> None:
    """Apply this revision.

    The table is created when absent and every missing bucket is seeded,
    so the revision applies to a database that already carries the table,
    one that carries some of the rows, and one that carries neither.
    """
    if _emitting_statements():
        table = _slot_table()
        op.create_table(
            TABLE_NAME,
            sa.Column(
                "bucket", sa.Integer, primary_key=True, autoincrement=False
            ),
            sa.Column(
                "attempts",
                sa.Integer,
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "observed_at",
                sa.DateTime(timezone=True),
                nullable=True,
                server_default=sa.text("NULL"),
            ),
        )
        _seed(table, range(SLOT_COUNT))
        return

    table = _slot_table()
    if not _table_present(TABLE_NAME):
        op.create_table(
            TABLE_NAME,
            sa.Column(
                "bucket", sa.Integer, primary_key=True, autoincrement=False
            ),
            sa.Column(
                "attempts",
                sa.Integer,
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "observed_at",
                sa.DateTime(timezone=True),
                nullable=True,
                server_default=sa.text("NULL"),
            ),
        )
        _seed(table, range(SLOT_COUNT))
        return

    missing = set(range(SLOT_COUNT)) - _seeded_buckets(table)
    if missing:
        _seed(table, missing)


def downgrade() -> None:
    """Reverse this revision.

    The table is dropped when present, with its rows. Nothing else is
    touched: no account, no subscription and no index created by an
    earlier revision.
    """
    if _emitting_statements():
        op.drop_table(TABLE_NAME)
        return
    if not _table_present(TABLE_NAME):
        return
    op.drop_table(TABLE_NAME)
