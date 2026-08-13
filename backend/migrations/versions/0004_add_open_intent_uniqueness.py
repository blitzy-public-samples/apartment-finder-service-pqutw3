"""Add open-intent uniqueness

Creates one partial unique index over ``subscriptions(user_id, plan_id)``
restricted to rows in the open payment window -- a status of ``pending``
or ``failed`` together with a ``NULL`` entitlement end. No column,
constraint, table or row is added, altered or removed.

The index carries an invariant the subscription creation route cannot
carry on its own: at most one open payment intent exists per owner and
plan. That route reads for a reusable intent and inserts when it finds
none, so two requests arriving together can both read nothing and both
insert. The database refuses the second insert, and the route reloads the
row the first request committed.

The predicate restricts the uniqueness to the window the route reuses:

* ``status IN ('pending', 'failed')`` -- the two statuses the route
  treats as reusable. A row recording a settlement or a reversal falls
  outside the predicate and carries no uniqueness from it.
* ``end_date IS NULL`` -- an open entitlement window. A row whose window
  has been closed falls outside the predicate.

A row whose ``plan_id`` is ``NULL`` carries no uniqueness from this index,
since SQL treats ``NULL`` values in an index key as distinct. Revision
0001 added ``plan_id`` as a nullable column, so subscription rows that
predate it apply this revision unchanged and remain unconstrained.

The mapped :class:`backend.app.db.models.Subscription` declares the same
index under the same name over the same predicate, so the mapped table
and the migrated table carry the same uniqueness.

``upgrade`` creates the index only when the table carries no index of
that name, so a database already carrying one is left with the index it
has. Before creating it, ``upgrade`` reads the rows the predicate covers
and refuses when any owner and plan already holds more than one open
intent, naming the affected pairs: the index cannot be created over data
that already violates it, and resolving which of several intents to keep
is a decision about a charge rather than one this revision makes.
``downgrade`` drops exactly the index this revision creates and nothing
else. A table that is absent is skipped on both paths.

Offline, no database is present to inspect, so ``--sql`` emits the
``CREATE UNIQUE INDEX`` statement unconditionally and ``--sql`` of the
reverse emits the ``DROP INDEX`` statement unconditionally, for a
database carrying the shape revision 0001 leaves behind.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-10 09:41:12.407715

"""
from alembic import context
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


#: Name of the index this revision creates. The mapped
#: :class:`backend.app.db.models.Subscription` declares the same name.
INDEX_NAME = "uq_subscriptions_open_intent_per_plan"

#: Table the index is created on.
TABLE_NAME = "subscriptions"

#: Index key, in order.
INDEX_COLUMNS = ("user_id", "plan_id")

#: Statuses the predicate admits. These mirror ``OPEN_INTENT_STATUSES``
#: in ``backend.app.db.models``.
OPEN_STATUSES = ("pending", "failed")

#: The ``WHERE`` clause restricting the uniqueness to the open window.
#: This mirrors ``OPEN_INTENT_INDEX_PREDICATE`` in
#: ``backend.app.db.models``.
INDEX_PREDICATE = "status IN ({0}) AND end_date IS NULL".format(
    ", ".join("'{0}'".format(status) for status in OPEN_STATUSES)
)

#: Number of conflicting pairs named in the refusal message.
_REPORTED_CONFLICT_LIMIT = 10


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


def _index_names(table):
    """Collect the index names ``table`` currently carries."""
    return set(
        index["name"] for index in _inspector().get_indexes(table)
    )


def _conflicting_pairs():
    """Collect owner and plan pairs already holding several open intents.

    Rows whose ``plan_id`` is ``NULL`` are excluded, matching the
    uniqueness the index declares over a ``NULL`` key.
    """
    result = op.get_bind().execute(
        sa.text(
            "SELECT user_id, plan_id, COUNT(*) AS open_intents "
            "FROM {table} "
            "WHERE {predicate} AND plan_id IS NOT NULL "
            "GROUP BY user_id, plan_id "
            "HAVING COUNT(*) > 1 "
            "ORDER BY user_id, plan_id".format(
                table=TABLE_NAME, predicate=INDEX_PREDICATE
            )
        )
    )
    return [tuple(row) for row in result]


def _refuse(conflicts):
    """Raise naming the pairs that hold more than one open intent."""
    reported = conflicts[:_REPORTED_CONFLICT_LIMIT]
    listed = "; ".join(
        "user_id={0} plan_id={1} open_intents={2}".format(*row)
        for row in reported
    )
    remainder = len(conflicts) - len(reported)
    if remainder > 0:
        listed = "{0}; and {1} further pair(s)".format(listed, remainder)
    raise RuntimeError(
        "Cannot create {index}: {count} owner/plan pair(s) already hold "
        "more than one open payment intent, which the index forbids. "
        "Resolve each pair by closing the intents that are not being "
        "settled -- set end_date, or set status to a settled or reversed "
        "value -- leaving at most one row per pair matching "
        "\"{predicate}\", then re-run this revision. Affected: "
        "{listed}.".format(
            index=INDEX_NAME,
            count=len(conflicts),
            predicate=INDEX_PREDICATE,
            listed=listed,
        )
    )


def upgrade() -> None:
    """Apply this revision.

    The index is created only when its table is present and carries no
    index of that name, and only when no owner and plan already holds
    more than one open intent.
    """
    if _emitting_statements():
        op.create_index(
            INDEX_NAME,
            TABLE_NAME,
            list(INDEX_COLUMNS),
            unique=True,
            postgresql_where=sa.text(INDEX_PREDICATE),
            sqlite_where=sa.text(INDEX_PREDICATE),
        )
        return
    if not _table_present(TABLE_NAME):
        return
    if INDEX_NAME in _index_names(TABLE_NAME):
        return
    conflicts = _conflicting_pairs()
    if conflicts:
        _refuse(conflicts)
    op.create_index(
        INDEX_NAME,
        TABLE_NAME,
        list(INDEX_COLUMNS),
        unique=True,
        postgresql_where=sa.text(INDEX_PREDICATE),
        sqlite_where=sa.text(INDEX_PREDICATE),
    )


def downgrade() -> None:
    """Reverse this revision.

    The index is dropped only when its table is present and carries an
    index of that name. No other index is touched.
    """
    if _emitting_statements():
        op.drop_index(INDEX_NAME, table_name=TABLE_NAME)
        return
    if not _table_present(TABLE_NAME):
        return
    if INDEX_NAME not in _index_names(TABLE_NAME):
        return
    op.drop_index(INDEX_NAME, table_name=TABLE_NAME)
