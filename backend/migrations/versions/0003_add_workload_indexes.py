"""Add workload indexes

Creates six non-unique indexes over columns the application already
filters, orders and joins on. No column, constraint, table or row is
added, altered or removed, so the revision changes what a query costs
and nothing about what it returns.

The indexes and the predicates they support:

* ``ix_filters_user_id_id`` over ``filters(user_id, id)`` -- the
  owner-scoped page ``backend/app/api/endpoints/filters.py`` reads,
  whose predicate is the owner and whose offset and order follow the
  primary key
* ``ix_zip_codes_filter_id`` over ``zip_codes(filter_id)`` and
  ``ix_criteria_filter_id`` over ``criteria(filter_id)`` -- the two
  page-wide child loads that same page issues, and the distinct postal
  code read the ingestion pass issues
* ``ix_subscriptions_user_id_status_end_date`` over
  ``subscriptions(user_id, status, end_date)`` -- the entitlement
  decision in ``backend/app/core/authorization.py`` and the two
  entitlement reads in ``backend/app/api/endpoints/subscriptions.py``
* ``ix_subscriptions_user_id_plan_id_status`` over
  ``subscriptions(user_id, plan_id, status)`` -- the open-attempt lookup
  the subscription creation route issues
* ``ix_listings_zillow_url`` over ``listings(zillow_url)`` -- the
  per-record reconciliation lookup ``backend/app/tasks/
  listing_updater.py`` issues

``ix_listings_zillow_url`` is **not** unique, and this revision declares
no uniqueness of any kind. Revision 0001 created ``listings`` with no
uniqueness over ``zillow_url`` and the mapped
:class:`backend.app.db.models.Listing` declares none, so a repeated
provider address is still stored rather than refused and a database
already holding repeated addresses applies this revision unchanged.

A column already covered by a uniqueness carries an index from that
uniqueness, so ``users.email``, ``subscriptions.paypal_order_id`` and
``webhook_events.transmission_id`` receive no index here.

``upgrade`` creates an index only when the table carries no index of
that name, so a database already carrying one is left with the index it
has. ``downgrade`` drops exactly the six names this revision creates and
nothing else: it removes no index a uniqueness owns and no index another
revision created. A table that is absent is skipped on both paths.

Offline, no database is present to inspect, so ``--sql`` emits the six
``CREATE INDEX`` statements unconditionally and ``--sql`` of the reverse
emits the six ``DROP INDEX`` statements unconditionally, for a database
carrying the shape revision 0001 leaves behind.

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-09 12:10:44.918233

"""
from alembic import context
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


#: Each index this revision creates, as
#: ``(index name, table name, column names)``. The order is the order the
#: indexes are created in, and the reverse is the order they are dropped
#: in. Every entry names a non-unique index.
WORKLOAD_INDEXES = (
    ("ix_filters_user_id_id", "filters", ("user_id", "id")),
    ("ix_zip_codes_filter_id", "zip_codes", ("filter_id",)),
    ("ix_criteria_filter_id", "criteria", ("filter_id",)),
    (
        "ix_subscriptions_user_id_status_end_date",
        "subscriptions",
        ("user_id", "status", "end_date"),
    ),
    (
        "ix_subscriptions_user_id_plan_id_status",
        "subscriptions",
        ("user_id", "plan_id", "status"),
    ),
    ("ix_listings_zillow_url", "listings", ("zillow_url",)),
)


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


def upgrade() -> None:
    """Apply this revision.

    Each index is created only when its table is present and carries no
    index of that name, so the revision applies to a database that
    already carries some of them and to one that carries none.
    """
    if _emitting_statements():
        for name, table, columns in WORKLOAD_INDEXES:
            op.create_index(name, table, list(columns), unique=False)
        return
    for name, table, columns in WORKLOAD_INDEXES:
        if not _table_present(table):
            continue
        if name in _index_names(table):
            continue
        op.create_index(name, table, list(columns), unique=False)


def downgrade() -> None:
    """Reverse this revision.

    Each index is dropped only when its table is present and carries an
    index of that name, in the reverse of the order they were created.
    No other index is touched.
    """
    if _emitting_statements():
        for name, table, _columns in reversed(WORKLOAD_INDEXES):
            op.drop_index(name, table_name=table)
        return
    for name, table, _columns in reversed(WORKLOAD_INDEXES):
        if not _table_present(table):
            continue
        if name not in _index_names(table):
            continue
        op.drop_index(name, table_name=table)
