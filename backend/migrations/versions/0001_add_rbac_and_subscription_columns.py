"""Add RBAC and subscription columns

Adds ``role``, ``failed_login_attempts`` and ``locked_until`` to
``users``. Adds ``plan_id``, ``amount``, ``currency`` and
``paypal_order_id`` to ``subscriptions``, the last under a uniqueness
constraint. Creates the ``webhook_events`` table, whose
``transmission_id`` is unique. No column or constraint of any other
table is added, altered or removed.

Every column added to a table that precedes this revision carries a
server default. An account already stored reads the role ``registered``
and a zero failed-attempt count, and a subscription row already stored
reads the currency ``USD``. This revision writes no other role and
promotes no account.

``upgrade`` first checks that none of the objects listed above is
already present, and raises when one is: a database already carrying
this revision's shape is stamped rather than migrated. Every object this
revision then adds is therefore an object it created, and ``downgrade``
reverses exactly that set -- the three ``users`` columns, the four
``subscriptions`` columns with their uniqueness constraint, and the
``webhook_events`` table. It removes no table or column that precedes
this revision. The uniqueness over ``paypal_order_id`` is removed with
the column it covers, on a backend that drops a constraint in place and
on one that only recreates the table.

A table this revision adds columns to is created in full when it is
absent, so the revision applies to an empty database as well as to one
holding the six tables that precede it. Offline, no database is present
to inspect, so ``--sql`` emits the additive statements unconditionally,
for a database already holding those six tables.

``listings`` is one of the tables created only when absent, and it is
created with no uniqueness over ``zillow_url``. The mapped
:class:`backend.app.db.models.Listing` declares none either, so the two
agree: a repeated provider address is stored rather than refused, a
database already holding repeated addresses applies this revision
unchanged, and ``backend/app/tasks/listing_updater.py`` reconciles by
reading the earliest row carrying the value rather than by relying on a
constraint.

Revision ID: 0001
Revises:
Create Date: 2026-08-08 09:14:22.517394

"""
from alembic import context
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


#: Role every account already stored takes.
ROLE_DEFAULT = "registered"

#: Failed-attempt count every account already stored takes.
FAILED_ATTEMPTS_DEFAULT = "0"

#: Currency every subscription row already stored takes.
CURRENCY_DEFAULT = "USD"

USERS = "users"
LISTINGS = "listings"
FILTERS = "filters"
ZIP_CODES = "zip_codes"
CRITERIA = "criteria"
SUBSCRIPTIONS = "subscriptions"
WEBHOOK_EVENTS = "webhook_events"

#: Column of ``subscriptions`` this revision constrains to be unique.
ORDER_COLUMN = "paypal_order_id"

#: Names this revision gives the uniqueness constraints it adds. Each
#: matches the name the mapped table declares, and each is dropped under
#: that name.
SUBSCRIPTIONS_ORDER_UNIQUE = "uq_subscriptions_paypal_order_id"
WEBHOOK_TRANSMISSION_UNIQUE = "uq_webhook_events_transmission_id"

#: Kinds of uniqueness a schema inspection reports over a column.
CONSTRAINT_UNIQUENESS = "constraint"
INDEX_UNIQUENESS = "index"

#: Backend on which a uniqueness is removed only by recreating the
#: table. ``batch_alter_table`` performs that recreation, which carries
#: the uniqueness away with the column it covers.
RECREATING_DIALECT = "sqlite"

#: Message of the failure raised when this revision's shape is already
#: present.
ALREADY_PRESENT_MESSAGE = (
    "Revision 0001 cannot run: the database already carries {objects}. "
    "Stamp this revision instead of applying it, so its reversal "
    "removes only objects it created."
)


def _users_added_columns():
    """Build the columns this revision adds to ``users``."""
    return [
        sa.Column(
            "role",
            sa.String(),
            nullable=False,
            server_default=ROLE_DEFAULT,
        ),
        sa.Column(
            "failed_login_attempts",
            sa.Integer(),
            nullable=False,
            server_default=FAILED_ATTEMPTS_DEFAULT,
        ),
        sa.Column(
            "locked_until",
            sa.DateTime(timezone=True),
            nullable=True,
            server_default=sa.text("NULL"),
        ),
    ]


def _subscriptions_added_columns():
    """Build the columns this revision adds to ``subscriptions``."""
    return [
        sa.Column(
            "plan_id",
            sa.String(),
            nullable=True,
            server_default=sa.text("NULL"),
        ),
        sa.Column(
            "amount",
            sa.Numeric(10, 2),
            nullable=True,
            server_default=sa.text("NULL"),
        ),
        sa.Column(
            "currency",
            sa.String(),
            nullable=False,
            server_default=CURRENCY_DEFAULT,
        ),
        sa.Column(
            "paypal_order_id",
            sa.String(),
            nullable=True,
            server_default=sa.text("NULL"),
        ),
    ]


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


def _column_names(table):
    """Collect the column names ``table`` currently carries."""
    return set(
        column["name"] for column in _inspector().get_columns(table)
    )


def _uniqueness_over(table, columns):
    """Return the uniqueness covering exactly ``columns``, or ``None``.

    The lookup is by covered column, so it finds a uniqueness the
    running schema carries whatever that uniqueness is called and
    whether the schema records it as a constraint or as a unique index.
    The result is the pair ``(kind, name)``, where ``kind`` is
    :data:`CONSTRAINT_UNIQUENESS` or :data:`INDEX_UNIQUENESS` and
    ``name`` is the name the schema reports, which is ``None`` for a
    constraint the schema left unnamed.
    """
    wanted = list(columns)
    inspector = _inspector()
    for constraint in inspector.get_unique_constraints(table):
        if list(constraint.get("column_names") or []) == wanted:
            return (CONSTRAINT_UNIQUENESS, constraint.get("name"))
    for index in inspector.get_indexes(table):
        if not index.get("unique"):
            continue
        if list(index.get("column_names") or []) == wanted:
            return (INDEX_UNIQUENESS, index.get("name"))
    return None


def _recreates_tables():
    """Report whether the bind removes a uniqueness by recreation."""
    return op.get_bind().dialect.name == RECREATING_DIALECT


def _create_users():
    """Create ``users`` carrying this revision's columns."""
    op.create_table(
        USERS,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_login", sa.DateTime(), nullable=True),
        *_users_added_columns(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )


def _create_listings():
    """Create ``listings`` as the schema preceding this revision has it.

    No uniqueness is declared over ``zillow_url``, matching both the
    preceding schema and the mapped table.
    """
    op.create_table(
        LISTINGS,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("rent", sa.Float(), nullable=False),
        sa.Column("broker_fee", sa.Float(), nullable=True),
        sa.Column("square_footage", sa.Float(), nullable=True),
        sa.Column("bedrooms", sa.Integer(), nullable=True),
        sa.Column("bathrooms", sa.Integer(), nullable=True),
        sa.Column("available_date", sa.DateTime(), nullable=True),
        sa.Column("street_address", sa.String(), nullable=True),
        sa.Column("zillow_url", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_filters():
    """Create ``filters`` as the schema preceding this revision has it."""
    op.create_table(
        FILTERS,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_zip_codes():
    """Create ``zip_codes`` as the preceding schema has it."""
    op.create_table(
        ZIP_CODES,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("filter_id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["filter_id"], ["filters.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_criteria():
    """Create ``criteria`` as the preceding schema has it."""
    op.create_table(
        CRITERIA,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("filter_id", sa.Integer(), nullable=False),
        sa.Column("field", sa.String(), nullable=False),
        sa.Column("operator", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["filter_id"], ["filters.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def _subscriptions_definition():
    """Build ``subscriptions`` as this revision leaves it.

    The columns that precede this revision come first, then the columns
    it adds, then the keys and the uniqueness over the order column.
    """
    return [
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("start_date", sa.DateTime(), nullable=False),
        sa.Column("end_date", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
    ] + _subscriptions_added_columns() + [
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            ORDER_COLUMN, name=SUBSCRIPTIONS_ORDER_UNIQUE
        ),
    ]


def _create_subscriptions():
    """Create ``subscriptions`` carrying this revision's columns."""
    op.create_table(SUBSCRIPTIONS, *_subscriptions_definition())


def _subscriptions_table():
    """Return the table this revision leaves ``subscriptions`` as.

    ``batch_alter_table`` is given this definition, so a backend that
    reverses a column by recreating the table reproduces the remaining
    columns and keys from this declaration, and the uniqueness it
    removes carries a name.
    """
    return sa.Table(
        SUBSCRIPTIONS, sa.MetaData(), *_subscriptions_definition()
    )


def _create_webhook_events():
    """Create the delivery-record table this revision introduces."""
    op.create_table(
        WEBHOOK_EVENTS,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("transmission_id", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "transmission_id", name=WEBHOOK_TRANSMISSION_UNIQUE
        ),
    )


def _present_objects():
    """Returns the names of this revision's objects already in place.

    Each name is reported as ``<table>.<column>`` for a column, as the
    constraint name for a uniqueness, and as the table name for a table.
    An empty list means the database carries none of them.
    """
    present = []
    if _table_present(USERS):
        existing = _column_names(USERS)
        present.extend(
            USERS + "." + column.name
            for column in _users_added_columns()
            if column.name in existing
        )
    if _table_present(SUBSCRIPTIONS):
        existing = _column_names(SUBSCRIPTIONS)
        present.extend(
            SUBSCRIPTIONS + "." + column.name
            for column in _subscriptions_added_columns()
            if column.name in existing
        )
        if _uniqueness_over(SUBSCRIPTIONS, [ORDER_COLUMN]) is not None:
            present.append(SUBSCRIPTIONS_ORDER_UNIQUE)
    if _table_present(WEBHOOK_EVENTS):
        present.append(WEBHOOK_EVENTS)
    return present


def _refuse_present_shape():
    """Raise when any object this revision adds is already in place."""
    present = _present_objects()
    if present:
        raise RuntimeError(
            ALREADY_PRESENT_MESSAGE.format(objects=", ".join(present))
        )


def _upgrade_users():
    """Bring ``users`` to this revision's shape."""
    if not _table_present(USERS):
        _create_users()
        return
    for column in _users_added_columns():
        op.add_column(USERS, column)


def _upgrade_listings():
    """Ensure ``listings`` exists; this revision alters no column of it."""
    if not _table_present(LISTINGS):
        _create_listings()


def _upgrade_filters():
    """Ensure ``filters`` exists; this revision alters no column of it."""
    if not _table_present(FILTERS):
        _create_filters()


def _upgrade_zip_codes():
    """Ensure ``zip_codes`` exists; no column of it is altered."""
    if not _table_present(ZIP_CODES):
        _create_zip_codes()


def _upgrade_criteria():
    """Ensure ``criteria`` exists; no column of it is altered."""
    if not _table_present(CRITERIA):
        _create_criteria()


def _upgrade_subscriptions():
    """Bring ``subscriptions`` to this revision's shape."""
    if not _table_present(SUBSCRIPTIONS):
        _create_subscriptions()
        return
    existing = _column_names(SUBSCRIPTIONS)
    for column in _subscriptions_added_columns():
        if column.name not in existing:
            op.add_column(SUBSCRIPTIONS, column)
    if _uniqueness_over(SUBSCRIPTIONS, [ORDER_COLUMN]) is not None:
        return
    with op.batch_alter_table(SUBSCRIPTIONS) as batch_op:
        batch_op.create_unique_constraint(
            SUBSCRIPTIONS_ORDER_UNIQUE, [ORDER_COLUMN]
        )


def _upgrade_webhook_events():
    """Create the delivery-record table when it is absent."""
    if not _table_present(WEBHOOK_EVENTS):
        _create_webhook_events()


def _upgrade_offline():
    """Emit this revision's additive statements unconditionally.

    The statements assume the six tables that precede this revision are
    present, which is the schema a statement stream is applied to.
    """
    for column in _users_added_columns():
        op.add_column(USERS, column)
    for column in _subscriptions_added_columns():
        op.add_column(SUBSCRIPTIONS, column)
    op.create_unique_constraint(
        SUBSCRIPTIONS_ORDER_UNIQUE, SUBSCRIPTIONS, [ORDER_COLUMN]
    )
    _create_webhook_events()


def upgrade() -> None:
    """Apply this revision.

    Raises ``RuntimeError`` when any object this revision adds is already
    present. The tables are visited in an order that satisfies their
    foreign keys.
    """
    if _emitting_statements():
        _upgrade_offline()
        return
    _refuse_present_shape()
    _upgrade_users()
    _upgrade_listings()
    _upgrade_filters()
    _upgrade_zip_codes()
    _upgrade_criteria()
    _upgrade_subscriptions()
    _upgrade_webhook_events()


def _downgrade_webhook_events():
    """Drop the delivery-record table this revision introduced."""
    if _table_present(WEBHOOK_EVENTS):
        op.drop_table(WEBHOOK_EVENTS)


def _drop_order_uniqueness(batch_op, uniqueness):
    """Drop the uniqueness over the order column within ``batch_op``.

    ``uniqueness`` is the pair :func:`_uniqueness_over` reported, or
    ``None`` when the running schema carries no uniqueness over the
    column. A backend that recreates the table has no statement emitted
    for it: on that backend the recreation is what removes the
    uniqueness, and it does so whether the running schema named the
    uniqueness or left it unnamed.
    """
    if uniqueness is None or _recreates_tables():
        return
    kind, name = uniqueness
    if name is None:
        name = SUBSCRIPTIONS_ORDER_UNIQUE
    if kind == INDEX_UNIQUENESS:
        batch_op.drop_index(name)
    else:
        batch_op.drop_constraint(name, type_="unique")


def _downgrade_subscriptions():
    """Remove this revision's ``subscriptions`` additions.

    The uniqueness over the order column is dropped before the column,
    and both are removed inside one batch operation so that a backend
    which reverses a column only by recreating the table does so once.
    """
    if not _table_present(SUBSCRIPTIONS):
        return
    existing = _column_names(SUBSCRIPTIONS)
    added = [
        column.name
        for column in reversed(_subscriptions_added_columns())
        if column.name in existing
    ]
    uniqueness = _uniqueness_over(SUBSCRIPTIONS, [ORDER_COLUMN])
    if not added and uniqueness is None:
        return
    with op.batch_alter_table(
        SUBSCRIPTIONS, copy_from=_subscriptions_table()
    ) as batch_op:
        _drop_order_uniqueness(batch_op, uniqueness)
        for name in added:
            batch_op.drop_column(name)


def _downgrade_users():
    """Remove this revision's ``users`` additions."""
    if not _table_present(USERS):
        return
    existing = _column_names(USERS)
    for column in reversed(_users_added_columns()):
        if column.name in existing:
            op.drop_column(USERS, column.name)


def _downgrade_offline():
    """Emit the reverse of this revision's statements unconditionally.

    The statements assume the shape ``upgrade`` leaves behind, which is
    the schema a statement stream is applied to. The uniqueness over the
    order column is dropped before the column it covers.
    """
    op.drop_table(WEBHOOK_EVENTS)
    op.drop_constraint(
        SUBSCRIPTIONS_ORDER_UNIQUE, SUBSCRIPTIONS, type_="unique"
    )
    for column in reversed(_subscriptions_added_columns()):
        op.drop_column(SUBSCRIPTIONS, column.name)
    for column in reversed(_users_added_columns()):
        op.drop_column(USERS, column.name)


def downgrade() -> None:
    """Reverse this revision.

    The uniqueness constraint is dropped before the column it covers.
    """
    if _emitting_statements():
        _downgrade_offline()
        return
    _downgrade_webhook_events()
    _downgrade_subscriptions()
    _downgrade_users()
