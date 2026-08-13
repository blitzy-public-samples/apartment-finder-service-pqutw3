"""Add RBAC, subscription, and webhook replay-protection schema."""
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

#: Bookkeeping table this revision writes the name of every table it
#: created into. It is owned by this revision alone, is created only when
#: at least one name is written to it, and is dropped by ``downgrade``.
#: It holds no application data.
CREATED_TABLES_RECORD = "alembic_0001_created_tables"

#: The bookkeeping table as a statement target.
created_tables_record = sa.table(
    CREATED_TABLES_RECORD, sa.column("table_name")
)

#: The tables that precede this revision, in an order that drops a child
#: before its parent. ``downgrade`` visits them in this order when it
#: removes the tables this revision created.
PRECEDING_TABLES_DROP_ORDER = (
    CRITERIA,
    ZIP_CODES,
    FILTERS,
    SUBSCRIPTIONS,
    LISTINGS,
    USERS,
)

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
    return sa.inspect(op.get_bind())


def _table_present(table):
    return _inspector().has_table(table)


def _column_names(table):
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
    return op.get_bind().dialect.name == RECREATING_DIALECT


def _create_users():
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
    op.create_table(
        ZIP_CODES,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("filter_id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["filter_id"], ["filters.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_criteria():
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
    present = _present_objects()
    if present:
        raise RuntimeError(
            ALREADY_PRESENT_MESSAGE.format(objects=", ".join(present))
        )


def _create_created_tables_record():
    op.create_table(
        CREATED_TABLES_RECORD,
        sa.Column("table_name", sa.String(length=63), nullable=False),
        sa.PrimaryKeyConstraint("table_name"),
    )


def _record_created_tables(names):
    """Write ``names`` to the bookkeeping table, creating it first.

    Nothing is created and nothing is written when ``names`` is empty, so
    a database that already held every preceding table carries no record
    and no bookkeeping table.
    """
    if not names:
        return
    _create_created_tables_record()
    op.get_bind().execute(
        created_tables_record.insert(),
        [{"table_name": name} for name in names],
    )


def _recorded_created_tables():
    """Return the table names the bookkeeping table holds.

    An empty set is returned when the bookkeeping table is absent, which
    is the state left by an upgrade that created no table.
    """
    if not _table_present(CREATED_TABLES_RECORD):
        return set()
    rows = op.get_bind().execute(
        sa.select(created_tables_record.c.table_name)
    ).fetchall()
    return set(row[0] for row in rows)


def _upgrade_users():
    if not _table_present(USERS):
        _create_users()
        return True
    for column in _users_added_columns():
        op.add_column(USERS, column)
    return False


def _upgrade_listings():
    if not _table_present(LISTINGS):
        _create_listings()
        return True
    return False


def _upgrade_filters():
    if not _table_present(FILTERS):
        _create_filters()
        return True
    return False


def _upgrade_zip_codes():
    if not _table_present(ZIP_CODES):
        _create_zip_codes()
        return True
    return False


def _upgrade_criteria():
    if not _table_present(CRITERIA):
        _create_criteria()
        return True
    return False


def _upgrade_subscriptions():
    if not _table_present(SUBSCRIPTIONS):
        _create_subscriptions()
        return True
    existing = _column_names(SUBSCRIPTIONS)
    for column in _subscriptions_added_columns():
        if column.name not in existing:
            op.add_column(SUBSCRIPTIONS, column)
    if _uniqueness_over(SUBSCRIPTIONS, [ORDER_COLUMN]) is None:
        with op.batch_alter_table(SUBSCRIPTIONS) as batch_op:
            batch_op.create_unique_constraint(
                SUBSCRIPTIONS_ORDER_UNIQUE, [ORDER_COLUMN]
            )
    return False


def _upgrade_webhook_events():
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
    foreign keys, and the name of each one created here is written to
    :data:`CREATED_TABLES_RECORD` so ``downgrade`` removes exactly that
    set. ``webhook_events`` is not recorded there: ``downgrade`` owns it
    unconditionally.
    """
    if _emitting_statements():
        _upgrade_offline()
        return
    _refuse_present_shape()
    created = []
    for table, upgrade_table in (
        (USERS, _upgrade_users),
        (LISTINGS, _upgrade_listings),
        (FILTERS, _upgrade_filters),
        (ZIP_CODES, _upgrade_zip_codes),
        (CRITERIA, _upgrade_criteria),
        (SUBSCRIPTIONS, _upgrade_subscriptions),
    ):
        if upgrade_table():
            created.append(table)
    _upgrade_webhook_events()
    _record_created_tables(created)


def _downgrade_webhook_events():
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


def _drop_created_tables(created):
    for table in PRECEDING_TABLES_DROP_ORDER:
        if table in created and _table_present(table):
            op.drop_table(table)


def _drop_created_tables_record():
    if _table_present(CREATED_TABLES_RECORD):
        op.drop_table(CREATED_TABLES_RECORD)


def downgrade() -> None:
    """Reverse this revision.

    The uniqueness constraint is dropped before the column it covers, and
    a table recorded in :data:`CREATED_TABLES_RECORD` is dropped whole
    rather than having its added columns removed. The record itself is
    dropped last, so the reversal leaves neither an application table nor
    a bookkeeping table behind on a database this revision built from
    nothing.
    """
    if _emitting_statements():
        _downgrade_offline()
        return
    created = _recorded_created_tables()
    _downgrade_webhook_events()
    if SUBSCRIPTIONS not in created:
        _downgrade_subscriptions()
    if USERS not in created:
        _downgrade_users()
    _drop_created_tables(created)
    _drop_created_tables_record()
