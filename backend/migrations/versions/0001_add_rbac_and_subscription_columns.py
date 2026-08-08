"""Add RBAC and subscription columns

Adds ``role``, ``failed_login_attempts`` and ``locked_until`` to
``users``. Adds ``plan_id``, ``amount``, ``currency`` and
``paypal_order_id`` to ``subscriptions``, the last under a uniqueness
constraint. Adds a uniqueness constraint over ``listings.zillow_url``.
Creates the ``webhook_events`` table, whose ``transmission_id`` is
unique.

Every column added to a table that precedes this revision carries a
server default. An account already stored reads the role ``registered``
and a zero failed-attempt count, and a subscription row already stored
reads the currency ``USD``. This revision writes no other role and
promotes no account.

Every operation is guarded by a schema inspection. The revision applies
to a database holding the six tables that precede it, to an empty
database, and to one already carrying the final shape. ``downgrade``
removes only what this revision adds, and never a table or column that
precedes it.

Revision ID: 0001
Revises:
Create Date: 2026-08-08 09:14:22.517394

"""
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

#: Names this revision gives the uniqueness constraints it adds. Each is
#: dropped under the same name.
LISTINGS_URL_UNIQUE = "uq_listings_zillow_url"
SUBSCRIPTIONS_ORDER_UNIQUE = "uq_subscriptions_paypal_order_id"
WEBHOOK_TRANSMISSION_UNIQUE = "uq_webhook_events_transmission_id"


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


def _unique_over(table, columns):
    """Report whether a uniqueness already covers exactly ``columns``.

    Both the uniqueness constraints and the unique indexes reported for
    ``table`` are examined. A uniqueness recorded either way counts.
    """
    wanted = list(columns)
    inspector = _inspector()
    for constraint in inspector.get_unique_constraints(table):
        if list(constraint.get("column_names") or []) == wanted:
            return True
    for index in inspector.get_indexes(table):
        if not index.get("unique"):
            continue
        if list(index.get("column_names") or []) == wanted:
            return True
    return False


def _named_unique_present(table, name):
    """Report whether ``table`` carries a uniqueness called ``name``."""
    inspector = _inspector()
    for constraint in inspector.get_unique_constraints(table):
        if constraint.get("name") == name:
            return True
    for index in inspector.get_indexes(table):
        if index.get("unique") and index.get("name") == name:
            return True
    return False


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
    """Create ``listings`` carrying this revision's uniqueness."""
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
        sa.UniqueConstraint("zillow_url", name=LISTINGS_URL_UNIQUE),
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


def _create_subscriptions():
    """Create ``subscriptions`` carrying this revision's columns."""
    op.create_table(
        SUBSCRIPTIONS,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("start_date", sa.DateTime(), nullable=False),
        sa.Column("end_date", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        *_subscriptions_added_columns(),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "paypal_order_id", name=SUBSCRIPTIONS_ORDER_UNIQUE
        ),
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


def _upgrade_users():
    """Bring ``users`` to this revision's shape."""
    if not _table_present(USERS):
        _create_users()
        return
    existing = _column_names(USERS)
    for column in _users_added_columns():
        if column.name not in existing:
            op.add_column(USERS, column)


def _upgrade_listings():
    """Bring the uniqueness over ``listings.zillow_url`` into place."""
    if not _table_present(LISTINGS):
        _create_listings()
        return
    if _unique_over(LISTINGS, ["zillow_url"]):
        return
    with op.batch_alter_table(LISTINGS) as batch_op:
        batch_op.create_unique_constraint(
            LISTINGS_URL_UNIQUE, ["zillow_url"]
        )


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
    if _unique_over(SUBSCRIPTIONS, ["paypal_order_id"]):
        return
    with op.batch_alter_table(SUBSCRIPTIONS) as batch_op:
        batch_op.create_unique_constraint(
            SUBSCRIPTIONS_ORDER_UNIQUE, ["paypal_order_id"]
        )


def _upgrade_webhook_events():
    """Create the delivery-record table when it is absent."""
    if not _table_present(WEBHOOK_EVENTS):
        _create_webhook_events()


def upgrade() -> None:
    """Apply this revision.

    The tables are visited in an order that satisfies their foreign
    keys.
    """
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


def _downgrade_subscriptions():
    """Remove this revision's ``subscriptions`` additions."""
    if not _table_present(SUBSCRIPTIONS):
        return
    if _named_unique_present(SUBSCRIPTIONS, SUBSCRIPTIONS_ORDER_UNIQUE):
        with op.batch_alter_table(SUBSCRIPTIONS) as batch_op:
            batch_op.drop_constraint(
                SUBSCRIPTIONS_ORDER_UNIQUE, type_="unique"
            )
    existing = _column_names(SUBSCRIPTIONS)
    for column in reversed(_subscriptions_added_columns()):
        if column.name in existing:
            op.drop_column(SUBSCRIPTIONS, column.name)


def _downgrade_listings():
    """Remove this revision's uniqueness over ``listings.zillow_url``."""
    if not _table_present(LISTINGS):
        return
    if not _named_unique_present(LISTINGS, LISTINGS_URL_UNIQUE):
        return
    with op.batch_alter_table(LISTINGS) as batch_op:
        batch_op.drop_constraint(LISTINGS_URL_UNIQUE, type_="unique")


def _downgrade_users():
    """Remove this revision's ``users`` additions."""
    if not _table_present(USERS):
        return
    existing = _column_names(USERS)
    for column in reversed(_users_added_columns()):
        if column.name in existing:
            op.drop_column(USERS, column.name)


def downgrade() -> None:
    """Reverse this revision.

    Each uniqueness constraint is dropped before the column it covers.
    """
    _downgrade_webhook_events()
    _downgrade_subscriptions()
    _downgrade_listings()
    _downgrade_users()
