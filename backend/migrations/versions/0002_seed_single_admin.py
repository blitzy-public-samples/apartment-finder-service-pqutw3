"""Seed the single administrator account

Leaves the address :data:`ADMIN_EMAIL` holding the role
:data:`ADMIN_ROLE`, and every other account holding the role it already
held. That address is the only address this revision names, and it is
fixed in this module.

``upgrade`` stores that address when no row carries it. The insert is one
statement whose guard against an already-stored address is part of the
statement, so nothing is read back: the row lands at the role
:data:`REGISTERED_ROLE` carrying :data:`LOCKED_CREDENTIAL`, which is not
a hash any password produces, so the account cannot be signed in to until
an operator sets a credential on it.

The promotion is then one conditional statement. The two statements'
affected-row counts separate the four outcomes from one another: the
account was stored here and granted the role, an account already stored
was granted it, an account already held it, or the driver reported no
count. The addresses holding :data:`ADMIN_ROLE` are read afterwards and
must be exactly one entry naming :data:`ADMIN_EMAIL`. Any other result
raises, and the transaction is rolled back.

``downgrade`` returns that one account to the role
:data:`REGISTERED_ROLE` and requires that the address no longer holds
:data:`ADMIN_ROLE` afterwards. It touches no other account, no other
column, no row's existence, and no table or column definition, so an
account another grant made an administrator is left as it stands.

Each outcome is recorded on the ``alembic`` logger with the counts it was
decided from, and no record carries a credential. ``--sql`` emits both
statements of each direction with their values inline; no count is read,
so no post-condition is checked in a statement stream.

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-08 09:31:48.204617

"""
import logging

import sqlalchemy as sa
from alembic import context, op

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


#: Address of the one account this revision stores and promotes.
ADMIN_EMAIL = "test@blitzy.com"

#: Role this revision grants that address.
ADMIN_ROLE = "admin"

#: Role ``downgrade`` returns that address to, and the role the row
#: ``upgrade`` stores is created at.
REGISTERED_ROLE = "registered"

#: Value written to ``users.hashed_password`` for an account this
#: revision stores. It is not a hash any password produces, and
#: :func:`backend.app.core.security.verify_password` reads an unparseable
#: stored value as a failed comparison, so no candidate can match it.
LOCKED_CREDENTIAL = "!locked-no-password-set"

#: Failed-attempt count an account this revision stores begins with.
FAILED_ATTEMPTS_START = 0

#: Message of the failure raised when the addresses holding the
#: administrator role after the promotion are not exactly one entry
#: naming :data:`ADMIN_EMAIL`.
COUNT_MESSAGE = (
    "Administrator seed post-condition failed: {count} accounts hold "
    "the role {role} and {email} is {among}among them, exactly one is "
    "required and at most one is permitted"
)

#: Message of the failure raised when the named address still holds the
#: administrator role after ``downgrade``.
DEMOTION_MESSAGE = (
    "Administrator seed reversal post-condition failed: {email} still "
    "holds the role {role}, none is permitted for that address once the "
    "reversal has run"
)

#: Logger carrying this revision's records. The name sits in the
#: ``alembic`` namespace ``backend/alembic.ini`` configures at INFO.
logger = logging.getLogger("alembic.runtime.migration")

#: The ``users`` columns this revision writes when it stores the target
#: account. ``id`` and every other column take their own default.
users = sa.table(
    "users",
    sa.column("email"),
    sa.column("hashed_password"),
    sa.column("created_at"),
    sa.column("role"),
    sa.column("failed_login_attempts"),
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


def _seed():
    """Build the statement that stores the target account when absent.

    The values are selected, so the guard against an account already
    carrying the address is part of the one statement and the statement
    stands alone with no value read back.
    """
    absent = ~sa.select(sa.literal(1)).where(
        users.c.email == ADMIN_EMAIL
    ).exists()
    return users.insert().from_select(
        [
            "email",
            "hashed_password",
            "created_at",
            "role",
            "failed_login_attempts",
        ],
        sa.select(
            sa.literal(ADMIN_EMAIL),
            sa.literal(LOCKED_CREDENTIAL),
            sa.func.current_timestamp(),
            sa.literal(REGISTERED_ROLE),
            sa.literal(FAILED_ATTEMPTS_START),
        ).where(absent),
    )


def _promotion():
    """Build the statement that grants the target address the role."""
    return sa.text(
        "UPDATE users SET role = :role"
        " WHERE email = :email AND role <> :role"
    ).bindparams(role=ADMIN_ROLE, email=ADMIN_EMAIL)


def _demotion():
    """Build the statement that returns the target to the default role."""
    return sa.text(
        "UPDATE users SET role = :registered"
        " WHERE email = :email AND role = :admin"
    ).bindparams(
        registered=REGISTERED_ROLE,
        email=ADMIN_EMAIL,
        admin=ADMIN_ROLE,
    )


def _administrators(connection):
    """Return the addresses holding :data:`ADMIN_ROLE`, ordered.

    The role is compared without regard to letter case, so a value
    stored in another case is counted rather than overlooked.
    """
    rows = connection.execute(
        sa.text(
            "SELECT email FROM users WHERE LOWER(role) = :role"
            " ORDER BY email"
        ),
        {"role": ADMIN_ROLE},
    ).fetchall()
    return [row[0] for row in rows]


def _rows_written(result) -> int:
    """Return how many rows ``result`` reports its statement wrote.

    A driver reporting no count for the statement yields a negative
    value, which is returned unchanged so a caller records the count as
    unavailable rather than reading it as zero.
    """
    return int(result.rowcount)


def _grant_outcome(stored: int, promoted: int) -> str:
    """Return what the seed and the promotion wrote, as one phrase."""
    if stored > 0:
        return "inserted the account and granted it the role"
    if promoted > 0:
        return "granted the role to the stored account"
    if stored == 0 and promoted == 0:
        return "left the account holding the role it already held"
    return "applied the role with no row count reported"


def _upgrade_offline() -> None:
    """Emit the seed and the promotion, each carrying its values."""
    op.execute(_seed())
    op.execute(_promotion())
    logger.info(
        "Provisioned %s at the role %s; its stored credential matches "
        "no password, so the account cannot be signed in to until that "
        "password is reset outside this revision",
        ADMIN_EMAIL,
        REGISTERED_ROLE,
    )
    logger.info(
        "Seeded the role %s for %s; a statement stream reads no count, "
        "so no administrator count is checked here",
        ADMIN_ROLE,
        ADMIN_EMAIL,
    )


def _upgrade_online() -> None:
    """Store and promote the target account, then check the count."""
    connection = op.get_bind()

    stored = _rows_written(connection.execute(_seed()))
    if stored > 0:
        logger.info(
            "Provisioned %s at the role %s; its stored credential "
            "matches no password, so the account cannot be signed in "
            "to until that password is reset outside this revision",
            ADMIN_EMAIL,
            REGISTERED_ROLE,
        )

    promoted = _rows_written(connection.execute(_promotion()))

    administrators = _administrators(connection)
    if administrators != [ADMIN_EMAIL]:
        raise RuntimeError(
            COUNT_MESSAGE.format(
                count=len(administrators),
                role=ADMIN_ROLE,
                email=ADMIN_EMAIL,
                among="" if ADMIN_EMAIL in administrators else "not ",
            )
        )

    logger.info(
        "Seeded the role %s for %s; %s, administrator count is %d",
        ADMIN_ROLE,
        ADMIN_EMAIL,
        _grant_outcome(stored, promoted),
        len(administrators),
    )


def upgrade() -> None:
    """Store and promote the single administrator account.

    Raises ``RuntimeError`` when the addresses holding
    :data:`ADMIN_ROLE` afterwards are not exactly one entry naming
    :data:`ADMIN_EMAIL`.
    """
    if _emitting_statements():
        _upgrade_offline()
        return
    _upgrade_online()


def _downgrade_offline() -> None:
    """Emit the demotion as one statement carrying its values."""
    op.execute(_demotion())
    logger.info(
        "Returned %s to the role %s; a statement stream reads no "
        "count, so no administrator count is checked here",
        ADMIN_EMAIL,
        REGISTERED_ROLE,
    )


def _downgrade_online() -> None:
    """Return the target account to the default role."""
    connection = op.get_bind()

    demoted = _rows_written(connection.execute(_demotion()))
    administrators = _administrators(connection)

    if ADMIN_EMAIL in administrators:
        raise RuntimeError(
            DEMOTION_MESSAGE.format(email=ADMIN_EMAIL, role=ADMIN_ROLE)
        )

    if demoted > 0:
        logger.info(
            "Returned %s to the role %s; %d row changed, administrator "
            "count is %d",
            ADMIN_EMAIL,
            REGISTERED_ROLE,
            demoted,
            len(administrators),
        )
    else:
        logger.info(
            "Left %s unchanged; it did not hold the role %s, "
            "administrator count is %d",
            ADMIN_EMAIL,
            ADMIN_ROLE,
            len(administrators),
        )


def downgrade() -> None:
    """Return the single administrator account to the default role.

    Raises ``RuntimeError`` when :data:`ADMIN_EMAIL` still holds
    :data:`ADMIN_ROLE` afterwards. An account another grant made an
    administrator is left as it stands.
    """
    if _emitting_statements():
        _downgrade_offline()
        return
    _downgrade_online()
