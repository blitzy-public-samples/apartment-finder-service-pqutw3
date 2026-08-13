"""Seed and promote the single configured administrator account."""
import hashlib
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

#: Hexadecimal digits of the account reference this revision records in
#: place of the address it promotes.
ACCOUNT_REFERENCE_LENGTH = 12

#: Message of the failure raised when the addresses holding the
#: administrator role after the promotion are not exactly one entry
#: naming :data:`ADMIN_EMAIL`. It names the count, the role and the
#: account reference, and no address.
COUNT_MESSAGE = (
    "Administrator seed post-condition failed: {count} accounts hold "
    "the role {role} and account {reference} is {among}among them, "
    "exactly one is required and at most one is permitted"
)

#: Message of the failure raised when the seeded account still holds the
#: administrator role after ``downgrade``. It names the account reference
#: and no address.
DEMOTION_MESSAGE = (
    "Administrator seed reversal post-condition failed: account "
    "{reference} still holds the role {role}, none is permitted for that "
    "account once the reversal has run"
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


def account_reference(email: str = ADMIN_EMAIL) -> str:
    """Return the stable, non-reversible reference for ``email``.

    The value is the leading :data:`ACCOUNT_REFERENCE_LENGTH` hexadecimal
    digits of the SHA-256 digest of the address. It is the same on every
    run and for every environment, so a record is correlated across runs
    without the address appearing in one.
    """
    digest = hashlib.sha256(email.encode("utf-8")).hexdigest()
    return digest[:ACCOUNT_REFERENCE_LENGTH]


#: Reference recorded in place of :data:`ADMIN_EMAIL`.
ADMIN_REFERENCE = account_reference()


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
    return sa.text(
        "UPDATE users SET role = :role"
        " WHERE email = :email AND role <> :role"
    ).bindparams(role=ADMIN_ROLE, email=ADMIN_EMAIL)


def _demotion():
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
    if stored > 0:
        return "inserted the account and granted it the role"
    if promoted > 0:
        return "granted the role to the stored account"
    if stored == 0 and promoted == 0:
        return "left the account holding the role it already held"
    return "applied the role with no row count reported"


def _upgrade_offline() -> None:
    op.execute(_seed())
    op.execute(_promotion())
    logger.info(
        "Provisioned account %s at the role %s; its stored credential "
        "matches no password, so the account cannot be signed in to "
        "until that password is reset outside this revision",
        ADMIN_REFERENCE,
        REGISTERED_ROLE,
    )
    logger.info(
        "Seeded the role %s for account %s; a statement stream reads no "
        "count, so no administrator count is checked here",
        ADMIN_ROLE,
        ADMIN_REFERENCE,
    )


def _upgrade_online() -> None:
    connection = op.get_bind()

    stored = _rows_written(connection.execute(_seed()))
    if stored > 0:
        logger.info(
            "Provisioned account %s at the role %s; its stored "
            "credential matches no password, so the account cannot be "
            "signed in to until that password is reset outside this "
            "revision",
            ADMIN_REFERENCE,
            REGISTERED_ROLE,
        )

    promoted = _rows_written(connection.execute(_promotion()))

    administrators = _administrators(connection)
    if administrators != [ADMIN_EMAIL]:
        raise RuntimeError(
            COUNT_MESSAGE.format(
                count=len(administrators),
                role=ADMIN_ROLE,
                reference=ADMIN_REFERENCE,
                among="" if ADMIN_EMAIL in administrators else "not ",
            )
        )

    logger.info(
        "Seeded the role %s for account %s; %s, administrator count "
        "is %d",
        ADMIN_ROLE,
        ADMIN_REFERENCE,
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
    op.execute(_demotion())
    logger.info(
        "Returned account %s to the role %s; a statement stream reads no "
        "count, so no administrator count is checked here",
        ADMIN_REFERENCE,
        REGISTERED_ROLE,
    )


def _downgrade_online() -> None:
    connection = op.get_bind()

    demoted = _rows_written(connection.execute(_demotion()))
    administrators = _administrators(connection)

    if ADMIN_EMAIL in administrators:
        raise RuntimeError(
            DEMOTION_MESSAGE.format(
                reference=ADMIN_REFERENCE, role=ADMIN_ROLE
            )
        )

    if demoted > 0:
        logger.info(
            "Returned account %s to the role %s; %d row changed, "
            "administrator count is %d",
            ADMIN_REFERENCE,
            REGISTERED_ROLE,
            demoted,
            len(administrators),
        )
    else:
        logger.info(
            "Left account %s unchanged; it did not hold the role %s, "
            "administrator count is %d",
            ADMIN_REFERENCE,
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
