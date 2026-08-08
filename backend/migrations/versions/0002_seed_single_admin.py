"""Seed the single administrator account

Promotes the account stored under the address :data:`ADMIN_EMAIL` to the
role :data:`ADMIN_ROLE`. That address is the only address this revision
names, and it is fixed in this module.

The promotion is one conditional statement: ``upgrade`` re-applied over
an already-promoted account updates no row. The administrator count is
read afterwards and checked. At most one administrator is present in
every case, exactly one once the target account is stored, and none
while it is absent. A count outside that shape raises, and the
transaction is rolled back. Each outcome is recorded on the ``alembic``
logger.

``downgrade`` returns that one account to the role
:data:`REGISTERED_ROLE`. It touches no other account, no other column,
and no table or column definition.

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-08 09:31:48.204617

"""
import logging

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


#: Address of the one account this revision promotes.
ADMIN_EMAIL = "test@blitzy.com"

#: Role this revision grants that address.
ADMIN_ROLE = "admin"

#: Role ``downgrade`` returns that address to.
REGISTERED_ROLE = "registered"

#: Logger carrying this revision's records. The name sits in the
#: ``alembic`` namespace ``backend/alembic.ini`` configures at INFO.
logger = logging.getLogger("alembic.runtime.migration")


def upgrade() -> None:
    """Promote the single administrator account."""
    connection = op.get_bind()

    connection.execute(
        sa.text(
            "UPDATE users SET role = :role"
            " WHERE email = :email AND role <> :role"
        ),
        {"role": ADMIN_ROLE, "email": ADMIN_EMAIL},
    )

    administrators = int(
        connection.execute(
            sa.text("SELECT COUNT(*) FROM users WHERE role = :role"),
            {"role": ADMIN_ROLE},
        ).scalar()
    )
    target_rows = int(
        connection.execute(
            sa.text("SELECT COUNT(*) FROM users WHERE email = :email"),
            {"email": ADMIN_EMAIL},
        ).scalar()
    )

    if administrators > 1:
        raise RuntimeError(
            "Administrator seed post-condition failed: "
            f"{administrators} accounts hold the role {ADMIN_ROLE}, "
            "at most one is permitted"
        )

    if target_rows == 0:
        if administrators != 0:
            raise RuntimeError(
                "Administrator seed post-condition failed: "
                f"{ADMIN_EMAIL} is not stored while "
                f"{administrators} account holds the role "
                f"{ADMIN_ROLE}"
            )
        logger.warning(
            "Administrator seed target %s is not stored; granted no "
            "administrator, administrator count is %d",
            ADMIN_EMAIL,
            administrators,
        )
        return

    if administrators != 1:
        raise RuntimeError(
            "Administrator seed post-condition failed: "
            f"{ADMIN_EMAIL} is stored while {administrators} accounts "
            f"hold the role {ADMIN_ROLE}"
        )

    logger.info(
        "Seeded the role %s for %s; administrator count is %d",
        ADMIN_ROLE,
        ADMIN_EMAIL,
        administrators,
    )


def downgrade() -> None:
    """Return the single administrator account to the default role."""
    connection = op.get_bind()

    connection.execute(
        sa.text(
            "UPDATE users SET role = :registered"
            " WHERE email = :email AND role = :admin"
        ),
        {
            "registered": REGISTERED_ROLE,
            "email": ADMIN_EMAIL,
            "admin": ADMIN_ROLE,
        },
    )

    logger.info(
        "Returned %s to the role %s",
        ADMIN_EMAIL,
        REGISTERED_ROLE,
    )
