"""Operator provisioning of the seeded administrator's credential.

``backend/migrations/versions/0002_seed_single_admin.py`` leaves the
address :data:`ADMIN_EMAIL` holding the role ``admin`` and the stored
value ``!locked-no-password-set``, which is not a hash any password
produces. The account therefore holds the role and no means of
authenticating. This module is the one supported path that gives it a
credential, and it is run by an operator rather than by the application.

Usage, from the repository root::

    ADMIN_SEED_PASSWORD=... python -m backend.app.core.admin_provisioning

The password is read from the process environment under
:data:`PASSWORD_VARIABLE` and never from an argument, so it does not
reach a shell history, a process listing or a log record. In a deployed
environment the value is delivered by Secret Manager through the same
mount the backend reads its other credentials from; see
``infrastructure/kubernetes/70-admin-credential-job.yaml``.

What the run does, and refuses to do:

* it addresses only :data:`ADMIN_EMAIL`, which is fixed in this module
  and equal to the address the grant revision names. No other account is
  read and none is written
* it applies the registration password policy to the supplied value, so a
  credential weaker than a registered account's is refused
* it writes a credential only when the stored value is the locked marker.
  A row already carrying a usable credential is left alone unless
  :data:`RESET_VARIABLE` is set to :data:`RESET_VALUE`, which is how a
  deliberate reset is expressed
* it re-asserts the grant revision's post-condition afterwards: exactly
  one account holds the administrative role and that account is
  :data:`ADMIN_EMAIL`. Any other result rolls the transaction back
* it grants no role. A row that does not already hold the administrative
  role is refused, so this module cannot be an escalation path
* every outcome is recorded on the redacting application logger, naming
  the address, the outcome and the number of administrators. No record
  carries the credential or its hash

Exit codes: ``0`` when the credential is in place, ``1`` when the run was
refused. Every refusal names its reason on standard error.
"""

import os
import sys
from typing import Optional, Tuple

from sqlalchemy.orm import Session

from backend.app.core.authorization import Role
from backend.app.core.logging import get_logger, redact, register_secret_values
from backend.app.core.security import get_password_hash
from backend.app.db.database import SessionLocal
from backend.app.db.models import User
from backend.app.schema.user import UserCreate

__all__ = [
    "ADMIN_EMAIL",
    "LOCKED_CREDENTIAL",
    "PASSWORD_VARIABLE",
    "RESET_VALUE",
    "RESET_VARIABLE",
    "AdminProvisioningError",
    "main",
    "provision_admin_credential",
]

#: The one address this module reads or writes. It is equal to
#: ``ADMIN_EMAIL`` in the grant revision.
ADMIN_EMAIL = "test@blitzy.com"

#: Role the target account must already hold. This module never writes
#: it.
ADMIN_ROLE = Role.ADMIN.value

#: Value the grant revision stores in ``users.hashed_password``. A row
#: carrying it has no usable credential.
LOCKED_CREDENTIAL = "!locked-no-password-set"

#: Environment variable the credential is read from.
PASSWORD_VARIABLE = "ADMIN_SEED_PASSWORD"

#: Environment variable that permits replacing a credential already in
#: place.
RESET_VARIABLE = "ADMIN_CREDENTIAL_RESET"

#: Value :data:`RESET_VARIABLE` carries to permit a replacement.
RESET_VALUE = "true"

#: Outcome recorded when the locked marker was replaced.
OUTCOME_PROVISIONED = "provisioned"

#: Outcome recorded when a credential already in place was replaced.
OUTCOME_RESET = "reset"

#: Outcome recorded when a credential was already in place and no reset
#: was requested.
OUTCOME_UNCHANGED = "unchanged"

#: Name this module's records are emitted under, for both an imported run
#: and a ``python -m`` run.
LOGGER_NAME = "app.core.admin_provisioning"

#: Logger this module records on. It sits under the application logger, so
#: the redacting filter applies to every record.
logger = get_logger(LOGGER_NAME)


class AdminProvisioningError(RuntimeError):
    """Raised when a provisioning run is refused."""


def _requested_reset() -> bool:
    """Report whether a replacement of a live credential was requested."""
    declared = (os.environ.get(RESET_VARIABLE) or "").strip().lower()
    return declared == RESET_VALUE


def _checked_password(supplied: Optional[str]) -> str:
    """Return the credential, refusing one outside the password policy.

    The value is checked against :class:`UserCreate`, the same contract a
    registration is checked against, whichever way the credential
    arrived. The refusal names the variable and the rule that rejected
    it, and never repeats the value.
    """
    if not supplied:
        raise AdminProvisioningError(
            "{0} is not set. Supply the credential in the process "
            "environment; it is never read from an argument.".format(
                PASSWORD_VARIABLE
            )
        )
    register_secret_values(supplied)
    try:
        UserCreate(email=ADMIN_EMAIL, password=supplied)
    except ValueError as rejected:
        raise AdminProvisioningError(
            "The credential supplied in {0} does not satisfy the "
            "password policy: {1}".format(
                PASSWORD_VARIABLE, redact(str(rejected))
            )
        )
    return supplied


def _read_password() -> str:
    """Return the checked credential the environment carries."""
    return _checked_password(os.environ.get(PASSWORD_VARIABLE))


def _load_target(session: Session) -> User:
    """Return the target account, refusing an absent or unprivileged one.

    The row is loaded for update where the backend supports it, so a
    concurrent run cannot interleave with this one.
    """
    account = (
        session.query(User)
        .filter(User.email == ADMIN_EMAIL)
        .with_for_update()
        .first()
    )
    if account is None:
        raise AdminProvisioningError(
            "No account is stored for {0}. Apply the migrations first: "
            "python -m alembic -c backend/alembic.ini upgrade head".format(
                ADMIN_EMAIL
            )
        )
    if account.role != ADMIN_ROLE:
        raise AdminProvisioningError(
            "{0} holds the role {1} rather than {2}. This step sets a "
            "credential and grants no role.".format(
                ADMIN_EMAIL, account.role, ADMIN_ROLE
            )
        )
    return account


def _administrator_addresses(session: Session) -> Tuple[str, ...]:
    """Return the addresses holding the administrative role, sorted."""
    rows = (
        session.query(User.email)
        .filter(User.role == ADMIN_ROLE)
        .order_by(User.email)
        .all()
    )
    return tuple(row[0] for row in rows)


def _assert_single_administrator(session: Session) -> int:
    """Assert exactly one account holds the role, and return the count.

    This is the post-condition the grant revision establishes, and it is
    re-asserted before this module's caller commits.
    """
    addresses = _administrator_addresses(session)
    if addresses != (ADMIN_EMAIL,):
        raise AdminProvisioningError(
            "Administrator post-condition failed: {0} accounts hold the "
            "role {1} and the expected set is exactly {2}.".format(
                len(addresses), ADMIN_ROLE, ADMIN_EMAIL
            )
        )
    return len(addresses)


def provision_admin_credential(
    session: Session, password: Optional[str] = None
) -> str:
    """Put a usable credential on the seeded administrator.

    ``session`` is the session the work runs in; the caller owns its
    lifetime. ``password`` defaults to the value
    :data:`PASSWORD_VARIABLE` carries, and is held to the registration
    password policy whichever way it arrived.

    Returns :data:`OUTCOME_PROVISIONED` when the locked marker was
    replaced, :data:`OUTCOME_RESET` when a credential already in place was
    replaced under an explicit reset, and :data:`OUTCOME_UNCHANGED` when
    one was already in place and no reset was requested. Raises
    :class:`AdminProvisioningError` on every refusal.

    A repeated run with the same credential and no reset reports
    :data:`OUTCOME_UNCHANGED` and writes nothing, so the operation is
    idempotent.
    """
    if password is None:
        password = _read_password()
    else:
        password = _checked_password(password)
    account = _load_target(session)
    locked = account.hashed_password == LOCKED_CREDENTIAL

    if not locked and not _requested_reset():
        count = _assert_single_administrator(session)
        logger.info(
            "Left the credential of %s in place; it is not the locked "
            "marker and no reset was requested. Set the variable %s to "
            "the value %r to replace it. Administrator count is %d.",
            ADMIN_EMAIL,
            RESET_VARIABLE,
            RESET_VALUE,
            count,
            extra={"outcome": OUTCOME_UNCHANGED, "email": ADMIN_EMAIL},
        )
        return OUTCOME_UNCHANGED

    account.hashed_password = get_password_hash(password)
    account.failed_login_attempts = 0
    account.locked_until = None
    session.flush()

    count = _assert_single_administrator(session)
    outcome = OUTCOME_PROVISIONED if locked else OUTCOME_RESET
    logger.info(
        "Stored a credential for %s; the previous value %s the locked "
        "marker, the failed-attempt count and any lock were cleared, and "
        "the administrator count is %d.",
        ADMIN_EMAIL,
        "was" if locked else "was not",
        count,
        extra={"outcome": outcome, "email": ADMIN_EMAIL},
    )
    return outcome


def main(argv: Optional[Tuple[str, ...]] = None) -> int:
    """Run one provisioning attempt and report it.

    The command takes no argument: a non-empty ``argv`` is refused with a
    message naming :data:`PASSWORD_VARIABLE`. Returns the process exit
    code, ``0`` when the credential is in place and ``1`` when the run
    was refused.
    """
    if argv:
        sys.stderr.write(
            "This command takes no argument. Supply the credential in "
            "{0}.\n".format(PASSWORD_VARIABLE)
        )
        return 1

    session = SessionLocal()
    try:
        outcome = provision_admin_credential(session)
        session.commit()
    except AdminProvisioningError as refused:
        session.rollback()
        sys.stderr.write("{0}\n".format(redact(str(refused))))
        return 1
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    sys.stdout.write(
        "The administrator {0} is {1}.\n".format(ADMIN_EMAIL, outcome)
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    sys.exit(main(tuple(sys.argv[1:])))
