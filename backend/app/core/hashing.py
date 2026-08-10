"""Password hashing, shared and free of application settings.

Two callers hash a password, and they resolve the cost factor from
different places:

* :mod:`backend.app.core.security` hashes on the request path and holds
  the cost in ``Settings.BCRYPT_ROUNDS``.
* :mod:`backend.app.core.admin_provisioning` runs as a one-shot command
  that is given the database credential and the seed password and nothing
  else, so it reads the cost itself rather than importing ``Settings``.

The primitive both reach is :func:`hash_at`, so one format and one
library call serve both. :func:`configured_cost` resolves the cost from
the process environment and the environment file -- the two sources
``Settings`` reads -- and holds it to the same bounds
``Settings.BCRYPT_ROUNDS`` declares, so a value the application would
refuse is refused here rather than replaced by a default.

This module imports no setting, opens no connection, reads no file at
import and publishes no mutable state, so a command may import it with
only the seed password in its environment.
"""

import bcrypt

from backend.app.core import db_contract

__all__ = [
    "BCRYPT_ROUNDS_SETTING",
    "COST_CEILING",
    "COST_FLOOR",
    "DEFAULT_COST",
    "configured_cost",
    "hash_at",
    "hash_password",
]

#: Name of the setting carrying the bcrypt cost factor.
BCRYPT_ROUNDS_SETTING = "BCRYPT_ROUNDS"

#: Lowest cost factor a password may be hashed at.
COST_FLOOR = db_contract.BCRYPT_ROUNDS_FLOOR

#: Highest cost factor a password may be hashed at.
COST_CEILING = db_contract.BCRYPT_ROUNDS_CEILING

#: Cost factor used when nothing names one.
DEFAULT_COST = db_contract.DEFAULT_BCRYPT_ROUNDS


def hash_at(password: str, cost: int) -> str:
    """Return a bcrypt hash of the password at ``cost``.

    The password is hashed as supplied, and bcrypt refuses an input
    longer than 72 bytes.
    """
    hashed = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=cost),
    )
    return hashed.decode("utf-8")


def configured_cost() -> int:
    """Return the cost factor the environment names, or :data:`DEFAULT_COST`.

    The process environment is read first and then the environment file
    ``ENV_FILE`` names. A value either source carries must be a whole
    number from :data:`COST_FLOOR` to :data:`COST_CEILING`; raises
    ``ValueError`` naming the setting and the range for anything else.
    """
    return db_contract.read_bound(
        BCRYPT_ROUNDS_SETTING, DEFAULT_COST, COST_FLOOR, COST_CEILING
    )


def hash_password(password: str) -> str:
    """Return a bcrypt hash of the password at :func:`configured_cost`."""
    return hash_at(password, configured_cost())
