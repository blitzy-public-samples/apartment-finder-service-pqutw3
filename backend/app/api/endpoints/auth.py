"""Registration and login endpoints.

Both endpoints accept a JSON body and are rate limited per remote
address at the rate their setting names. Each mints its token through
:func:`backend.app.core.security.create_access_token`, passing the
user's integer identifier rendered as a string as the subject and the
role stored on the row beside it. The role claim is descriptive: an
authorization decision reads the role from the stored row, not from the
token.

Registration stores the creation timestamp taken from the server clock,
and returns the created user beside the token.

Login answers with one response -- ``401`` carrying
:data:`INVALID_CREDENTIALS_DETAIL` -- for an address that names no
account, for an account whose lock is still in force, and for a password
that does not match. Each of those three paths runs one password
comparison, against :data:`backend.app.core.security.DECOY_HASH` where
there is no stored hash to compare with. A password that does not match
is counted on the row, reaching ``settings.LOGIN_MAX_ATTEMPTS`` locks
the account for ``settings.LOGIN_LOCKOUT_MINUTES`` minutes, and a login
that succeeds clears both the count and the lock.

:data:`limiter` is defined here and is the object the application binds
to ``app.state.limiter``.

Usage::

    POST /auth/register  {"email": ..., "password": ...}
    POST /auth/login     {"email": ..., "password": ...}
"""

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.core.logging import get_logger
from backend.app.core.security import (
    create_access_token,
    get_password_hash,
    verify_decoy,
    verify_password,
)
from backend.app.db.database import get_db
from backend.app.schema.user import UserCreate, UserLogin
from backend.app.db.models import User

__all__ = [
    "INVALID_CREDENTIALS_DETAIL",
    "limiter",
    "login_user",
    "register_user",
    "router",
]

logger = get_logger(__name__)

#: Detail carried by every rejected login.
INVALID_CREDENTIALS_DETAIL = "Incorrect email or password"

#: Rate limiter keyed by remote address. The application binds this
#: object to ``app.state.limiter`` and the handlers below decorate
#: against it.
limiter = Limiter(key_func=get_remote_address)

router = APIRouter()


def _invalid_credentials() -> HTTPException:
    """Return the response raised by every rejected login.

    The status and the detail are the same whatever the rejection.
    """
    return HTTPException(
        status_code=401,
        detail=INVALID_CREDENTIALS_DETAIL,
    )


def _as_aware(moment: datetime) -> datetime:
    """Return ``moment`` with UTC attached when it carries no offset.

    Timestamps read back from the ``users`` table carry no offset, and
    this renders them comparable with the server clock.
    """
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def _is_locked(user: User, moment: datetime) -> bool:
    """Report whether the account's lock is in force at ``moment``."""
    locked_until = user.locked_until
    if locked_until is None:
        return False
    return _as_aware(locked_until) > moment


def _record_failed_attempt(
    db: Session,
    user: User,
    moment: datetime,
) -> None:
    """Count one failed attempt, locking the account at the threshold.

    A lock that has already expired restarts the count at one. Reaching
    ``settings.LOGIN_MAX_ATTEMPTS`` sets ``locked_until`` to
    ``settings.LOGIN_LOCKOUT_MINUTES`` minutes after ``moment``.
    """
    if user.locked_until is None:
        attempts = (user.failed_login_attempts or 0) + 1
    else:
        attempts = 1
        user.locked_until = None
    user.failed_login_attempts = attempts
    if attempts >= settings.LOGIN_MAX_ATTEMPTS:
        user.locked_until = moment + timedelta(
            minutes=settings.LOGIN_LOCKOUT_MINUTES
        )
        logger.warning(
            "Locked an account on reaching the failed-attempt limit",
            extra={
                "user_id": user.id,
                "failed_login_attempts": attempts,
                "lockout_minutes": settings.LOGIN_LOCKOUT_MINUTES,
            },
        )
    db.commit()


def _record_successful_attempt(db: Session, user: User) -> None:
    """Clear the failed-attempt count and the lock on the account."""
    if user.failed_login_attempts or user.locked_until is not None:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()


@router.post('/register')
@limiter.limit(settings.RATE_LIMIT_REGISTER)
def register_user(
    request: Request,
    user: UserCreate,
    db: Session = Depends(get_db),
):
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create new user with hashed password
    hashed_password = get_password_hash(user.password)
    new_user = User(
        email=user.email,
        hashed_password=hashed_password,
        created_at=datetime.now(timezone.utc),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Generate access token
    access_token = create_access_token(
        data={"sub": str(new_user.id), "role": new_user.role}
    )

    # Return user info and token
    return {
        "user": {
            "id": new_user.id,
            "email": new_user.email
        },
        "access_token": access_token,
        "token_type": "bearer"
    }


@router.post('/login')
@limiter.limit(settings.RATE_LIMIT_LOGIN)
def login_user(
    request: Request,
    user: UserLogin,
    db: Session = Depends(get_db),
):
    # Verify user credentials
    db_user = db.query(User).filter(User.email == user.email).first()
    attempted_at = datetime.now(timezone.utc)
    if db_user is None:
        verify_decoy(user.password)
        raise _invalid_credentials()
    if _is_locked(db_user, attempted_at):
        verify_decoy(user.password)
        logger.warning(
            "Refused a login while the account lock was in force",
            extra={"user_id": db_user.id},
        )
        raise _invalid_credentials()
    if not verify_password(user.password, db_user.hashed_password):
        _record_failed_attempt(db, db_user, attempted_at)
        raise _invalid_credentials()
    _record_successful_attempt(db, db_user)

    # Generate access token
    access_token = create_access_token(
        data={"sub": str(db_user.id), "role": db_user.role}
    )

    # Return token
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }
