"""Registration and login endpoints.

Both endpoints accept a JSON body and are rate limited per remote
address. The token subject is the user's integer identifier rendered as
a string; the role claim beside it is descriptive, because an
authorization decision reads the role from the stored row.

Registration stores the creation timestamp taken from the server clock,
and returns the created user beside the token. An address already taken
is answered ``400`` carrying :data:`DUPLICATE_EMAIL_DETAIL`, whether the
address is found by the lookup or by the unique constraint on the
insert. The ``users.email`` unique constraint is the authority on
whether an address is taken, so a race between two registrations for one
address ends with the loser rolled back and answered exactly as the
ordinary duplicate is.

Login answers with one response -- ``401`` carrying
:data:`INVALID_CREDENTIALS_DETAIL` -- for an address that names no
account, for an account whose lock is still in force, and for a password
that does not match. Each of those three paths runs one password
comparison, against :data:`backend.app.core.security.DECOY_HASH` where
there is no stored hash to compare with. A password that does not match
is counted on the row, reaching ``settings.LOGIN_MAX_ATTEMPTS`` locks
the account for ``settings.LOGIN_LOCKOUT_MINUTES`` minutes, and a login
that succeeds clears both the count and the lock. Both of those writes
re-read the row under a write lock held for the transaction, so
attempts arriving at once are counted one by one and no count is lost.
Neither write can change the response: a failure to persist one is
rolled back and recorded, and the caller answers as it would have
anyway.

:data:`limiter` is defined here and is the object the application binds
to ``app.state.limiter``.

Usage::

    POST /auth/register  {"email": ..., "password": ...}
    POST /auth/login     {"email": ..., "password": ...}
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.core.logging import get_logger, log_exception
from backend.app.core.rate_limit import build_limiter
from backend.app.core.security import (
    create_access_token,
    get_password_hash,
    verify_credential,
)
from backend.app.db.database import get_db
from backend.app.schema.user import UserCreate, UserLogin
from backend.app.db.models import User

__all__ = [
    "DUPLICATE_EMAIL_DETAIL",
    "INVALID_CREDENTIALS_DETAIL",
    "REGISTRATION_FAILED_DETAIL",
    "limiter",
    "login_user",
    "register_user",
    "router",
]

logger = get_logger(__name__)

INVALID_CREDENTIALS_DETAIL = "Incorrect email or password"

#: Detail carried by every registration refused for a taken address. One
#: detail covers an address the pre-check finds and an address the unique
#: constraint rejects, so the two paths are indistinguishable.
DUPLICATE_EMAIL_DETAIL = "Email already registered"

#: Detail returned when a registration cannot be persisted.
REGISTRATION_FAILED_DETAIL = "Registration could not be completed"

#: Outcome recorded when a counted failure does not persist.
DECISION_FAILED_ATTEMPT = "failed_attempt"

#: Outcome recorded when a cleared count does not persist.
DECISION_SUCCESSFUL_ATTEMPT = "successful_attempt"

#: Rate limiter keyed by remote address, counting in the store named by
#: ``settings.RATE_LIMIT_STORAGE_URI`` and holding a bounded number of
#: keys. The application binds this object to ``app.state.limiter``, the
#: handlers below decorate against it, and the rate-limit gate
#: middleware evaluates it before a request body is read.
limiter = build_limiter()

router = APIRouter()


def _invalid_credentials() -> HTTPException:
    """Return the ``HTTPException`` every rejected login raises.

    It carries status ``401`` and :data:`INVALID_CREDENTIALS_DETAIL`
    whatever the reason for the rejection.
    """
    return HTTPException(
        status_code=401,
        detail=INVALID_CREDENTIALS_DETAIL,
    )


def _as_aware(moment: datetime) -> datetime:
    """Return ``moment`` as an offset-aware instant.

    ``users.locked_until`` is declared ``DateTime(timezone=True)``, so a
    value read back over PostgreSQL already carries its offset and is
    returned unchanged. A backend that does not store an offset returns
    the value naive; UTC is attached to it, which is the instant it
    holds, because the engine opens every PostgreSQL session with its
    time zone set to UTC and this module only ever writes UTC.
    """
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def _is_locked(user: User, moment: datetime) -> bool:
    locked_until = user.locked_until
    if locked_until is None:
        return False
    return _as_aware(locked_until) > moment


def _lock_row(db: Session, user_id: int) -> Optional[User]:
    """Return the account row held under a write lock, or ``None``.

    The row is re-read inside the current transaction and the lock is
    held until that transaction ends, so two requests touching the same
    account are serialised rather than interleaved.
    ``populate_existing`` discards the copy the request loaded earlier,
    so the attributes returned are the persisted ones.
    """
    return (
        db.query(User)
        .filter(User.id == user_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )


def _abandon(db: Session, decision: str, user: User) -> None:
    """Discard the pending change and record that it did not persist.

    The session is left clean so the request can still be answered, and
    the record names the decision and the account rather than any
    credential.
    """
    db.rollback()
    logger.error(
        "Failed to persist a login attempt outcome",
        extra={"decision": decision, "user_id": user.id},
    )


def _record_failed_attempt(
    db: Session,
    user: User,
    moment: datetime,
) -> None:
    """Count one failed attempt, locking the account at the threshold.

    The count is read back from the locked row and incremented in the
    same transaction, so concurrent failures each advance it once.

    A lock that has already expired restarts the count at one, and a
    lock still in force is left in place. Reaching
    ``settings.LOGIN_MAX_ATTEMPTS`` sets ``locked_until`` to
    ``settings.LOGIN_LOCKOUT_MINUTES`` minutes after ``moment``.

    A persistence failure is rolled back and recorded rather than
    raised: the caller answers the same
    :data:`INVALID_CREDENTIALS_DETAIL` either way, so a database fault
    never discloses that the account exists.
    """
    try:
        row = _lock_row(db, user.id)
        if row is None:
            db.rollback()
            return
        locked_until = row.locked_until
        if locked_until is not None and _as_aware(locked_until) <= moment:
            row.locked_until = None
            attempts = 1
        else:
            attempts = (row.failed_login_attempts or 0) + 1
        row.failed_login_attempts = attempts
        if attempts >= settings.LOGIN_MAX_ATTEMPTS:
            row.locked_until = moment + timedelta(
                minutes=settings.LOGIN_LOCKOUT_MINUTES
            )
            logger.warning(
                "Locked an account on reaching the failed-attempt limit",
                extra={
                    "user_id": row.id,
                    "failed_login_attempts": attempts,
                    "lockout_minutes": settings.LOGIN_LOCKOUT_MINUTES,
                },
            )
        db.commit()
    except SQLAlchemyError:
        _abandon(db, DECISION_FAILED_ATTEMPT, user)


def _record_successful_attempt(db: Session, user: User) -> None:
    """Clear the failed-attempt count and the lock on the account.

    The row is re-read under the same write lock the failure path takes,
    so a failure running alongside this one cannot reinstate the count
    it clears.

    A persistence failure is rolled back and recorded rather than raised,
    because the credential has already been verified and the login
    stands.
    """
    try:
        row = _lock_row(db, user.id)
        if row is None:
            db.rollback()
            return
        if row.failed_login_attempts or row.locked_until is not None:
            row.failed_login_attempts = 0
            row.locked_until = None
            db.commit()
        else:
            db.rollback()
    except SQLAlchemyError:
        _abandon(db, DECISION_SUCCESSFUL_ATTEMPT, user)


@router.post('/register')
@limiter.limit(settings.RATE_LIMIT_REGISTER)
def register_user(
    request: Request,
    user: UserCreate,
    db: Session = Depends(get_db),
):
    """Register one account and return it beside a token.

    The ``users.email`` unique constraint is the authority on whether the
    address is taken. The pre-check below answers the ordinary case
    without a failed insert, and the constraint answers the race two
    concurrent registrations for one address can win together: the loser
    is rolled back and receives the same
    :data:`DUPLICATE_EMAIL_DETAIL` response as the pre-check, so the two
    outcomes are indistinguishable.
    """
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(
            status_code=400, detail=DUPLICATE_EMAIL_DETAIL
        )

    hashed_password = get_password_hash(user.password)
    new_user = User(
        email=user.email,
        hashed_password=hashed_password,
        created_at=datetime.now(timezone.utc),
    )
    db.add(new_user)
    # A conflict on the unique address constraint is answered with the
    # same status and detail as the lookup above.
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        logger.warning(
            "Refused a registration that lost the address to a "
            "concurrent request"
        )
        raise HTTPException(
            status_code=400, detail=DUPLICATE_EMAIL_DETAIL
        ) from None
    except SQLAlchemyError as exc:
        db.rollback()
        log_exception(logger, "Failed to persist a registration", exc)
        raise HTTPException(
            status_code=500, detail=REGISTRATION_FAILED_DETAIL
        ) from None
    db.refresh(new_user)

    access_token = create_access_token(
        data={"sub": str(new_user.id), "role": new_user.role}
    )

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
    db_user = db.query(User).filter(User.email == user.email).first()
    attempted_at = datetime.now(timezone.utc)
    if db_user is None:
        verify_credential(user.password, None)
        raise _invalid_credentials()
    if _is_locked(db_user, attempted_at):
        verify_credential(user.password, db_user.hashed_password)
        logger.warning(
            "Refused a login while the account lock was in force",
            extra={"user_id": db_user.id},
        )
        raise _invalid_credentials()
    if not verify_credential(user.password, db_user.hashed_password):
        _record_failed_attempt(db, db_user, attempted_at)
        raise _invalid_credentials()
    _record_successful_attempt(db, db_user)

    access_token = create_access_token(
        data={"sub": str(db_user.id), "role": db_user.role}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }
