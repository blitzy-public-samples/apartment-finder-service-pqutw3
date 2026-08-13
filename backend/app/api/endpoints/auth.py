"""Authentication endpoints with uniform login refusals and
per-address throttling.
"""

import time
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
    equalize_login_refusal,
    get_password_hash,
    login_attempt_slot,
    verify_credential,
)
from backend.app.db.database import get_db
from backend.app.schema.user import UserCreate, UserLogin
from backend.app.db.models import LoginAttemptSlot, User

__all__ = [
    "DECISION_ACCOUNT_LOCKED",
    "DECISION_ADDRESS_CONFLICT",
    "DECISION_BUCKETED_REFUSAL",
    "DECISION_FAILED_ATTEMPT",
    "DECISION_INVALID_PASSWORD",
    "DECISION_LOCK_APPLIED",
    "DECISION_SUCCESSFUL_ATTEMPT",
    "DECISION_UNKNOWN_ACCOUNT",
    "DUPLICATE_EMAIL_DETAIL",
    "INVALID_CREDENTIALS_DETAIL",
    "LOGIN_REFUSED_MESSAGE",
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

#: Decision recorded when the address carries no account. The record
#: carries no address and no identifier; this code is what distinguishes
#: the refusal from the others in a query, and the response it accompanies
#: is identical to every other refusal.
DECISION_UNKNOWN_ACCOUNT = "login_unknown_account"

#: Decision recorded when the account lock is still in force.
DECISION_ACCOUNT_LOCKED = "login_account_locked"

#: Decision recorded when the account exists and the password does not
#: match it.
DECISION_INVALID_PASSWORD = "login_invalid_password"

#: Decision recorded when a counted failure reaches the threshold and the
#: lock is applied.
DECISION_LOCK_APPLIED = "login_lock_applied"

#: Decision recorded when a refusal is counted against a throttling
#: bucket. It names no account, since the branches that record it either
#: found none or hold one whose lock is already in force.
DECISION_BUCKETED_REFUSAL = "login_bucketed_refusal"

#: Decision recorded when a registration loses the address to a
#: concurrent request that committed first.
DECISION_ADDRESS_CONFLICT = "registration_address_conflict"

#: Message carried by every login refusal record. The record is told
#: apart by its ``decision`` field, not by its text.
LOGIN_REFUSED_MESSAGE = "Refused a login"

#: Rate limiter keyed by remote address, counting in the store named by
#: ``settings.RATE_LIMIT_STORAGE_URI`` and holding a bounded number of
#: keys. The application binds this object to ``app.state.limiter``, the
#: handlers below decorate against it, and the rate-limit gate
#: middleware evaluates it before a request body is read.
limiter = build_limiter()

router = APIRouter()


def _invalid_credentials(started: float) -> HTTPException:
    """Return the 401 every rejected login raises, once the shared
    refusal timing budget has elapsed.
    """
    equalize_login_refusal(started)
    return HTTPException(
        status_code=401,
        detail=INVALID_CREDENTIALS_DETAIL,
    )


def _as_aware(moment: datetime) -> datetime:
    """Return moment as an offset-aware UTC instant."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def _is_locked(user: User, moment: datetime) -> bool:
    locked_until = user.locked_until
    if locked_until is None:
        return False
    return _as_aware(locked_until) > moment


def _lock_row(db: Session, user_id: int) -> Optional[User]:
    """Return the account row re-read under a write lock held to the end
    of the transaction, or None.
    """
    return (
        db.query(User)
        .filter(User.id == user_id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )


def _abandon(db: Session, decision: str, user: User) -> None:
    """Roll back the pending change and record that the attempt outcome
    did not persist.
    """
    db.rollback()
    logger.error(
        "Failed to persist a login attempt outcome",
        extra={"decision": decision, "user_id": user.id},
    )


def _record_refusal(
    request: Request,
    decision: str,
    user_id: Optional[int],
) -> None:
    """Record one refused login under its decision code, carrying no
    address and no credential.
    """
    logger.warning(
        LOGIN_REFUSED_MESSAGE,
        extra={
            "decision": decision,
            "user_id": user_id,
            "path": request.scope.get("path"),
        },
    )


def _lock_slot(db: Session, bucket: int) -> Optional[LoginAttemptSlot]:
    """Return the throttling slot row held under a write lock.

    The row is re-read inside the current transaction and the lock is
    held until that transaction ends, exactly as :func:`_lock_row` does
    for an account. ``None`` means the seeded row is absent.
    """
    return (
        db.query(LoginAttemptSlot)
        .filter(LoginAttemptSlot.bucket == bucket)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )


def _record_bucketed_refusal(
    db: Session,
    email: str,
    moment: datetime,
) -> None:
    """Count one refusal against the bucket ``email`` falls in.

    This is the write the two refusal branches that hold no countable
    account row perform: the address carrying no account, and the account
    whose lock is already in force. It takes one write lock, issues one
    update and commits once, which is the same shape and the same number
    of statements :func:`_record_failed_attempt` issues against an
    account row.

    No address, credential or account identifier is written. The bucket is
    a keyed digest and the row records only a count and an instant.

    A persistence failure is rolled back and recorded rather than raised.
    The caller is answered the same
    :data:`INVALID_CREDENTIALS_DETAIL` either way.
    """
    bucket = login_attempt_slot(email)
    try:
        row = _lock_slot(db, bucket)
        if row is None:
            db.rollback()
            logger.error(
                "Login throttling slot is absent",
                extra={
                    "decision": DECISION_BUCKETED_REFUSAL,
                    "login_attempt_bucket": bucket,
                },
            )
            return
        row.attempts = (row.attempts or 0) + 1
        row.observed_at = moment
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.error(
            "Failed to persist a login refusal observation",
            extra={
                "decision": DECISION_BUCKETED_REFUSAL,
                "login_attempt_bucket": bucket,
            },
        )


def _record_failed_attempt(
    db: Session,
    user: User,
    moment: datetime,
) -> None:
    """Count one failed attempt on the locked row and apply the lockout
    at the configured threshold.
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
                    "decision": DECISION_LOCK_APPLIED,
                    "user_id": row.id,
                    "failed_login_attempts": attempts,
                    "lockout_minutes": settings.LOGIN_LOCKOUT_MINUTES,
                },
            )
        db.commit()
    except SQLAlchemyError:
        _abandon(db, DECISION_FAILED_ATTEMPT, user)


def _record_successful_attempt(db: Session, user: User) -> None:
    """Clear the failed-attempt count and the lock on the locked row."""
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
    """Register one account and return it beside a token, refusing a
    taken address identically from the pre-check and the unique
    constraint.
    """
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
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        logger.warning(
            "Refused a registration that lost the address to a "
            "concurrent request",
            extra={
                "decision": DECISION_ADDRESS_CONFLICT,
                "path": request.scope.get("path"),
            },
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
    started = time.monotonic()
    db_user = db.query(User).filter(User.email == user.email).first()
    attempted_at = datetime.now(timezone.utc)
    if db_user is None:
        verify_credential(user.password, None)
        _record_bucketed_refusal(db, user.email, attempted_at)
        _record_refusal(request, DECISION_UNKNOWN_ACCOUNT, None)
        raise _invalid_credentials(started)
    # Read before any write commits. Committing expires the loaded
    # instance, so an attribute read after the commit issues another
    # select against the account, which the branch holding no account
    # cannot issue.
    account_id = db_user.id
    if _is_locked(db_user, attempted_at):
        verify_credential(user.password, db_user.hashed_password)
        _record_bucketed_refusal(db, user.email, attempted_at)
        _record_refusal(request, DECISION_ACCOUNT_LOCKED, account_id)
        raise _invalid_credentials(started)
    if not verify_credential(user.password, db_user.hashed_password):
        _record_failed_attempt(db, db_user, attempted_at)
        _record_refusal(request, DECISION_INVALID_PASSWORD, account_id)
        raise _invalid_credentials(started)
    _record_successful_attempt(db, db_user)

    access_token = create_access_token(
        data={"sub": str(db_user.id), "role": db_user.role}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }
