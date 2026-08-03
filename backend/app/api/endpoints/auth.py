import hmac
import math
import secrets
import threading
import time
from datetime import datetime
from hashlib import sha256
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.core.security import (
    SESSION_COOKIE_NAME,
    create_access_token,
    get_password_hash,
    verify_password,
)
from backend.app.db.database import get_db
from backend.app.schema.user import UserCreate, UserLogin
from backend.app.db.models import User

router = APIRouter()

# SEC-07: the single application limiter; main.py registers this object,
# its middleware and its rejection handler
limiter = Limiter(key_func=get_remote_address)

# SEC-07: the address-keyed limit enforced on the login route (CWE-307)
LOGIN_RATE_LIMIT = "{0}/{1} minutes".format(
    settings.LOGIN_RATE_LIMIT_ATTEMPTS,
    settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES,
)

# SEC-07: login-failure counters, one key per account, bounding guessing
# spread across client addresses (CWE-307)
_LOGIN_FAILURE_TRACKING_CAP = 4096
_ACCOUNT_KEY_PREFIX = "acct:"
_login_failures = {}
_login_failures_lock = threading.Lock()

# SEC-07: per-process key for the audit marker (CWE-916). DL-365
_AUDIT_MARKER_KEY = secrets.token_bytes(32)

# SEC-06: attributes of the HttpOnly/Secure/SameSite session cookie,
# shared by the set and the clear; keeps the token out of script-readable
# storage (CWE-1004). DL-365
_SESSION_COOKIE_PATH = "/"
_SESSION_COOKIE_SAMESITE = "strict"

# SEC-08: stand-in hash the unknown-address branch verifies against; the
# scheme and cost of a stored hash, over a per-process random secret
# (CWE-208). DL-365
_ABSENT_ACCOUNT_HASH = get_password_hash(secrets.token_urlsafe(32))


def _account_key(email: str) -> str:
    # SEC-07: one counter per stored account identity, keyed on the value
    # the credential query filters on (CWE-307, CWE-287). DL-365
    return _ACCOUNT_KEY_PREFIX + (email or "")


def _account_marker(throttle_key: str) -> str:
    # SEC-07: keyed, redacted account reference for the audit record
    return hmac.new(
        _AUDIT_MARKER_KEY, throttle_key.encode("utf-8"), sha256
    ).hexdigest()[:16]


# SEC-08: one detail for every way an attempt fails; an unknown address and
# a wrong secret are indistinguishable to the caller (CWE-209)
_UNIFORM_CREDENTIAL_DETAIL = "Incorrect email or password"


class CredentialRejected(HTTPException):
    # SEC-07: the single 401 the credential path returns, whatever refused
    # the attempt. SEC-08: audit_context holds redacted markers only
    def __init__(self, hasher_refusal: str = ""):
        super().__init__(
            status_code=401, detail=_UNIFORM_CREDENTIAL_DETAIL
        )
        if hasher_refusal:
            self.audit_context = {"hasher": hasher_refusal}


def _verified_credentials(db_user, submitted_password: str):
    # SEC-04/SEC-08: every hasher refusal is answered by the counted
    # uniform 401, never a 500 and never a distinguishable 422 (CWE-209,
    # CWE-307). Returns (matched, refusing exception type name)
    # SEC-08: both branches perform one verification with the stored scheme
    # and cost; tests assert invocation count, not total response-time
    # equality (CWE-208, CWE-203). DL-365
    stored_hash = (
        _ABSENT_ACCOUNT_HASH if db_user is None else db_user.hashed_password
    )
    try:
        matched = verify_password(submitted_password, stored_hash)
    except ValueError as refusal:
        return False, type(refusal).__name__
    return bool(matched and db_user is not None), ""


# SEC-07: the recovery hint on a throttled attempt. Retry-After alone;
# the RateLimit-* family would publish the attempt threshold (CWE-209).
RETRY_AFTER_HEADER = "Retry-After"


def _configured_window_seconds() -> int:
    # SEC-07: the throttle window, in seconds
    return settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES * 60


def retry_after_seconds(remaining: float) -> int:
    # SEC-07: a whole number of seconds inside the window, so a client
    # that waits it out is admitted and never told to wait longer than
    # the window itself. A rounded-down hint would invite a retry the
    # limiter still refuses, so the value rounds up.
    window = _configured_window_seconds()
    if remaining <= 0:
        return window
    return max(1, min(window, math.ceil(remaining)))


def _seconds_until_admission(*throttle_keys: str) -> int:
    # SEC-07: seconds until the earliest exhausted key admits another
    # attempt. A refusal raised by the capacity guard holds no expiry,
    # so the configured window is the answer.
    now = time.monotonic()
    with _login_failures_lock:
        expiries = [
            _login_failures[key][1]
            for key in throttle_keys
            if key in _login_failures
        ]
    if not expiries:
        return _configured_window_seconds()
    return retry_after_seconds(min(expiries) - now)


class AccountThrottled(HTTPException):
    # SEC-07: 429 carrying the account marker to the error boundary, which
    # logs one record under the same error_id the client receives, and the
    # Retry-After a throttled caller needs to recover.
    # SEC-08: audit_context holds redacted markers only.
    def __init__(self, account_marker: str, retry_after: int):
        super().__init__(
            status_code=429,
            headers={RETRY_AFTER_HEADER: str(retry_after)},
        )
        self.audit_context = {"account": account_marker}


def _prune_expired_login_failures(now: float) -> None:
    # SEC-07: drops entries whose window has already elapsed
    for key in [k for k, entry in _login_failures.items() if entry[1] <= now]:
        del _login_failures[key]


def _evict_unexhausted_login_keys(limit: int, needed: int) -> bool:
    # SEC-07: frees slots from the keys closest to expiry that sit below
    # the limit; a key at the limit is never evicted, and False denies the
    # attempt (CWE-307). DL-365
    candidates = sorted(
        (entry[1], key) for key, entry in _login_failures.items()
        if entry[0] < limit
    )
    if len(candidates) < needed:
        return False
    for _expires_at, key in candidates[:needed]:
        del _login_failures[key]
    return True


def _reserve_login_attempt(*throttle_keys: str) -> bool:
    # SEC-07: counts the attempt and decides admission inside one critical
    # section; a concurrent burst shares no allowance (CWE-367). False
    # means a key is at the limit or the map is full. DL-365
    now = time.monotonic()
    window = settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES * 60
    limit = settings.LOGIN_RATE_LIMIT_ATTEMPTS
    with _login_failures_lock:
        _prune_expired_login_failures(now)
        entries = [(key, _login_failures.get(key)) for key in throttle_keys]
        if any(
            entry is not None and entry[0] >= limit
            for _key, entry in entries
        ):
            return False
        missing = sum(1 for _key, entry in entries if entry is None)
        overflow = len(_login_failures) + missing - _LOGIN_FAILURE_TRACKING_CAP
        if overflow > 0 and not _evict_unexhausted_login_keys(limit, overflow):
            return False
        for key, entry in entries:
            if entry is None:
                _login_failures[key] = (1, now + window)
            else:
                _login_failures[key] = (entry[0] + 1, entry[1])
        return True


def _clear_login_failures(*throttle_keys: str) -> None:
    with _login_failures_lock:
        for key in throttle_keys:
            _login_failures.pop(key, None)


def _set_session_cookie(response: Response, access_token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=access_token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path=_SESSION_COOKIE_PATH,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=_SESSION_COOKIE_SAMESITE,
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path=_SESSION_COOKIE_PATH,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=_SESSION_COOKIE_SAMESITE,
    )

@router.post('/register')
def register_user(
    response: Response,
    user: UserCreate,
    db: Session = Depends(get_db),
):
    # Hash the submitted secret first
    # SEC-08: both answers pay the hashing cost, so the elapsed time of a
    # refusal does not disclose whether the address is already registered
    # (CWE-208, CWE-203)
    hashed_password = get_password_hash(user.password)

    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user with the hash computed above
    new_user = User(email=user.email, hashed_password=hashed_password,
                    created_at=datetime.utcnow())
    db.add(new_user)
    # SEC-08: a concurrent registration losing the unique-email race
    # returns the same 400 the pre-check raises, never a 500 (CWE-367)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400, detail="Email already registered"
        )
    db.refresh(new_user)
    
    # Generate access token
    # SEC-02: mints sub as user id; closes the sub/User.id identity mismatch
    access_token = create_access_token(data={"sub": str(new_user.id)})
    _set_session_cookie(response, access_token)
    
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
@limiter.limit(LOGIN_RATE_LIMIT)
def login_user(
    request: Request,
    response: Response,
    user: UserLogin,
    db: Session = Depends(get_db),
):
    # SEC-07: the decorator bounds attempts per client address and the
    # counter below bounds them per account, before the credentials are
    # read (CWE-307)
    account_key = _account_key(user.email)
    if not _reserve_login_attempt(account_key):
        # SEC-07: the error boundary logs this attempt under the response
        # error_id; SEC-08: neither the client address nor the submitted
        # email reaches the record
        raise AccountThrottled(
            _account_marker(account_key),
            _seconds_until_admission(account_key),
        )

    # Verify user credentials
    db_user = db.query(User).filter(User.email == user.email).first()
    matched, hasher_refusal = _verified_credentials(db_user, user.password)
    if not matched:
        # SEC-07: the reserved attempt stands, counted once per account
        raise CredentialRejected(hasher_refusal)
    
    # SEC-07: on success the counter retains no state
    _clear_login_failures(account_key)

    # Generate access token
    # SEC-02: mints sub as user id; closes the sub/User.id identity mismatch
    access_token = create_access_token(data={"sub": str(db_user.id)})
    _set_session_cookie(response, access_token)
    
    # Return token
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


@router.post('/logout')
def logout_user(response: Response):
    # SEC-06: clears the session cookie server-side
    _clear_session_cookie(response)
    return {"detail": "Logged out"}