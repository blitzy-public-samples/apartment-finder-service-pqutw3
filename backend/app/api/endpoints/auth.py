import threading
import time
from datetime import datetime
from hashlib import sha256
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from slowapi import Limiter
from slowapi.util import get_remote_address
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

# SEC-07: the single application limiter; main.py registers this object
limiter = Limiter(key_func=get_remote_address)

# SEC-07: login-attempt counters, one key per account and one per client
# address. Entries expire with the throttle window; at the cap only a key
# below the limit is evicted.
_LOGIN_FAILURE_TRACKING_CAP = 4096
_ACCOUNT_KEY_PREFIX = "acct:"
_ADDRESS_KEY_PREFIX = "addr:"
_login_failures = {}
_login_failures_lock = threading.Lock()

# SEC-06: HttpOnly/Secure/SameSite session cookie; removes the token from
# script-readable storage. The set and the clear share these attributes.
_SESSION_COOKIE_PATH = "/"
_SESSION_COOKIE_SAMESITE = "strict"


def _account_key(email: str) -> str:
    # SEC-07: one counter per account regardless of case or padding
    return _ACCOUNT_KEY_PREFIX + (email or "").strip().lower()


def _address_key(request: Request) -> str:
    # SEC-07: one counter per client address
    return _ADDRESS_KEY_PREFIX + (get_remote_address(request) or "")


def _account_marker(throttle_key: str) -> str:
    # SEC-07: redacted account reference for the audit record
    return sha256(throttle_key.encode("utf-8")).hexdigest()[:16]


class AccountThrottled(HTTPException):
    # SEC-07: 429 carrying the account marker to the error boundary, which
    # logs one record under the same error_id the client receives.
    # SEC-08: audit_context holds redacted markers only.
    def __init__(self, account_marker: str):
        super().__init__(status_code=429)
        self.audit_context = {"account": account_marker}


def _prune_expired_login_failures(now: float) -> None:
    # SEC-07: drops entries whose window has already elapsed
    for key in [k for k, entry in _login_failures.items() if entry[1] <= now]:
        del _login_failures[key]


def _evict_unexhausted_login_keys(limit: int, needed: int) -> bool:
    # SEC-07: frees slots from the keys closest to expiry that are still below
    # the limit; entries are (count, expires_at), so eviction orders by
    # expires_at alone and a key at the limit is never evicted. Returns False
    # when too few evictable keys exist, so a full map denies the attempt
    # instead of dropping a lockout.
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
    # SEC-07: counts the attempt on every key and decides admission inside one
    # critical section, so a concurrent burst cannot share one allowance
    # (CWE-367). Returns False when any key is at the limit, and when the map
    # is at capacity with no evictable key. A successful authentication
    # releases the reservation through _clear_login_failures.
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
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user with hashed password
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password,
                    created_at=datetime.utcnow())
    db.add(new_user)
    db.commit()
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
def login_user(
    request: Request,
    response: Response,
    user: UserLogin,
    db: Session = Depends(get_db),
):
    # SEC-07: account-keyed and address-keyed throttle; both attempts are
    # counted before the credentials are read, and bound credential-guessing
    # attempts (CWE-307)
    account_key = _account_key(user.email)
    address_key = _address_key(request)
    if not _reserve_login_attempt(account_key, address_key):
        # SEC-07: the error boundary logs this attempt under the response
        # error_id; SEC-08: neither the client address nor the submitted
        # email reaches the record
        raise AccountThrottled(_account_marker(account_key))

    # Verify user credentials
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        # SEC-07: the reserved attempt stands, so a credential failure is
        # counted exactly once on both keys
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    # SEC-07: authentication succeeded, so neither counter retains state
    _clear_login_failures(account_key, address_key)

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