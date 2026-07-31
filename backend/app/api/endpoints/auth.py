import logging
import threading
import time
from datetime import datetime
from hashlib import sha256
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.core.security import SESSION_COOKIE_NAME, create_access_token, get_password_hash, verify_password
from backend.app.db.database import get_db
from backend.app.schema.user import UserCreate, UserLogin
from backend.app.db.models import User

logger = logging.getLogger(__name__)

router = APIRouter()

# SEC-07: five attempts per fifteen minutes on login
LOGIN_RATE_LIMIT = (
    f"{settings.LOGIN_RATE_LIMIT_ATTEMPTS}"
    f"/{settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES} minutes"
)
limiter = Limiter(key_func=get_remote_address)

# SEC-07: per-account failed-login counter keyed by normalized email.
# Entries expire with the throttle window and the map size is capped.
_LOGIN_FAILURE_TRACKING_CAP = 4096
_login_failures = {}
_login_failures_lock = threading.Lock()

# SEC-06: HttpOnly/Secure/SameSite session cookie; removes the token from
# script-readable storage. The set and the clear share these attributes.
_SESSION_COOKIE_PATH = "/"
_SESSION_COOKIE_SAMESITE = "strict"


def _throttle_key(email: str) -> str:
    # SEC-07: one counter per account regardless of case or padding
    return (email or "").strip().lower()


def _account_marker(throttle_key: str) -> str:
    # SEC-07: redacted account reference for the audit record
    return sha256(throttle_key.encode("utf-8")).hexdigest()[:16]


def _prune_login_failures(now: float, headroom: int = 0) -> None:
    # SEC-07: bounds the counter map for an attempt flood; headroom reserves
    # slots for keys the caller is about to add
    for key in [k for k, entry in _login_failures.items() if entry[1] <= now]:
        del _login_failures[key]
    overflow = len(_login_failures) + headroom - _LOGIN_FAILURE_TRACKING_CAP
    if overflow > 0:
        oldest = sorted(_login_failures.items(), key=lambda item: item[1])
        for key, _entry in oldest[:overflow]:
            del _login_failures[key]


def _login_attempts_exhausted(throttle_key: str) -> bool:
    now = time.monotonic()
    with _login_failures_lock:
        _prune_login_failures(now)
        entry = _login_failures.get(throttle_key)
    if entry is None:
        return False
    return entry[0] >= settings.LOGIN_RATE_LIMIT_ATTEMPTS


def _record_login_failure(throttle_key: str) -> None:
    now = time.monotonic()
    window = settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES * 60
    with _login_failures_lock:
        _prune_login_failures(
            now, 0 if throttle_key in _login_failures else 1)
        entry = _login_failures.get(throttle_key)
        if entry is None:
            _login_failures[throttle_key] = (1, now + window)
        else:
            _login_failures[throttle_key] = (entry[0] + 1, entry[1])


def _clear_login_failures(throttle_key: str) -> None:
    with _login_failures_lock:
        _login_failures.pop(throttle_key, None)


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
@limiter.limit(LOGIN_RATE_LIMIT)
def login_user(
    request: Request,
    response: Response,
    user: UserLogin,
    db: Session = Depends(get_db),
):
    # SEC-07: account-keyed throttle; the address-keyed limit is applied by
    # the route decorator above
    throttle_key = _throttle_key(user.email)
    if _login_attempts_exhausted(throttle_key):
        logger.warning(
            "login throttled account=%s remote=%s",
            _account_marker(throttle_key),
            get_remote_address(request),
        )
        raise HTTPException(status_code=429)

    # Verify user credentials
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        _record_login_failure(throttle_key)
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    _clear_login_failures(throttle_key)

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