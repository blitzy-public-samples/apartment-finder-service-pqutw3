import re
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyCookie, HTTPAuthorizationCredentials
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.db.database import get_db
from backend.app.db.models import User

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

# SEC-06: session cookie name; the auth routes set and clear this cookie
SESSION_COOKIE_NAME = "access_token"

# QA-04: the two credential channels the guard actually accepts, published
# under their real mechanisms. The pre-fix declaration advertised an OAuth2
# password flow whose token URL resolves to no route, so a reader was
# directed at an endpoint that answers 404 (CWE-1059). DL-441
_COOKIE_DESCRIPTION = (
    "Session cookie set by POST /auth/register and POST /auth/login and "
    "cleared by POST /auth/logout. HttpOnly, so a browser sends it "
    "automatically and script cannot read it. Read before the bearer header."
)
_BEARER_DESCRIPTION = (
    "Bearer token for a non-browser client. Obtain it from the "
    "access_token field of the POST /auth/login JSON response body. Used "
    "only when no session cookie is present."
)

# SEC-06: both optional, so a cookie-only request reaches the guard body
session_cookie_scheme = APIKeyCookie(
    name=SESSION_COOKIE_NAME,
    scheme_name="SessionCookie",
    description=_COOKIE_DESCRIPTION,
    auto_error=False,
)
bearer_scheme = HTTPBearer(
    scheme_name="BearerToken",
    description=_BEARER_DESCRIPTION,
    auto_error=False,
)

# SEC-02: accepted sub claim - the canonical decimal spelling of a User.id,
# bounded by the range the INTEGER primary key holds (CWE-287)
_CANONICAL_SUBJECT = re.compile(r"[1-9][0-9]{0,9}")
_MAX_SUBJECT_ID = 2 ** 31 - 1

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    # SEC-02: stamps the issuance time on every minted token
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def get_current_user(
    session_cookie: Optional[str] = Depends(session_cookie_scheme),
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    # SEC-06: session cookie read before the bearer header
    token = session_cookie or (bearer.credentials if bearer else None)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: Optional[str] = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # SEC-02: coerces sub to int and rejects a non-canonical decimal User.id
    # subject; closes the sub/User.id identity mismatch (CWE-287)
    if (
        not isinstance(user_id, str)
        or not _CANONICAL_SUBJECT.fullmatch(user_id)
        or int(user_id) > _MAX_SUBJECT_ID
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_key = int(user_id)
    user = db.query(User).filter(User.id == user_key).first()
    if user is None:
        # SEC-02/SEC-08: uniform 401 removes the account-state oracle
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user