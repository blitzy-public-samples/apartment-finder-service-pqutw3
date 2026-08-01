import re
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.db.database import get_db
from backend.app.db.models import User

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
# SEC-06: optional header; a cookie-only request reaches the guard body
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token', auto_error=False)

# SEC-06: session cookie name; the auth routes set and clear this cookie
SESSION_COOKIE_NAME = "access_token"

# SEC-02: a sub claim must be the canonical decimal spelling of a User.id;
# the ceiling is the signed 64-bit range the id column binds
_CANONICAL_SUBJECT = re.compile(r"[1-9][0-9]{0,18}")
_MAX_SUBJECT_ID = 2 ** 63 - 1

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

# HUMAN ASSISTANCE NEEDED
# This function might need additional error handling and token validation
def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    # SEC-06: session cookie read before the bearer header
    token = request.cookies.get(SESSION_COOKIE_NAME) or token
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