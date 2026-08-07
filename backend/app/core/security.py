"""Access token minting and verification, and password hashing.

Tokens are signed with the symmetric key and the algorithm allowlist
held in :mod:`backend.app.core.config`. The algorithm named in a token
header is never consulted: verification accepts only the configured
allowlist, and every claim in :data:`REQUIRED_CLAIMS` must be present
and must match the configured issuer and audience for a token to
resolve to a user.

The subject of a token is the user's integer identifier. The role claim
a token carries is descriptive only: :func:`get_current_user` resolves
the user from the stored row and copies no claim onto it.

Passwords are hashed with bcrypt at the configured cost factor, in the
format bcrypt already stores, and verification reports a mismatch
rather than raising when a stored hash cannot be parsed.

Usage::

    token = create_access_token({"sub": str(user.id), "role": user.role})
    hashed = get_password_hash(password)
    matched = verify_password(password, hashed)
"""

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.db.database import get_db
from backend.app.db.models import User

__all__ = [
    "DECOY_HASH",
    "REQUIRED_CLAIMS",
    "create_access_token",
    "get_current_user",
    "get_password_hash",
    "oauth2_scheme",
    "verify_decoy",
    "verify_password",
]

#: Claims a token must carry for :func:`get_current_user` to accept it.
REQUIRED_CLAIMS = ("exp", "iat", "nbf", "sub", "aud", "iss", "jti")

# Byte length of the random value :data:`DECOY_HASH` is built from.
_DECOY_INPUT_BYTES = 32

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


def _credentials_exception() -> HTTPException:
    """Return the response raised for every failed authentication.

    The status, the detail and the headers are the same whatever the
    reason for the rejection.
    """
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return whether the candidate matches the stored bcrypt hash.

    Accepts any hash format bcrypt reads, including ``$2a$`` and
    ``$2b$``. Returns ``False`` rather than raising when the stored hash
    cannot be parsed, or when either argument is a value bcrypt does not
    accept, such as an over-long candidate or a non-string.
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except (AttributeError, TypeError, ValueError):
        return False


def get_password_hash(password: str) -> str:
    """Return a bcrypt hash of the password at the configured cost.

    The password is hashed as supplied, and bcrypt refuses an input
    longer than 72 bytes.
    """
    hashed = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS),
    )
    return hashed.decode("utf-8")


#: Hash of a random value, carrying the configured cost factor, built
#: once when this module is imported.
DECOY_HASH = get_password_hash(secrets.token_urlsafe(_DECOY_INPUT_BYTES))


def verify_decoy(plain_password: str) -> bool:
    """Compare the candidate against :data:`DECOY_HASH`, returning False.

    The comparison is carried out in full, at the cost of a verification
    against a stored hash, and the result is always ``False``.
    """
    verify_password(plain_password, DECOY_HASH)
    return False


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Return a signed access token carrying ``data`` and the claims.

    ``data`` supplies the subject and the role. The issuer, audience,
    issue time, not-before time, expiry and token identifier are set
    here, after ``data`` has been copied, so a value in ``data`` cannot
    replace any of them. Each timestamp is timezone aware, the token
    identifier is unique per token, and the lifetime is the configured
    one unless ``expires_delta`` is given. The token is signed with the
    first algorithm in the configured allowlist.
    """
    to_encode = data.copy()
    issued_at = datetime.now(timezone.utc)
    if expires_delta:
        expire = issued_at + expires_delta
    else:
        expire = issued_at + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expire,
        "jti": uuid.uuid4().hex,
    })
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHMS[0],
    )
    return encoded_jwt


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Return the stored user the token identifies.

    The token is verified against the configured algorithm allowlist,
    audience and issuer, and every claim in :data:`REQUIRED_CLAIMS` must
    be present. The subject is read as the user's integer identifier and
    the stored row is returned unchanged. A token that fails any check, a
    subject that is blank or not an integer, and a subject naming no
    stored user each raise :func:`_credentials_exception`.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=settings.JWT_ALGORITHMS,
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            options={"require": list(REQUIRED_CLAIMS)},
        )
        subject = payload.get("sub")
        if subject is None or not str(subject).strip():
            raise _credentials_exception()
        user_id = int(subject)
    except jwt.PyJWTError:
        raise _credentials_exception()
    except (TypeError, ValueError):
        raise _credentials_exception()
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise _credentials_exception()
    return user
