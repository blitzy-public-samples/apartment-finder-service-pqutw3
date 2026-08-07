"""Access token minting and verification, and password hashing.

Tokens are signed with the symmetric key held in
:mod:`backend.app.core.config` and with :data:`SIGNING_ALGORITHM`, and
verified against :data:`JWT_ALGORITHMS`. Both are fixed when this module
is imported, so a later change to ``settings.JWT_ALGORITHMS`` alters
neither. The algorithm named in a token header is never consulted, and
every claim in :data:`REQUIRED_CLAIMS` must be present and must match the
configured issuer and audience for a token to resolve to a user.

No token may outlive :data:`MAX_TOKEN_LIFETIME`: a caller may ask for a
shorter lifetime, and a longer or non-positive one is refused.

The subject of a token is the user's integer identifier. The role claim
a token carries is descriptive only: :func:`get_current_user` resolves
the user from the stored row and copies no claim onto it. The claim is
recorded on ``request.state`` under :data:`CLAIMED_ROLE_ATTRIBUTE` so
that a refusal can name the role the caller asserted alongside the role
the row actually carries. Nothing reads it to decide anything, and
:func:`claimed_role` is the only accessor.

Passwords are hashed with bcrypt at the configured cost factor, in the
format bcrypt already stores, and verification reports a mismatch
rather than raising when a stored hash cannot be parsed.

:func:`verify_credential` is the entry point every login path takes. It
performs the same work whatever it is given, so the time a login takes
reveals neither whether an address holds an account nor what cost factor
that account's stored hash carries.

Usage::

    token = create_access_token({"sub": str(user.id), "role": user.role})
    hashed = get_password_hash(password)
    matched = verify_credential(password, user.hashed_password)
"""

import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import jwt
import bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.db.database import get_db
from backend.app.db.models import User

__all__ = [
    "CLAIMED_ROLE_ATTRIBUTE",
    "DECOY_HASH",
    "JWT_ALGORITHMS",
    "MAX_TOKEN_LIFETIME",
    "MIN_CREDENTIAL_CHECK_SECONDS",
    "REQUIRED_CLAIMS",
    "ROLE_CLAIM",
    "SIGNING_ALGORITHM",
    "claimed_role",
    "create_access_token",
    "get_current_user",
    "get_password_hash",
    "oauth2_scheme",
    "verify_credential",
    "verify_password",
]

#: Claims a token must carry for :func:`get_current_user` to accept it.
REQUIRED_CLAIMS = ("exp", "iat", "nbf", "sub", "aud", "iss", "jti")

#: The algorithms this process accepts, fixed when the module is
#: imported. Reassigning or mutating ``settings.JWT_ALGORITHMS`` after
#: import changes neither signing nor verification.
JWT_ALGORITHMS: Tuple[str, ...] = tuple(settings.JWT_ALGORITHMS)

#: The single algorithm every token issued by this process is signed
#: with: the first entry of :data:`JWT_ALGORITHMS`.
SIGNING_ALGORITHM = JWT_ALGORITHMS[0]

#: The longest lifetime any token may carry, fixed when this module is
#: imported. :func:`create_access_token` refuses a longer one.
MAX_TOKEN_LIFETIME = timedelta(
    minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
)

#: Name of the descriptive role claim a token may carry.
ROLE_CLAIM = "role"

#: Attribute of ``request.state`` that carries the role claim of a
#: verified token. The value is descriptive: it records what the caller
#: asserted and takes part in no decision.
CLAIMED_ROLE_ATTRIBUTE = "claimed_role"

# Byte length of the random value :data:`DECOY_HASH` is built from.
_DECOY_INPUT_BYTES = 32

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


def _credentials_exception() -> HTTPException:
    """Return the ``HTTPException`` for every failed authentication.

    The returned exception carries status ``401``, the detail
    ``"Could not validate credentials"`` and a
    ``WWW-Authenticate: Bearer`` header, whatever the reason for the
    rejection. The caller raises it.
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


DECOY_HASH = get_password_hash(secrets.token_urlsafe(_DECOY_INPUT_BYTES))


def _measure_decoy_comparison() -> float:
    """Return the seconds one comparison against the decoy takes."""
    started = time.monotonic()
    verify_password(secrets.token_urlsafe(_DECOY_INPUT_BYTES), DECOY_HASH)
    return time.monotonic() - started


#: Seconds every credential check is padded out to, measured once when
#: this module is imported. The value is the cost of one comparison
#: against :data:`DECOY_HASH` multiplied by the two comparisons
#: :func:`verify_credential` performs.
MIN_CREDENTIAL_CHECK_SECONDS = _measure_decoy_comparison() * 2


def verify_credential(
    plain_password: str, hashed_password: Optional[str]
) -> bool:
    """Report whether the candidate matches ``hashed_password``.

    This is the single credential-checking entry point every login path
    takes, whether an account was found or not. ``hashed_password`` is
    the stored hash, or ``None`` when there is no account to compare
    with, in which case :data:`DECOY_HASH` stands in and the result is
    ``False``.

    Every call performs the same work: one comparison against the stored
    or stand-in hash, then one comparison against :data:`DECOY_HASH` at
    the configured cost factor, and finally a wait until
    :data:`MIN_CREDENTIAL_CHECK_SECONDS` have elapsed. A stored hash
    carrying a cost factor below the configured one therefore does not
    complete sooner than one that matched no account, so the elapsed time
    reveals neither whether an address holds an account nor whether that
    account is locked.
    """
    started = time.monotonic()
    candidate = hashed_password if hashed_password else DECOY_HASH
    matched = verify_password(plain_password, candidate)
    verify_password(plain_password, DECOY_HASH)
    if hashed_password is None or not hashed_password:
        matched = False
    remaining = MIN_CREDENTIAL_CHECK_SECONDS - (
        time.monotonic() - started
    )
    if remaining > 0:
        time.sleep(remaining)
    return matched


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Return a signed access token carrying ``data`` and the claims.

    ``data`` supplies the subject and the role. The issuer, audience,
    issue time, not-before time, expiry and token identifier are set
    here, after ``data`` has been copied, so a value in ``data`` cannot
    replace any of them. Each timestamp is timezone aware and the token
    identifier is unique per token.

    The lifetime is :data:`MAX_TOKEN_LIFETIME` unless ``expires_delta``
    is given, and ``expires_delta`` may only shorten it: a value that is
    zero, negative or longer than :data:`MAX_TOKEN_LIFETIME` raises
    ``ValueError``, so no caller can mint a token that outlives the
    configured maximum.

    The token is signed with :data:`SIGNING_ALGORITHM`.
    """
    to_encode = data.copy()
    issued_at = datetime.now(timezone.utc)
    lifetime = MAX_TOKEN_LIFETIME
    if expires_delta is not None:
        if expires_delta <= timedelta(0):
            raise ValueError("expires_delta must be positive")
        if expires_delta > MAX_TOKEN_LIFETIME:
            raise ValueError(
                "expires_delta must not exceed the configured maximum "
                "of {0} seconds".format(
                    int(MAX_TOKEN_LIFETIME.total_seconds())
                )
            )
        lifetime = expires_delta
    to_encode.update({
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + lifetime,
        "jti": uuid.uuid4().hex,
    })
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=SIGNING_ALGORITHM,
    )
    return encoded_jwt


def claimed_role(request: Optional[Request]) -> Optional[str]:
    """Return the role claim of the verified token, or ``None``.

    The value is whatever :func:`get_current_user` recorded on
    ``request.state``, and is present only for a request whose token
    verified and carried a textual role claim. It describes what the
    caller asserted and is not the role any decision is taken against.
    Reading it never raises.
    """
    if request is None:
        return None
    try:
        value = getattr(
            request.state, CLAIMED_ROLE_ATTRIBUTE, None
        )
    except Exception:
        return None
    return value if isinstance(value, str) else None


def _record_claimed_role(
    request: Optional[Request], payload: dict
) -> None:
    """Record the token's role claim on ``request.state``.

    Only a non-blank textual claim is recorded, stripped. Recording is
    for observability alone, so a request object that carries no writable
    state is left as it is rather than failing the request.
    """
    if request is None:
        return
    value = payload.get(ROLE_CLAIM)
    if not isinstance(value, str) or not value.strip():
        return
    try:
        setattr(request.state, CLAIMED_ROLE_ATTRIBUTE, value.strip())
    except Exception:
        return


def get_current_user(
    request: Request = None,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Return the stored user the token identifies.

    The token is verified against :data:`JWT_ALGORITHMS`, the configured
    audience and the configured issuer, and every claim in
    :data:`REQUIRED_CLAIMS` must
    be present. The subject is read as the user's integer identifier and
    the stored row is returned unchanged. A token that fails any check, a
    subject that is blank or not an integer, and a subject naming no
    stored user each raise :func:`_credentials_exception`.

    The token's role claim is recorded on ``request.state`` once the
    token has verified, and is never copied onto the returned row nor
    consulted by any check here.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=list(JWT_ALGORITHMS),
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
    _record_claimed_role(request, payload)
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise _credentials_exception()
    return user
