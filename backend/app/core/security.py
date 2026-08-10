"""JWT issuance and verification plus bcrypt password operations."""

import hashlib
import hmac
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
from backend.app.core import hashing
from backend.app.core.config import settings
from backend.app.core.logging import get_logger
from backend.app.db.database import get_db
from backend.app.db.models import LOGIN_ATTEMPT_SLOT_COUNT, User

__all__ = [
    "CLAIMED_ROLE_ATTRIBUTE",
    "DECOY_HASH",
    "JWT_ALGORITHMS",
    "MAX_SUPPORTED_BCRYPT_COST",
    "MAX_TOKEN_LIFETIME",
    "MIN_CREDENTIAL_CHECK_SECONDS",
    "MIN_LOGIN_REFUSAL_SECONDS",
    "MIN_SUPPORTED_BCRYPT_COST",
    "REQUIRED_CLAIMS",
    "ROLE_CLAIM",
    "SIGNING_ALGORITHM",
    "UNSUPPORTED_COST_MESSAGE",
    "claimed_role",
    "create_access_token",
    "equalize_login_refusal",
    "get_current_user",
    "get_password_hash",
    "login_attempt_slot",
    "oauth2_scheme",
    "stored_bcrypt_cost",
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

#: Lowest stored bcrypt cost factor a credential check will compare
#: against. It is bcrypt's own lowest accepted cost.
MIN_SUPPORTED_BCRYPT_COST = 4

#: Cost factor the password hashes this schema arrived with were written
#: at. It is the floor of :data:`MAX_SUPPORTED_BCRYPT_COST`, so lowering
#: ``BCRYPT_ROUNDS`` never makes a stored hash unverifiable.
INHERITED_BCRYPT_COST = 12

#: Highest stored bcrypt cost factor a credential check will compare
#: against: the configured cost, or the inherited one when that is
#: higher. A stored hash above it is reported as a mismatch without being
#: compared, so no comparison exceeds the measured budget.
MAX_SUPPORTED_BCRYPT_COST = max(
    settings.BCRYPT_ROUNDS, INHERITED_BCRYPT_COST
)

#: Message of the record emitted for a stored hash whose cost factor lies
#: outside the supported range.
UNSUPPORTED_COST_MESSAGE = (
    "Refused a stored password hash whose bcrypt cost factor is outside "
    "the supported range"
)

#: Fraction of :data:`MIN_CREDENTIAL_CHECK_SECONDS` added to reach
#: :data:`MIN_LOGIN_REFUSAL_SECONDS`. It covers the statements a refusal
#: branch issues after the comparison.
REFUSAL_WORK_ALLOWANCE = 0.25

# Byte length of the random value :data:`DECOY_HASH` is built from.
_DECOY_INPUT_BYTES = 32

# Number of fields a bcrypt hash carries before its salt and digest.
_COST_FIELD_INDEX = 2

logger = get_logger(__name__)

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


def stored_bcrypt_cost(hashed_password: object) -> Optional[int]:
    """Return the cost factor a stored bcrypt hash declares.

    ``None`` is returned for a value that is not a string, does not carry
    the ``$<identifier>$<cost>$`` prefix bcrypt writes, or names a cost
    that is not a number.
    """
    if not isinstance(hashed_password, str):
        return None
    fields = hashed_password.split("$")
    if len(fields) <= _COST_FIELD_INDEX:
        return None
    try:
        return int(fields[_COST_FIELD_INDEX])
    except ValueError:
        return None


def _cost_is_supported(hashed_password: object) -> bool:
    """Report whether a stored hash's cost factor may be compared.

    A cost outside :data:`MIN_SUPPORTED_BCRYPT_COST` to
    :data:`MAX_SUPPORTED_BCRYPT_COST` is refused and recorded, naming the
    cost and the supported range and never the hash itself. A value
    carrying no readable cost is left to :func:`verify_password`, which
    reports it as a mismatch.
    """
    cost = stored_bcrypt_cost(hashed_password)
    if cost is None:
        return True
    if MIN_SUPPORTED_BCRYPT_COST <= cost <= MAX_SUPPORTED_BCRYPT_COST:
        return True
    logger.error(
        UNSUPPORTED_COST_MESSAGE,
        extra={
            "stored_cost": cost,
            "min_supported_cost": MIN_SUPPORTED_BCRYPT_COST,
            "max_supported_cost": MAX_SUPPORTED_BCRYPT_COST,
        },
    )
    return False


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return whether the candidate matches the stored bcrypt hash.

    Accepts any hash format bcrypt reads, including ``$2a$`` and
    ``$2b$``, whose cost factor lies within the supported range. Returns
    ``False`` rather than raising when the stored hash cannot be parsed,
    when its cost factor is outside that range, or when either argument
    is a value bcrypt does not accept, such as an over-long candidate or
    a non-string.
    """
    if not _cost_is_supported(hashed_password):
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _hash_at(password: str, cost: int) -> str:
    """Return a bcrypt hash of the password at ``cost``.

    The hash is produced by
    :func:`backend.app.core.hashing.hash_at`, which the administrative
    credential command hashes through as well, so both write one format.
    """
    return hashing.hash_at(password, cost)


def get_password_hash(password: str) -> str:
    """Return a bcrypt hash of the password at the configured cost.

    The password is hashed as supplied, and bcrypt refuses an input
    longer than 72 bytes.
    """
    return _hash_at(password, settings.BCRYPT_ROUNDS)


#: Hash every credential check compares against in addition to the stored
#: one. It carries :data:`MAX_SUPPORTED_BCRYPT_COST`, so one comparison
#: against it costs at least as much as one against any hash the check
#: will run.
DECOY_HASH = _hash_at(
    secrets.token_urlsafe(_DECOY_INPUT_BYTES), MAX_SUPPORTED_BCRYPT_COST
)


def _measure_decoy_comparison() -> float:
    """Return the seconds one comparison against the decoy takes."""
    started = time.monotonic()
    verify_password(secrets.token_urlsafe(_DECOY_INPUT_BYTES), DECOY_HASH)
    return time.monotonic() - started


#: Seconds every credential check is padded out to, measured once when
#: this module is imported. The value is the cost of one comparison
#: against :data:`DECOY_HASH`, which carries
#: :data:`MAX_SUPPORTED_BCRYPT_COST`, multiplied by the two comparisons
#: :func:`verify_credential` performs.
MIN_CREDENTIAL_CHECK_SECONDS = _measure_decoy_comparison() * 2

#: Seconds a refused login is padded out to, measured from the moment the
#: handler was entered. It is :data:`MIN_CREDENTIAL_CHECK_SECONDS` plus
#: :data:`REFUSAL_WORK_ALLOWANCE` of it, which covers the statements one
#: refusal branch issues and another does not.
MIN_LOGIN_REFUSAL_SECONDS = MIN_CREDENTIAL_CHECK_SECONDS * (
    1.0 + REFUSAL_WORK_ALLOWANCE
)


def _pad_until(started: float, budget: float) -> None:
    """Wait until ``budget`` seconds have elapsed since ``started``."""
    remaining = budget - (time.monotonic() - started)
    if remaining > 0:
        time.sleep(remaining)


def login_attempt_slot(email: str) -> int:
    """Return the throttling bucket ``email`` is counted in.

    The bucket is the submitted address reduced to one of
    :data:`backend.app.db.models.LOGIN_ATTEMPT_SLOT_COUNT` values, so a
    refusal for any address -- one holding an account or not -- names a
    row that already exists and can be locked and updated. The address is
    lowercased and stripped first, so the same address always reaches the
    same bucket however it was typed.

    The digest is an HMAC under :data:`settings.SECRET_KEY`, so which
    addresses share a bucket is not computable without the signing key.
    The value is a bucket index and not a credential: it is one-way, it
    is not stored alongside the address, and several addresses map to it.
    """
    normalized = email.strip().lower().encode("utf-8")
    digest = hmac.new(
        settings.SECRET_KEY.encode("utf-8"), normalized, hashlib.sha256
    ).digest()
    return int.from_bytes(digest, "big") % LOGIN_ATTEMPT_SLOT_COUNT


def equalize_login_refusal(started: float) -> None:
    """Hold a refused login until its budget has elapsed.

    ``started`` is the ``time.monotonic()`` reading taken when the login
    handler was entered. The call returns once
    :data:`MIN_LOGIN_REFUSAL_SECONDS` have elapsed since then, and returns
    at once when they already have. Every refusal branch calls it, so the
    account lookup, the credential comparison and the attempt-counting
    statements one branch issues are all covered by one budget.
    """
    _pad_until(started, MIN_LOGIN_REFUSAL_SECONDS)


def verify_credential(
    plain_password: str, hashed_password: Optional[str]
) -> bool:
    """Compare a candidate with the stored or decoy hash under a fixed
    two-comparison timing budget.
    """
    started = time.monotonic()
    candidate = hashed_password if hashed_password else DECOY_HASH
    matched = verify_password(plain_password, candidate)
    verify_password(plain_password, DECOY_HASH)
    if hashed_password is None or not hashed_password:
        matched = False
    _pad_until(started, MIN_CREDENTIAL_CHECK_SECONDS)
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
