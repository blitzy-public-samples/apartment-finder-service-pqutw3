import re
from pydantic import BaseModel, constr, validator
from datetime import datetime
from typing import Optional

_EMAIL_MIN_LENGTH = 3
_EMAIL_MAX_LENGTH = 254
_PASSWORD_MIN_LENGTH = 12
_PASSWORD_MAX_BYTES = 72

# Accepted address shape: a local part, a single "@", and a dotted
# domain, with no whitespace in any part.
_EMAIL_REGEX = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"

_UPPERCASE_PATTERN = re.compile(r"[A-Z]")
_LOWERCASE_PATTERN = re.compile(r"[a-z]")
_DIGIT_PATTERN = re.compile(r"\d")
_SPECIAL_CHARACTER_PATTERN = re.compile(
    r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]"
)

# Address shape accepted by the client-side validator: a local part and a
# domain separated by a single "@", with at least one dot in the domain
# and no whitespace in either part.
_EMAIL_PATTERN = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")

# Code points refused anywhere in an address: the C0 range, delete, and
# the C1 range.
_CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f]")

_EmailField = constr(
    strip_whitespace=True,
    min_length=_EMAIL_MIN_LENGTH,
    max_length=_EMAIL_MAX_LENGTH,
    regex=_EMAIL_REGEX,
)


def _enforce_email_format(value: str) -> str:
    """Reject an address that does not match the accepted shape.

    Control characters are refused first. The shape is then tested with
    :func:`re.fullmatch`, which requires the whole value to match, so a
    trailing newline does not satisfy the pattern.
    """
    if _CONTROL_CHARACTER_PATTERN.search(value):
        raise ValueError("email must not contain control characters")
    if not _EMAIL_PATTERN.fullmatch(value):
        raise ValueError(
            "email must be a local part and a domain separated by '@', "
            "with a dot in the domain and no whitespace"
        )
    return value


def _enforce_password_byte_ceiling(value: str) -> str:
    """Reject a password exceeding the maximum UTF-8 byte length."""
    if len(value.encode("utf-8")) > _PASSWORD_MAX_BYTES:
        raise ValueError(
            f"password must not exceed {_PASSWORD_MAX_BYTES} bytes "
            "once UTF-8 encoded"
        )
    return value


def _enforce_password_complexity(value: str) -> str:
    """Require the minimum length and all four character classes."""
    if len(value) < _PASSWORD_MIN_LENGTH:
        raise ValueError(
            f"password must be at least {_PASSWORD_MIN_LENGTH} characters"
        )
    if not _UPPERCASE_PATTERN.search(value):
        raise ValueError("password must contain an uppercase letter")
    if not _LOWERCASE_PATTERN.search(value):
        raise ValueError("password must contain a lowercase letter")
    if not _DIGIT_PATTERN.search(value):
        raise ValueError("password must contain a digit")
    if not _SPECIAL_CHARACTER_PATTERN.search(value):
        raise ValueError("password must contain a special character")
    return value


class User(BaseModel):
    """Response model for a stored user record."""

    id: int
    email: str
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        orm_mode = True


class UserCreate(BaseModel):
    """Request body accepted by the registration endpoint."""

    email: _EmailField
    password: str

    class Config:
        extra = "forbid"

    @validator("email")
    def validate_email(cls, value: str) -> str:
        """Apply the accepted address shape."""
        return _enforce_email_format(value)

    @validator("password")
    def validate_password(cls, value: str) -> str:
        return _enforce_password_complexity(
            _enforce_password_byte_ceiling(value)
        )


class UserLogin(BaseModel):
    """Request body accepted by the login endpoint."""

    email: _EmailField
    password: str

    class Config:
        extra = "forbid"

    @validator("email")
    def validate_email(cls, value: str) -> str:
        """Apply the accepted address shape."""
        return _enforce_email_format(value)

    @validator("password")
    def validate_password(cls, value: str) -> str:
        return _enforce_password_byte_ceiling(value)
