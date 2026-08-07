import re
from pydantic import BaseModel, constr, validator
from datetime import datetime
from typing import Optional

_EMAIL_MIN_LENGTH = 3
_EMAIL_MAX_LENGTH = 254
_PASSWORD_MIN_LENGTH = 12
_PASSWORD_MAX_BYTES = 72

_UPPERCASE_PATTERN = re.compile(r"[A-Z]")
_LOWERCASE_PATTERN = re.compile(r"[a-z]")
_DIGIT_PATTERN = re.compile(r"\d")
_SPECIAL_CHARACTER_PATTERN = re.compile(
    r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]"
)

_EmailField = constr(
    strip_whitespace=True,
    min_length=_EMAIL_MIN_LENGTH,
    max_length=_EMAIL_MAX_LENGTH,
)


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

    @validator("password")
    def validate_password(cls, value: str) -> str:
        """Apply the byte ceiling, then the full complexity policy."""
        return _enforce_password_complexity(
            _enforce_password_byte_ceiling(value)
        )


class UserLogin(BaseModel):
    """Request body accepted by the login endpoint."""

    email: _EmailField
    password: str

    class Config:
        extra = "forbid"

    @validator("password")
    def validate_password(cls, value: str) -> str:
        """Apply the byte ceiling only."""
        return _enforce_password_byte_ceiling(value)
