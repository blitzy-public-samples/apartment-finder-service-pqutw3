import unicodedata
from pydantic import BaseModel, EmailStr, StrictStr, validator
from datetime import datetime
from typing import Optional


def _require_json_string(value):
    # SEC-05: rejects a non-string JSON value before any coercion runs
    if not isinstance(value, str):
        raise TypeError("must be a JSON string")
    return value


class User(BaseModel):
    # SEC-02: matches the integer primary key; ends the identity type mismatch
    id: int
    email: str
    created_at: datetime
    last_login: Optional[datetime]


# SEC-04: policy constants mirror frontend/src/utils/validators.ts:19-23
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_BYTES = 72
PASSWORD_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
PASSWORD_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
PASSWORD_DIGITS = "0123456789"
PASSWORD_SPECIAL_CHARACTERS = "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?"


def _reject_unhashable_password(value: str) -> str:
    # SEC-05: bcrypt aborts the hash on a control character and passlib
    # refuses a secret past its own size limit (auth.py:156, auth.py:206)
    # SEC-04: 72-byte bcrypt ceiling; blocks silent truncation
    if len(value.encode("utf-8")) > PASSWORD_MAX_BYTES:
        raise ValueError(
            f"must not exceed {PASSWORD_MAX_BYTES} UTF-8 bytes"
        )
    if any(unicodedata.category(c) == "Cc" for c in value):
        raise ValueError("must not contain control characters")
    return value


class UserCreate(BaseModel):
    email: EmailStr
    password: StrictStr

    # SEC-05: email must arrive as a JSON string; no type coercion
    _require_string_email = validator(
        "email", pre=True, allow_reuse=True)(_require_json_string)

    # SEC-04: server-side password policy; mirrors the client rule
    @validator("password")
    def validate_password(cls, value: str) -> str:
        if len(value) < PASSWORD_MIN_LENGTH:
            raise ValueError(
                f"must be at least {PASSWORD_MIN_LENGTH} characters long"
            )
        # SEC-04: 72-byte ceiling and control-character rejection
        _reject_unhashable_password(value)
        if not any(c in PASSWORD_UPPERCASE for c in value):
            raise ValueError("must include at least one uppercase letter")
        if not any(c in PASSWORD_LOWERCASE for c in value):
            raise ValueError("must include at least one lowercase letter")
        if not any(c in PASSWORD_DIGITS for c in value):
            raise ValueError("must include at least one digit")
        if not any(c in PASSWORD_SPECIAL_CHARACTERS for c in value):
            raise ValueError(
                "must include at least one special character from "
                + PASSWORD_SPECIAL_CHARACTERS
            )
        return value

    class Config:
        # SEC-05: rejects unknown keys; closes the CWE-915 vector
        extra = "forbid"


class UserLogin(BaseModel):
    email: EmailStr
    password: StrictStr

    # SEC-05: email must arrive as a JSON string; no type coercion
    _require_string_email = validator(
        "email", pre=True, allow_reuse=True)(_require_json_string)

    # SEC-05: refuses the two shapes the hasher cannot process; an
    # unauthenticated caller can no longer force a 500 out of verify_password
    # (CWE-20). Policy length and character-class rules stay on UserCreate.
    _reject_unhashable = validator(
        "password", allow_reuse=True)(_reject_unhashable_password)

    class Config:
        # SEC-05: rejects unknown keys; closes the CWE-915 vector
        extra = "forbid"
