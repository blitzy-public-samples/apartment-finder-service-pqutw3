from pydantic import BaseModel, EmailStr, validator
from datetime import datetime
from typing import Optional

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


class UserCreate(BaseModel):
    email: EmailStr
    password: str

    # SEC-04: server-side password policy; mirrors the client rule
    @validator("password")
    def validate_password(cls, value: str) -> str:
        if len(value) < PASSWORD_MIN_LENGTH:
            raise ValueError(
                f"must be at least {PASSWORD_MIN_LENGTH} characters long"
            )
        # SEC-04: 72-byte bcrypt ceiling; blocks silent truncation
        if len(value.encode("utf-8")) > PASSWORD_MAX_BYTES:
            raise ValueError(
                f"must not exceed {PASSWORD_MAX_BYTES} UTF-8 bytes"
            )
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
        extra = "forbid"   # SEC-05: rejects unknown keys; closes the CWE-915 vector


class UserLogin(BaseModel):
    email: EmailStr
    password: str

    class Config:
        extra = "forbid"   # SEC-05: rejects unknown keys; closes the CWE-915 vector
