from pydantic import BaseModel, EmailStr, Field, StrictStr, validator
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


# SEC-04: length and character-class constants mirror
# frontend/src/utils/validators.ts:19-23; the bcrypt byte ceiling is
# server-only
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_BYTES = 72
PASSWORD_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
PASSWORD_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
PASSWORD_DIGITS = "0123456789"
PASSWORD_SPECIAL_CHARACTERS = "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?"


def _reject_nul_character(value: str) -> str:
    # SEC-05: the hasher refuses a NUL byte in a secret (CWE-20)
    if "\x00" in value:
        raise ValueError("must not contain a NUL character")
    return value


# QA-05: the policy as a published sentence. The declarative bounds below
# carry the two lengths a schema can express; the character classes, the NUL
# refusal and the byte ceiling are stated here because a JSON Schema keyword
# cannot express any of them. DL-442
PASSWORD_POLICY_DESCRIPTION = (
    "Account password. At least {minimum} characters and at most "
    "{maximum} UTF-8 bytes, which is the bcrypt input ceiling, so a "
    "multi-byte password may be refused below {maximum} characters. Must "
    "contain at least one uppercase letter, one lowercase letter, one "
    "digit and one of {specials} . Must not contain a NUL character. "
    "Rejection returns 422 naming the password field and never echoes the "
    "submitted value."
).format(
    minimum=PASSWORD_MIN_LENGTH,
    maximum=PASSWORD_MAX_BYTES,
    specials=PASSWORD_SPECIAL_CHARACTERS,
)

EMAIL_DESCRIPTION = (
    "Account email address, and the identity the credential lookup and the "
    "login throttle are keyed on. Must arrive as a JSON string."
)


class UserCreate(BaseModel):
    email: EmailStr = Field(..., description=EMAIL_DESCRIPTION)
    # QA-05: publishes the two bounds a schema keyword can carry. Neither
    # replaces the validator below: the character-count minimum is stricter
    # than nothing but weaker than the byte ceiling, so the validator still
    # decides. DL-442
    password: StrictStr = Field(
        ...,
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_BYTES,
        description=PASSWORD_POLICY_DESCRIPTION,
    )

    # SEC-05: email must arrive as a JSON string; no type coercion
    _require_string_email = validator(
        "email", pre=True, allow_reuse=True)(_require_json_string)

    # SEC-04: server-side password policy; mirrors the client rule
    @validator("password")
    def validate_password(cls, value: str) -> str:
        # SEC-05: the one byte the hasher refuses
        _reject_nul_character(value)
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
        # SEC-05: rejects unknown keys; closes the CWE-915 vector
        extra = "forbid"


class UserLogin(BaseModel):
    email: EmailStr = Field(..., description=EMAIL_DESCRIPTION)
    # QA-05: no policy bound here. The login path compares a submitted
    # secret against a stored hash, so a bound would refuse the credentials
    # of an account registered before the policy and turn a 401 into a 422,
    # which is an account-state oracle. DL-442
    password: StrictStr = Field(
        ...,
        description=(
            "Account password, compared against the stored hash. Carries no "
            "policy bound: every refusal answers 401 with one detail."
        ),
    )

    # SEC-05: email must arrive as a JSON string; no type coercion
    _require_string_email = validator(
        "email", pre=True, allow_reuse=True)(_require_json_string)

    class Config:
        # SEC-05: rejects unknown keys; closes the CWE-915 vector
        extra = "forbid"


# QA-06: documentation-only models for the three frozen auth response
# bodies. They are attached through the route's `responses` mapping, never as
# a `response_model`, so they publish the body without filtering a key out of
# it (CWE-1059). DL-443
class RegisteredUser(BaseModel):
    """The user object the registration body carries."""

    id: int = Field(..., description="Server-assigned account identifier.")
    email: str = Field(..., description="The registered email address.")


class RegisterResponse(BaseModel):
    """The frozen body of POST /auth/register."""

    user: RegisteredUser
    access_token: str = Field(
        ...,
        description=(
            "Signed session token. Also set as the HttpOnly session cookie "
            "on the same response, which is what a browser client uses."
        ),
    )
    token_type: str = Field(
        ..., description='Always the literal "bearer".'
    )


class LoginResponse(BaseModel):
    """The frozen body of POST /auth/login."""

    access_token: str = Field(
        ...,
        description=(
            "Signed session token. Also set as the HttpOnly session cookie "
            "on the same response, which is what a browser client uses."
        ),
    )
    token_type: str = Field(
        ..., description='Always the literal "bearer".'
    )


class LogoutResponse(BaseModel):
    """The body of POST /auth/logout."""

    detail: str = Field(
        ...,
        description=(
            'Always the literal "Logged out". The response also clears the '
            "session cookie, which is the part a browser client depends on."
        ),
    )
