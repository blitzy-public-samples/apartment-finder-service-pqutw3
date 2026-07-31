from pydantic import BaseSettings, Field, validator
from typing import List, Optional
from urllib.parse import urlsplit

class Settings(BaseSettings):
    DATABASE_URL: str
    # SEC-12: RFC 7518 sec. 3.2 key-length floor for HMAC-SHA2 signing
    SECRET_KEY: str = Field(..., min_length=32)
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    ZILLOW_API_KEY: str
    PAYPAL_CLIENT_ID: str
    PAYPAL_CLIENT_SECRET: str
    SENTRY_DSN: Optional[str]

    # SEC-03: fail-closed origin allow-list; required, no default
    ALLOWED_ORIGINS: List[str]

    # SEC-09: payment environment domain
    PAYPAL_MODE: str = "sandbox"

    # SEC-10: explicit database transport encryption mode
    DB_SSLMODE: str = "require"

    # SEC-06: cookie Secure attribute is environment-driven
    COOKIE_SECURE: bool = True

    # SEC-07: login throttle thresholds
    LOGIN_RATE_LIMIT_ATTEMPTS: int = 5
    LOGIN_RATE_LIMIT_WINDOW_MINUTES: int = 15

    # SEC-12: settings read at module scope by the service layer
    SENDGRID_API_KEY: str
    FROM_EMAIL: str
    ZILLOW_API_URL: str

    @validator("ALGORITHM")
    def validate_algorithm(cls, value):
        # SEC-02, SEC-12: HMAC-only signing domain; rejects alg=none and
        # keeps the ecdsa signing path (PYSEC-2026-1325) unreachable.
        if value not in ("HS256", "HS384", "HS512"):
            raise ValueError(
                "ALGORITHM must be one of HS256, HS384, HS512, "
                f"got: {value!r}"
            )
        return value

    @validator("PAYPAL_MODE")
    def validate_paypal_mode(cls, value):
        # SEC-09: payment environment domain; blocks an unintended
        # transaction environment (CWE-1188).
        if value not in ("sandbox", "live"):
            raise ValueError(
                "PAYPAL_MODE must be either 'sandbox' or 'live', "
                f"got: {value!r}"
            )
        return value

    @validator("ALLOWED_ORIGINS")
    def validate_allowed_origins(cls, value):
        # SEC-03: rejects an empty allow-list, the wildcard, the null
        # origin and any entry that is not a bare origin; closes
        # CWE-942 and CWE-346 and keeps matching exact-equality only.
        if not value:
            raise ValueError(
                "ALLOWED_ORIGINS must contain at least one origin"
            )
        for origin in value:
            if origin in ("*", "null"):
                raise ValueError(
                    "ALLOWED_ORIGINS forbids the wildcard and the null "
                    f"origin, got: {origin!r}"
                )
            parts = urlsplit(origin)
            host = parts.netloc
            # SEC-03: also rejects whitespace, control and non-ASCII
            # characters, which a browser never sends in an Origin
            is_origin = (
                parts.scheme in ("http", "https")
                and host != ""
                and host == host.lower()
                and "@" not in host
                and "*" not in host
                and origin == f"{parts.scheme}://{host}"
                and origin.isascii()
                and not any(
                    c.isspace() or not c.isprintable() for c in origin
                )
            )
            if not is_origin:
                raise ValueError(
                    "ALLOWED_ORIGINS entries must be lowercase "
                    "scheme://host[:port] origins with no path, "
                    f"got: {origin!r}"
                )
        return value

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()