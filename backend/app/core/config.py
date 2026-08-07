"""Application settings, validated when this module is imported.

Values are read from the process environment and from the ``.env`` file,
and every security-relevant value is checked before the module finishes
loading. A rejected value raises and stops startup: no value is
defaulted, generated or downgraded in response to a failed check.

The checks applied here are:

* the token signing key must be at least
  :data:`MIN_SIGNING_KEY_BYTES` bytes long and must not be a known
  placeholder value
* the JWT algorithm list must be non-empty and must name only entries
  present in :data:`ALLOWED_JWT_ALGORITHMS`, with ``none`` refused in
  any letter case
* the CORS origin list must be non-empty and must carry no wildcard
* the PayPal certificate-host allowlist must be non-empty and must
  carry bare PayPal hostnames only
* the PayPal API base must be an ``https`` URL
* the production environment must not be paired with sandbox payment
  configuration

This module imports nothing from the application, and it reports a
rejected value by raising rather than by logging.

Usage::

    from backend.app.core.config import settings

    engine = create_engine(settings.DATABASE_URL)
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from pydantic import BaseSettings, Field, root_validator, validator

__all__ = [
    "ALLOWED_JWT_ALGORITHMS",
    "ENVIRONMENT_NAMES",
    "MIN_SIGNING_KEY_BYTES",
    "PAYPAL_MODES",
    "PRODUCTION_ENVIRONMENT",
    "SANDBOX_MODE",
    "SECRET_BACKENDS",
    "Settings",
    "settings",
]

#: JWT algorithms accepted for signing and verification.
ALLOWED_JWT_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})

#: Deployment environment names accepted by ``Settings.ENVIRONMENT``.
ENVIRONMENT_NAMES = frozenset(
    {"local", "development", "staging", "production"}
)

#: Environment name that activates the payment-configuration guard.
PRODUCTION_ENVIRONMENT = "production"

#: PayPal environments accepted by ``Settings.PAYPAL_MODE``.
PAYPAL_MODES = frozenset({"sandbox", "live"})

#: PayPal environment name that identifies non-live credentials.
SANDBOX_MODE = "sandbox"

#: Secret sources accepted by ``Settings.SECRET_BACKEND``.
SECRET_BACKENDS = frozenset({"env", "gcp-secret-manager"})

#: Smallest accepted length of the token signing key, in bytes.
MIN_SIGNING_KEY_BYTES = 32

# Algorithm name that carries no signature.
_UNSIGNED_ALGORITHM = "none"

# Domain every PayPal certificate host must fall under.
_PAYPAL_DOMAIN = "paypal.com"

# Substring that marks a PayPal API host as non-live.
_SANDBOX_HOST_MARKER = "sandbox"

# Characters that disqualify an entry from being a bare hostname.
_HOST_FORBIDDEN_CHARS = ("/", ":", "?", "#", "@", "*", " ", "\t")

# Signing-key values refused whatever their length or letter case.
_REJECTED_KEY_VALUES = frozenset(
    {
        "your_secret_key_here",
        "your-secret-key-here",
        "yoursecretkeyhere",
        "changeme",
        "change_me",
        "change-me",
        "secret",
        "secret_key",
        "secretkey",
        "mysecretkey",
        "password",
        "test",
        "testing",
        "example",
        "placeholder",
        "dummy",
        "insecure",
        "none",
        "null",
        "string",
    }
)

# Signing-key openings refused whatever follows them.
_PLACEHOLDER_KEY_PREFIXES = (
    "changeme",
    "change_me",
    "change-me",
    "replaceme",
    "replace_",
    "replace-",
    "placeholder",
    "insecure",
)

# Settings whose environment value is accepted either as a JSON array
# or as a comma-separated string.
_LIST_VALUED_FIELDS = (
    "ALLOWED_HOSTS",
    "ALLOWED_ORIGINS",
    "JWT_ALGORITHMS",
    "PAYPAL_CERT_HOST_ALLOWLIST",
)

# Settings whose value is required to be non-blank text.
_REQUIRED_TEXT_FIELDS = (
    "DATABASE_URL",
    "FROM_EMAIL",
    "JWT_AUDIENCE",
    "JWT_ISSUER",
    "PAYPAL_CLIENT_ID",
    "PAYPAL_CLIENT_SECRET",
    "PAYPAL_WEBHOOK_ID",
    "SENDGRID_API_KEY",
    "ZILLOW_API_KEY",
    "ZILLOW_API_URL",
)

# Shape of a rate-limit expression: a count, a separator, an optional
# period multiple and a period name.
_RATE_LIMIT_PATTERN = re.compile(
    r"^\d+\s*(?:/|\s+per\s+)\s*(?:\d+\s*)?"
    r"(?:second|minute|hour|day|month|year)s?$",
    re.IGNORECASE,
)


def _strip_entries(value: List[str]) -> List[str]:
    """Return the entries stripped, refusing an empty or blank list."""
    if not value:
        raise ValueError("must not be empty")
    entries = [str(entry).strip() for entry in value]
    if not all(entries):
        raise ValueError("must not contain an empty entry")
    return entries


class Settings(BaseSettings):
    """Validated application settings.

    Instances are built from the process environment and the ``.env``
    file, and may also be built directly from keyword arguments.
    Construction raises ``ValidationError`` when a value fails a check,
    so importing this module fails while a rejected value is in place.
    """

    # Runtime environment
    ENVIRONMENT: str = "development"

    # Database
    DATABASE_URL: str

    # JWT / token signing
    SECRET_KEY: str
    JWT_ALGORITHMS: List[str] = ["HS256"]
    JWT_ISSUER: str = "apartment-finder-service"
    JWT_AUDIENCE: str = "apartment-finder-web"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(30, ge=1, le=1440)

    # Password hashing
    BCRYPT_ROUNDS: int = Field(12, ge=10, le=15)

    # HTTP surface, CORS and hosts
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:80",
    ]
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    MAX_REQUEST_BODY_BYTES: int = Field(1048576, ge=1, le=104857600)
    MAX_PAGE_SIZE: int = Field(100, ge=1, le=1000)
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_REGISTER: str = "3/minute"

    # Login lockout
    LOGIN_MAX_ATTEMPTS: int = Field(5, ge=1, le=100)
    LOGIN_LOCKOUT_MINUTES: int = Field(15, ge=1, le=1440)

    # Listing ingestion
    ZILLOW_API_URL: str = "https://zillow-api.example.com/v2/listings"
    ZILLOW_API_KEY: str
    HTTP_TIMEOUT_SECONDS: float = Field(10.0, gt=0, le=300)

    # PayPal integration
    PAYPAL_MODE: str = SANDBOX_MODE
    PAYPAL_API_BASE: str = "https://api-m.sandbox.paypal.com"
    PAYPAL_CLIENT_ID: str
    PAYPAL_CLIENT_SECRET: str
    PAYPAL_WEBHOOK_ID: str
    PAYPAL_CERT_HOST_ALLOWLIST: List[str] = [
        "api.paypal.com",
        "api.sandbox.paypal.com",
        "api-m.paypal.com",
        "api-m.sandbox.paypal.com",
    ]

    # Email delivery
    SENDGRID_API_KEY: str
    FROM_EMAIL: str = "no-reply@example.com"

    # Secret management and observability
    SECRET_BACKEND: str = Field("env")
    SENTRY_DSN: Optional[str]

    @validator(*_LIST_VALUED_FIELDS, pre=True)
    def _split_delimited_list(cls, value: Any) -> Any:
        """Return a comma-separated string as a list of its entries."""
        if isinstance(value, str):
            return [
                entry.strip()
                for entry in value.split(",")
                if entry.strip()
            ]
        return value

    @validator(*_REQUIRED_TEXT_FIELDS)
    def _require_non_blank_text(cls, value: str) -> str:
        """Return the value stripped, refusing a blank value."""
        candidate = value.strip()
        if not candidate:
            raise ValueError("must not be empty")
        return candidate

    @validator("SECRET_KEY")
    def _check_signing_key(cls, value: str) -> str:
        """Return the signing key, refusing weak and placeholder keys.

        A key measuring fewer than :data:`MIN_SIGNING_KEY_BYTES`
        encoded bytes is refused, as is a key matching the rejected-value
        set or opening with a placeholder marker. Comparison ignores
        surrounding whitespace and letter case, and an accepted key is
        returned unchanged.
        """
        if len(value.encode("utf-8")) < MIN_SIGNING_KEY_BYTES:
            raise ValueError(
                f"must be at least {MIN_SIGNING_KEY_BYTES} bytes long"
            )
        candidate = value.strip().lower()
        if candidate in _REJECTED_KEY_VALUES:
            raise ValueError("must not be a placeholder value")
        if candidate.startswith(_PLACEHOLDER_KEY_PREFIXES):
            raise ValueError("must not be a placeholder value")
        return value

    @validator("JWT_ALGORITHMS")
    def _check_jwt_algorithms(cls, value: List[str]) -> List[str]:
        """Return the algorithm list, refusing anything not allowed.

        An empty list is refused, ``none`` is refused in any letter
        case, and every remaining entry must appear in
        :data:`ALLOWED_JWT_ALGORITHMS`.
        """
        entries = _strip_entries(value)
        accepted: List[str] = []
        for entry in entries:
            if entry.lower() == _UNSIGNED_ALGORITHM:
                raise ValueError("must not name an unsigned algorithm")
            if entry not in ALLOWED_JWT_ALGORITHMS:
                raise ValueError(
                    f"must name only {sorted(ALLOWED_JWT_ALGORITHMS)}"
                )
            accepted.append(entry)
        return accepted

    @validator("ENVIRONMENT")
    def _check_environment(cls, value: str) -> str:
        """Return the environment name in lower case."""
        candidate = value.strip().lower()
        if candidate not in ENVIRONMENT_NAMES:
            raise ValueError(
                f"must be one of {sorted(ENVIRONMENT_NAMES)}"
            )
        return candidate

    @validator("PAYPAL_MODE")
    def _check_paypal_mode(cls, value: str) -> str:
        """Return the PayPal environment name in lower case."""
        candidate = value.strip().lower()
        if candidate not in PAYPAL_MODES:
            raise ValueError(f"must be one of {sorted(PAYPAL_MODES)}")
        return candidate

    @validator("SECRET_BACKEND")
    def _check_secret_source(cls, value: str) -> str:
        """Return the secret source name in lower case."""
        candidate = value.strip().lower()
        if candidate not in SECRET_BACKENDS:
            raise ValueError(
                f"must be one of {sorted(SECRET_BACKENDS)}"
            )
        return candidate

    @validator("ALLOWED_ORIGINS")
    def _check_allowed_origins(cls, value: List[str]) -> List[str]:
        """Return the origin list, refusing a wildcard origin."""
        entries = _strip_entries(value)
        for entry in entries:
            if "*" in entry:
                raise ValueError("must not carry a wildcard origin")
        return entries

    @validator("ALLOWED_HOSTS")
    def _check_allowed_hosts(cls, value: List[str]) -> List[str]:
        """Return the host list, refusing an empty list."""
        return _strip_entries(value)

    @validator("PAYPAL_CERT_HOST_ALLOWLIST")
    def _check_cert_hosts(cls, value: List[str]) -> List[str]:
        """Return the certificate-host list in lower case.

        Every entry must be a bare hostname carrying no scheme, port,
        path, wildcard or user information, and must fall under
        :data:`_PAYPAL_DOMAIN`.
        """
        hosts: List[str] = []
        for entry in _strip_entries(value):
            candidate = entry.lower()
            if any(char in candidate for char in _HOST_FORBIDDEN_CHARS):
                raise ValueError("must carry bare hostnames only")
            if candidate != _PAYPAL_DOMAIN and not candidate.endswith(
                "." + _PAYPAL_DOMAIN
            ):
                raise ValueError(
                    f"must carry {_PAYPAL_DOMAIN} hostnames only"
                )
            hosts.append(candidate)
        return hosts

    @validator("PAYPAL_API_BASE")
    def _check_paypal_api_base(cls, value: str) -> str:
        """Return the PayPal API base without a trailing slash.

        The value must use the ``https`` scheme and must carry a host.
        """
        candidate = value.strip().rstrip("/")
        parts = urlsplit(candidate)
        if parts.scheme != "https":
            raise ValueError("must use the https scheme")
        if not parts.hostname:
            raise ValueError("must carry a host")
        return candidate

    @validator("RATE_LIMIT_LOGIN", "RATE_LIMIT_REGISTER")
    def _check_rate_limit(cls, value: str) -> str:
        """Return the rate-limit expression stripped.

        The value must be one or more semicolon-separated
        ``<count>/<period>`` expressions.
        """
        candidate = value.strip()
        if not candidate:
            raise ValueError("must not be empty")
        expressions = [part.strip() for part in candidate.split(";")]
        if not all(expressions):
            raise ValueError("must not carry an empty expression")
        for expression in expressions:
            if not _RATE_LIMIT_PATTERN.match(expression):
                raise ValueError(
                    "must be a <count>/<period> expression"
                )
        return candidate

    @root_validator(skip_on_failure=True)
    def _check_production_payment_setup(
        cls, values: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Refuse sandbox payment configuration in production.

        Applies when ``ENVIRONMENT`` names
        :data:`PRODUCTION_ENVIRONMENT` and either ``PAYPAL_MODE`` names
        :data:`SANDBOX_MODE` or ``PAYPAL_API_BASE`` addresses a sandbox
        host.
        """
        if values.get("ENVIRONMENT") != PRODUCTION_ENVIRONMENT:
            return values
        if values.get("PAYPAL_MODE") == SANDBOX_MODE:
            raise ValueError(
                f"PAYPAL_MODE must not be {SANDBOX_MODE} when "
                f"ENVIRONMENT is {PRODUCTION_ENVIRONMENT}"
            )
        host = urlsplit(values.get("PAYPAL_API_BASE") or "").hostname
        if _SANDBOX_HOST_MARKER in (host or "").lower():
            raise ValueError(
                "PAYPAL_API_BASE must not address a "
                f"{_SANDBOX_HOST_MARKER} host when ENVIRONMENT is "
                f"{PRODUCTION_ENVIRONMENT}"
            )
        return values

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

        @classmethod
        def parse_env_var(cls, field_name: str, raw_val: str) -> Any:
            """Return the parsed value of one environment variable.

            A list-valued setting accepts either a JSON array or a
            comma-separated string. Every other setting is parsed with
            the default JSON handling.
            """
            if field_name in _LIST_VALUED_FIELDS:
                candidate = raw_val.strip()
                if candidate.startswith("["):
                    return cls.json_loads(candidate)
                return [
                    entry.strip()
                    for entry in candidate.split(",")
                    if entry.strip()
                ]
            return cls.json_loads(raw_val)


settings = Settings()
