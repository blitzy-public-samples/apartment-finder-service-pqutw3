"""Validated application settings loaded from the environment and ``.env``.

Values are read from the process environment and from the ``.env`` file,
and every security-relevant value is checked before the module finishes
loading. A rejected value raises and stops startup: no value is
defaulted, generated or downgraded in response to a failed check.

The checks applied here are:

* the token signing key must carry no surrounding whitespace, must be
  at least :data:`MIN_SIGNING_KEY_BYTES` UTF-8 bytes long once measured
  on its canonical form, and must not be a known placeholder value
* the JWT algorithm list must be non-empty and must name only entries
  present in :data:`ALLOWED_JWT_ALGORITHMS`, with ``none`` refused in
  any letter case
* the database URL must name a supported PostgreSQL driver and carry a
  host and a database name; ``sqlite`` is accepted only when
  ``ENVIRONMENT`` names :data:`LOCAL_ENVIRONMENT`
* the CORS origin list must be non-empty and must carry complete
  ``<scheme>://<host>[:<port>]`` origins with no wildcard
* the trusted-host list must be non-empty and must carry bare hostnames
  or IP addresses with no wildcard
* the listing-provider URL must be an ``https`` URL addressing a named
  public host under :data:`ZILLOW_API_DOMAINS`, carrying no user
  information, query string or fragment
* the PayPal certificate-host allowlist must be non-empty and must
  carry bare PayPal hostnames only
* the PayPal API base must be the entry in :data:`PAYPAL_API_BASES`
  that corresponds to ``PAYPAL_MODE``
* the production environment must not be paired with sandbox payment
  configuration
* the sender address must be a routable ``<local-part>@<domain>``
  address
* each rate limit must carry a positive, bounded count and period
  multiple
* placeholder values and reserved example domains are refused outside
  :data:`LOCAL_ENVIRONMENT`
* when ``SECRET_BACKEND`` names :data:`MANAGED_BACKEND_NAME`, every
  setting listed in :data:`MANAGED_SECRET_SETTINGS` must arrive from
  the process environment rather than from an environment file

Constructing :class:`Settings` raises ``ValidationError`` for a rejected
value, and the module-level :data:`settings` instance applies that
validation during import.

This module imports nothing from the application, and it reports a
rejected value by raising rather than by logging.

Usage::

    from backend.app.core.config import settings

    engine = create_engine(settings.DATABASE_URL)
"""

import ipaddress
import json
import os
import re
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlsplit

from pydantic import BaseSettings, Field, root_validator, validator

__all__ = [
    "ALLOWED_JWT_ALGORITHMS",
    "ENVIRONMENT_BACKEND_NAME",
    "ENVIRONMENT_NAMES",
    "LIVE_MODE",
    "LOCAL_ENVIRONMENT",
    "MANAGED_BACKEND_NAME",
    "MANAGED_SECRET_SETTINGS",
    "MIN_SIGNING_KEY_BYTES",
    "PAYPAL_API_BASES",
    "PAYPAL_MODES",
    "PRODUCTION_ENVIRONMENT",
    "SANDBOX_MODE",
    "SECRET_BACKENDS",
    "Settings",
    "TLS_SCHEME",
    "ZILLOW_API_DOMAINS",
    "is_allowed_listing_provider_url",
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

#: Environment name under which placeholder values are tolerated and a
#: plaintext provider URL is accepted.
LOCAL_ENVIRONMENT = "local"

#: PayPal environment name that identifies non-live credentials.
SANDBOX_MODE = "sandbox"

#: PayPal environment name that identifies live credentials.
LIVE_MODE = "live"

#: The only PayPal REST API base accepted for each
#: ``Settings.PAYPAL_MODE``.
PAYPAL_API_BASES: Mapping[str, str] = MappingProxyType(
    {
        SANDBOX_MODE: "https://api-m.sandbox.paypal.com",
        LIVE_MODE: "https://api-m.paypal.com",
    }
)

#: Domains the listing-provider URL may address. A host equal to one of
#: these, or a subdomain of one of them, is accepted.
ZILLOW_API_DOMAINS = frozenset({"zillow.com", "zillow-api.example.com"})

#: PayPal environments accepted by ``Settings.PAYPAL_MODE``.
PAYPAL_MODES = frozenset(PAYPAL_API_BASES)

#: ``Settings.SECRET_BACKEND`` name for values read from the process
#: environment or from an environment file.
ENVIRONMENT_BACKEND_NAME = "env"

#: ``Settings.SECRET_BACKEND`` name for values provisioned in Google
#: Cloud Secret Manager and injected into the process environment.
MANAGED_BACKEND_NAME = "gcp-secret-manager"

#: Secret sources accepted by ``Settings.SECRET_BACKEND``.
SECRET_BACKENDS = frozenset(
    {ENVIRONMENT_BACKEND_NAME, MANAGED_BACKEND_NAME}
)

#: Settings that must arrive from the process environment when
#: ``Settings.SECRET_BACKEND`` names :data:`MANAGED_BACKEND_NAME`.
MANAGED_SECRET_SETTINGS = (
    "SECRET_KEY",
    "DATABASE_URL",
    "ZILLOW_API_KEY",
    "PAYPAL_CLIENT_SECRET",
    "PAYPAL_WEBHOOK_ID",
    "SENDGRID_API_KEY",
)

#: Smallest accepted length of the token signing key, in UTF-8 bytes.
MIN_SIGNING_KEY_BYTES = 32

#: URL scheme required of every outbound provider endpoint.
TLS_SCHEME = "https"

# Algorithm name that carries no signature.
_UNSIGNED_ALGORITHM = "none"

# Domain every PayPal certificate host must fall under.
_PAYPAL_DOMAIN = "paypal.com"

# PayPal REST API bases accepted by ``Settings.PAYPAL_API_BASE``.
_PAYPAL_API_BASE_VALUES = frozenset(PAYPAL_API_BASES.values())

# Characters that disqualify an entry from being a bare hostname.
_HOST_FORBIDDEN_CHARS = ("/", ":", "?", "#", "@", "*", " ", "\t")

# Schemes accepted in a CORS origin.
_ORIGIN_SCHEMES = frozenset({"http", "https"})

# URL schemes accepted in ``Settings.DATABASE_URL``.
_DATABASE_SCHEMES = frozenset({"postgresql", "postgresql+psycopg2"})

# URL schemes accepted in ``Settings.DATABASE_URL`` under
# :data:`LOCAL_ENVIRONMENT` only.
_LOCAL_DATABASE_SCHEMES = frozenset({"sqlite", "sqlite+pysqlite"})

# Scheme whose SQLAlchemy support was withdrawn.
_WITHDRAWN_DATABASE_SCHEME = "postgres"

# Longest accepted hostname, in characters.
_MAX_HOSTNAME_LENGTH = 253

# Shape of one dot-separated hostname, with an optional trailing dot.
_HOSTNAME_PATTERN = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)

# Shape of a mail address: one local part, one at sign, one domain.
_EMAIL_PATTERN = re.compile(r"^[^@\s,;<>\"]+@[^@\s,;<>\"]+$")

# Hostnames that address the running host or its metadata service.
_INTERNAL_HOST_NAMES = frozenset(
    {
        "localhost",
        "metadata",
        "metadata.google.internal",
        "instance-data",
    }
)

# Hostname endings that address the running host or a private network.
_INTERNAL_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
)

# Hostnames reserved for documentation and testing.
_RESERVED_HOST_NAMES = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "example.edu",
    }
)

# Hostname endings reserved for documentation and testing.
_RESERVED_HOST_SUFFIXES = (
    ".example.com",
    ".example.org",
    ".example.net",
    ".example.edu",
    ".example",
    ".invalid",
    ".test",
    ".localhost",
)

# Value openings and fragments that mark a setting as unconfigured.
_PLACEHOLDER_MARKERS = (
    "change_me",
    "changeme",
    "change-me",
    "replace_",
    "replace-",
    "replaceme",
    "your_",
    "your-",
    "placeholder",
    "insert_",
    "insert-",
    "<",
    ">",
)

# Settings whose value is refused when it carries a placeholder marker
# or addresses a reserved example domain, outside
# :data:`LOCAL_ENVIRONMENT`.
_PLACEHOLDER_GUARDED_FIELDS = (
    "DATABASE_URL",
    "ZILLOW_API_URL",
    "ZILLOW_API_KEY",
    "PAYPAL_CLIENT_ID",
    "PAYPAL_CLIENT_SECRET",
    "PAYPAL_WEBHOOK_ID",
    "SENDGRID_API_KEY",
    "FROM_EMAIL",
)

# Largest accepted request count in a rate-limit expression.
_MAX_RATE_LIMIT_COUNT = 10000

# Largest accepted period multiple in a rate-limit expression.
_MAX_RATE_LIMIT_PERIOD_MULTIPLE = 1000

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
    "your_",
    "your-",
    "yoursecret",
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
# period multiple and a period name. The count and the multiple are
# captured so that each can be measured numerically.
_RATE_LIMIT_PATTERN = re.compile(
    r"^(?P<count>\d+)\s*(?:/|\s+per\s+)\s*(?:(?P<multiple>\d+)\s*)?"
    r"(?:second|minute|hour|day|month|year)s?$",
    re.IGNORECASE,
)


def _parse_delimited_list(value: Any) -> Any:
    """Return a list for a JSON array or comma-separated string value.

    A value that is not a string is returned unchanged, which makes this
    the single parsing implementation for both the environment and the
    keyword-argument path. Empty comma-separated segments are preserved
    so that the field validators refuse them.
    """
    if not isinstance(value, str):
        return value
    candidate = value.strip()
    if candidate.startswith("["):
        return json.loads(candidate)
    return [entry.strip() for entry in candidate.split(",")]


def _strip_entries(value: List[str]) -> List[str]:
    """Return the entries stripped, refusing an empty or blank list."""
    if not value:
        raise ValueError("must not be empty")
    entries = [str(entry).strip() for entry in value]
    if not all(entries):
        raise ValueError("must not contain an empty entry")
    return entries


def _as_ip_address(host: str) -> Optional[Any]:
    """Return the parsed IP address for a literal, otherwise ``None``."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _require_hostname(host: str) -> str:
    """Return the host in lower case, refusing a malformed host.

    An IP literal is accepted as written. Any other value must be a
    dot-separated hostname carrying no scheme, port, path, wildcard or
    user information.
    """
    candidate = host.strip().lower()
    if not candidate:
        raise ValueError("must carry a host")
    if _as_ip_address(candidate) is not None:
        return candidate
    if any(char in candidate for char in _HOST_FORBIDDEN_CHARS):
        raise ValueError("must be a bare hostname or IP address")
    if len(candidate) > _MAX_HOSTNAME_LENGTH:
        raise ValueError("must be a bare hostname or IP address")
    if not _HOSTNAME_PATTERN.match(candidate):
        raise ValueError("must be a bare hostname or IP address")
    return candidate


def _is_internal_host(host: str) -> bool:
    """Report whether the host addresses this host or a private network."""
    candidate = host.strip().lower().rstrip(".")
    if candidate in _INTERNAL_HOST_NAMES:
        return True
    if candidate.endswith(_INTERNAL_HOST_SUFFIXES):
        return True
    address = _as_ip_address(candidate)
    if address is None:
        return False
    return (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _is_reserved_host(host: str) -> bool:
    """Report whether the host is reserved for documentation or testing."""
    candidate = host.strip().lower().rstrip(".")
    if candidate in _RESERVED_HOST_NAMES:
        return True
    return candidate.endswith(_RESERVED_HOST_SUFFIXES)


def _carries_placeholder(value: str) -> bool:
    """Report whether the value carries a placeholder marker."""
    folded = value.strip().lower()
    return any(marker in folded for marker in _PLACEHOLDER_MARKERS)


def _value_host(value: str) -> Optional[str]:
    """Return the host addressed by a URL or mail address value."""
    candidate = value.strip()
    if "://" in candidate:
        try:
            return (urlsplit(candidate).hostname or "").lower() or None
        except ValueError:
            return None
    if "@" in candidate:
        return candidate.rsplit("@", 1)[1].strip().lower() or None
    return None


def _split_url(value: str) -> Any:
    """Return the split URL, refusing a value that cannot be parsed."""
    try:
        parts = urlsplit(value)
        # Reading the port raises for a non-integer port.
        _ = parts.port
    except ValueError:
        raise ValueError("must be a well-formed URL")
    return parts


def is_allowed_listing_provider_url(url: Any) -> bool:
    """Report whether ``url`` may receive the listing-provider key.

    A URL qualifies only when it uses the :data:`TLS_SCHEME` scheme,
    carries no user information, names a host, and that host is one of
    :data:`ZILLOW_API_DOMAINS` or a subdomain of one of them.
    """
    if not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return False
    if parts.scheme.lower() != TLS_SCHEME:
        return False
    if parts.username or parts.password:
        return False
    if not host or not _HOSTNAME_PATTERN.match(host):
        return False
    candidate = host.rstrip(".")
    return any(
        candidate == domain or candidate.endswith("." + domain)
        for domain in ZILLOW_API_DOMAINS
    )


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
        """Return a JSON array or comma-separated string as a list.

        A value that is not a string is returned unchanged.
        """
        return _parse_delimited_list(value)

    @validator(*_REQUIRED_TEXT_FIELDS)
    def _require_non_blank_text(cls, value: str) -> str:
        """Return the value stripped, refusing a blank value."""
        candidate = value.strip()
        if not candidate:
            raise ValueError("must not be empty")
        return candidate

    @validator("SECRET_KEY")
    def _check_signing_key(cls, value: str) -> str:
        """Return the canonical signing key, refusing a weak key.

        The value is refused when it is blank once stripped, when it
        carries surrounding whitespace, when its canonical form measures
        fewer than :data:`MIN_SIGNING_KEY_BYTES` UTF-8 bytes, and when
        it matches the rejected-value set or opens with a placeholder
        marker. The returned value is the canonical form, and the
        placeholder comparison ignores letter case.
        """
        candidate = value.strip()
        if not candidate:
            raise ValueError("must not be blank")
        if candidate != value:
            raise ValueError(
                "must not carry leading or trailing whitespace"
            )
        if len(candidate.encode("utf-8")) < MIN_SIGNING_KEY_BYTES:
            raise ValueError(
                f"must be at least {MIN_SIGNING_KEY_BYTES} UTF-8 bytes"
                " long"
            )
        folded = candidate.lower()
        if folded in _REJECTED_KEY_VALUES:
            raise ValueError("must not be a placeholder value")
        if folded.startswith(_PLACEHOLDER_KEY_PREFIXES):
            raise ValueError("must not be a placeholder value")
        return candidate

    @validator("DATABASE_URL")
    def _check_database_url(
        cls, value: str, values: Dict[str, Any]
    ) -> str:
        """Return the database URL, refusing an unsupported target.

        The URL must name a scheme in :data:`_DATABASE_SCHEMES` and must
        carry both a host and a database name. A scheme in
        :data:`_LOCAL_DATABASE_SCHEMES` is accepted only while
        ``ENVIRONMENT`` names :data:`LOCAL_ENVIRONMENT`.
        """
        candidate = value.strip()
        parts = _split_url(candidate)
        scheme = parts.scheme.lower()
        accepted = sorted(_DATABASE_SCHEMES)
        if scheme in _LOCAL_DATABASE_SCHEMES:
            if values.get("ENVIRONMENT") != LOCAL_ENVIRONMENT:
                raise ValueError(
                    f"must use one of {accepted} unless ENVIRONMENT is "
                    f"{LOCAL_ENVIRONMENT}"
                )
            return candidate
        if scheme == _WITHDRAWN_DATABASE_SCHEME:
            raise ValueError(
                f"must use one of {accepted} rather than "
                f"{_WITHDRAWN_DATABASE_SCHEME}"
            )
        if scheme not in _DATABASE_SCHEMES:
            raise ValueError(f"must use one of {accepted}")
        if not parts.hostname:
            raise ValueError("must carry a host")
        database = parts.path.lstrip("/")
        if not database or "/" in database:
            raise ValueError("must carry a database name")
        return candidate

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
        """Return the origin list in canonical form.

        Every entry must be a complete
        ``<scheme>://<host>[:<port>]`` origin whose scheme appears in
        :data:`_ORIGIN_SCHEMES`, carrying no wildcard, path, query
        string, fragment or user information. The scheme and host are
        returned in lower case and the port is returned as written.
        """
        origins: List[str] = []
        for entry in _strip_entries(value):
            if "*" in entry:
                raise ValueError("must not carry a wildcard origin")
            parts = _split_url(entry)
            if parts.scheme.lower() not in _ORIGIN_SCHEMES:
                raise ValueError(
                    "must carry a <scheme>://<host>[:<port>] origin "
                    f"using one of {sorted(_ORIGIN_SCHEMES)}"
                )
            if parts.path or parts.query or parts.fragment:
                raise ValueError(
                    "must not carry a path, query string or fragment"
                )
            if parts.username or parts.password:
                raise ValueError("must not carry user information")
            _require_hostname(parts.hostname or "")
            origins.append(
                f"{parts.scheme.lower()}://{parts.netloc.lower()}"
            )
        return origins

    @validator("ALLOWED_HOSTS")
    def _check_allowed_hosts(cls, value: List[str]) -> List[str]:
        """Return the host list in lower case.

        Every entry must be a bare hostname or IP address, and a
        wildcard entry is refused.
        """
        hosts: List[str] = []
        for entry in _strip_entries(value):
            if "*" in entry:
                raise ValueError("must not carry a wildcard host")
            hosts.append(_require_hostname(entry))
        return hosts

    @validator("PAYPAL_CERT_HOST_ALLOWLIST")
    def _check_cert_hosts(cls, value: List[str]) -> List[str]:
        """Return the certificate-host list in lower case.

        Every entry must be a bare hostname carrying no scheme, port,
        path, wildcard or user information, and must fall under
        :data:`_PAYPAL_DOMAIN`.
        """
        hosts: List[str] = []
        for entry in _strip_entries(value):
            candidate = _require_hostname(entry)
            if candidate != _PAYPAL_DOMAIN and not candidate.endswith(
                "." + _PAYPAL_DOMAIN
            ):
                raise ValueError(
                    f"must carry {_PAYPAL_DOMAIN} hostnames only"
                )
            hosts.append(candidate)
        return hosts

    @validator("ZILLOW_API_URL")
    def _check_zillow_api_url(cls, value: str) -> str:
        """Return the listing-provider URL, refusing an unsafe target.

        The URL must use the ``https`` scheme, must address a named
        public host of at least two labels under
        :data:`ZILLOW_API_DOMAINS`, and must carry no user information,
        query string or fragment. A host addressing this host, a private
        network or a metadata service is refused.
        """
        candidate = value.strip()
        parts = _split_url(candidate)
        if parts.scheme.lower() != TLS_SCHEME:
            raise ValueError(f"must use the {TLS_SCHEME} scheme")
        if parts.username or parts.password:
            raise ValueError("must not carry user information")
        if parts.query or parts.fragment:
            raise ValueError(
                "must not carry a query string or fragment"
            )
        host = _require_hostname(parts.hostname or "")
        if _as_ip_address(host) is not None:
            raise ValueError("must address a named host")
        if "." not in host.rstrip("."):
            raise ValueError(
                "must address a host carrying a top-level label"
            )
        if _is_internal_host(host):
            raise ValueError(
                "must not address this host, a private network or a "
                "metadata service"
            )
        if not is_allowed_listing_provider_url(candidate):
            raise ValueError(
                "must address a host under "
                f"{sorted(ZILLOW_API_DOMAINS)}"
            )
        return candidate

    @validator("FROM_EMAIL")
    def _check_from_email(cls, value: str) -> str:
        """Return the sender address, refusing a malformed address.

        The value must be one ``<local-part>@<domain>`` address whose
        domain is a hostname carrying a top-level label.
        """
        candidate = value.strip()
        if not _EMAIL_PATTERN.match(candidate):
            raise ValueError(
                "must be a <local-part>@<domain> address"
            )
        domain = _require_hostname(candidate.rsplit("@", 1)[1])
        if "." not in domain.rstrip("."):
            raise ValueError(
                "must carry a domain with a top-level label"
            )
        return candidate

    @validator("PAYPAL_API_BASE")
    def _check_paypal_api_base(cls, value: str) -> str:
        """Return the PayPal API base in canonical form.

        The value must be one of the entries in
        :data:`PAYPAL_API_BASES`, compared without a trailing slash and
        without regard to letter case.
        """
        candidate = value.strip().rstrip("/").lower()
        if candidate not in _PAYPAL_API_BASE_VALUES:
            raise ValueError(
                f"must be one of {sorted(_PAYPAL_API_BASE_VALUES)}"
            )
        return candidate

    @validator("RATE_LIMIT_LOGIN", "RATE_LIMIT_REGISTER")
    def _check_rate_limit(cls, value: str) -> str:
        """Return the rate-limit expression stripped.

        The value must be one or more semicolon-separated
        ``<count>/<period>`` expressions. Each count must lie between 1
        and :data:`_MAX_RATE_LIMIT_COUNT`, and each period multiple must
        lie between 1 and
        :data:`_MAX_RATE_LIMIT_PERIOD_MULTIPLE`.
        """
        candidate = value.strip()
        if not candidate:
            raise ValueError("must not be empty")
        expressions = [part.strip() for part in candidate.split(";")]
        if not all(expressions):
            raise ValueError("must not carry an empty expression")
        for expression in expressions:
            match = _RATE_LIMIT_PATTERN.match(expression)
            if match is None:
                raise ValueError(
                    "must be a <count>/<period> expression"
                )
            count = int(match.group("count"))
            if not 1 <= count <= _MAX_RATE_LIMIT_COUNT:
                raise ValueError(
                    "must carry a count between 1 and "
                    f"{_MAX_RATE_LIMIT_COUNT}"
                )
            raw_multiple = match.group("multiple")
            if raw_multiple is None:
                continue
            multiple = int(raw_multiple)
            if not 1 <= multiple <= _MAX_RATE_LIMIT_PERIOD_MULTIPLE:
                raise ValueError(
                    "must carry a period multiple between 1 and "
                    f"{_MAX_RATE_LIMIT_PERIOD_MULTIPLE}"
                )
        return candidate

    @root_validator(skip_on_failure=True)
    def _check_payment_configuration(
        cls, values: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Refuse a payment base that does not match the payment mode.

        ``PAYPAL_API_BASE`` must equal the :data:`PAYPAL_API_BASES` entry
        for ``PAYPAL_MODE`` in every environment, and ``PAYPAL_MODE``
        must not name :data:`SANDBOX_MODE` while ``ENVIRONMENT`` names
        :data:`PRODUCTION_ENVIRONMENT`.
        """
        mode = values.get("PAYPAL_MODE")
        base = values.get("PAYPAL_API_BASE")
        if mode is None or base is None:
            return values
        expected = PAYPAL_API_BASES[mode]
        if base != expected:
            raise ValueError(
                f"PAYPAL_API_BASE must be {expected} when PAYPAL_MODE "
                f"is {mode}"
            )
        if (
            values.get("ENVIRONMENT") == PRODUCTION_ENVIRONMENT
            and mode == SANDBOX_MODE
        ):
            raise ValueError(
                f"PAYPAL_MODE must not be {SANDBOX_MODE} when "
                f"ENVIRONMENT is {PRODUCTION_ENVIRONMENT}"
            )
        return values

    @root_validator(skip_on_failure=True)
    def _check_configured_values(
        cls, values: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Refuse placeholder and reserved values outside local runs.

        Each setting listed in :data:`_PLACEHOLDER_GUARDED_FIELDS` is
        refused when it carries a marker from
        :data:`_PLACEHOLDER_MARKERS` or addresses a host reserved for
        documentation and testing. No check applies while
        ``ENVIRONMENT`` names :data:`LOCAL_ENVIRONMENT`.
        """
        if values.get("ENVIRONMENT") == LOCAL_ENVIRONMENT:
            return values
        refused: List[str] = []
        for name in _PLACEHOLDER_GUARDED_FIELDS:
            value = values.get(name)
            if not isinstance(value, str):
                continue
            if _carries_placeholder(value):
                refused.append(f"{name} carries a placeholder value")
                continue
            host = _value_host(value)
            if host is not None and _is_reserved_host(host):
                refused.append(
                    f"{name} addresses a reserved example domain"
                )
        if refused:
            raise ValueError(
                "; ".join(refused)
                + " (accepted only when ENVIRONMENT is "
                + LOCAL_ENVIRONMENT
                + ")"
            )
        return values

    @root_validator(skip_on_failure=True)
    def _check_value_source(
        cls, values: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Require managed values to arrive from the environment.

        When ``SECRET_BACKEND`` names :data:`MANAGED_BACKEND_NAME`,
        every setting listed in :data:`MANAGED_SECRET_SETTINGS` must be
        present and non-blank in the process environment. An environment
        file is then not an accepted source for those values.
        """
        if values.get("SECRET_BACKEND") != MANAGED_BACKEND_NAME:
            return values
        supplied = {
            name.upper()
            for name, raw in os.environ.items()
            if raw and raw.strip()
        }
        missing = [
            name
            for name in MANAGED_SECRET_SETTINGS
            if name not in supplied
        ]
        if missing:
            raise ValueError(
                f"SECRET_BACKEND is {MANAGED_BACKEND_NAME}, so "
                f"{', '.join(missing)} must be supplied by the process "
                "environment rather than by an environment file"
            )
        return values

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

        @classmethod
        def parse_env_var(cls, field_name: str, raw_val: str) -> Any:
            """Return the parsed value of one environment variable.

            A list-valued setting accepts either a JSON array or a
            comma-separated string, parsed by
            :func:`_parse_delimited_list`. Every other setting is parsed
            with the default JSON handling.
            """
            if field_name in _LIST_VALUED_FIELDS:
                return _parse_delimited_list(raw_val)
            return cls.json_loads(raw_val)


settings = Settings()
