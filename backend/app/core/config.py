"""Validated application settings loaded from the environment and ``.env``.

Values are read from the process environment and from the ``.env`` file,
and every security-relevant value is checked before the module finishes
loading. A rejected value raises and stops startup: no value is
defaulted, generated or downgraded in response to a failed check.

The checks applied here are:

* the token signing key must carry no surrounding whitespace, must be
  at least :data:`MIN_SIGNING_KEY_BYTES` UTF-8 bytes long once measured
  on its canonical form -- and at least the floor
  :data:`MIN_SIGNING_KEY_BYTES_BY_ALGORITHM` sets for the strongest
  configured algorithm -- must carry at least
  :data:`MIN_SIGNING_KEY_DISTINCT_CHARS` distinct characters with no run
  longer than :data:`MAX_SIGNING_KEY_REPEAT_RUN` repeated characters or
  :data:`MAX_SIGNING_KEY_SEQUENCE_RUN` consecutive code points, and
  must not be a known placeholder value
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
* the PayPal hosted-redirect base must be one complete
  ``<scheme>://<host>[:<port>]`` base carrying no wildcard, path, query
  string, fragment or user information, and outside
  :data:`LOCAL_ENVIRONMENT` must use :data:`TLS_SCHEME` and address
  neither this host nor a private network
* the production environment must not be paired with sandbox payment
  configuration
* each setting named by :data:`PROVIDER_SECRET_SETTINGS` must be at
  least :data:`MIN_PROVIDER_SECRET_LENGTH` characters long, which is the
  shortest value the redaction registry in
  :mod:`backend.app.core.logging` accepts
* the sender address must be a routable ``<local-part>@<domain>``
  address
* each rate limit must carry a positive, bounded count and period
  multiple
* the rate-limit storage URI must name a scheme in
  :data:`RATE_LIMIT_STORAGE_SCHEMES`, and a scheme outside
  :data:`IN_PROCESS_RATE_LIMIT_SCHEMES` must carry the address of the
  store it names
* outside :data:`LOCAL_ENVIRONMENT` the rate-limit storage URI must name
  a scheme in :data:`DEPLOYABLE_RATE_LIMIT_STORAGE_SCHEMES`, which holds
  the shared schemes and excludes every in-process scheme
* placeholder values and reserved example domains are refused outside
  :data:`LOCAL_ENVIRONMENT`
* when ``SECRET_BACKEND`` names :data:`MANAGED_BACKEND_NAME`, every
  setting listed in :data:`MANAGED_SECRET_SETTINGS` must arrive from
  the process environment rather than from an environment file

Constructing :class:`Settings` raises ``ValidationError`` for a rejected
value, and the module-level :data:`settings` instance applies that
validation during import.

This module imports nothing from the application. A rejected value is
reported by raising.

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
    "BOUNDED_MEMORY_SCHEME",
    "DEFAULT_ENV_FILE",
    "DEFAULT_MAX_PAGINATION_OFFSET",
    "DEPLOYABLE_RATE_LIMIT_STORAGE_SCHEMES",
    "ENVIRONMENT_BACKEND_NAME",
    "ENV_FILE_VARIABLE",
    "ENVIRONMENT_NAMES",
    "IN_PROCESS_RATE_LIMIT_SCHEMES",
    "LIVE_MODE",
    "LOCAL_ENVIRONMENT",
    "MANAGED_BACKEND_NAME",
    "MANAGED_SECRET_SETTINGS",
    "MAX_PAGINATION_OFFSET_CEILING",
    "MAX_SIGNING_KEY_REPEAT_RUN",
    "MAX_SIGNING_KEY_SEQUENCE_RUN",
    "MIN_PROVIDER_SECRET_LENGTH",
    "MIN_SIGNING_KEY_BYTES",
    "MIN_SIGNING_KEY_BYTES_BY_ALGORITHM",
    "MIN_SIGNING_KEY_DISTINCT_CHARS",
    "PROVIDER_SECRET_SETTINGS",
    "PAYPAL_API_BASES",
    "PAYPAL_MODES",
    "PRODUCTION_ENVIRONMENT",
    "RATE_LIMIT_STORAGE_SCHEMES",
    "REPOSITORY_ROOT",
    "SANDBOX_MODE",
    "SECRET_BACKENDS",
    "SHARED_RATE_LIMIT_STORAGE_SCHEMES",
    "Settings",
    "TLS_SCHEME",
    "UNBOUNDED_RATE_LIMIT_STORAGE_SCHEMES",
    "ZILLOW_API_DOMAINS",
    "is_allowed_listing_provider_url",
    "required_signing_key_bytes",
    "rate_limit_storage_scheme",
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

#: Environment variable naming the file settings are also read from. An
#: empty value reads no file at all, leaving the process environment as
#: the only source.
ENV_FILE_VARIABLE = "ENV_FILE"

#: Directory the repository is checked out at: four levels above this
#: module, which lives at ``backend/app/core/config.py``.
REPOSITORY_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
)

#: File settings are also read from when :data:`ENV_FILE_VARIABLE` is
#: absent from the process environment. It is an absolute path under
#: :data:`REPOSITORY_ROOT`, so the same file is read whichever directory
#: the process was started in.
DEFAULT_ENV_FILE = os.path.join(REPOSITORY_ROOT, ".env")

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

#: Rate-limit storage scheme served from this process's own memory and
#: bounded by ``Settings.RATE_LIMIT_MAX_TRACKED_KEYS``. Implemented by
#: :mod:`backend.app.core.rate_limit`.
BOUNDED_MEMORY_SCHEME = "bounded-memory"

#: Storage schemes accepted by ``Settings.RATE_LIMIT_STORAGE_URI``. The
#: names are the ones the rate-limiting backend registers, together with
#: the bounded in-process scheme this application registers itself.
RATE_LIMIT_STORAGE_SCHEMES = frozenset(
    {
        BOUNDED_MEMORY_SCHEME,
        "memcached",
        "memory",
        "mongodb",
        "mongodb+srv",
        "redis",
        "redis+cluster",
        "redis+sentinel",
        "redis+unix",
        "rediss",
        "etcd",
        "async+memory",
        "async+redis",
        "async+rediss",
        "async+redis+unix",
        "async+redis+cluster",
        "async+redis+sentinel",
        "async+memcached",
        "async+mongodb",
        "async+mongodb+srv",
        "async+etcd",
    }
)

#: The accepted schemes that keep their counters inside this process, so
#: each process counts separately and the counters end with it.
IN_PROCESS_RATE_LIMIT_SCHEMES = frozenset(
    {BOUNDED_MEMORY_SCHEME, "memory", "async+memory"}
)

#: Rate-limit storage schemes whose counters are shared by every process
#: that addresses them. A scheme outside this set keeps its counters in
#: the memory of one process.
SHARED_RATE_LIMIT_STORAGE_SCHEMES = frozenset(
    scheme
    for scheme in RATE_LIMIT_STORAGE_SCHEMES
    if scheme not in IN_PROCESS_RATE_LIMIT_SCHEMES
)

#: The in-process schemes whose number of tracked keys has no ceiling.
#: :data:`BOUNDED_MEMORY_SCHEME` is absent:
#: :mod:`backend.app.core.rate_limit` caps it at
#: ``Settings.RATE_LIMIT_MAX_TRACKED_KEYS``.
UNBOUNDED_RATE_LIMIT_STORAGE_SCHEMES = frozenset(
    scheme
    for scheme in IN_PROCESS_RATE_LIMIT_SCHEMES
    if scheme != BOUNDED_MEMORY_SCHEME
)

#: Rate-limit storage schemes accepted outside :data:`LOCAL_ENVIRONMENT`:
#: the shared schemes only. Every scheme in
#: :data:`IN_PROCESS_RATE_LIMIT_SCHEMES` is absent, so a deployment
#: running more than one process cannot configure counters that each of
#: its processes holds separately.
DEPLOYABLE_RATE_LIMIT_STORAGE_SCHEMES = frozenset(
    SHARED_RATE_LIMIT_STORAGE_SCHEMES
)

#: Largest value ``Settings.MAX_PAGINATION_OFFSET`` may be set to. An
#: offset above it is refused by settings validation.
MAX_PAGINATION_OFFSET_CEILING = 1000000

#: Row offset applied to ``Settings.MAX_PAGINATION_OFFSET`` when the
#: environment names none.
DEFAULT_MAX_PAGINATION_OFFSET = 10000

#: Smallest accepted length of the token signing key, in UTF-8 bytes.
MIN_SIGNING_KEY_BYTES = 32

#: Smallest accepted signing-key length for each accepted algorithm, in
#: UTF-8 bytes. Each value equals the algorithm's hash output size, which
#: RFC 7518 section 3.2 requires an HMAC key to match or exceed. The
#: floor applied to a configuration is the largest value among the
#: algorithms it names.
MIN_SIGNING_KEY_BYTES_BY_ALGORITHM: Mapping[str, int] = MappingProxyType(
    {
        "HS256": 32,
        "HS384": 48,
        "HS512": 64,
    }
)

#: Smallest accepted number of distinct characters in a signing key.
MIN_SIGNING_KEY_DISTINCT_CHARS = 12

#: Settings carrying a provider credential that is registered for
#: redaction by the module that reads it. Each value passes through
#: :func:`backend.app.core.logging.register_secret_values`.
PROVIDER_SECRET_SETTINGS = (
    "PAYPAL_CLIENT_SECRET",
    "PAYPAL_WEBHOOK_ID",
    "SENDGRID_API_KEY",
    "ZILLOW_API_KEY",
)

#: Smallest accepted length of a setting named by
#: :data:`PROVIDER_SECRET_SETTINGS`, in characters. It equals
#: ``backend.app.core.logging.MIN_SECRET_VALUE_LENGTH``, the shortest
#: value that module's registry accepts, so every accepted value here is
#: a value the registry holds and replaces.
MIN_PROVIDER_SECRET_LENGTH = 8

#: Longest accepted run of one repeated character in a signing key.
MAX_SIGNING_KEY_REPEAT_RUN = 3

#: Longest accepted run of consecutive code points in a signing key,
#: ascending or descending.
MAX_SIGNING_KEY_SEQUENCE_RUN = 4

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
# captured, and each is measured numerically.
_RATE_LIMIT_PATTERN = re.compile(
    r"^(?P<count>\d+)\s*(?:/|\s+per\s+)\s*(?:(?P<multiple>\d+)\s*)?"
    r"(?:second|minute|hour|day|month|year)s?$",
    re.IGNORECASE,
)


def _parse_delimited_list(value: Any) -> Any:
    """Return a list for a JSON array or comma-separated string value.

    Applies to both the environment and the keyword-argument path. A
    value that is not a string is returned unchanged. Empty
    comma-separated segments are preserved, and the field validators
    refuse them.
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


def _rate_limit_storage_scheme(value: str) -> str:
    """Return the scheme of a rate-limit storage URI, in lower case."""
    return value.strip().split("://", 1)[0].strip().lower()


def required_signing_key_bytes(algorithms: Any) -> int:
    """Return the signing-key length ``algorithms`` requires, in bytes.

    The result is the largest per-algorithm floor among the named
    algorithms, and never less than :data:`MIN_SIGNING_KEY_BYTES`. An
    algorithm carrying no declared floor contributes only that global
    minimum, and a value that is not an iterable of names returns it
    unchanged.
    """
    floor = MIN_SIGNING_KEY_BYTES
    if not isinstance(algorithms, (list, tuple, set, frozenset)):
        return floor
    for entry in algorithms:
        if not isinstance(entry, str):
            continue
        required = MIN_SIGNING_KEY_BYTES_BY_ALGORITHM.get(
            entry.strip().upper()
        )
        if required is not None and required > floor:
            floor = required
    return floor


def _longest_repeat_run(value: str) -> int:
    """Return the length of the longest run of one repeated character."""
    longest = 0
    run = 0
    previous = None
    for char in value:
        run = run + 1 if char == previous else 1
        previous = char
        if run > longest:
            longest = run
    return longest


def _longest_sequence_run(value: str) -> int:
    """Return the longest run of consecutive code points in ``value``.

    A run counts characters whose code points step by exactly one in a
    single direction, so both ``abcd`` and ``4321`` are runs of four.
    """
    longest = 0
    run = 1
    step = 0
    for index in range(1, len(value)):
        delta = ord(value[index]) - ord(value[index - 1])
        if delta in (1, -1) and (step == 0 or delta == step):
            step = delta
            run += 1
        else:
            step = delta if delta in (1, -1) else 0
            run = 2 if step else 1
        if run > longest:
            longest = run
    return max(longest, 1 if value else 0)


def rate_limit_storage_scheme(uri: Any) -> str:
    """Return the storage scheme ``uri`` names, in lower case.

    Returns an empty string for a value that is not a string or that
    carries no scheme.
    """
    if not isinstance(uri, str):
        return ""
    try:
        return urlsplit(uri.strip()).scheme.strip().lower()
    except ValueError:
        return ""


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


def _configured_env_file() -> Optional[str]:
    """Return the environment file to read, or ``None`` to read none.

    :data:`DEFAULT_ENV_FILE` is returned when
    :data:`ENV_FILE_VARIABLE` is absent from the process environment,
    and ``None`` when it is present and names nothing. A process that
    supplies every setting itself therefore reads no file.

    The default is an absolute path under :data:`REPOSITORY_ROOT`, so the
    file a process reads does not depend on the directory it was started
    in. A value supplied through :data:`ENV_FILE_VARIABLE` is used as
    given, so a relative one is still resolved against that directory.
    """
    declared = os.environ.get(ENV_FILE_VARIABLE)
    if declared is None:
        return DEFAULT_ENV_FILE
    trimmed = declared.strip()
    return trimmed or None


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
    MAX_REQUEST_BODY_CHUNKS: int = Field(2048, ge=1, le=1048576)
    MAX_PAGE_SIZE: int = Field(100, ge=1, le=1000)
    MAX_PAGINATION_OFFSET: int = Field(
        DEFAULT_MAX_PAGINATION_OFFSET,
        ge=0,
        le=MAX_PAGINATION_OFFSET_CEILING,
    )
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_REGISTER: str = "3/minute"
    RATE_LIMIT_WEBHOOK: str = "60/minute"
    RATE_LIMIT_STORAGE_URI: str = BOUNDED_MEMORY_SCHEME + "://"
    RATE_LIMIT_MAX_TRACKED_KEYS: int = Field(4096, ge=64, le=1048576)

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
    PAYPAL_MAX_CONNECTIONS: int = Field(20, ge=1, le=1000)
    PAYPAL_RETURN_URL: str = (
        "http://localhost:3000/subscription?paypal=return"
    )
    PAYPAL_CANCEL_URL: str = (
        "http://localhost:3000/subscription?paypal=cancel"
    )

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

    @validator(*PROVIDER_SECRET_SETTINGS)
    def _check_provider_secret_length(cls, value: str) -> str:
        """Return the credential, refusing one too short to redact.

        A value shorter than :data:`MIN_PROVIDER_SECRET_LENGTH` is
        refused, because the redaction registry accepts no shorter value
        and would hold no entry for it.
        """
        if len(value) < MIN_PROVIDER_SECRET_LENGTH:
            raise ValueError(
                "must be at least "
                f"{MIN_PROVIDER_SECRET_LENGTH} characters long so it can"
                " be redacted from every log record"
            )
        return value

    @validator("SECRET_KEY")
    def _check_signing_key(cls, value: str) -> str:
        """Return the canonical signing key, refusing a weak key.

        The value is refused when it is blank once stripped, when it
        carries surrounding whitespace, when its canonical form measures
        fewer than :data:`MIN_SIGNING_KEY_BYTES` UTF-8 bytes, when it
        matches the rejected-value set or opens with a placeholder
        marker, and when it carries too little variety: fewer than
        :data:`MIN_SIGNING_KEY_DISTINCT_CHARS` distinct characters, a
        repeated character run longer than
        :data:`MAX_SIGNING_KEY_REPEAT_RUN`, or a consecutive code-point
        run longer than :data:`MAX_SIGNING_KEY_SEQUENCE_RUN`.

        The length floor applied here is the one that holds whatever
        algorithms are configured. The algorithm-specific floor is
        applied by :meth:`_check_signing_key_strength`, which runs once
        both this field and ``JWT_ALGORITHMS`` have been validated.

        The returned value is the canonical form, and the placeholder
        comparison ignores letter case.
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
        if len(set(candidate)) < MIN_SIGNING_KEY_DISTINCT_CHARS:
            raise ValueError(
                "must carry at least "
                f"{MIN_SIGNING_KEY_DISTINCT_CHARS} distinct characters"
            )
        if _longest_repeat_run(candidate) > MAX_SIGNING_KEY_REPEAT_RUN:
            raise ValueError(
                "must not repeat one character more than "
                f"{MAX_SIGNING_KEY_REPEAT_RUN} times in a row"
            )
        if (
            _longest_sequence_run(candidate)
            > MAX_SIGNING_KEY_SEQUENCE_RUN
        ):
            raise ValueError(
                "must not carry a run of more than "
                f"{MAX_SIGNING_KEY_SEQUENCE_RUN} consecutive characters"
            )
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

    @validator("RATE_LIMIT_STORAGE_URI")
    def _check_rate_limit_storage(cls, value: str) -> str:
        """Return the rate-limit storage URI, refusing an unknown scheme.

        The value must be a ``<scheme>://`` URI whose scheme appears in
        :data:`RATE_LIMIT_STORAGE_SCHEMES`. A scheme outside
        :data:`SHARED_RATE_LIMIT_STORAGE_SCHEMES` keeps its counters in
        one process, which :meth:`_check_rate_limit_sharing` refuses
        outside :data:`LOCAL_ENVIRONMENT`.
        """
        candidate = value.strip()
        if not candidate:
            raise ValueError("must not be empty")
        if "://" not in candidate:
            raise ValueError("must be a <scheme>:// URI")
        scheme = _rate_limit_storage_scheme(candidate)
        if scheme not in RATE_LIMIT_STORAGE_SCHEMES:
            raise ValueError(
                f"must name one of {sorted(RATE_LIMIT_STORAGE_SCHEMES)}"
            )
        return candidate

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

    @validator("PAYPAL_RETURN_URL", "PAYPAL_CANCEL_URL")
    def _check_paypal_callback_url(
        cls, value: str, values: Dict[str, Any]
    ) -> str:
        """Return one payer-callback address in canonical form.

        The value must be one complete
        ``<scheme>://<host>[:<port>][/<path>][?<query>]`` address whose
        scheme appears in :data:`_ORIGIN_SCHEMES`, carrying no wildcard,
        fragment or user information. A query string is carried through,
        which is what lets both addresses name the single subscription
        page the frontend router declares while staying distinguishable.
        Outside
        :data:`LOCAL_ENVIRONMENT` the scheme must be :data:`TLS_SCHEME`
        and the host must not address this host or a private network, so
        a plaintext or loopback payment callback cannot reach a deployed
        environment. A trailing slash is removed, and the scheme and host
        are returned in lower case with the port, path and query string as
        written.
        """
        candidate = value.strip().rstrip("/")
        if not candidate:
            raise ValueError("must not be empty")
        if "*" in candidate:
            raise ValueError("must not carry a wildcard host")
        parts = _split_url(candidate)
        scheme = parts.scheme.lower()
        if scheme not in _ORIGIN_SCHEMES:
            raise ValueError(
                "must carry a <scheme>://<host>[:<port>][/<path>] "
                f"address using one of {sorted(_ORIGIN_SCHEMES)}"
            )
        if parts.fragment:
            raise ValueError("must not carry a fragment")
        if parts.username or parts.password:
            raise ValueError("must not carry user information")
        host = _require_hostname(parts.hostname or "")
        if values.get("ENVIRONMENT") != LOCAL_ENVIRONMENT:
            if scheme != TLS_SCHEME:
                raise ValueError(
                    f"must use the {TLS_SCHEME} scheme unless "
                    f"ENVIRONMENT is {LOCAL_ENVIRONMENT}"
                )
            if _is_internal_host(host):
                raise ValueError(
                    "must not address this host or a private network "
                    f"unless ENVIRONMENT is {LOCAL_ENVIRONMENT}"
                )
        query = f"?{parts.query}" if parts.query else ""
        return f"{scheme}://{parts.netloc.lower()}{parts.path}{query}"

    @validator("PAYPAL_CANCEL_URL")
    def _check_paypal_cancel_url_is_distinct(
        cls, value: str, values: Dict[str, Any]
    ) -> str:
        """Refuse a cancel address equal to the return address.

        The two values are handed to PayPal as the separate addresses an
        approving and an abandoning payer are returned to, and an equal
        pair is rejected.
        """
        if value == values.get("PAYPAL_RETURN_URL"):
            raise ValueError(
                "must differ from PAYPAL_RETURN_URL"
            )
        return value

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

    @validator(
        "RATE_LIMIT_LOGIN", "RATE_LIMIT_REGISTER", "RATE_LIMIT_WEBHOOK"
    )
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

    @validator("RATE_LIMIT_STORAGE_URI")
    def _check_rate_limit_storage_uri(cls, value: str) -> str:
        """Return the rate-limit storage URI, refusing an unusable one.

        The scheme must appear in :data:`RATE_LIMIT_STORAGE_SCHEMES`. A
        scheme outside :data:`IN_PROCESS_RATE_LIMIT_SCHEMES` addresses a
        separate store and must therefore carry that store's address.
        """
        candidate = value.strip()
        if not candidate:
            raise ValueError("must not be empty")
        scheme = rate_limit_storage_scheme(candidate)
        if scheme not in RATE_LIMIT_STORAGE_SCHEMES:
            raise ValueError(
                f"must name one of {sorted(RATE_LIMIT_STORAGE_SCHEMES)}"
            )
        if scheme in IN_PROCESS_RATE_LIMIT_SCHEMES:
            return candidate
        parts = _split_url(candidate)
        if not (parts.netloc or parts.path.strip("/")):
            raise ValueError(
                f"must carry the address of the {scheme} store"
            )
        return candidate

    @root_validator(skip_on_failure=True)
    def _check_rate_limit_sharing(
        cls, values: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Require shared rate-limit storage outside local runs.

        Outside :data:`LOCAL_ENVIRONMENT` the scheme must appear in
        :data:`DEPLOYABLE_RATE_LIMIT_STORAGE_SCHEMES`, which holds the
        shared schemes only. Every scheme in
        :data:`IN_PROCESS_RATE_LIMIT_SCHEMES` is refused there, including
        :data:`BOUNDED_MEMORY_SCHEME`: counters held inside one process
        admit each configured limit once per process and are discarded
        when that process ends.

        ``ENVIRONMENT`` set to :data:`LOCAL_ENVIRONMENT` accepts an
        in-process scheme, and
        :func:`backend.app.core.rate_limit.build_limiter` records one
        line naming this setting, the scheme and the environment whenever
        the configured store counts inside a single process.
        """
        uri = values.get("RATE_LIMIT_STORAGE_URI")
        if not isinstance(uri, str):
            return values
        if values.get("ENVIRONMENT") == LOCAL_ENVIRONMENT:
            return values
        if _rate_limit_storage_scheme(uri) not in (
            DEPLOYABLE_RATE_LIMIT_STORAGE_SCHEMES
        ):
            raise ValueError(
                "RATE_LIMIT_STORAGE_URI must name storage shared by "
                "every process, one of "
                f"{sorted(DEPLOYABLE_RATE_LIMIT_STORAGE_SCHEMES)}, "
                f"unless ENVIRONMENT is {LOCAL_ENVIRONMENT}"
            )
        return values

    @root_validator(skip_on_failure=True)
    def _check_signing_key_strength(
        cls, values: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Refuse a signing key too short for the configured algorithms.

        The floor is the largest entry of
        :data:`MIN_SIGNING_KEY_BYTES_BY_ALGORITHM` among the algorithms
        ``JWT_ALGORITHMS`` names, as returned by
        :func:`required_signing_key_bytes`. A configuration naming
        ``HS384`` therefore requires 48 UTF-8 bytes and one naming
        ``HS512`` requires 64, while ``HS256`` alone keeps the
        32-byte floor :meth:`_check_signing_key` already applied.
        """
        key = values.get("SECRET_KEY")
        algorithms = values.get("JWT_ALGORITHMS")
        if not isinstance(key, str) or algorithms is None:
            return values
        required = required_signing_key_bytes(algorithms)
        measured = len(key.encode("utf-8"))
        if measured < required:
            raise ValueError(
                f"SECRET_KEY must be at least {required} UTF-8 bytes "
                f"long for JWT_ALGORITHMS {sorted(algorithms)}, and "
                f"measures {measured}"
            )
        return values

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
        env_file = _configured_env_file()
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
