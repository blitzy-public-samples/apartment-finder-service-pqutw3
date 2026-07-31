from ipaddress import IPv6Address, ip_address
from pydantic import BaseSettings, Field, root_validator, validator
from typing import List, Optional
from urllib.parse import urlsplit

# SEC-03: the omitted scheme ports of a browser-serialized origin
_ORIGIN_DEFAULT_PORTS = {"http": 80, "https": 443}


# SEC-12: RFC 7518 sec. 3.2 key-length floor per HMAC-SHA2 algorithm, in
# UTF-8 bytes of SECRET_KEY
HMAC_KEY_MIN_BYTES = {"HS256": 32, "HS384": 48, "HS512": 64}

# SEC-03: origin syntax limits applied to every ALLOWED_ORIGINS entry
_ORIGIN_SCHEMES = ("http", "https")
_MAX_PORT = 65535
_MAX_HOSTNAME_LENGTH = 253
_MAX_LABEL_LENGTH = 63
_LABEL_CHARACTERS = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def _is_dns_name(host: str) -> bool:
    # SEC-03: per-label DNS syntax; a label must be non-empty, at most 63
    # characters of lowercase letters, digits or hyphen, and may not start or
    # end with a hyphen; the whole name is at most 253 characters
    if not host or len(host) > _MAX_HOSTNAME_LENGTH:
        return False
    for label in host.split("."):
        if not label or len(label) > _MAX_LABEL_LENGTH:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not set(label) <= _LABEL_CHARACTERS:
            return False
    return True


def _is_valid_host(host: str) -> bool:
    # SEC-03: accepts a bracketed IPv6 literal, an IPv4 literal or a
    # syntactically valid DNS name; rejects every other host form
    if host.startswith("[") and host.endswith("]"):
        try:
            return ip_address(host[1:-1]).version == 6
        except ValueError:
            return False
    try:
        return ip_address(host).version == 4
    except ValueError:
        return _is_dns_name(host)


def _split_authority(netloc: str):
    # SEC-03: separates host from port and rejects a malformed authority,
    # including an empty port, a stray colon and an unterminated IPv6 literal.
    # Returns (host, port_text) with port_text None when no port is present.
    if netloc.startswith("["):
        closing = netloc.find("]")
        if closing == -1:
            return None
        host, remainder = netloc[:closing + 1], netloc[closing + 1:]
        if remainder == "":
            return host, None
        if not remainder.startswith(":") or remainder == ":":
            return None
        return host, remainder[1:]
    if netloc.count(":") > 1:
        return None
    host, separator, port_text = netloc.partition(":")
    if separator == "":
        return host, None
    if port_text == "":
        return None
    return host, port_text


def _is_valid_origin(origin: str) -> bool:
    # SEC-03: accepts only the exact serialization a browser sends in an
    # Origin header - scheme://host[:port] over http or https, in printable
    # lowercase ASCII with no userinfo, wildcard, path, query or fragment -
    # and rejects every other spelling instead of repairing it
    if not origin.isascii():
        return False
    if any(c.isspace() or not c.isprintable() for c in origin):
        return False
    try:
        parts = urlsplit(origin)
    except ValueError:
        return False
    if parts.scheme not in _ORIGIN_SCHEMES:
        return False
    if parts.path or parts.query or parts.fragment:
        return False
    netloc = parts.netloc
    if netloc != netloc.lower() or "@" in netloc or "*" in netloc:
        return False
    if origin != f"{parts.scheme}://{netloc}":
        return False
    authority = _split_authority(netloc)
    if authority is None:
        return False
    host, port_text = authority
    try:
        # SEC-03: a non-numeric or out-of-range port raises here
        port = parts.port
    except ValueError:
        return False
    if port_text is not None:
        if not port_text.isdigit() or port is None:
            return False
        if not 1 <= port <= _MAX_PORT:
            return False
        # SEC-03: a browser omits the scheme default port, so an entry
        # carrying it can never match an Origin header
        if port == _ORIGIN_DEFAULT_PORTS[parts.scheme]:
            return False
    if not _is_valid_host(host):
        return False
    hostname = parts.hostname
    if not hostname or "%" in hostname:
        return False
    if host.startswith("["):
        # SEC-03: only the canonical IPv6 serialization is accepted
        try:
            serialized = "[{0}]".format(IPv6Address(hostname))
        except ValueError:
            return False
    else:
        serialized = hostname
    if port is not None:
        serialized = "{0}:{1}".format(serialized, port)
    return origin == "{0}://{1}".format(parts.scheme, serialized)


class Settings(BaseSettings):
    DATABASE_URL: str
    # SEC-12: 32-character floor on the HMAC signing key; the byte floor for
    # the configured ALGORITHM is applied by validate_secret_key_bytes
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
        # SEC-02/SEC-12: accepts only HMAC token-signing algorithms.
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
        # origin and any entry that is not a browser-serialized http or
        # https origin; closes CWE-942, CWE-346 and CWE-20 and keeps
        # matching exact-equality only.
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
            if not _is_valid_origin(origin):
                raise ValueError(
                    "ALLOWED_ORIGINS entries must be lowercase http or "
                    "https origins carrying a valid host and, when "
                    "present, a non-default port in 1-65535, with no "
                    "userinfo, path, query or fragment, "
                    f"got: {origin!r}"
                )
        return value

    @root_validator(skip_on_failure=True)
    def validate_secret_key_bytes(cls, values):
        # SEC-12: couples the SECRET_KEY byte floor to the configured
        # algorithm; HS384 and HS512 require 48 and 64 UTF-8 bytes
        # (RFC 7518 sec. 3.2).
        algorithm = values.get("ALGORITHM")
        secret_key = values.get("SECRET_KEY")
        minimum = HMAC_KEY_MIN_BYTES.get(algorithm)
        if minimum is None or secret_key is None:
            return values
        length = len(secret_key.encode("utf-8"))
        if length < minimum:
            raise ValueError(
                f"SECRET_KEY must be at least {minimum} UTF-8 bytes for "
                f"{algorithm}, got {length}"
            )
        return values

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()