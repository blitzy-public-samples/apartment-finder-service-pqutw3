"""Structured JSON logging with credential redaction.

This module is the application's single logging entry point. It emits one
JSON object per record on standard output and rewrites credential-shaped
substrings to a fixed placeholder before a record leaves the process.

Redaction covers ``key``, ``token``, ``secret`` and ``password`` style
names -- including compound spellings such as ``api_key``, ``apikey``,
``access_token``, ``refresh_token``, ``client_secret``, ``passwd`` and
``pwd`` -- in the following shapes:

* ``k=v`` and ``k: v`` assignments, quoted or bare, as they appear in
  query strings and in free text
* ``"k": "v"`` and ``'k': 'v'`` JSON and dict mappings
* ``Authorization: Bearer <credential>`` headers and bare
  ``Bearer <credential>`` values
* ``scheme://user:<credential>@host`` URL user information

Both the log message and the formatted exception traceback are covered,
as are values nested inside fields supplied through ``extra={...}``.
Every field passed through ``extra={...}`` is emitted under the
``context`` key of the JSON object.

Redaction runs twice. Every part of a record -- message, interpolated
arguments, formatted exception text and each ``extra`` value, walked
recursively through mappings and sequences -- is rewritten before the
JSON payload is serialised, and the serialised payload is rewritten once
more before it leaves the process. A credential-shaped key name is
matched after percent-decoding, and a mapping is matched whether its
quotes are plain or backslash-escaped.

The handler is installed on the ``backend`` logger and, at WARNING, on
the third-party ``python_http_client`` and ``sendgrid`` loggers, whose
records carry outbound request headers and bodies. Propagation is
disabled on each, so no record reaches a handler installed elsewhere.
Discovery and installation run under a lock, and a handler found under
the reserved name whose type, formatter, filter or stream does not match
is replaced.

The module uses only the Python standard library and reads no
configuration and no environment variable.

Usage::

    configure_logging()
    logger = get_logger(__name__)
    logger.info("listing refresh finished", extra={"count": 12})
    logger.exception("listing refresh failed")
"""

import json
import logging
import re
import sys
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import unquote

__all__ = [
    "BASE_LOGGER_NAME",
    "CONTEXT_FIELD",
    "DEFAULT_LOG_LEVEL",
    "HANDLER_NAME",
    "REDACTION_PLACEHOLDER",
    "THIRD_PARTY_LOGGER_NAMES",
    "THIRD_PARTY_LOG_LEVEL",
    "RedactingFilter",
    "RedactingJsonFormatter",
    "configure_logging",
    "get_logger",
    "redact",
    "redact_structure",
]

#: Name of the logger that owns the redacting handler.
BASE_LOGGER_NAME = "backend"

#: Name assigned to the installed handler.
HANDLER_NAME = "redacting-json-stream"

#: Third-party logger namespaces placed under the redacting handler.
THIRD_PARTY_LOGGER_NAMES = ("python_http_client", "sendgrid")

#: Level applied to the third-party loggers named above.
THIRD_PARTY_LOG_LEVEL = logging.WARNING

#: JSON key that carries the fields supplied through ``extra={...}``.
CONTEXT_FIELD = "context"

#: Fixed marker substituted for every redacted value.
REDACTION_PLACEHOLDER = "[REDACTED]"

#: Level applied to the base logger when the handler is installed.
DEFAULT_LOG_LEVEL = logging.INFO

# Deepest level of nesting walked when redacting a structured value.
_MAX_REDACTION_DEPTH = 8

# Serialises handler discovery and installation across threads.
_CONFIGURE_LOCK = threading.RLock()

# Key-name fragments that mark a value as credential-shaped. Matching is
# case-insensitive and substring-based, and covers compound spellings
# such as "api_key", "access_token" and "client_secret".
_SENSITIVE_KEY_STEMS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "key",
    "credential",
    "authorization",
)

# HTTP authentication scheme words that introduce a credential.
_AUTH_SCHEMES = ("bearer", "basic", "digest", "token")

# Captured values that are emitted unchanged. Only an already
# substituted placeholder qualifies, so a value that happens to spell an
# authentication scheme word is still rewritten.
_SKIP_VALUES = frozenset((REDACTION_PLACEHOLDER.lower(),))

# Characters accepted inside a key name. The percent sign is accepted so
# a percent-encoded key name is captured and can be normalized before
# the sensitivity test.
_KEY_CHARS = r"[A-Za-z0-9_.\-%]"

# A key name that contains one of the stems literally, with bounded
# affixes on either side.
_SENSITIVE_KEY = (
    _KEY_CHARS + r"{0,32}?"
    r"(?:" + "|".join(_SENSITIVE_KEY_STEMS) + r")"
    + _KEY_CHARS + r"{0,32}"
)

# A key name carrying at least one percent escape. Such a key spells its
# stem in encoded form, so :func:`_is_sensitive_key` decides it after
# decoding rather than the pattern deciding it by shape.
_ENCODED_KEY = _KEY_CHARS + r"{0,64}%" + _KEY_CHARS + r"{0,64}"

# Largest number of percent-decoding passes applied to a key name.
_MAX_KEY_DECODE_PASSES = 3

# Characters removed from a key name before the stem test.
_KEY_NOISE_RE = re.compile(r"[^a-z0-9]+")

# Characters accepted inside an unquoted value. The class stops at
# separators, at brackets, at quotes and at a backslash. A value
# embedded in an escaped JSON string terminates at the escape sequence,
# and an already substituted placeholder is not matched again.
_BARE_VALUE = r"[^\s\"'&,;)\[\]}\\<>#]+"

# "Authorization: Bearer <credential>", '"authorization": "<credential>"'
# and "authorization=<credential>".
_AUTH_HEADER_RE = re.compile(
    r"(?P<key>authorization)"
    r"(?P<sep>[\"']?\s*[:=]\s*)"
    r"(?P<open>[\"']?)"
    r"(?P<scheme>(?:" + "|".join(_AUTH_SCHEMES) + r")\s+)?"
    r"(?P<value>" + _BARE_VALUE + r")",
    re.IGNORECASE,
)

# A scheme word followed by a credential, without a header name.
_BEARER_RE = re.compile(
    r"(?P<scheme>\b(?:bearer|basic|digest)\s+)"
    r"(?P<value>[A-Za-z0-9\-._~+/]+=*)",
    re.IGNORECASE,
)

# A credential embedded in the user information of a URL.
_URL_CREDENTIAL_RE = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]{0,31}://)"
    r"(?P<user>[^\s:/@\"']{1,128}:)"
    r"(?P<value>[^\s@/\"']{1,256})"
    r"(?P<at>@)",
)


def _mapping_pattern(key_pattern: str) -> "re.Pattern":
    """Builds the '"key": "value"' mapping pattern for a key shape.

    Each quote may be preceded by a backslash, so a mapping nested
    inside an already serialised JSON string is matched as well.
    """
    return re.compile(
        r"(?P<kopen>\\?[\"'])(?P<key>" + key_pattern + r")"
        r"(?P<kclose>\\?[\"'])"
        r"(?P<sep>\s*:\s*)"
        r"(?:(?P<vopen>\\?[\"'])(?P<qval>(?:\\.|[^\"'\\]){0,4096})"
        r"(?P<vclose>\\?[\"'])"
        r"|(?P<bare>[^\s,}\[\]]+))",
        re.IGNORECASE,
    )


def _assignment_pattern(key_pattern: str) -> "re.Pattern":
    """Builds the "key=value" / "key: value" pattern for a key shape."""
    return re.compile(
        r"(?<!" + _KEY_CHARS + r")"
        r"(?P<key>" + key_pattern + r")"
        r"(?P<sep>\s*[:=]\s*)"
        r"(?:\"(?P<dq>[^\"]*)\""
        r"|'(?P<sq>[^']*)'"
        r"|(?P<bare>" + _BARE_VALUE + r"))",
        re.IGNORECASE,
    )


# Mappings and assignments whose key spells a stem literally.
_MAPPING_RE = _mapping_pattern(_SENSITIVE_KEY)
_ASSIGNMENT_RE = _assignment_pattern(_SENSITIVE_KEY)

# Mappings and assignments whose key spells a stem in percent-encoded
# form.
_ENCODED_MAPPING_RE = _mapping_pattern(_ENCODED_KEY)
_ENCODED_ASSIGNMENT_RE = _assignment_pattern(_ENCODED_KEY)

# Value groups in match order, paired with the quote character that
# surrounds the replacement.
_VALUE_GROUPS = (("dq", '"'), ("sq", "'"), ("bare", ""))


def _normalize_key(key: str) -> str:
    """Returns a key name reduced to lower-case letters and digits.

    Percent-encoding is decoded repeatedly, up to
    :data:`_MAX_KEY_DECODE_PASSES` passes, so ``api%5Fkey`` and a fully
    encoded spelling both reduce to the same form as ``api_key``.
    """
    candidate = key
    for _ in range(_MAX_KEY_DECODE_PASSES):
        if "%" not in candidate:
            break
        try:
            decoded = unquote(candidate, errors="strict")
        except Exception:
            break
        if decoded == candidate:
            break
        candidate = decoded
    return _KEY_NOISE_RE.sub("", candidate.lower())


def _is_sensitive_key(key: str) -> bool:
    """Reports whether a key name marks its value as a credential."""
    normalized = _normalize_key(key)
    if not normalized:
        return False
    return any(stem in normalized for stem in _SENSITIVE_KEY_STEMS)


def _is_skipped_value(value: str) -> bool:
    """Reports whether a captured value is emitted unchanged."""
    return value.strip().lower() in _SKIP_VALUES


def _replace_url_credential(match: "re.Match") -> str:
    """Replaces the credential in the user information of a URL."""
    value = match.group("value")
    if not value or _is_skipped_value(value):
        return match.group(0)
    return "{0}{1}{2}{3}".format(
        match.group("scheme"),
        match.group("user"),
        REDACTION_PLACEHOLDER,
        match.group("at"),
    )


def _replace_auth_header(match: "re.Match") -> str:
    """Replaces the credential of an ``Authorization`` key/value pair.

    The scheme word is replaced together with the credential, so the
    substituted text carries no value the later assignment rule would
    match again.
    """
    value = match.group("value")
    if not value or _is_skipped_value(value):
        return match.group(0)
    return "{0}{1}{2}{3}".format(
        match.group("key"),
        match.group("sep"),
        match.group("open"),
        REDACTION_PLACEHOLDER,
    )


def _replace_bearer(match: "re.Match") -> str:
    """Replaces the credential that follows an authentication scheme."""
    value = match.group("value")
    if not value or _is_skipped_value(value):
        return match.group(0)
    return match.group("scheme") + REDACTION_PLACEHOLDER


def _replace_mapping(match: "re.Match") -> str:
    """Replaces the value of a quoted-key JSON or dict mapping."""
    key = match.group("key")
    if not _is_sensitive_key(key):
        return match.group(0)
    prefix = "{0}{1}{2}{3}".format(
        match.group("kopen"),
        key,
        match.group("kclose"),
        match.group("sep"),
    )
    quoted = match.group("qval")
    if quoted is not None:
        if not quoted or _is_skipped_value(quoted):
            return match.group(0)
        return "{0}{1}{2}{3}".format(
            prefix,
            match.group("vopen"),
            REDACTION_PLACEHOLDER,
            match.group("vclose"),
        )
    bare = match.group("bare")
    if not bare or _is_skipped_value(bare):
        return match.group(0)
    return prefix + REDACTION_PLACEHOLDER


def _replace_assignment(match: "re.Match") -> str:
    """Replaces the value of an unquoted-key assignment."""
    key = match.group("key")
    if not _is_sensitive_key(key):
        return match.group(0)
    for group, quote in _VALUE_GROUPS:
        value = match.group(group)
        if value is None:
            continue
        if not value or _is_skipped_value(value):
            return match.group(0)
        return "{0}{1}{2}{3}{2}".format(
            key,
            match.group("sep"),
            quote,
            REDACTION_PLACEHOLDER,
        )
    return match.group(0)


# Redaction rules in application order. Each pattern is compiled once at
# module import.
_REDACTION_RULES: Tuple[Tuple[Any, Callable[[Any], str]], ...] = (
    (_AUTH_HEADER_RE, _replace_auth_header),
    (_BEARER_RE, _replace_bearer),
    (_URL_CREDENTIAL_RE, _replace_url_credential),
    (_MAPPING_RE, _replace_mapping),
    (_ENCODED_MAPPING_RE, _replace_mapping),
    (_ASSIGNMENT_RE, _replace_assignment),
    (_ENCODED_ASSIGNMENT_RE, _replace_assignment),
)


def redact(text: Any) -> str:
    """Returns ``text`` with credential-shaped values replaced.

    The key name is preserved and only the value is substituted. A
    non-string input is rendered with :func:`str` first. Any failure
    during redaction yields the placeholder in place of the whole input.
    """
    try:
        rendered = text if isinstance(text, str) else str(text)
        if not rendered:
            return rendered
        for pattern, replacement in _REDACTION_RULES:
            rendered = pattern.sub(replacement, rendered)
        return rendered
    except Exception:
        return REDACTION_PLACEHOLDER


def _redact_value(value: Any) -> Any:
    """Redacts string values and returns every other value unchanged."""
    if isinstance(value, str):
        return redact(value)
    return value


def _redact_deep(value: Any, depth: int = 0, seen: Any = None) -> Any:
    """Returns ``value`` with every nested credential replaced.

    Strings are rewritten by :func:`redact` and byte strings are replaced
    outright. Mappings and sequences are walked, and a mapping entry
    whose key is credential-shaped has its whole value replaced by the
    placeholder whatever that value's type is. Recursion stops at
    :data:`_MAX_REDACTION_DEPTH`, past which a value is rendered with
    :func:`str` and rewritten as text, and a container already visited on
    the current path is not descended into again. A value of any other
    type is returned unchanged, keeping the record's own formatting
    intact; the pass over the serialised payload covers it.
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, (bytes, bytearray)):
        return REDACTION_PLACEHOLDER
    if depth >= _MAX_REDACTION_DEPTH:
        return redact(value)
    if isinstance(value, (dict, list, tuple, set, frozenset)):
        visited = set() if seen is None else seen
        marker = id(value)
        if marker in visited:
            return REDACTION_PLACEHOLDER
        visited = visited | {marker}
    else:
        visited = seen
    if isinstance(value, dict):
        redacted: Dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and _is_sensitive_key(key):
                redacted[key] = REDACTION_PLACEHOLDER
            else:
                redacted[key] = _redact_deep(item, depth + 1, visited)
        return redacted
    if isinstance(value, (list, tuple, set, frozenset)):
        members = [
            _redact_deep(item, depth + 1, visited) for item in value
        ]
        try:
            return type(value)(members)
        except Exception:
            return members
    return value


def redact_structure(value: Any) -> Any:
    """Returns ``value`` with credential-shaped entries replaced.

    Any failure while walking yields the placeholder in place of the
    offending value, so a record can never fail to be redacted.
    """
    try:
        return _redact_deep(value)
    except Exception:
        return REDACTION_PLACEHOLDER


def _redact_args(args: Any) -> Any:
    """Redacts the members of a log record's argument set.

    A mapping argument set -- the form ``%(name)s`` interpolation uses --
    is redacted by key as well as by value, so a credential named by its
    key is replaced before interpolation renders it into the message.
    """
    if isinstance(args, dict):
        return {
            key: (
                REDACTION_PLACEHOLDER
                if isinstance(key, str) and _is_sensitive_key(key)
                else _redact_deep(item)
            )
            for key, item in args.items()
        }
    if isinstance(args, tuple):
        return tuple(_redact_deep(item) for item in args)
    return _redact_deep(args)


def _redact_format(template: str, has_args: bool) -> str:
    """Redacts a message template, keeping its conversion specifiers.

    A template whose specifier count changes under redaction is returned
    unchanged; the rendered record is redacted by the formatter.
    """
    rewritten = redact(template)
    if has_args and rewritten.count("%") != template.count("%"):
        return template
    return rewritten


class RedactingFilter(logging.Filter):
    """Scrubs credential-shaped values from a record's message and args.

    The filter rewrites ``record.msg`` and ``record.args`` in place and
    always admits the record. A failure while scrubbing replaces the
    message with the placeholder and drops the arguments.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Rewrites the record in place and admits it."""
        try:
            if record.msg is not None:
                template = record.msg
                if not isinstance(template, str):
                    template = str(template)
                record.msg = _redact_format(template, bool(record.args))
            if record.args:
                record.args = _redact_args(record.args)
        except Exception:
            record.msg = REDACTION_PLACEHOLDER
            record.args = None
        return True


# Attributes the logging module itself places on a record. Every other
# attribute originates from an ``extra={...}`` mapping.
_RESERVED_RECORD_ATTRS = frozenset(
    (
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    )
)


def _extract_context(record: logging.LogRecord) -> Dict[str, Any]:
    """Collects the redacted fields supplied through ``extra={...}``.

    A field whose name is credential-shaped is replaced outright; every
    other field is walked by :func:`_redact_deep`.
    """
    context: Dict[str, Any] = {}
    for name, value in vars(record).items():
        if name in _RESERVED_RECORD_ATTRS or name.startswith("_"):
            continue
        if _is_sensitive_key(name):
            context[name] = REDACTION_PLACEHOLDER
        else:
            context[name] = _redact_deep(value)
    return context


class RedactingJsonFormatter(logging.Formatter):
    """Renders a record as a single redacted JSON object.

    The base implementation renders the message, the interpolated
    arguments and the exception traceback. Every part of that rendered
    text, and every ``extra`` field, is redacted before the JSON payload
    is serialised, and the redaction patterns are applied once more to
    the serialised payload.
    """

    def formatTime(
        self,
        record: logging.LogRecord,
        datefmt: Optional[str] = None,
    ) -> str:
        """Returns the creation time as an ISO-8601 UTC string."""
        moment = datetime.fromtimestamp(record.created, tz=timezone.utc)
        if datefmt:
            return moment.strftime(datefmt)
        return moment.isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )

    def _build_payload(
        self,
        record: logging.LogRecord,
        rendered: str,
    ) -> Dict[str, Any]:
        """Assembles the redacted JSON payload for a rendered record.

        The message and the exception detail are redacted here, before
        serialisation, so a credential embedded in exception text cannot
        reach the payload with its quotes escaped.
        """
        message = record.getMessage()
        if rendered.startswith(message):
            detail = rendered[len(message):].strip("\n")
        else:
            detail = "" if rendered == message else rendered
        payload: Dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(message),
        }
        if detail:
            payload["exception"] = redact(detail)
        context = _extract_context(record)
        if context:
            payload[CONTEXT_FIELD] = context
        return payload

    def _fallback(self, record: logging.LogRecord) -> str:
        """Serialises a minimal payload for an unrenderable record."""
        return json.dumps(
            {
                "level": str(getattr(record, "levelname", "ERROR")),
                "logger": str(getattr(record, "name", BASE_LOGGER_NAME)),
                "message": REDACTION_PLACEHOLDER,
            }
        )

    def format(self, record: logging.LogRecord) -> str:
        """Returns the record as one redacted JSON line."""
        try:
            rendered = super().format(record)
            serialized = json.dumps(
                self._build_payload(record, rendered),
                default=str,
                ensure_ascii=False,
            )
        except Exception:
            try:
                serialized = self._fallback(record)
            except Exception:
                serialized = "{}"
        return redact(serialized)


def _find_named_handlers(logger: logging.Logger) -> List[logging.Handler]:
    """Returns every handler on ``logger`` carrying the reserved name."""
    return [
        handler
        for handler in list(logger.handlers)
        if getattr(handler, "name", None) == HANDLER_NAME
    ]


def _is_redacting_handler(handler: Any) -> bool:
    """Reports whether ``handler`` is configured as this module builds it.

    A handler is accepted only when it is a stream handler carrying an
    open stream, a :class:`RedactingJsonFormatter` and a
    :class:`RedactingFilter`. Anything else occupying the reserved name is
    treated as foreign.
    """
    if not isinstance(handler, logging.StreamHandler):
        return False
    if not isinstance(handler.formatter, RedactingJsonFormatter):
        return False
    if not any(
        isinstance(entry, RedactingFilter) for entry in handler.filters
    ):
        return False
    stream = getattr(handler, "stream", None)
    if stream is None or getattr(stream, "closed", False):
        return False
    return True


def _resolve_level(level: Optional[Union[int, str]]) -> int:
    """Converts a level name or number to a logging level number."""
    if level is None or isinstance(level, bool):
        return DEFAULT_LOG_LEVEL
    if isinstance(level, int):
        return level
    resolved = logging.getLevelName(str(level).strip().upper())
    if isinstance(resolved, int):
        return resolved
    return DEFAULT_LOG_LEVEL


def _build_handler() -> logging.Handler:
    """Creates the redacting stream handler."""
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.set_name(HANDLER_NAME)
    handler.setFormatter(RedactingJsonFormatter())
    handler.addFilter(RedactingFilter())
    return handler


def _install_handler(logger: logging.Logger) -> bool:
    """Ensures ``logger`` carries exactly one valid redacting handler.

    Every handler under the reserved name is inspected. One that matches
    the expected configuration is kept and the rest are removed; a
    non-matching handler is removed and replaced. Returns ``True`` when a
    new handler was installed.
    """
    keep = None
    for handler in _find_named_handlers(logger):
        if keep is None and _is_redacting_handler(handler):
            keep = handler
        else:
            logger.removeHandler(handler)
    if keep is not None:
        return False
    logger.addHandler(_build_handler())
    return True


def _configure_third_party_loggers() -> None:
    """Routes the third-party namespaces through the redacting handler.

    Each logger named in :data:`THIRD_PARTY_LOGGER_NAMES` is held at
    :data:`THIRD_PARTY_LOG_LEVEL`, given the redacting handler and stopped
    from propagating, so its records cannot reach a handler installed
    elsewhere.
    """
    for name in THIRD_PARTY_LOGGER_NAMES:
        logger = logging.getLogger(name)
        _install_handler(logger)
        logger.setLevel(THIRD_PARTY_LOG_LEVEL)
        logger.propagate = False


def configure_logging(
    level: Optional[Union[int, str]] = None,
) -> logging.Logger:
    """Installs the redacting handler on the governed loggers.

    Discovery and installation are performed under a lock, so repeated or
    concurrent calls from different modules in one process leave exactly
    one handler per logger and produce no duplicated output. A handler
    found under the reserved name whose formatter, filter, type or stream
    does not match is replaced.

    Passing ``level`` sets the base logger's level; omitting it keeps the
    level already in effect, or applies :data:`DEFAULT_LOG_LEVEL` on the
    first call. The third-party loggers are always held at
    :data:`THIRD_PARTY_LOG_LEVEL`.

    Returns the base logger.
    """
    with _CONFIGURE_LOCK:
        logger = logging.getLogger(BASE_LOGGER_NAME)
        installed = _install_handler(logger)
        logger.propagate = False
        if installed or level is not None:
            logger.setLevel(_resolve_level(level))
        _configure_third_party_loggers()
        return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Returns a logger that routes through the redacting handler.

    Callers pass ``__name__``. A name outside the base logger's
    namespace is placed underneath it, and every returned logger
    resolves to a descendant of the base logger. Omitting ``name``
    returns the base logger.
    """
    configure_logging()
    if not name:
        return logging.getLogger(BASE_LOGGER_NAME)
    normalized = str(name).strip().strip(".")
    if not normalized or normalized == BASE_LOGGER_NAME:
        return logging.getLogger(BASE_LOGGER_NAME)
    if normalized.startswith(BASE_LOGGER_NAME + "."):
        return logging.getLogger(normalized)
    return logging.getLogger(BASE_LOGGER_NAME + "." + normalized)
