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
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple, Union

__all__ = [
    "BASE_LOGGER_NAME",
    "CONTEXT_FIELD",
    "DEFAULT_LOG_LEVEL",
    "HANDLER_NAME",
    "REDACTION_PLACEHOLDER",
    "RedactingFilter",
    "RedactingJsonFormatter",
    "configure_logging",
    "get_logger",
    "redact",
]

#: Name of the logger that owns the redacting handler.
BASE_LOGGER_NAME = "backend"

#: Name assigned to the installed handler.
HANDLER_NAME = "redacting-json-stream"

#: JSON key that carries the fields supplied through ``extra={...}``.
CONTEXT_FIELD = "context"

#: Fixed marker substituted for every redacted value.
REDACTION_PLACEHOLDER = "[REDACTED]"

#: Level applied to the base logger when the handler is installed.
DEFAULT_LOG_LEVEL = logging.INFO

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

# Captured values that are emitted unchanged.
_SKIP_VALUES = frozenset(
    (REDACTION_PLACEHOLDER.lower(),) + _AUTH_SCHEMES[:-1]
)

# Characters accepted inside a key name.
_KEY_CHARS = r"[A-Za-z0-9_.\-]"

# A key name that contains one of the stems, with bounded affixes on
# either side. Only a key matching this fragment is rewritten.
_SENSITIVE_KEY = (
    _KEY_CHARS + r"{0,32}?"
    r"(?:" + "|".join(_SENSITIVE_KEY_STEMS) + r")"
    + _KEY_CHARS + r"{0,32}"
)

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

# '"key": "value"', "'key': 'value'" and '"key": value' mappings.
_MAPPING_RE = re.compile(
    r"(?P<kq>[\"'])(?P<key>" + _SENSITIVE_KEY + r")(?P=kq)"
    r"(?P<sep>\s*:\s*)"
    r"(?:\"(?P<dq>(?:[^\"\\]|\\.)*)\""
    r"|'(?P<sq>[^']*)'"
    r"|(?P<bare>[^\s,}\[\]]+))",
    re.IGNORECASE,
)

# "key=value" and "key: value" assignments with an unquoted key.
_ASSIGNMENT_RE = re.compile(
    r"(?<!" + _KEY_CHARS + r")"
    r"(?P<key>" + _SENSITIVE_KEY + r")"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?:\"(?P<dq>[^\"]*)\""
    r"|'(?P<sq>[^']*)'"
    r"|(?P<bare>" + _BARE_VALUE + r"))",
    re.IGNORECASE,
)

# Value groups in match order, paired with the quote character that
# surrounds the replacement.
_VALUE_GROUPS = (("dq", '"'), ("sq", "'"), ("bare", ""))


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
    """Replaces the credential of an ``Authorization`` key/value pair."""
    value = match.group("value")
    if not value or _is_skipped_value(value):
        return match.group(0)
    return "{0}{1}{2}{3}{4}".format(
        match.group("key"),
        match.group("sep"),
        match.group("open"),
        match.group("scheme") or "",
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
    key_quote = match.group("kq")
    for group, quote in _VALUE_GROUPS:
        value = match.group(group)
        if value is None:
            continue
        if not value or _is_skipped_value(value):
            return match.group(0)
        return "{0}{1}{0}{2}{3}{4}{3}".format(
            key_quote,
            key,
            match.group("sep"),
            quote,
            REDACTION_PLACEHOLDER,
        )
    return match.group(0)


def _replace_assignment(match: "re.Match") -> str:
    """Replaces the value of an unquoted-key assignment."""
    key = match.group("key")
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
    (_ASSIGNMENT_RE, _replace_assignment),
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


def _redact_args(args: Any) -> Any:
    """Redacts the string members of a log record's argument set."""
    if isinstance(args, dict):
        return {key: _redact_value(item) for key, item in args.items()}
    if isinstance(args, tuple):
        return tuple(_redact_value(item) for item in args)
    return _redact_value(args)


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
    """Collects the fields supplied through ``extra={...}``."""
    context: Dict[str, Any] = {}
    for name, value in vars(record).items():
        if name in _RESERVED_RECORD_ATTRS or name.startswith("_"):
            continue
        context[name] = value
    return context


class RedactingJsonFormatter(logging.Formatter):
    """Renders a record as a single redacted JSON object.

    The base implementation renders the message, the interpolated
    arguments and the exception traceback. That rendered text is placed
    in a JSON payload together with the timestamp, the level, the logger
    name and the ``extra`` fields, and the redaction patterns are then
    applied to the serialised payload.
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
        """Assembles the JSON payload for a rendered record."""
        message = record.getMessage()
        if rendered.startswith(message):
            detail = rendered[len(message):].strip("\n")
        else:
            detail = "" if rendered == message else rendered
        payload: Dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        if detail:
            payload["exception"] = detail
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


def _find_redacting_handler(
    logger: logging.Logger,
) -> Optional[logging.Handler]:
    """Returns the installed redacting handler, or ``None``."""
    for handler in logger.handlers:
        if getattr(handler, "name", None) == HANDLER_NAME:
            return handler
    return None


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


def configure_logging(
    level: Optional[Union[int, str]] = None,
) -> logging.Logger:
    """Installs the redacting handler on the base logger once.

    The handler is added only when it is not already present. Repeated
    calls from different modules in one process leave a single handler
    and produce no duplicated output. Passing ``level`` sets the base
    logger's level; omitting it keeps the level already in effect, or
    applies :data:`DEFAULT_LOG_LEVEL` on the first call.

    Returns the base logger.
    """
    logger = logging.getLogger(BASE_LOGGER_NAME)
    if _find_redacting_handler(logger) is None:
        logger.addHandler(_build_handler())
        logger.propagate = False
        logger.setLevel(_resolve_level(level))
    elif level is not None:
        logger.setLevel(_resolve_level(level))
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
