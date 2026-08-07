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

Alongside credential shapes, two further classes of value are rewritten:

* internal filesystem paths -- traceback frame paths are reduced to the
  file's base name, drive-letter absolute paths are replaced, and
  POSIX paths that name a file are replaced. A request path such as
  ``/subscriptions/webhook`` names no file and is left intact, so audit
  fields keep their route values.
* electronic mail addresses, replaced whole.

Both the log message and the formatted exception traceback are covered,
as are values nested inside fields supplied through ``extra={...}``.
Every field passed through ``extra={...}`` is emitted under the
``context`` key of the JSON object.

:func:`log_exception` is the supported way to report a caught error. It
emits the exception's type, defining module and redacted message as
discrete fields at the caller's level, and emits the formatted traceback
only at ``DEBUG``, which the level applied by :func:`configure_logging`
suppresses.

:func:`bind_request_id` records an identifier for the current task or
thread, and every record emitted while it is bound carries it under
``context.request_id``, joining an inbound request to the outbound calls
and database transitions it caused. :func:`mark_audited` records that an
exception's rejection has already been written to the audit trail, so a
generic handler downstream can leave it at one record.

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
disabled on each, so no record reaches a handler installed elsewhere,
whatever level the root logger is configured at. Loggers outside those
namespaces are not governed by this module. Discovery and installation
run under a lock and are idempotent: repeated or concurrent calls leave
exactly one handler per logger, and a handler found under the reserved
name whose type, target, formatter, filter or stream does not match is
replaced.

Governance covers *every* handler each of those loggers carries, not
only one found under the reserved name: exactly one handler configured
as this module builds it is kept and every other handler is removed, so
no handler without the redacting formatter and filter can emit a record
from a governed namespace. Descendant loggers of a governed namespace
are governed too -- each has its own handlers removed and is made to
propagate, so its records reach the one governed handler.
:func:`unredacted_handler_names` reports any handler that was removed,
so a caller may treat the condition as a startup failure.

Emission is queue-backed. The handler installed on each governed logger
places the record on a bounded queue and returns; a single listener
thread then applies the redaction filter, renders the JSON payload and
writes it to standard output. Redaction, formatting, the write and the
flush therefore run on that thread rather than on the thread that logged
-- which for this application is the request path, including its
asynchronous middleware, dependencies and handlers. A record placed on a
full queue is emitted inline instead, so the queue caps memory without
discarding a record. :func:`flush_log_queue` waits for the queue to
drain, and the listener is stopped at interpreter exit.

The record object itself is queued, so a mutable value passed through
``extra={...}`` is read at emission rather than at the call.

The module uses only the Python standard library and reads no
configuration and no environment variable.

Usage::

    configure_logging()
    logger = get_logger(__name__)
    logger.info("listing refresh finished", extra={"count": 12})
    token = bind_request_id("d34db33f")
    try:
        ...
    except OSError as error:
        log_exception(logger, "listing refresh failed", error)
    finally:
        reset_request_id(token)
"""

import atexit
import contextvars
import json
import logging
import logging.handlers
import os
import queue
import re
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import unquote

__all__ = [
    "AUDITED_ATTRIBUTE",
    "BASE_LOGGER_NAME",
    "CONTEXT_FIELD",
    "DEFAULT_LOG_LEVEL",
    "EXCEPTION_MESSAGE_LIMIT",
    "GOVERNED_LOGGER_NAMES",
    "HANDLER_NAME",
    "QUEUE_CAPACITY",
    "QUEUE_DRAIN_TIMEOUT_SECONDS",
    "REDACTION_PLACEHOLDER",
    "REQUEST_ID_FIELD",
    "THIRD_PARTY_LOGGER_NAMES",
    "THIRD_PARTY_LOG_LEVEL",
    "TRACE_MESSAGE",
    "QueueDispatchHandler",
    "RedactingFilter",
    "RedactingJsonFormatter",
    "bind_request_id",
    "configure_logging",
    "current_request_id",
    "exception_fields",
    "flush_log_queue",
    "get_logger",
    "is_audited",
    "log_audit_fallback",
    "log_exception",
    "mark_audited",
    "redact",
    "redact_structure",
    "reset_request_id",
    "unredacted_handler_names",
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

#: Every logger namespace this module governs.
GOVERNED_LOGGER_NAMES = (BASE_LOGGER_NAME,) + THIRD_PARTY_LOGGER_NAMES

#: JSON context key carrying the bound request identifier.
REQUEST_ID_FIELD = "request_id"

#: Message of the record that carries a formatted traceback.
TRACE_MESSAGE = "Exception traceback"

#: Longest exception message emitted as a discrete field.
EXCEPTION_MESSAGE_LIMIT = 512

#: Attribute set on an exception whose rejection is already audited.
AUDITED_ATTRIBUTE = "_audit_record_emitted"
#: Records the queue holds before an emission falls back to inline
#: writing on the calling thread.
QUEUE_CAPACITY = 4096

#: Seconds :func:`flush_log_queue` waits for the queue to drain.
QUEUE_DRAIN_TIMEOUT_SECONDS = 5.0

# Deepest level of nesting walked when redacting a structured value.
_MAX_REDACTION_DEPTH = 8

# Serialises handler discovery and installation across threads.
_CONFIGURE_LOCK = threading.RLock()

# Labels of the handlers removed from the governed namespaces, in the
# order they were first removed. Read through
# :func:`unredacted_handler_names`.
_REMOVED_HANDLERS: List[str] = []

# Identifier bound to the current task or thread, or None.
_REQUEST_ID: "contextvars.ContextVar[Optional[str]]" = (
    contextvars.ContextVar("blitzy_request_id", default=None)
)

# Longest identifier accepted by :func:`bind_request_id`.
_MAX_REQUEST_ID_LENGTH = 128

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

# Marker substituted for the directory part of an internal path.
_PATH_PLACEHOLDER = "<path>"

# A traceback frame header naming the source file it executed in.
_TRACE_FRAME_RE = re.compile(
    r"(?P<open>File\s+\")(?P<path>[^\"\n]{1,4096})(?P<close>\")",
)

# A drive-letter absolute path, with either separator.
_WINDOWS_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"[A-Za-z]:[\\/](?:[^\\/\s\"'<>|]{1,255}[\\/]){0,32}"
    r"[^\\/\s\"'<>|]{0,255}",
)

# A POSIX path naming a file. At least two separators and a trailing
# extension are required, so a request path is not matched.
_POSIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=\-])"
    r"/(?:[A-Za-z0-9._+\-]{1,255}/){1,32}"
    r"[A-Za-z0-9._+\-]{0,255}"
    r"\.[A-Za-z0-9]{1,8}",
)

# An electronic mail address. The domain must carry a dot and an
# alphabetic final label.
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])"
    r"[A-Za-z0-9._%+\-]{1,64}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){1,8}"
    r"[A-Za-z]{2,24}"
    r"(?![A-Za-z0-9\-])",
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


def _replace_trace_frame(match: "re.Match") -> str:
    """Reduces a traceback frame's path to the file's base name."""
    path = match.group("path")
    base = os.path.basename(path.replace("\\", "/").rstrip("/"))
    if not base:
        base = _PATH_PLACEHOLDER
    return "{0}{1}/{2}{3}".format(
        match.group("open"),
        _PATH_PLACEHOLDER,
        base,
        match.group("close"),
    )


def _replace_path(match: "re.Match") -> str:
    """Replaces the directory part of an internal filesystem path."""
    matched = match.group(0)
    base = os.path.basename(matched.replace("\\", "/").rstrip("/"))
    if not base:
        return _PATH_PLACEHOLDER
    return _PATH_PLACEHOLDER + "/" + base


def _replace_email(match: "re.Match") -> str:
    """Replaces an electronic mail address outright."""
    return REDACTION_PLACEHOLDER


# Redaction rules in application order. Each pattern is compiled once at
# module import. The traceback frame rule runs before the general path
# rules so a frame header keeps its quoted shape.
_REDACTION_RULES: Tuple[Tuple[Any, Callable[[Any], str]], ...] = (
    (_AUTH_HEADER_RE, _replace_auth_header),
    (_BEARER_RE, _replace_bearer),
    (_URL_CREDENTIAL_RE, _replace_url_credential),
    (_MAPPING_RE, _replace_mapping),
    (_ENCODED_MAPPING_RE, _replace_mapping),
    (_ASSIGNMENT_RE, _replace_assignment),
    (_ENCODED_ASSIGNMENT_RE, _replace_assignment),
    (_TRACE_FRAME_RE, _replace_trace_frame),
    (_WINDOWS_PATH_RE, _replace_path),
    (_POSIX_PATH_RE, _replace_path),
    (_EMAIL_RE, _replace_email),
)


def redact(text: Any) -> str:
    """Returns ``text`` with unsafe values replaced.

    Credential-shaped values, internal filesystem paths and electronic
    mail addresses are all substituted. For a credential the key name is
    preserved and only the value is replaced; for a path the file's base
    name is preserved and the directory part is replaced. A non-string
    input is rendered with :func:`str` first. Any failure during
    redaction yields the placeholder in place of the whole input.
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


def bind_request_id(request_id: Any) -> Any:
    """Binds ``request_id`` to the current task or thread.

    Every record emitted while the identifier is bound carries it under
    ``context.request_id``. The value is rendered with :func:`str`,
    stripped, truncated to :data:`_MAX_REQUEST_ID_LENGTH` and redacted; a
    blank value binds ``None``. Returns the token
    :func:`reset_request_id` restores the previous value with.
    """
    if request_id is None:
        return _REQUEST_ID.set(None)
    try:
        rendered = str(request_id).strip()[:_MAX_REQUEST_ID_LENGTH]
    except Exception:
        rendered = ""
    return _REQUEST_ID.set(redact(rendered) if rendered else None)


def reset_request_id(token: Any) -> None:
    """Restores the identifier bound before ``token`` was issued."""
    try:
        _REQUEST_ID.reset(token)
    except Exception:
        _REQUEST_ID.set(None)


def current_request_id() -> Optional[str]:
    """Returns the identifier bound to the current task, or ``None``."""
    try:
        return _REQUEST_ID.get()
    except Exception:
        return None


def mark_audited(exc: Any) -> Any:
    """Records that ``exc``'s rejection is already in the audit trail.

    Returns ``exc`` so the marker may be applied where it is raised. An
    object that accepts no attribute is returned unmarked.
    """
    try:
        setattr(exc, AUDITED_ATTRIBUTE, True)
    except Exception:
        return exc
    return exc


def is_audited(exc: Any) -> bool:
    """Reports whether ``exc``'s rejection is already audited."""
    try:
        return bool(getattr(exc, AUDITED_ATTRIBUTE, False))
    except Exception:
        return False


def exception_fields(exc: Any) -> Dict[str, Any]:
    """Returns the discrete, safe fields describing ``exc``.

    The fields are the exception's class name, the module that defines
    it, and its message redacted and truncated to
    :data:`EXCEPTION_MESSAGE_LIMIT` characters. No traceback, no frame,
    no source path and no local value is included, so the result is safe
    to emit at any level.
    """
    fields: Dict[str, Any] = {
        "exception_type": None,
        "exception_module": None,
        "exception_message": None,
    }
    if exc is None:
        return fields
    try:
        fields["exception_type"] = type(exc).__name__
        fields["exception_module"] = getattr(
            type(exc), "__module__", None
        )
        rendered = str(exc)
    except Exception:
        return fields
    if rendered:
        fields["exception_message"] = redact(
            rendered[:EXCEPTION_MESSAGE_LIMIT]
        )
    return fields


def log_exception(
    logger: logging.Logger,
    message: str,
    exc: Any,
    level: int = logging.ERROR,
    **context: Any
) -> None:
    """Reports ``exc`` as discrete fields, and its traceback at DEBUG.

    One record is emitted at ``level`` carrying ``message``, the fields
    :func:`exception_fields` returns and any ``context`` supplied. The
    formatted traceback is emitted as a second record at ``DEBUG``, which
    the level :func:`configure_logging` applies suppresses, and which the
    redacting formatter rewrites when it is enabled.
    """
    fields = exception_fields(exc)
    fields.update(context)
    try:
        logger.log(level, message, extra=fields)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(TRACE_MESSAGE, exc_info=exc, extra=context)
    except Exception:
        _emit_fallback(message, fields)


def log_audit_fallback(message: str, fields: Any = None) -> None:
    """Writes one redacted record to standard error, bypassing logging.

    The sink of last resort for a record that must not be lost when the
    logging machinery itself fails. Never raises, performs no database
    or network work, and redacts both the message and the fields. The
    bound request identifier is added when the fields carry none.
    """
    payload: Dict[str, Any] = {}
    if isinstance(fields, dict):
        payload.update(fields)
    elif fields is not None:
        payload["detail"] = fields
    if payload.get(REQUEST_ID_FIELD) is None:
        bound = current_request_id()
        if bound is not None:
            payload[REQUEST_ID_FIELD] = bound
    _emit_fallback(message, payload)


def _emit_fallback(message: str, fields: Dict[str, Any]) -> None:
    """Writes one record to standard error without the logging module.

    Used when the logging machinery itself fails, so a record that must
    not be lost still reaches an operator-visible stream.
    """
    try:
        payload = json.dumps(
            {
                "level": "ERROR",
                "logger": BASE_LOGGER_NAME,
                "message": redact(message),
                CONTEXT_FIELD: redact_structure(fields),
            },
            default=str,
            ensure_ascii=False,
        )
    except Exception:
        payload = '{"level":"ERROR","message":"' + (
            REDACTION_PLACEHOLDER + '"}'
        )
    try:
        sys.stderr.write(redact(payload) + "\n")
        sys.stderr.flush()
    except Exception:
        return


class RedactingFilter(logging.Filter):
    """Scrubs unsafe values from a record and adds the request id.

    The filter rewrites ``record.msg`` and ``record.args`` in place,
    attaches the bound request identifier when the record carries none,
    and always admits the record. A failure while scrubbing replaces the
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
        try:
            if getattr(record, REQUEST_ID_FIELD, None) is None:
                bound = current_request_id()
                if bound is not None:
                    setattr(record, REQUEST_ID_FIELD, bound)
        except Exception:
            return True
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


def _handler_label(handler: Any) -> str:
    """Returns a printable identifier for ``handler``."""
    try:
        named = getattr(handler, "name", None)
        if named:
            return str(named)
        return type(handler).__name__
    except Exception:
        return "unknown"


class QueueDispatchHandler(logging.handlers.QueueHandler):
    """Hands a record to the listener queue without rendering it.

    ``prepare`` returns the record unchanged, so no redaction, no
    formatting and no serialisation happens on the thread that logged.
    The queue is drained in the same process, so the record needs no
    pickling and keeps its ``exc_info`` and its ``extra`` fields.

    A record that finds the queue full is written through ``target``
    inline. That bounds the queue's memory without discarding a record,
    at the cost of the caller performing that one write itself.
    """

    def __init__(
        self,
        record_queue: "queue.Queue",
        target: logging.Handler,
    ) -> None:
        super().__init__(record_queue)
        self.target = target

    def prepare(self, record: logging.LogRecord) -> logging.LogRecord:
        """Returns ``record`` unchanged."""
        return record

    def enqueue(self, record: logging.LogRecord) -> None:
        """Places ``record`` on the queue without waiting."""
        self.queue.put_nowait(record)

    def emit(self, record: logging.LogRecord) -> None:
        """Queues ``record``, writing it inline if the queue is full."""
        try:
            self.enqueue(self.prepare(record))
        except queue.Full:
            try:
                self.target.handle(record)
            except Exception:
                self.handleError(record)
        except Exception:
            self.handleError(record)


# Queue every governed logger dispatches through, and the listener
# thread and stream handler that drain it. All three are created together
# by _ensure_listener under _CONFIGURE_LOCK.
_record_queue = None  # type: Optional[queue.Queue]
_listener = None  # type: Optional[logging.handlers.QueueListener]
_stream_handler = None  # type: Optional[logging.Handler]


def _is_redacting_stream_handler(handler: Any) -> bool:
    """Reports whether ``handler`` writes redacted JSON to a live stream.

    A handler is accepted only when it is a stream handler carrying an
    open stream, a :class:`RedactingJsonFormatter` and a
    :class:`RedactingFilter`. The reserved name belongs to the queue
    handler installed on a governed logger, not to the stream handler the
    listener drains to, so no name is required here.
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


def _is_redacting_handler(handler: Any) -> bool:
    """Reports whether ``handler`` is configured as this module builds it.

    A handler is accepted only when it dispatches to the live listener
    queue and its target is the redacting stream handler that listener
    drains to. Anything else occupying the reserved name is treated as
    foreign, including a queue handler left behind by a stopped
    listener.
    """
    if not isinstance(handler, QueueDispatchHandler):
        return False
    if _record_queue is None or handler.queue is not _record_queue:
        return False
    if _stream_handler is None or handler.target is not _stream_handler:
        return False
    if not _is_redacting_stream_handler(handler.target):
        return False
    return _listener is not None and _listener_is_running()


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


def _build_stream_handler() -> logging.Handler:
    """Creates the redacting stream handler the listener drains to."""
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(RedactingJsonFormatter())
    handler.addFilter(RedactingFilter())
    return handler


def _listener_is_running() -> bool:
    """Reports whether the listener thread is alive."""
    thread = getattr(_listener, "_thread", None)
    return thread is not None and thread.is_alive()


def _ensure_listener() -> None:
    """Creates and starts the queue, stream handler and listener once.

    Called with :data:`_CONFIGURE_LOCK` held. A listener whose thread is
    no longer alive is replaced, so a stopped listener does not leave the
    governed loggers dispatching into a queue nothing drains.
    """
    global _record_queue, _listener, _stream_handler
    if (
        _record_queue is not None
        and _stream_handler is not None
        and _is_redacting_stream_handler(_stream_handler)
        and _listener_is_running()
    ):
        return
    _stop_listener()
    _record_queue = queue.Queue(maxsize=QUEUE_CAPACITY)
    _stream_handler = _build_stream_handler()
    _listener = logging.handlers.QueueListener(
        _record_queue, _stream_handler, respect_handler_level=False
    )
    _listener.start()


def _stop_listener() -> None:
    """Drains the queue and stops the listener thread, if one is running.

    Registered to run at interpreter exit, and called before a listener
    is replaced. Leaves the module ready to build a fresh listener.
    """
    global _listener
    listener = _listener
    if listener is None:
        return
    _listener = None
    if _listener_is_running():
        flush_log_queue()
        try:
            listener.stop()
        except Exception:
            return


def flush_log_queue(
    timeout: float = QUEUE_DRAIN_TIMEOUT_SECONDS,
) -> bool:
    """Waits for every queued record to be written, then flushes.

    Returns True when the queue emptied within ``timeout`` seconds.
    Returns False when the wait elapsed first, which leaves the
    outstanding records queued rather than discarding them.
    """
    record_queue = _record_queue
    handler = _stream_handler
    drained = True
    if record_queue is not None and _listener_is_running():
        deadline = time.monotonic() + max(timeout, 0.0)
        while True:
            outstanding = getattr(
                record_queue, "unfinished_tasks", None
            )
            if outstanding is None:
                outstanding = 0 if record_queue.empty() else 1
            if outstanding <= 0:
                break
            if time.monotonic() >= deadline:
                drained = False
                break
            time.sleep(0.002)
    if handler is not None:
        try:
            handler.flush()
        except Exception:
            return False
    return drained


def _build_handler() -> logging.Handler:
    """Creates the queue handler installed on a governed logger."""
    _ensure_listener()
    handler = QueueDispatchHandler(_record_queue, _stream_handler)
    handler.set_name(HANDLER_NAME)
    return handler


def _install_handler(logger: logging.Logger) -> bool:
    """Ensures ``logger`` carries exactly one valid dispatching handler.

    **Every** handler on ``logger`` is inspected, not only one found
    under the reserved name. The first that matches the expected
    configuration -- dispatching to the live queue whose listener drains
    to the redacting stream handler -- is kept; every other handler is
    removed and its label recorded by
    :func:`unredacted_handler_names`. Returns ``True`` when a new handler
    was installed.
    """
    keep = None
    for handler in list(logger.handlers):
        if keep is None and _is_redacting_handler(handler):
            keep = handler
            continue
        logger.removeHandler(handler)
        _record_removed_handler(logger.name, handler)
    if keep is not None:
        return False
    logger.addHandler(_build_handler())
    return True


def _record_removed_handler(
    logger_name: str, handler: Any
) -> None:
    """Records that a handler was removed from a governed logger."""
    label = "{0}:{1}".format(logger_name, _handler_label(handler))
    if label in _REMOVED_HANDLERS:
        return
    _REMOVED_HANDLERS.append(label)


def unredacted_handler_names() -> Tuple[str, ...]:
    """Returns the handlers removed from the governed namespaces.

    Each entry names the logger and the handler taken off it. A non-empty
    result means a handler that would have emitted records without
    redaction was attached, and a caller may treat that as a startup
    failure.
    """
    with _CONFIGURE_LOCK:
        return tuple(_REMOVED_HANDLERS)


def _governed_descendants() -> List[logging.Logger]:
    """Returns every existing descendant of a governed namespace."""
    prefixes = tuple(name + "." for name in GOVERNED_LOGGER_NAMES)
    descendants: List[logging.Logger] = []
    try:
        registry = dict(logging.Logger.manager.loggerDict)
    except Exception:
        return descendants
    for name, entry in registry.items():
        if not isinstance(name, str) or not name.startswith(prefixes):
            continue
        if not isinstance(entry, logging.Logger):
            continue
        descendants.append(entry)
    return descendants


def _govern_descendants() -> None:
    """Removes handlers from descendants and makes them propagate.

    A descendant of a governed namespace carries no handler of its own,
    so every record it emits travels to the one governed handler on the
    namespace root.
    """
    for logger in _governed_descendants():
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            _record_removed_handler(logger.name, handler)
        logger.propagate = True


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
    """Installs the dispatching handler on the governed loggers.

    Discovery and installation are performed under a lock, so repeated or
    concurrent calls from different modules in one process leave exactly
    one handler per logger, one queue and one listener thread, and
    produce no duplicated output. A handler found under the reserved name
    whose type, queue, target, formatter, filter or stream does not
    match, or whose listener thread has stopped, is replaced.

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
        _govern_descendants()
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


# Registered after the logging module's own exit hook, so it runs first
# and every queued record is written before the handlers are closed.
atexit.register(_stop_listener)
