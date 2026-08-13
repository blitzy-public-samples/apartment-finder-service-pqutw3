"""Structured JSON logging with credential redaction and bounded queue
handling.
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
    "EMIT_FAILURE_MESSAGE",
    "EMIT_FAILURE_SIGNAL",
    "EXCEPTION_MESSAGE_LIMIT",
    "GOVERNED_LOGGER_NAMES",
    "HANDLER_NAME",
    "MAX_REGISTERED_SECRETS",
    "MIGRATION_LOGGER_NAMES",
    "MIGRATION_LOG_LEVEL",
    "MIN_SECRET_VALUE_LENGTH",
    "LISTENER_JOIN_TIMEOUT_SECONDS",
    "LISTENER_SENTINEL_TIMEOUT_SECONDS",
    "QUEUE_CAPACITY",
    "QUEUE_DRAIN_TIMEOUT_SECONDS",
    "REDACTION_PLACEHOLDER",
    "REQUEST_ID_FIELD",
    "SERVER_LOGGER_NAMES",
    "SERVER_LOG_LEVEL",
    "SIGNAL_FIELD",
    "SPAN_ID_FIELD",
    "SPAN_ID_LENGTH",
    "SQL_LOG_LEVEL",
    "STOP_REASON_NOT_DRAINED",
    "STOP_REASON_SENTINEL_REFUSED",
    "STOP_REASON_THREAD_ALIVE",
    "THIRD_PARTY_LOGGER_NAMES",
    "THIRD_PARTY_LOG_LEVEL",
    "TRACEPARENT_HEADER",
    "TRACEPARENT_VERSION",
    "TRACESTATE_HEADER",
    "TRACE_FLAG_NOT_SAMPLED",
    "TRACE_FLAG_SAMPLED",
    "TRACE_ID_FIELD",
    "TRACE_ID_LENGTH",
    "TRACE_MESSAGE",
    "QueueDispatchHandler",
    "RedactingFilter",
    "RedactingJsonFormatter",
    "RedactingStreamHandler",
    "bind_request_id",
    "bind_trace_context",
    "configure_logging",
    "configure_migration_logging",
    "current_request_id",
    "current_traceparent",
    "current_trace_context",
    "exception_fields",
    "flush_log_queue",
    "format_traceparent",
    "get_logger",
    "is_audited",
    "listener_stop_failures",
    "log_audit_fallback",
    "log_exception",
    "logging_failure_count",
    "mark_audited",
    "new_span_id",
    "new_trace_id",
    "outbound_trace_headers",
    "parse_traceparent",
    "redact",
    "redact_structure",
    "redirect_log_stream",
    "registered_secret_count",
    "register_required_secret_values",
    "register_secret_values",
    "report_emit_failure",
    "reset_logging_failure_count",
    "reset_request_id",
    "reset_trace_context",
    "unredacted_handler_names",
]

#: Name of the logger that owns the redacting handler.
BASE_LOGGER_NAME = "backend"

#: Name assigned to the installed handler.
HANDLER_NAME = "redacting-json-stream"

#: Third-party logger namespaces placed under the redacting handler.
THIRD_PARTY_LOGGER_NAMES = (
    "python_http_client",
    "sendgrid",
    "httpx",
    "httpcore",
)

#: Level applied to the third-party loggers named above.
THIRD_PARTY_LOG_LEVEL = logging.WARNING

#: Namespaces the ASGI server writes its own records to, placed under the
#: redacting handler. The server configures these itself, with its own
#: stream handlers and no propagation, before this application's modules
#: are imported: ``uvicorn.error`` carries the traceback of an unhandled
#: exception and ``uvicorn.access`` carries the request target of every
#: request, complete with its query string. Governing them is what routes
#: both through the redaction rules rather than straight to the console.
SERVER_LOGGER_NAMES = (
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
)

#: Level applied to the server namespaces named above. It admits the
#: access record, which the server writes at INFO.
SERVER_LOG_LEVEL = logging.INFO

#: Migration logger namespaces placed under the redacting handler by
#: :func:`configure_migration_logging`.
MIGRATION_LOGGER_NAMES = ("alembic", "sqlalchemy")

#: Level applied to the ``alembic`` namespace, which carries each
#: revision's own record of what it changed.
MIGRATION_LOG_LEVEL = logging.INFO

#: Level applied to the ``sqlalchemy`` namespace, whose INFO records
#: carry executed statement text.
SQL_LOG_LEVEL = logging.WARNING

#: JSON key that carries the fields supplied through ``extra={...}``.
CONTEXT_FIELD = "context"

#: Fixed marker substituted for every redacted value.
REDACTION_PLACEHOLDER = "[REDACTED]"

#: Level applied to the base logger when the handler is installed.
DEFAULT_LOG_LEVEL = logging.INFO

#: Every logger namespace this module governs.
GOVERNED_LOGGER_NAMES = (
    (BASE_LOGGER_NAME,)
    + THIRD_PARTY_LOGGER_NAMES
    + MIGRATION_LOGGER_NAMES
    + SERVER_LOGGER_NAMES
)

#: JSON context key carrying the bound request identifier.
REQUEST_ID_FIELD = "request_id"

#: JSON context key carrying the bound W3C trace identifier.
TRACE_ID_FIELD = "trace_id"

#: JSON context key carrying the bound W3C span identifier.
SPAN_ID_FIELD = "span_id"

#: Request header carrying the W3C trace context.
TRACEPARENT_HEADER = "traceparent"

#: Request header carrying the vendor-specific W3C trace state.
TRACESTATE_HEADER = "tracestate"

#: Version field of every ``traceparent`` value this module writes.
TRACEPARENT_VERSION = "00"

#: Trace-flags field marking a sampled trace.
TRACE_FLAG_SAMPLED = "01"

#: Trace-flags field marking an unsampled trace.
TRACE_FLAG_NOT_SAMPLED = "00"

#: Hexadecimal digits in a W3C trace identifier.
TRACE_ID_LENGTH = 32

#: Hexadecimal digits in a W3C span identifier.
SPAN_ID_LENGTH = 16

#: Message of the record that carries a formatted traceback.
TRACE_MESSAGE = "Exception traceback"

#: Longest exception message emitted as a discrete field.
EXCEPTION_MESSAGE_LIMIT = 512

#: Attribute set on an exception whose rejection is already audited.
AUDITED_ATTRIBUTE = "_audit_record_emitted"

#: Message of the record written when a handler could not emit.
EMIT_FAILURE_MESSAGE = "Log record could not be emitted"

#: Field naming the degradation a record reports, read by the log-based
#: metric the deployment alerts on.
SIGNAL_FIELD = "signal"

#: Value of :data:`SIGNAL_FIELD` on a record reporting that a handler
#: could not emit.
EMIT_FAILURE_SIGNAL = "log_emit_failed"

#: Shortest value :func:`register_secret_values` accepts. A shorter value
#: is refused.
MIN_SECRET_VALUE_LENGTH = 8

#: Most values the registry holds. A further value is refused once the
#: registry is full.
MAX_REGISTERED_SECRETS = 32

#: Records the queue holds before an emission falls back to inline
#: writing on the calling thread.
QUEUE_CAPACITY = 4096

#: Seconds :func:`flush_log_queue` waits for the queue to drain.
QUEUE_DRAIN_TIMEOUT_SECONDS = 5.0

#: Seconds :func:`_stop_listener` waits to hand the listener thread its
#: sentinel. ``QueueListener.enqueue_sentinel`` uses ``put_nowait``, which
#: raises on a queue at capacity, so the sentinel is offered under a
#: bounded wait instead.
LISTENER_SENTINEL_TIMEOUT_SECONDS = 1.0

#: Seconds :func:`_stop_listener` waits for the listener thread to exit
#: after it has been handed the sentinel. ``QueueListener.stop`` joins
#: without a timeout, so a thread blocked inside a write never returns.
LISTENER_JOIN_TIMEOUT_SECONDS = 2.0

#: Reason recorded when the queued records did not drain before the
#: listener was asked to stop.
STOP_REASON_NOT_DRAINED = "queued records did not drain"

#: Reason recorded when the sentinel could not be handed to the listener
#: within :data:`LISTENER_SENTINEL_TIMEOUT_SECONDS`.
STOP_REASON_SENTINEL_REFUSED = "listener sentinel was not accepted"

#: Reason recorded when the listener thread was still alive after
#: :data:`LISTENER_JOIN_TIMEOUT_SECONDS`.
STOP_REASON_THREAD_ALIVE = "listener thread did not exit"

# Deepest level of nesting walked when redacting a structured value.
_MAX_REDACTION_DEPTH = 8

# Serialises handler discovery and installation across threads.
_CONFIGURE_LOCK = threading.RLock()

# Serialises registration of secret values across threads.
_SECRETS_LOCK = threading.RLock()

# Serialises the emit-failure counter across threads.
_EMIT_FAILURE_LOCK = threading.Lock()

# Records a handler could not emit. Read through
# :func:`logging_failure_count`.
_EMIT_FAILURES = 0

# Values replaced wherever they appear, longest first so a value that
# contains another is replaced whole. Rebound as a complete tuple under
# _SECRETS_LOCK and read without the lock, so a reader always sees one
# consistent generation of it.
_SECRET_VALUES: Tuple[str, ...] = ()

# Labels of the handlers removed from the governed namespaces, in the
# order they were first removed. Read through
# :func:`unredacted_handler_names`.
_REMOVED_HANDLERS: List[str] = []

# Reasons a listener shutdown did not complete, in the order they were
# first recorded. Read through :func:`listener_stop_failures`.
_STOP_FAILURES: List[str] = []

# Identifier bound to the current task or thread, or None.
_REQUEST_ID: "contextvars.ContextVar[Optional[str]]" = (
    contextvars.ContextVar("blitzy_request_id", default=None)
)

# Longest identifier accepted by :func:`bind_request_id`.
_MAX_REQUEST_ID_LENGTH = 128

# Trace identifier, span identifier and trace flags bound to the current
# task or thread, or None.
_TRACE_CONTEXT: "contextvars.ContextVar[Optional[Tuple[str, str, str]]]" = (
    contextvars.ContextVar("blitzy_trace_context", default=None)
)

# A trace identifier of the required length, which must not be all zeros.
_TRACE_ID_RE = re.compile(r"^[0-9a-f]{" + str(TRACE_ID_LENGTH) + r"}$")

# A span identifier of the required length, which must not be all zeros.
_SPAN_ID_RE = re.compile(r"^[0-9a-f]{" + str(SPAN_ID_LENGTH) + r"}$")

# Trace flags: two lower-case hexadecimal digits.
_TRACE_FLAGS_RE = re.compile(r"^[0-9a-f]{2}$")

# The version field of a traceparent value: two hexadecimal digits that
# are not the reserved all-ones value.
_TRACE_VERSION_RE = re.compile(r"^[0-9a-f]{2}$")

# Reserved version value a receiver must reject.
_TRACE_VERSION_INVALID = "ff"

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

# The query string of a URL, from the first question mark to the end of
# the target. The whole query is replaced, so a value carried in it is
# removed whether or not its key name spells a credential stem.
_URL_QUERY_RE = re.compile(
    r"(?P<url>[A-Za-z][A-Za-z0-9+.\-]{0,31}://[^\s\"'<>\\?]{0,2048})"
    r"\?(?P<query>[^\s\"'<>\\]{1,4096})",
)

# The query string of a request target that carries no scheme or host,
# which is the form an access record writes: the path is kept and the
# whole query replaced. The target must start a token -- the character
# before it, if any, is whitespace, a quote, an opening bracket or an
# equals sign -- so a query already matched by the rule above, and a
# fragment of some longer value, are not matched again here.
_TARGET_QUERY_RE = re.compile(
    r"(?<![^\s\"'(\[=])"
    r"(?P<url>/[^\s\"'<>\\?]{0,2048})"
    r"\?(?P<query>[^\s\"'<>\\]{1,4096})",
)

# One printf-style conversion specifier, in each of the forms the
# logging module interpolates: an optional mapping key, optional flags,
# width and precision, an optional length modifier, and the conversion
# character. The whole specifier is captured, so two templates are
# compared by the specifiers they carry rather than by how many percent
# signs they hold.
_FORMAT_SPECIFIERS_RE = re.compile(
    r"%(?:\([^)]*\))?[-+ #0]*(?:\*|\d+)?(?:\.(?:\*|\d+))?"
    r"[hlL]?[diouxXeEfFgGcrsa%]"
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


def _replace_url_query(match: "re.Match") -> str:
    """Replaces the whole query string of a URL, keeping the target.

    The scheme, host and path are emitted unchanged, so a record still
    names what was called. A query already reduced to the placeholder is
    left as it is, so applying the rules twice is idempotent.
    """
    query = match.group("query")
    if not query or _is_skipped_value(query):
        return match.group(0)
    return match.group("url") + "?" + REDACTION_PLACEHOLDER


# Redaction rules in application order. Each pattern is compiled once at
# module import. The two query rules run before the mapping and
# assignment rules, so a parameter carried in a query is replaced with
# the whole query, and the scheme-bearing form runs before the
# scheme-less one. The traceback frame rule runs before the general path
# rules so a frame header keeps its quoted shape.
_REDACTION_RULES: Tuple[Tuple[Any, Callable[[Any], str]], ...] = (
    (_AUTH_HEADER_RE, _replace_auth_header),
    (_BEARER_RE, _replace_bearer),
    (_URL_CREDENTIAL_RE, _replace_url_credential),
    (_URL_QUERY_RE, _replace_url_query),
    (_TARGET_QUERY_RE, _replace_url_query),
    (_MAPPING_RE, _replace_mapping),
    (_ENCODED_MAPPING_RE, _replace_mapping),
    (_ASSIGNMENT_RE, _replace_assignment),
    (_ENCODED_ASSIGNMENT_RE, _replace_assignment),
    (_TRACE_FRAME_RE, _replace_trace_frame),
    (_WINDOWS_PATH_RE, _replace_path),
    (_POSIX_PATH_RE, _replace_path),
    (_EMAIL_RE, _replace_email),
)


def register_secret_values(*values: Any) -> int:
    """Registers values replaced wherever they appear in a record.

    Each caller registers the credential it handles. A value is accepted
    when it is text of at least :data:`MIN_SECRET_VALUE_LENGTH`
    characters, is not the placeholder itself, and the registry holds
    fewer than :data:`MAX_REGISTERED_SECRETS` values; anything else is
    ignored. Registering a value already held changes nothing. Returns the
    number of values the registry holds afterwards, and never raises.
    """
    global _SECRET_VALUES
    try:
        with _SECRETS_LOCK:
            held = set(_SECRET_VALUES)
            for value in values:
                if len(held) >= MAX_REGISTERED_SECRETS:
                    break
                if not isinstance(value, str):
                    continue
                candidate = value.strip()
                if len(candidate) < MIN_SECRET_VALUE_LENGTH:
                    continue
                if candidate.lower() in _SKIP_VALUES:
                    continue
                held.add(candidate)
            _SECRET_VALUES = tuple(
                sorted(held, key=lambda entry: (-len(entry), entry))
            )
            return len(_SECRET_VALUES)
    except Exception:
        return len(_SECRET_VALUES)


def register_required_secret_values(*values: Any) -> int:
    """Registers values whose redaction the caller depends on.

    Each value is registered through :func:`register_secret_values` and
    then confirmed to be held. Raises :class:`ValueError` naming how many
    values the registry did not accept -- never a value itself -- so a
    caller whose credential could not be registered fails rather than
    continuing with that credential unredacted. Returns the number of
    values the registry holds afterwards.
    """
    held_count = register_secret_values(*values)
    held = set(_SECRET_VALUES)
    refused = sum(
        1
        for value in values
        if not isinstance(value, str) or value.strip() not in held
    )
    if refused:
        raise ValueError(
            "{0} of {1} required secret value(s) could not be "
            "registered for redaction".format(refused, len(values))
        )
    return held_count


def registered_secret_count() -> int:
    """Returns how many values the secret registry holds."""
    return len(_SECRET_VALUES)


def _replace_secret_values(rendered: str) -> str:
    for secret in _SECRET_VALUES:
        if secret in rendered:
            rendered = rendered.replace(secret, REDACTION_PLACEHOLDER)
    return rendered


def redact(text: Any) -> str:
    """Returns ``text`` with unsafe values replaced.

    Registered secret values, credential-shaped values, internal
    filesystem paths and electronic mail addresses are all substituted. A
    registered value is replaced wherever it appears, including inside
    free prose that names no key. For a credential matched by shape the
    key name is preserved and only the value is replaced; for a path the
    file's base name is preserved and the directory part is replaced. A
    non-string input is rendered with :func:`str` first. Any failure
    during redaction yields the placeholder in place of the whole input.
    """
    try:
        rendered = text if isinstance(text, str) else str(text)
        if not rendered:
            return rendered
        rendered = _replace_secret_values(rendered)
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

    A template whose specifiers do not survive redaction unchanged is
    returned as it was; the rendered record is redacted by the formatter,
    so nothing is emitted unredacted either way. The specifiers
    themselves are compared rather than the number of percent signs: a
    template such as ``"%s://%s:%d"`` keeps its three percent signs while
    the first specifier is rewritten into text no interpolation accepts,
    which counting alone does not detect and which would raise while the
    record was rendered.
    """
    rewritten = redact(template)
    if has_args and _FORMAT_SPECIFIERS_RE.findall(
        rewritten
    ) != _FORMAT_SPECIFIERS_RE.findall(template):
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


def new_trace_id() -> str:
    """Returns a fresh W3C trace identifier."""
    return os.urandom(TRACE_ID_LENGTH // 2).hex()


def new_span_id() -> str:
    """Returns a fresh W3C span identifier."""
    return os.urandom(SPAN_ID_LENGTH // 2).hex()


def parse_traceparent(value: Any) -> Optional[Tuple[str, str, str]]:
    """Returns the trace identifier, span identifier and flags in ``value``.

    ``value`` is a W3C ``traceparent`` header. ``None`` is returned unless
    every field is well formed: the version is two hexadecimal digits and
    is not the reserved all-ones value, the trace identifier is
    :data:`TRACE_ID_LENGTH` hexadecimal digits and not all zeros, the span
    identifier is :data:`SPAN_ID_LENGTH` hexadecimal digits and not all
    zeros, and the flags are two hexadecimal digits. A version above the
    one this module writes may carry further fields, which are ignored.
    """
    if not isinstance(value, str):
        return None
    parts = value.strip().lower().split("-")
    if len(parts) < 4:
        return None
    version, trace_id, span_id, flags = parts[0], parts[1], parts[2], parts[3]
    if not _TRACE_VERSION_RE.match(version):
        return None
    if version == _TRACE_VERSION_INVALID:
        return None
    if version == TRACEPARENT_VERSION and len(parts) != 4:
        return None
    if not _TRACE_ID_RE.match(trace_id) or not _TRACE_FLAGS_RE.match(flags):
        return None
    if not _SPAN_ID_RE.match(span_id):
        return None
    if trace_id == "0" * TRACE_ID_LENGTH:
        return None
    if span_id == "0" * SPAN_ID_LENGTH:
        return None
    return (trace_id, span_id, flags)


def format_traceparent(
    trace_id: str, span_id: str, flags: str = TRACE_FLAG_SAMPLED
) -> str:
    """Returns the ``traceparent`` value for the fields supplied."""
    return "-".join((TRACEPARENT_VERSION, trace_id, span_id, flags))


def bind_trace_context(
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    flags: str = TRACE_FLAG_SAMPLED,
) -> Any:
    """Binds a trace context to the current task or thread.

    Every record emitted while the context is bound carries its trace
    identifier under ``context.trace_id`` and its span identifier under
    ``context.span_id``. A value that is not a well-formed identifier is
    replaced by a fresh one, so a caller may pass an inbound value
    directly. Returns the token :func:`reset_trace_context` restores the
    previous context with.
    """
    resolved_trace = (
        trace_id
        if isinstance(trace_id, str) and _TRACE_ID_RE.match(trace_id.lower())
        else None
    )
    resolved_span = (
        span_id
        if isinstance(span_id, str) and _SPAN_ID_RE.match(span_id.lower())
        else None
    )
    resolved_flags = (
        flags.lower()
        if isinstance(flags, str) and _TRACE_FLAGS_RE.match(flags.lower())
        else TRACE_FLAG_SAMPLED
    )
    return _TRACE_CONTEXT.set(
        (
            (resolved_trace or new_trace_id()).lower(),
            (resolved_span or new_span_id()).lower(),
            resolved_flags,
        )
    )


def reset_trace_context(token: Any) -> None:
    """Restores the trace context bound before ``token`` was issued."""
    try:
        _TRACE_CONTEXT.reset(token)
    except Exception:
        _TRACE_CONTEXT.set(None)


def current_trace_context() -> Optional[Tuple[str, str, str]]:
    """Returns the trace context bound to the current task, or ``None``."""
    try:
        return _TRACE_CONTEXT.get()
    except Exception:
        return None


def _bound_trace_field(index: int) -> Optional[str]:
    """Returns one field of the bound trace context, or ``None``."""
    bound = current_trace_context()
    if bound is None:
        return None
    try:
        return bound[index]
    except Exception:
        return None


def current_traceparent() -> Optional[str]:
    """Returns the ``traceparent`` value for the bound context."""
    bound = current_trace_context()
    if bound is None:
        return None
    return format_traceparent(bound[0], bound[1], bound[2])


def outbound_trace_headers() -> Dict[str, str]:
    """Returns the trace headers an outbound call carries.

    The mapping holds :data:`TRACEPARENT_HEADER` for the bound context and
    is empty when no context is bound, so a caller may merge it into its
    own header mapping unconditionally.
    """
    header = current_traceparent()
    if header is None:
        return {}
    return {TRACEPARENT_HEADER: header}


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


def _trim_to_limit(value: str) -> str:
    """Returns ``value`` cut to :data:`EXCEPTION_MESSAGE_LIMIT`.

    A cut that lands inside a substituted placeholder removes that
    partial placeholder as well, so the result carries whole
    placeholders only.
    """
    if len(value) <= EXCEPTION_MESSAGE_LIMIT:
        return value
    trimmed = value[:EXCEPTION_MESSAGE_LIMIT]
    tail = trimmed[-(len(REDACTION_PLACEHOLDER) - 1):]
    for length in range(len(tail), 0, -1):
        fragment = tail[-length:]
        if REDACTION_PLACEHOLDER.startswith(fragment):
            return trimmed[:-length]
    return trimmed


def exception_fields(exc: Any) -> Dict[str, Any]:
    """Returns the discrete, safe fields describing ``exc``.

    The fields are the exception's class name, the module that defines
    it, and its message. The message is redacted first and cut to
    :data:`EXCEPTION_MESSAGE_LIMIT` characters afterwards, so a
    credential straddling the cut is rewritten while the pattern that
    matches it is still whole. No traceback, no frame, no source path
    and no local value is included, so the result is safe to emit at any
    level.
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
        fields["exception_message"] = _trim_to_limit(redact(rendered))
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


def _count_emit_failure() -> None:
    global _EMIT_FAILURES
    with _EMIT_FAILURE_LOCK:
        _EMIT_FAILURES += 1


def logging_failure_count() -> int:
    """Returns how many records a handler could not emit.

    A non-zero value means at least one record reached the standard-error
    fallback instead of the configured handler. The record itself was
    still written; the count reports that the primary sink degraded, and
    is the signal a deployment alerts on.
    """
    with _EMIT_FAILURE_LOCK:
        return _EMIT_FAILURES


def reset_logging_failure_count() -> int:
    """Clears the emit-failure count and returns the value it held."""
    global _EMIT_FAILURES
    with _EMIT_FAILURE_LOCK:
        previous = _EMIT_FAILURES
        _EMIT_FAILURES = 0
        return previous


def _safe_record_fields(record: Any) -> Dict[str, Any]:
    """Returns the stable, redacted fields describing ``record``.

    Only the logger name, the level name and the record's own message are
    read, and the message is redacted and cut to
    :data:`EXCEPTION_MESSAGE_LIMIT`. No traceback, no frame, no source
    path, no ``extra`` value and no interpolated argument is included, so
    the result carries nothing the record's own formatting would have
    expanded.
    """
    fields: Dict[str, Any] = {
        "logger": None,
        "level": None,
        "original_message": None,
    }
    try:
        fields["logger"] = str(getattr(record, "name", None))
        fields["level"] = str(getattr(record, "levelname", None))
    except Exception:
        return fields
    try:
        rendered = str(getattr(record, "msg", ""))
    except Exception:
        rendered = ""
    if rendered:
        fields["original_message"] = _trim_to_limit(redact(rendered))
    return fields


def report_emit_failure(record: Any) -> None:
    """Reports that a handler could not emit ``record``.

    Counts the failure and writes one redacted, structured line to
    standard error carrying the logger, the level, the record's redacted
    message and the bound correlation identifiers. The failure signal
    :data:`EMIT_FAILURE_SIGNAL` is carried on that line, so the record is
    neither dropped silently nor written as a raw traceback. Never
    raises.
    """
    _count_emit_failure()
    fields = _safe_record_fields(record)
    fields[SIGNAL_FIELD] = EMIT_FAILURE_SIGNAL
    try:
        fields["log_emit_failures"] = logging_failure_count()
    except Exception:
        fields["log_emit_failures"] = None
    for name, value in (
        (REQUEST_ID_FIELD, current_request_id()),
        (TRACE_ID_FIELD, _bound_trace_field(0)),
        (SPAN_ID_FIELD, _bound_trace_field(1)),
    ):
        if value is not None:
            fields[name] = value
    _emit_fallback(EMIT_FAILURE_MESSAGE, fields)


def _attach_request_id(record: logging.LogRecord) -> None:
    """Attaches the bound correlation identifiers to ``record``.

    The request identifier and the trace context are read from the
    current task or thread, so this must run on the thread that logged
    rather than on the listener thread. A record already carrying one of
    the fields keeps its value, and a failure leaves the record
    untouched.
    """
    try:
        if getattr(record, REQUEST_ID_FIELD, None) is None:
            bound = current_request_id()
            if bound is not None:
                setattr(record, REQUEST_ID_FIELD, bound)
        for name, index in (
            (TRACE_ID_FIELD, 0),
            (SPAN_ID_FIELD, 1),
        ):
            if getattr(record, name, None) is None:
                value = _bound_trace_field(index)
                if value is not None:
                    setattr(record, name, value)
    except Exception:
        return


class RedactingFilter(logging.Filter):
    """Scrubs unsafe values from a record and adds the request id.

    The filter rewrites ``record.msg`` and ``record.args`` in place,
    attaches the bound request identifier when the record carries none,
    and always admits the record. A failure while scrubbing replaces the
    message with the placeholder and drops the arguments.

    On the queue-backed path the identifier is attached earlier, by
    :meth:`QueueDispatchHandler.prepare` on the thread that logged; the
    attachment here covers a record reaching this filter without having
    passed through that handler.
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
        _attach_request_id(record)
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

# Attributes dropped from the emitted context. The ASGI server attaches
# ``color_message`` to its own records: the same message again, carrying
# terminal escape sequences, which is both a duplicate and the one source
# of control characters reaching the sink.
_DISCARDED_RECORD_ATTRS = frozenset(("color_message",))


def _extract_context(record: logging.LogRecord) -> Dict[str, Any]:
    """Collects the redacted fields supplied through ``extra={...}``.

    A field whose name is credential-shaped is replaced outright; every
    other field is walked by :func:`_redact_deep`. A field named in
    :data:`_DISCARDED_RECORD_ATTRS` is left out.
    """
    context: Dict[str, Any] = {}
    for name, value in vars(record).items():
        if name in _RESERVED_RECORD_ATTRS or name.startswith("_"):
            continue
        if name in _DISCARDED_RECORD_ATTRS:
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
    try:
        named = getattr(handler, "name", None)
        if named:
            return str(named)
        return type(handler).__name__
    except Exception:
        return "unknown"


class QueueDispatchHandler(logging.handlers.QueueHandler):
    """Hands a record to the listener queue without rendering it.

    ``prepare`` attaches the bound request identifier and returns the
    record otherwise unchanged: no redaction, no formatting and no
    serialisation happens on the thread that logged. The identifier is
    bound per task and per thread and is read on that thread; the listener
    that drains the queue runs on a thread of its own. The queue is
    drained in the same process, and the record is neither pickled nor
    stripped of its ``exc_info`` and ``extra`` fields.

    A record that finds the queue full is written through ``target``
    inline, on the thread that logged it, and is not discarded.
    """

    def __init__(
        self,
        record_queue: "queue.Queue",
        target: logging.Handler,
    ) -> None:
        super().__init__(record_queue)
        self.target = target

    def prepare(self, record: logging.LogRecord) -> logging.LogRecord:
        """Attaches the bound request identifier and returns ``record``."""
        _attach_request_id(record)
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

    def handleError(self, record: logging.LogRecord) -> None:
        """Reports the failure through the sanitized fallback sink.

        The standard-library implementation is replaced: it writes the
        record's own representation and the raw traceback to standard
        error when ``logging.raiseExceptions`` is set, and discards the
        record otherwise. :func:`report_emit_failure` counts the failure
        and writes one redacted structured line instead.
        """
        report_emit_failure(record)


# Queue every governed logger dispatches through, and the listener
# thread and stream handler that drain it. All three are created together
# by _ensure_listener under _CONFIGURE_LOCK.
_record_queue = None  # type: Optional[queue.Queue]
_listener = None  # type: Optional[logging.handlers.QueueListener]
_stream_handler = None  # type: Optional[logging.Handler]


class RedactingStreamHandler(logging.StreamHandler):
    """Writes a rendered record to a stream, reporting an emit failure.

    The standard-library error path is replaced for the same reason it is
    replaced on :class:`QueueDispatchHandler`: it writes the record's own
    representation and the raw traceback to standard error, or discards
    the record. :func:`report_emit_failure` counts the failure and writes
    one redacted structured line instead.
    """

    def handleError(self, record: logging.LogRecord) -> None:
        """Reports the failure through the sanitized fallback sink."""
        report_emit_failure(record)


def _is_redacting_stream_handler(handler: Any) -> bool:
    """Reports whether ``handler`` writes redacted JSON to a live stream.

    A handler is accepted only when it is a
    :class:`RedactingStreamHandler` carrying an open stream, a
    :class:`RedactingJsonFormatter` and a :class:`RedactingFilter`. The
    reserved name belongs to the queue handler installed on a governed
    logger, not to the stream handler the listener drains to, so no name
    is required here.
    """
    if not isinstance(handler, RedactingStreamHandler):
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
    handler = RedactingStreamHandler(stream=sys.stdout)
    handler.setFormatter(RedactingJsonFormatter())
    handler.addFilter(RedactingFilter())
    return handler


def _thread_is_alive(listener: Any) -> bool:
    thread = getattr(listener, "_thread", None)
    return thread is not None and thread.is_alive()


def _listener_is_running() -> bool:
    return _thread_is_alive(_listener)


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


def _record_stop_failure(reason: str) -> None:
    if reason in _STOP_FAILURES:
        return
    _STOP_FAILURES.append(reason)


def listener_stop_failures() -> Tuple[str, ...]:
    """Returns the reasons a listener shutdown did not complete.

    Each entry names one step of :func:`_stop_listener` that did not
    finish within its bound: the queue did not drain, the sentinel was not
    accepted, or the thread did not exit. A non-empty result means a
    listener thread was left running with its queue undrained, and a
    caller may treat that as a shutdown failure.
    """
    return tuple(_STOP_FAILURES)


def _offer_sentinel(listener: Any, timeout: float) -> bool:
    """Hands ``listener`` its sentinel, waiting at most ``timeout``.

    ``QueueListener.enqueue_sentinel`` puts the sentinel with
    ``put_nowait``, which raises ``queue.Full`` on a queue at capacity, so
    the sentinel is offered here under a bounded wait. Returns True when
    the queue accepted it.
    """
    record_queue = getattr(listener, "queue", None)
    if record_queue is None:
        return False
    sentinel = getattr(listener, "_sentinel", None)
    try:
        if timeout > 0:
            record_queue.put(sentinel, True, timeout)
        else:
            record_queue.put_nowait(sentinel)
    except Exception:
        return False
    return True


def _stop_listener() -> None:
    """Drain and stop the listener using bounded queue, sentinel, and
    thread waits; record any incomplete step.
    """
    global _listener
    listener = _listener
    if not _thread_is_alive(listener):
        _listener = None
        return
    if not flush_log_queue():
        _record_stop_failure(STOP_REASON_NOT_DRAINED)
    if not _offer_sentinel(listener, LISTENER_SENTINEL_TIMEOUT_SECONDS):
        _record_stop_failure(STOP_REASON_SENTINEL_REFUSED)
        return
    thread = getattr(listener, "_thread", None)
    if thread is not None:
        try:
            thread.join(LISTENER_JOIN_TIMEOUT_SECONDS)
        except Exception:
            pass
    if _thread_is_alive(listener):
        _record_stop_failure(STOP_REASON_THREAD_ALIVE)
        return
    try:
        listener._thread = None
    except Exception:
        pass
    _listener = None


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
    """Returns every logger under a governed namespace, roots excluded.

    A governed namespace may itself sit under another -- ``uvicorn.error``
    under ``uvicorn`` -- and such a logger is governed in its own right,
    with its own handler and no propagation, so it is not treated as a
    descendant to be normalized.
    """
    prefixes = tuple(name + "." for name in GOVERNED_LOGGER_NAMES)
    roots = frozenset(GOVERNED_LOGGER_NAMES)
    descendants: List[logging.Logger] = []
    try:
        registry = dict(logging.Logger.manager.loggerDict)
    except Exception:
        return descendants
    for name, entry in registry.items():
        if not isinstance(name, str) or not name.startswith(prefixes):
            continue
        if name in roots:
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


def _governed_namespace_levels() -> Tuple[Tuple[str, int], ...]:
    """Returns each governed namespace outside the base logger and its level.

    The outbound HTTP namespaces are held at
    :data:`THIRD_PARTY_LOG_LEVEL`, which is above the level their request
    records are written at, so a request target never reaches a handler.
    ``alembic`` is held at :data:`MIGRATION_LOG_LEVEL` so each revision's
    own record of what it changed is emitted, and ``sqlalchemy`` at
    :data:`SQL_LOG_LEVEL`, which is above the level its statement records
    are written at. The server namespaces are held at
    :data:`SERVER_LOG_LEVEL`, which admits the access record, and every
    record they carry passes the redaction rules on its way to the
    handler.
    """
    entries: List[Tuple[str, int]] = [
        (name, THIRD_PARTY_LOG_LEVEL) for name in THIRD_PARTY_LOGGER_NAMES
    ]
    for name in MIGRATION_LOGGER_NAMES:
        entries.append(
            (
                name,
                MIGRATION_LOG_LEVEL
                if name == "alembic"
                else SQL_LOG_LEVEL,
            )
        )
    entries.extend(
        (name, SERVER_LOG_LEVEL) for name in SERVER_LOGGER_NAMES
    )
    return tuple(entries)


def _configure_third_party_loggers() -> None:
    """Routes every governed namespace through the redacting handler.

    Each logger named by :func:`_governed_namespace_levels` is held at the
    level recorded there, given the redacting handler and stopped from
    propagating, so its records cannot reach a handler installed
    elsewhere.
    """
    for name, level in _governed_namespace_levels():
        logger = logging.getLogger(name)
        _install_handler(logger)
        logger.setLevel(level)
        logger.propagate = False


def configure_logging(
    level: Optional[Union[int, str]] = None,
) -> logging.Logger:
    """Install one queue-backed redacting handler on each governed logger
    and normalize descendants.
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


def configure_migration_logging() -> logging.Logger:
    """Installs the dispatching handler for the migration namespaces.

    The Alembic environment calls this in place of applying a logging
    configuration file, so every record a revision writes is rendered as
    redacted JSON by the same handler the application uses and reaches no
    handler installed elsewhere. Returns the ``alembic`` logger.
    """
    configure_logging()
    return logging.getLogger(MIGRATION_LOGGER_NAMES[0])


def redirect_log_stream(stream: Any) -> Optional[Any]:
    """Points the installed handler at ``stream`` and returns the previous.

    Used by a process whose standard output carries a product rather than
    diagnostics -- an Alembic ``--sql`` run, whose statement stream is
    that product -- so that its records go elsewhere and the two are not
    interleaved. ``None`` is returned when no handler is installed.
    """
    with _CONFIGURE_LOCK:
        configure_logging()
        if _stream_handler is None:
            return None
        return _stream_handler.setStream(stream)


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
