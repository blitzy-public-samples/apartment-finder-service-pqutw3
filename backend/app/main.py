import logging
import os
import re
import sys
import traceback
import uuid
from http import HTTPStatus
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError, StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy.exc import SQLAlchemyError
from backend.app.api.endpoints.auth import limiter
from backend.app.api.router import api_router
from backend.app.core.config import settings
from backend.app.db.database import engine
from backend.app.db.models import Base

logger = logging.getLogger(__name__)

# SEC-08: the package logger every application record propagates through
_APPLICATION_LOGGER_NAME = "backend.app"

# SEC-08: the level and the shape of a record on the diagnostic channel
_LOG_LEVEL = logging.INFO
_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"

# SEC-08: what replaces a newline inside one record
_JOINED_LINE_MARKER = "\\n"


class _SingleLineFormatter(logging.Formatter):
    # SEC-08: one record occupies one line. A traceback split across
    # lines loses the correlation identifier a line-oriented collector
    # files it under (CWE-778).
    def format(self, record: logging.LogRecord) -> str:
        return super().format(record).replace("\n", _JOINED_LINE_MARKER)


class _ApplicationLogHandler(logging.StreamHandler):
    # SEC-08: the diagnostic-channel handler this module owns
    pass


def _configure_application_logging() -> None:
    # SEC-08: the server configures its own loggers and leaves this
    # package on logging.lastResort, which emits the message alone -
    # no level, no timestamp, no logger name (CWE-778)
    application_logger = logging.getLogger(_APPLICATION_LOGGER_NAME)
    application_logger.setLevel(_LOG_LEVEL)
    for handler in application_logger.handlers:
        if isinstance(handler, _ApplicationLogHandler):
            return
    handler = _ApplicationLogHandler(stream=sys.stderr)
    handler.setLevel(_LOG_LEVEL)
    handler.setFormatter(_SingleLineFormatter(_LOG_FORMAT))
    application_logger.addHandler(handler)


_configure_application_logging()

app = FastAPI()

# SEC-07: registers the single login throttle limiter defined in auth.py
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

def create_tables():
    # SEC-11: issues DDL for absent tables only. Against a database
    # provisioned by scripts/setup_dev_environment.sh every table already
    # exists and is owned by the owner role, so the runtime role reaches this
    # call holding no CREATE on the schema. An unprovisioned PostgreSQL
    # database fails closed here with InsufficientPrivilege.
    Base.metadata.create_all(bind=engine, checkfirst=True)


class SanitizedServerErrorMiddleware:
    # SEC-08: answers an unhandled exception with the sanitized envelope from
    # inside the CORS layer (CWE-209)
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def send_started(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, send_started)
        except Exception as exc:
            # SEC-08: a partially sent response cannot be replaced; the
            # framework boundary outside this layer completes it
            if started:
                raise
            response = handle_unhandled_exception(
                Request(scope, receive), exc
            )
            await response(scope, receive, send)


# SEC-08: registered before CORSMiddleware, which places this layer inside it
app.add_middleware(SanitizedServerErrorMiddleware)

# HUMAN ASSISTANCE NEEDED
# The following setup section has a confidence level below 0.8 and may need review
# Application setup and configuration
# SEC-03: explicit method/header allow-list; closes the
# wildcard-with-credentials CORS policy (CWE-942, CWE-346)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Accept", "Authorization", "Content-Type"],
    max_age=600,
)

app.include_router(api_router)

create_tables()

# SEC-08: uniform sanitized error envelope; keeps tracebacks, driver text,
# SQL and file paths out of every error response (CWE-209, CWE-497)
_REQUEST_LOCATIONS = ("body", "query", "path", "header", "cookie")
_GENERIC_SERVER_DETAIL = "Internal server error"

# SEC-08: a request path and a request method are client-supplied text. A
# record names the matched route template and a served verb, so a token
# or an address carried in the request line reaches no record (CWE-532).
_UNMATCHED_ROUTE = "<unmatched>"
_UNSERVED_METHOD = "<method>"
_SERVED_METHODS = frozenset({"GET", "HEAD", "POST", "OPTIONS"})

# SEC-08: pydantic reports an undeclared key by name, and that name is
# submitted text. A record names the position and withholds the key.
_UNDECLARED_ERROR_TYPES = ("value_error.extra", "extra_forbidden")
_UNDECLARED_FIELD = "<undeclared>"
_MAX_LOGGED_FIELDS = 8
_MAX_LOGGED_NAME_LENGTH = 40

# SEC-08: the client reference and the server diagnostics are two
# channels joined by one correlation identifier. The type chain and the
# frame summary below are the indexable part of a record.
_MAX_LOGGED_CAUSES = 4
_MAX_LOGGED_FRAMES = 6
_APPLICATION_ROOT = os.path.dirname(os.path.abspath(__file__))

# SEC-08: bounds on the cause chain a formatted report is scrubbed
# against, and the shortest provider text worth removing from it
_MAX_RENDERED_MEMBERS = 16
_MIN_DRIVER_TEXT_LENGTH = 4

# SEC-08: a diagnostic record carries the formatted traceback, which
# quotes exception messages. Held secrets and secret-shaped text are
# removed from it before it reaches a log handler (CWE-209, CWE-532).
_REDACTED = "[redacted]"
_MIN_SECRET_LENGTH = 8
_SECRET_SETTING_NAMES = (
    "SECRET_KEY",
    "PAYPAL_CLIENT_SECRET",
    "SENDGRID_API_KEY",
    "ZILLOW_API_KEY",
)
_SECRET_SHAPES = (
    # a JSON Web Token in compact serialization
    (
        re.compile(
            r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"
        ),
        _REDACTED,
    ),
    # the password component of a URL or a database connection string
    (
        re.compile(r"(://[^\s:/@]+:)[^\s@]+(@)"),
        r"\g<1>" + _REDACTED + r"\g<2>",
    ),
    # the credential carried by an HTTP bearer authorization scheme
    (
        re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
        r"\g<1>" + _REDACTED,
    ),
    # a credential named in assignment, keyword or mapping syntax. The name
    # match ends an identifier: signing_key, client_secret and api-token are
    # covered alongside key, secret and token. The lookahead skips a value
    # a previous pattern already replaced; one marker per value.
    (
        re.compile(
            r"(?i)([A-Za-z0-9_.\-]*(?:pass(?:word|wd|phrase)?|secret"
            r"|token|key|credential|auth(?:orization)?|cookie)"
            r"[\"']?\s*[:=]\s*)"
            r"(?!\[redacted\])"
            r"('[^']*'|\"[^\"]*\"|[^\s,;)}\]]+)"
        ),
        r"\g<1>" + _REDACTED,
    ),
)


def _error_envelope(detail: str, error_id: str, fields=()) -> dict:
    return {"detail": detail, "error_id": error_id, "fields": list(fields)}


def _status_phrase(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return "Request failed"


def _route_label(request: Request) -> str:
    # SEC-08: the template of the matched route, never the request path.
    # A path carries whatever the caller put in the request line, which a
    # link sent to a victim can make a token or an address (CWE-532).
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    if isinstance(template, str) and template:
        return template
    return _UNMATCHED_ROUTE


def _method_label(request: Request) -> str:
    # SEC-08: a served verb; an unserved method is caller-supplied text
    method = request.method
    if method in _SERVED_METHODS:
        return method
    return _UNSERVED_METHOD


def _exception_type(exc: BaseException) -> str:
    # SEC-08: the qualified type name, never str(exc)
    exc_type = type(exc)
    module = getattr(exc_type, "__module__", "") or ""
    if module in ("", "builtins"):
        return exc_type.__name__
    return "%s.%s" % (module, exc_type.__name__)


def _exception_chain(exc: BaseException) -> str:
    # SEC-08: type names along the cause chain, including a DBAPI driver
    # error reached through SQLAlchemy's orig attribute
    names = []
    seen = set()
    current = exc
    while (
        isinstance(current, BaseException)
        and id(current) not in seen
        and len(names) < _MAX_LOGGED_CAUSES
    ):
        seen.add(id(current))
        names.append(_exception_type(current))
        current = (
            getattr(current, "orig", None)
            or current.__cause__
            or current.__context__
        )
    return "<-".join(names)


def _exception_origin(exc: BaseException) -> str:
    # SEC-08: a compact single-line frame summary for indexing, with source
    # lookup disabled. The innermost application frame is kept alongside the
    # innermost frames overall.
    frames = traceback.StackSummary.extract(
        traceback.walk_tb(exc.__traceback__), lookup_lines=False
    )
    selected = frames[-_MAX_LOGGED_FRAMES:]
    application = [
        frame for frame in frames
        if os.path.abspath(frame.filename).startswith(_APPLICATION_ROOT)
    ]
    if application and application[-1] not in selected:
        selected = [application[-1]] + selected
    return ";".join(
        "%s:%s:%s" % (frame.filename, frame.lineno, frame.name)
        for frame in selected
    )


def _dsn_password(url: str) -> str:
    # SEC-08: the credential a connection string carries inline
    try:
        return urlsplit(url).password or ""
    except ValueError:
        return ""


def _secret_literals() -> tuple:
    # SEC-08: the values this process holds that no record may quote
    values = [
        getattr(settings, name, None) for name in _SECRET_SETTING_NAMES
    ]
    values.append(_dsn_password(str(settings.DATABASE_URL or "")))
    literals = {
        str(value)
        for value in values
        if value and len(str(value)) >= _MIN_SECRET_LENGTH
    }
    # SEC-08: longest first; a shorter secret nested in a longer one leaves
    # no remainder of the longer one in the record
    return tuple(sorted(literals, key=len, reverse=True))


def _redact(text: str) -> str:
    # SEC-08: removes held secrets and secret-shaped text (CWE-532)
    for literal in _secret_literals():
        text = text.replace(literal, _REDACTED)
    for pattern, replacement in _SECRET_SHAPES:
        text = pattern.sub(replacement, text)
    return text


def _exception_members(exc: BaseException) -> list:
    # SEC-08: every exception a formatted report renders - the raised one
    # plus its driver origin, its cause and its context
    members = []
    seen = set()
    pending = [exc]
    while pending and len(members) < _MAX_RENDERED_MEMBERS:
        current = pending.pop(0)
        if not isinstance(current, BaseException) or id(current) in seen:
            continue
        seen.add(id(current))
        members.append(current)
        pending.extend(
            [
                getattr(current, "orig", None),
                current.__cause__,
                current.__context__,
            ]
        )
    return members


def _driver_literals(exc: BaseException) -> tuple:
    # SEC-08: the provider-supplied text a database exception renders -
    # the driver message, whose diagnostic lines quote the column value
    # that failed, and the statement that carried it (CWE-532)
    literals = set()
    for member in _exception_members(exc):
        if not isinstance(member, SQLAlchemyError):
            continue
        origin = getattr(member, "orig", None)
        if isinstance(origin, BaseException):
            message = str(origin)
            literals.add(message)
            literals.update(message.splitlines())
        statement = getattr(member, "statement", None)
        if isinstance(statement, str):
            literals.add(statement)
    return tuple(
        sorted(
            (
                literal.strip()
                for literal in literals
                if len(literal.strip()) >= _MIN_DRIVER_TEXT_LENGTH
            ),
            key=len,
            reverse=True,
        )
    )


def _suppress_bound_parameters(exc: BaseException) -> None:
    # SEC-08: a rendered database exception quotes the parameters it bound,
    # which are the row values the caller submitted. Every member of the
    # chain is suppressed, because a driver failure caught and re-raised as
    # an ordinary error is still rendered through its context (CWE-532).
    for member in _exception_members(exc):
        if hasattr(member, "hide_parameters"):
            member.hide_parameters = True


def _diagnostics(exc: BaseException) -> str:
    # SEC-08: the full formatted traceback, including the stack, the
    # exception messages and the cause chain, with held secrets, bound
    # parameters and provider message text removed
    _suppress_bound_parameters(exc)
    report = "".join(
        traceback.format_exception(type(exc), exc, exc.__traceback__)
    )
    for literal in _driver_literals(exc):
        report = report.replace(literal, _REDACTED)
    return _redact(report)


def _audit_context(exc: BaseException) -> str:
    # SEC-08: appends only the redacted markers an exception publishes on
    # its audit_context mapping; raised detail and exception text are never
    # promoted into the record
    context = getattr(exc, "audit_context", None)
    if not isinstance(context, dict):
        return ""
    return "".join(
        " %s=%s" % (key, context[key]) for key in sorted(context)
    )


def _error_location(error) -> tuple:
    # SEC-08: the field path one rejection names, with the request
    # location prefix removed
    location = tuple(error.get("loc", ()))
    if len(location) > 1 and location[0] in _REQUEST_LOCATIONS:
        location = location[1:]
    return location


def _measures_the_body(location) -> bool:
    # SEC-08: a body that is not JSON is located by a byte offset rather
    # than a field; the offset measures the submitted content (CWE-209)
    return len(location) == 1 and isinstance(location[0], int)


def _validation_field_names(errors) -> list:
    # SEC-08: emits field paths only; withholds the submitted values
    # carried by msg, ctx and input
    names = []
    for error in errors:
        location = _error_location(error)
        if _measures_the_body(location):
            continue
        name = ".".join(str(part) for part in location)
        if name and name not in names:
            names.append(name)
    return names


def _loggable_field_names(errors) -> str:
    # SEC-08: the record carries schema-declared names only. An
    # undeclared key is text the caller chose, so its position is named
    # and the key itself withheld; the list is bounded in count and in
    # the length of each name (CWE-532).
    names = []
    for error in errors:
        location = _error_location(error)
        if _measures_the_body(location):
            continue
        parts = [str(part)[:_MAX_LOGGED_NAME_LENGTH] for part in location]
        if parts and str(error.get("type", "")) in _UNDECLARED_ERROR_TYPES:
            parts[-1] = _UNDECLARED_FIELD
        name = ".".join(parts)
        if name and name not in names:
            names.append(name)
    kept = names[:_MAX_LOGGED_FIELDS]
    rendered = ",".join(kept)
    withheld = len(names) - len(kept)
    if withheld > 0:
        rendered = "{0},+{1}".format(rendered, withheld)
    return rendered


def handle_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    # SEC-08: a field path is submitted content; the rendered name list
    # passes through the same redaction the diagnostic channel applies
    error_id = uuid.uuid4().hex
    errors = exc.errors()
    fields = _validation_field_names(errors)
    logger.warning(
        "error_id=%s validation rejected %s %s fields=%s count=%s",
        error_id, _method_label(request), _route_label(request),
        _redact(_loggable_field_names(errors)), len(errors),
    )
    return JSONResponse(
        status_code=422,
        content=_error_envelope(
            "Request validation failed", error_id, fields
        ),
    )


def handle_http_exception(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    # SEC-08: preserves the raised status and replaces the raised detail.
    # One record carries the response error_id and the raiser's redacted
    # audit context; a throttled or rejected attempt is traceable from the
    # client reference alone. The diagnostic channel opens at 500 (CWE-209).
    error_id = uuid.uuid4().hex
    server_fault = exc.status_code >= 500
    diagnostics = (
        "\ndiagnostics:\n%s" % _diagnostics(exc) if server_fault else ""
    )
    emit = logger.error if server_fault else logger.warning
    emit(
        "error_id=%s http_exception status=%s on %s %s detail=%s%s%s",
        error_id, exc.status_code, _method_label(request),
        _route_label(request), _redact(repr(exc.detail)),
        _audit_context(exc), diagnostics,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_envelope(_status_phrase(exc.status_code), error_id),
        headers=exc.headers,
    )


def handle_rate_limit_exceeded(
    request: Request, exc: RateLimitExceeded
) -> JSONResponse:
    # SEC-07: throttled attempts are logged, not silently dropped. The
    # record carries the response status, matching the record the
    # account-keyed layer produces through handle_http_exception.
    error_id = uuid.uuid4().hex
    logger.warning(
        "error_id=%s rate limit exceeded status=429 limit=%s on %s %s",
        error_id, _redact(str(exc.detail)), _method_label(request),
        _route_label(request),
    )
    return JSONResponse(
        status_code=429,
        content=_error_envelope(_status_phrase(429), error_id),
    )


def _driver_error_code(exc: SQLAlchemyError) -> str:
    # SEC-08: SQLSTATE identifies the failure without carrying a column value
    origin = getattr(exc, "orig", None)
    code = getattr(origin, "pgcode", None) or getattr(origin, "sqlstate", None)
    return str(code) if code else "none"


def handle_database_error(
    request: Request, exc: SQLAlchemyError
) -> JSONResponse:
    # SEC-08: records the exception type chain, the driver exception type
    # inside it, SQLSTATE, frame locations, the matched route and the
    # correlation id. No provider message text and no bound parameter
    # reaches the record: a driver diagnostic quotes the column value
    # that failed, and the statement quotes the row it wrote (CWE-532).
    error_id = uuid.uuid4().hex
    _suppress_bound_parameters(exc)
    logger.error(
        "error_id=%s database error on %s %s exception=%s sqlstate=%s"
        " origin=%s",
        error_id, _method_label(request), _route_label(request),
        _exception_chain(exc), _driver_error_code(exc),
        _exception_origin(exc),
    )
    return JSONResponse(
        status_code=500,
        content=_error_envelope(_GENERIC_SERVER_DETAIL, error_id),
    )


def handle_unhandled_exception(
    request: Request, exc: Exception
) -> JSONResponse:
    # SEC-08: the caller receives a reference; this record carries the
    # diagnostics that reference resolves to - the type chain, the frame
    # locations and the redacted traceback with its exception messages
    error_id = uuid.uuid4().hex
    logger.error(
        "error_id=%s unhandled exception on %s %s exception=%s origin=%s"
        "\ndiagnostics:\n%s",
        error_id, _method_label(request), _route_label(request),
        _exception_chain(exc), _exception_origin(exc), _diagnostics(exc),
    )
    return JSONResponse(
        status_code=500,
        content=_error_envelope(_GENERIC_SERVER_DETAIL, error_id),
    )


app.add_exception_handler(RequestValidationError, handle_validation_error)
app.add_exception_handler(StarletteHTTPException, handle_http_exception)
app.add_exception_handler(RateLimitExceeded, handle_rate_limit_exceeded)
app.add_exception_handler(SQLAlchemyError, handle_database_error)
app.add_exception_handler(Exception, handle_unhandled_exception)