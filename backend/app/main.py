import logging
import os
import re
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

app = FastAPI()

# SEC-07: registers the single login throttle limiter defined in auth.py
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

def create_tables():
    # SEC-11: the owner role provisions schema objects; this call issues DDL
    # only for absent tables and the application role holds no CREATE
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

# SEC-08: the client reference and the server diagnostics are two
# channels joined by one correlation identifier. The type chain and the
# frame summary below are the indexable part of a record.
_MAX_LOGGED_CAUSES = 4
_MAX_LOGGED_FRAMES = 6
_APPLICATION_ROOT = os.path.dirname(os.path.abspath(__file__))

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


def _diagnostics(exc: BaseException) -> str:
    # SEC-08: the full formatted traceback, including the stack, the
    # exception messages and the cause chain, with secrets removed
    report = "".join(
        traceback.format_exception(type(exc), exc, exc.__traceback__)
    )
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


def _validation_field_names(errors) -> list:
    # SEC-08: emits field paths only; withholds the submitted values
    # carried by msg, ctx and input
    names = []
    for error in errors:
        location = tuple(error.get("loc", ()))
        if len(location) > 1 and location[0] in _REQUEST_LOCATIONS:
            location = location[1:]
        # SEC-08: a body that is not JSON is located by a byte offset rather
        # than a field; the offset measures the submitted content (CWE-209)
        if len(location) == 1 and isinstance(location[0], int):
            continue
        name = ".".join(str(part) for part in location)
        if name and name not in names:
            names.append(name)
    return names


def handle_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    # SEC-08: a field path is submitted content; the rendered path list
    # passes through the same redaction the diagnostic channel applies
    error_id = uuid.uuid4().hex
    fields = _validation_field_names(exc.errors())
    logger.warning(
        "error_id=%s validation rejected %s %s fields=%s",
        error_id, request.method, request.url.path,
        _redact("%s" % (fields,)),
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
    # client reference alone. The diagnostic channel opens at 500. A 4xx
    # traceback quotes the rejected request, and the caller already holds
    # the client fault a 4xx states (CWE-209).
    error_id = uuid.uuid4().hex
    server_fault = exc.status_code >= 500
    diagnostics = (
        "\ndiagnostics:\n%s" % _diagnostics(exc) if server_fault else ""
    )
    emit = logger.error if server_fault else logger.warning
    emit(
        "error_id=%s http_exception status=%s on %s %s detail=%s%s%s",
        error_id, exc.status_code, request.method, request.url.path,
        _redact(repr(exc.detail)), _audit_context(exc), diagnostics,
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
        error_id, _redact(str(exc.detail)), request.method,
        request.url.path,
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
    # SEC-08: records the exception type chain, SQLSTATE, frame locations,
    # the route, the correlation id and the redacted traceback. Bound
    # parameter values are suppressed at the driver boundary and held
    # secrets are removed from the traceback (CWE-532).
    error_id = uuid.uuid4().hex
    if hasattr(exc, "hide_parameters"):
        exc.hide_parameters = True
    logger.error(
        "error_id=%s database error on %s %s exception=%s sqlstate=%s"
        " origin=%s\ndiagnostics:\n%s",
        error_id, request.method, request.url.path,
        _exception_chain(exc), _driver_error_code(exc),
        _exception_origin(exc), _diagnostics(exc),
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
        error_id, request.method, request.url.path,
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