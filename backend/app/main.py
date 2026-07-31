import logging
import os
import traceback
import uuid
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError, StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from backend.app.api.endpoints.auth import limiter
from backend.app.api.router import api_router
from backend.app.core.config import settings
from backend.app.db.database import engine, SessionLocal
from backend.app.db.models import Base

logger = logging.getLogger(__name__)

app = FastAPI()

# SEC-07: registers the single login throttle limiter defined in auth.py
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    # SEC-11: the owner role provisions schema objects; this call issues DDL
    # only for absent tables and the application role holds no CREATE
    Base.metadata.create_all(bind=engine, checkfirst=True)

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

# SEC-08: server-log diagnostics are built from exception types and frame
# locations only; exception messages carry SQL text, bound parameters,
# credentials and tokens (CWE-209, CWE-532)
_MAX_LOGGED_CAUSES = 4
_MAX_LOGGED_FRAMES = 6
_APPLICATION_ROOT = os.path.dirname(os.path.abspath(__file__))


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
    # SEC-08: frame locations with source lookup disabled, so neither source
    # text nor frame locals can reach the record. The innermost application
    # frame is kept alongside the innermost frames overall.
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
        parts = [str(part) for part in error.get("loc", ())]
        if len(parts) > 1 and parts[0] in _REQUEST_LOCATIONS:
            parts = parts[1:]
        name = ".".join(parts)
        if name and name not in names:
            names.append(name)
    return names


def handle_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    error_id = uuid.uuid4().hex
    fields = _validation_field_names(exc.errors())
    logger.warning(
        "error_id=%s validation rejected %s %s fields=%s",
        error_id, request.method, request.url.path, fields,
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
    # audit context, so a throttled or rejected attempt is traceable from
    # the client reference alone.
    error_id = uuid.uuid4().hex
    logger.warning(
        "error_id=%s http_exception status=%s on %s %s detail=%r%s",
        error_id, exc.status_code, request.method, request.url.path,
        exc.detail, _audit_context(exc),
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_envelope(_status_phrase(exc.status_code), error_id),
        headers=exc.headers,
    )


def handle_rate_limit_exceeded(
    request: Request, exc: RateLimitExceeded
) -> JSONResponse:
    # SEC-07: throttled attempts are logged, not silently dropped
    error_id = uuid.uuid4().hex
    logger.warning(
        "error_id=%s rate limit exceeded limit=%s on %s %s",
        error_id, exc.detail, request.method, request.url.path,
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
    # SEC-08: withholds bound parameter values and driver message text, which
    # carry credentials and column values (CWE-532); records the exception
    # type chain, SQLSTATE, frame locations, the route and the correlation id
    error_id = uuid.uuid4().hex
    if hasattr(exc, "hide_parameters"):
        exc.hide_parameters = True
    logger.error(
        "error_id=%s database error on %s %s exception=%s sqlstate=%s"
        " origin=%s",
        error_id, request.method, request.url.path,
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
    # SEC-08: an arbitrary exception message can carry a token, a key or a
    # personal identifier, so only types and frame locations are recorded
    error_id = uuid.uuid4().hex
    logger.error(
        "error_id=%s unhandled exception on %s %s exception=%s origin=%s",
        error_id, request.method, request.url.path,
        _exception_chain(exc), _exception_origin(exc),
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