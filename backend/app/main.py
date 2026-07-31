import logging
import uuid
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException
from backend.app.api.router import api_router
from backend.app.core.config import settings
from backend.app.db.database import engine, SessionLocal
from backend.app.db.models import Base

logger = logging.getLogger(__name__)

app = FastAPI()

# SEC-07: per-address login throttle; bounds credential-guessing attempts
# (CWE-307). Counters are in-process and per worker.
LOGIN_RATE_LIMIT = (
    f"{settings.LOGIN_RATE_LIMIT_ATTEMPTS}"
    f"/{settings.LOGIN_RATE_LIMIT_WINDOW_MINUTES} minutes"
)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    Base.metadata.create_all(bind=engine)

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


def _error_envelope(detail: str, error_id: str, fields=()) -> dict:
    return {"detail": detail, "error_id": error_id, "fields": list(fields)}


def _status_phrase(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return "Request failed"


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
    # SEC-08: preserves the raised status and replaces the raised detail
    error_id = uuid.uuid4().hex
    logger.warning(
        "error_id=%s http_exception status=%s on %s %s detail=%r",
        error_id, exc.status_code, request.method, request.url.path,
        exc.detail,
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


def handle_database_error(
    request: Request, exc: SQLAlchemyError
) -> JSONResponse:
    error_id = uuid.uuid4().hex
    logger.error(
        "error_id=%s database error on %s %s",
        error_id, request.method, request.url.path, exc_info=exc,
    )
    return JSONResponse(
        status_code=500,
        content=_error_envelope(_GENERIC_SERVER_DETAIL, error_id),
    )


def handle_unhandled_exception(
    request: Request, exc: Exception
) -> JSONResponse:
    error_id = uuid.uuid4().hex
    logger.error(
        "error_id=%s unhandled exception on %s %s",
        error_id, request.method, request.url.path, exc_info=exc,
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