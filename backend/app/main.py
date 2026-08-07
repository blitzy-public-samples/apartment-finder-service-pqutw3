"""ASGI application assembly, middleware stack and error handling.

This module builds the application. Every request traverses the
following layers, listed from the outermost inbound layer inwards:

* protective response headers applied to every response
* host validation against the configured host allowlist
* a cap on the size of every request body, whatever its content type
* cross-origin access limited to an explicit list of origins, methods
  and request headers
* the request rate limiter that the credential endpoints share

The API router is then mounted at the application root, so every route
keeps the path its own router declares. An unauthenticated liveness
endpoint is exposed at ``/health``, and error handlers return bodies
that carry no internal detail.

The database schema is owned by the Alembic revisions under
``backend/migrations/versions``. Importing this module issues no DDL.

Usage::

    uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
"""

from types import MappingProxyType
from typing import Dict, List, Mapping, Optional, Tuple

from fastapi import FastAPI, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.utils import is_body_allowed_for_status_code
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIASGIMiddleware
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from starlette.datastructures import Headers
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import (
    BaseHTTPMiddleware,
    RequestResponseEndpoint,
)
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.app.core.config import settings
from backend.app.core.logging import get_logger

__all__ = [
    "BODY_TOO_LARGE_DETAIL",
    "CORS_ALLOW_HEADERS",
    "CORS_ALLOW_METHODS",
    "HEALTH_STATUS",
    "INVALID_REQUEST_DETAIL",
    "LOGIN_RATE_LIMIT",
    "REGISTER_RATE_LIMIT",
    "SECURITY_HEADERS",
    "SERVER_ERROR_DETAIL",
    "BodySizeLimitMiddleware",
    "SecurityHeadersMiddleware",
    "app",
    "create_tables",
    "get_db",
    "health_check",
    "http_exception_handler",
    "limiter",
    "unhandled_exception_handler",
    "validation_exception_handler",
]

logger = get_logger(__name__)

#: Response headers set on every response leaving the application.
SECURITY_HEADERS: Mapping[str, str] = MappingProxyType(
    {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": (
            "default-src 'none'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'none'"
        ),
        "Permissions-Policy": (
            "accelerometer=(), ambient-light-sensor=(), autoplay=(), "
            "camera=(), display-capture=(), encrypted-media=(), "
            "geolocation=(), gyroscope=(), magnetometer=(), "
            "microphone=(), midi=(), payment=(), usb=(), "
            "xr-spatial-tracking=()"
        ),
        "Cache-Control": "no-store",
    }
)

#: HTTP methods advertised to cross-origin callers.
CORS_ALLOW_METHODS: Tuple[str, ...] = ("GET", "POST", "OPTIONS")

#: Request headers advertised to cross-origin callers.
CORS_ALLOW_HEADERS: Tuple[str, ...] = (
    "Authorization",
    "Content-Type",
    "Accept",
)

#: Detail returned when a request body exceeds the configured cap.
BODY_TOO_LARGE_DETAIL = "Request body too large"

#: Detail returned when a request body fails schema validation.
INVALID_REQUEST_DETAIL = "Invalid request"

#: Detail returned for an error that reached no dedicated handler.
SERVER_ERROR_DETAIL = "Internal server error"

#: Value reported by the liveness endpoint.
HEALTH_STATUS = "ok"

# Request header carrying the body size the client declares.
_CONTENT_LENGTH_HEADER = "content-length"

# ASGI scope type of an HTTP request.
_HTTP_SCOPE = "http"

# ASGI message type carrying one request-body chunk.
_REQUEST_MESSAGE = "http.request"

# ASGI message type reported once the client has gone away.
_DISCONNECT_MESSAGE = "http.disconnect"

#: Rate limiter keyed by remote address. The credential endpoints
#: decorate their handlers against this object.
limiter = Limiter(key_func=get_remote_address)

#: Rate limit applied to the login endpoint.
LOGIN_RATE_LIMIT = settings.RATE_LIMIT_LOGIN

#: Rate limit applied to the registration endpoint.
REGISTER_RATE_LIMIT = settings.RATE_LIMIT_REGISTER

# Ordering invariant: ``limiter`` is bound above these imports. The
# endpoint modules they reach reference it from this module while this
# module is still initialising.
from backend.app.api.router import api_router  # noqa: E402
from backend.app.db.database import (  # noqa: E402
    Base,
    SessionLocal,
    engine,
)

app = FastAPI()
app.state.limiter = limiter


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    Base.metadata.create_all(bind=engine)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Sets :data:`SECURITY_HEADERS` on every outgoing response."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response


def _declared_body_size(scope: Scope) -> Optional[int]:
    """Returns the body size the request declares, if it declares one.

    Returns ``None`` when the header is absent, unparsable or negative,
    which routes the request to the streaming check instead.
    """
    raw = Headers(scope=scope).get(_CONTENT_LENGTH_HEADER)
    if raw is None:
        return None
    try:
        declared = int(raw)
    except (TypeError, ValueError):
        return None
    if declared < 0:
        return None
    return declared


def _body_too_large_response() -> JSONResponse:
    """Builds the response returned for an oversized request body."""
    return JSONResponse(
        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        content={"detail": BODY_TOO_LARGE_DETAIL},
    )


async def _read_body_within_limit(
    receive: Receive, max_body_bytes: int
) -> Tuple[List[Message], bool]:
    """Reads body messages, stopping once ``max_body_bytes`` is passed.

    Returns the messages read and whether the cap was exceeded. Reading
    stops on the first chunk that carries the running total past the
    cap, so at most that cap plus one chunk is ever held.
    """
    messages: List[Message] = []
    received = 0
    while True:
        message = await receive()
        if message["type"] != _REQUEST_MESSAGE:
            messages.append(message)
            return messages, False
        received += len(message.get("body", b""))
        if received > max_body_bytes:
            return messages, True
        messages.append(message)
        if not message.get("more_body", False):
            return messages, False


def _replay_messages(messages: List[Message]) -> Receive:
    """Returns a receive callable that yields ``messages`` in order."""
    pending = list(messages)

    async def receive() -> Message:
        if pending:
            return pending.pop(0)
        return {"type": _DISCONNECT_MESSAGE}

    return receive


class BodySizeLimitMiddleware:
    """Rejects a request body above ``max_body_bytes`` with HTTP 413.

    A size declared by ``content-length`` is checked before any body is
    read. A request that declares no size, as a chunked request does, is
    read one chunk at a time and abandoned as soon as the running total
    passes the cap. The cap applies to every request on every route,
    whatever content type the body carries.
    """

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != _HTTP_SCOPE:
            await self.app(scope, receive, send)
            return

        declared = _declared_body_size(scope)
        if declared is not None:
            if declared > self.max_body_bytes:
                self._log_rejection(scope, declared)
                response = _body_too_large_response()
                await response(scope, receive, send)
                return
            await self.app(scope, receive, send)
            return

        messages, exceeded = await _read_body_within_limit(
            receive, self.max_body_bytes
        )
        replayed = _replay_messages(messages)
        if exceeded:
            self._log_rejection(scope, None)
            response = _body_too_large_response()
            await response(scope, replayed, send)
            return
        await self.app(scope, replayed, send)

    def _log_rejection(
        self, scope: Scope, declared: Optional[int]
    ) -> None:
        """Records one rejected request body."""
        logger.warning(
            "Request body exceeds the configured cap",
            extra={
                "path": scope.get("path"),
                "method": scope.get("method"),
                "declared_bytes": declared,
                "max_bytes": self.max_body_bytes,
            },
        )


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> Response:
    """Returns the status, detail and headers that ``exc`` carries.

    A deliberate rejection raised by endpoint code keeps its status code
    and its detail, so the messages those endpoints return are
    unchanged. Statuses that permit no body are answered without one.
    """
    logger.warning(
        "Request rejected",
        extra={
            "path": request.scope.get("path"),
            "method": request.scope.get("method"),
            "status_code": exc.status_code,
        },
    )
    headers = getattr(exc, "headers", None)
    if not is_body_allowed_for_status_code(exc.status_code):
        return Response(status_code=exc.status_code, headers=headers)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=headers,
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> Response:
    """Returns a fixed detail for a body that failed validation.

    Only the number of failures is recorded; the rejected values are
    neither returned nor logged.
    """
    logger.warning(
        "Request failed validation",
        extra={
            "path": request.scope.get("path"),
            "method": request.scope.get("method"),
            "error_count": len(exc.errors()),
        },
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": INVALID_REQUEST_DETAIL},
    )


async def unhandled_exception_handler(
    request: Request, exc: Exception
) -> Response:
    """Returns a fixed detail for an error that reached no handler.

    The response carries no exception text, no traceback and no
    identifier of the code that raised. The error itself is recorded
    through the redacting logger. This handler runs outside the
    middleware stack and therefore sets :data:`SECURITY_HEADERS` on the
    response it builds.
    """
    logger.error(
        "Unhandled application error",
        exc_info=exc,
        extra={
            "path": request.scope.get("path"),
            "method": request.scope.get("method"),
        },
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": SERVER_ERROR_DETAIL},
        headers=dict(SECURITY_HEADERS),
    )


app.add_exception_handler(
    StarletteHTTPException, http_exception_handler
)
app.add_exception_handler(
    RequestValidationError, validation_exception_handler
)
app.add_exception_handler(
    RateLimitExceeded, _rate_limit_exceeded_handler
)
app.add_exception_handler(Exception, unhandled_exception_handler)

# Registered innermost first: the layer added last is the first to run
# on an inbound request. The resulting inbound order is response
# headers, host validation, body-size cap, cross-origin policy, rate
# limiter, router.
app.add_middleware(SlowAPIASGIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=list(CORS_ALLOW_METHODS),
    allow_headers=list(CORS_ALLOW_HEADERS),
)
app.add_middleware(
    BodySizeLimitMiddleware,
    max_body_bytes=settings.MAX_REQUEST_BODY_BYTES,
)
app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS
)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(api_router)


@app.get("/health")
def health_check() -> Dict[str, str]:
    """Reports that the process is able to serve requests."""
    return {"status": HEALTH_STATUS}
