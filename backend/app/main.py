"""ASGI application assembly, middleware stack and error handling.

This module builds the application. The API router is mounted at the
application root, so every route keeps the path its own router declares.

Every request traverses the following layers, listed from the outermost
inbound layer inwards:

* a request identifier, taken from the inbound
  :data:`REQUEST_ID_HEADER` when it carries one and generated otherwise,
  bound for the duration of the request and returned on every response
* protective response headers applied to every response
* host validation against the configured host allowlist
* cross-origin access limited to an explicit list of origins, methods
  and request headers
* the request rate limiter that the credential endpoints share,
  evaluated here before any part of the request body is read
* a cap on the size and on the chunk count of every request body,
  whatever its content type, applied as the body streams rather than by
  buffering it

Cross-origin access sits outside the body-size cap and the host check so
that the responses those two layers generate themselves -- ``413`` and
``400`` -- carry the same cross-origin headers as any other response,
and an allowed browser origin therefore sees the documented JSON rather
than an opaque network failure.

One response is produced outside every layer above: the catch-all
handler for an error that reached no other handler runs in the server's
outermost error layer, which no application middleware can wrap. That
handler therefore sets both :data:`SECURITY_HEADERS` and, for an origin
on the configured list, the same credentialed cross-origin headers the
cross-origin layer would have set. No wildcard origin is ever emitted.

The API router is then mounted at the application root, so every route
keeps the path its own router declares. An unauthenticated liveness
endpoint is exposed at ``/health``, and error handlers return bodies
that carry no internal detail.

The request identifier is carried on every structured record emitted
while the request is being served, including the records the outbound
PayPal calls and the authorization decisions emit, so one transaction is
joinable from the inbound rejection to the provider call it caused. It is
also returned in the body of a ``500`` response as a support handle.

A rejection already written to the audit trail by the code that raised it
is marked, and :func:`http_exception_handler` leaves it at that one
record rather than adding a second. A throttling decision and an error
that reached no dedicated handler are each recorded once, the latter as
the exception's type, defining module and redacted message rather than a
traceback.

The shared asynchronous HTTP client the PayPal integration issues its
calls through is opened when the application starts and closed when it
stops.
The shared PayPal HTTP client is closed and the log queue is drained
when the server stops.

The database schema is owned by the Alembic revisions under
``backend/migrations/versions``. This module issues no DDL, exposes no
schema-creation entry point, and holds no engine or session factory of
its own: a route that needs a session declares
:func:`backend.app.db.database.get_db`.

Usage::

    uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
"""

import uuid
from contextlib import asynccontextmanager
from types import MappingProxyType
from typing import (
    AsyncIterator,
    Callable,
    Dict,
    Mapping,
    Optional,
    Tuple,
)

from fastapi import FastAPI, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.utils import is_body_allowed_for_status_code
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import (
    BaseHTTPMiddleware,
    RequestResponseEndpoint,
)
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Match
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.app.core.config import LOCAL_ENVIRONMENT, settings
from backend.app.core.logging import (
    bind_request_id,
    current_request_id,
    flush_log_queue,
    get_logger,
    is_audited,
    log_exception,
    reset_request_id,
    unredacted_handler_names,
)

__all__ = [
    "BODY_TOO_LARGE_DETAIL",
    "CORS_ALLOW_CREDENTIALS_HEADER",
    "CORS_ALLOW_HEADERS",
    "CORS_ALLOW_METHODS",
    "CORS_ALLOW_ORIGIN_HEADER",
    "DOCS_PATH",
    "DOCUMENTATION_ENABLED",
    "HEALTH_STATUS",
    "INVALID_REQUEST_DETAIL",
    "OPENAPI_PATH",
    "REDOC_PATH",
    "REQUEST_ID_FIELD",
    "REQUEST_ID_HEADER",
    "REQUEST_ID_MAX_LENGTH",
    "MIN_BODY_MESSAGES",
    "MIN_CHUNK_BYTES",
    "REASON_BYTE_COUNT",
    "REASON_DECLARED_SIZE",
    "REASON_MESSAGE_COUNT",
    "SECURITY_HEADERS",
    "SERVER_ERROR_DETAIL",
    "THROTTLED_MESSAGE",
    "BodySizeLimitMiddleware",
    "RequestIdMiddleware",
    "RateLimitGateMiddleware",
    "SecurityHeadersMiddleware",
    "app",
    "health_check",
    "http_exception_handler",
    "limiter",
    "rate_limit_exceeded_handler",
    "unhandled_exception_handler",
    "validation_exception_handler",
]

logger = get_logger(__name__)

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

CORS_ALLOW_METHODS: Tuple[str, ...] = ("GET", "POST", "OPTIONS")

CORS_ALLOW_HEADERS: Tuple[str, ...] = (
    "Authorization",
    "Content-Type",
    "Accept",
)

#: Response header naming the single origin a response is shared with.
CORS_ALLOW_ORIGIN_HEADER = "Access-Control-Allow-Origin"

#: Response header permitting a credentialed cross-origin response.
CORS_ALLOW_CREDENTIALS_HEADER = "Access-Control-Allow-Credentials"

# Request header naming the origin a browser is calling from.
_ORIGIN_HEADER = "origin"

# Response header naming what a cached response varies by.
_VARY_HEADER = "Vary"

# Value set on CORS_ALLOW_CREDENTIALS_HEADER.
_CREDENTIALS_ALLOWED = "true"

#: Detail returned when a request body exceeds the configured cap.
BODY_TOO_LARGE_DETAIL = "Request body too large"

INVALID_REQUEST_DETAIL = "Invalid request"

SERVER_ERROR_DETAIL = "Internal server error"

HEALTH_STATUS = "ok"

#: Path the interactive documentation is published at.
DOCS_PATH = "/docs"

#: Path the alternative documentation viewer is published at.
REDOC_PATH = "/redoc"

#: Path the OpenAPI schema is published at.
OPENAPI_PATH = "/openapi.json"

#: Whether the interactive documentation and the schema are published.
#: True only while ``ENVIRONMENT`` names the local environment, so a
#: deployed run publishes neither the schema nor a viewer for it.
DOCUMENTATION_ENABLED = settings.ENVIRONMENT == LOCAL_ENVIRONMENT

#: Header the request identifier is read from and returned on.
REQUEST_ID_HEADER = "X-Request-ID"

#: Body and record field carrying the request identifier.
REQUEST_ID_FIELD = "request_id"

#: Longest inbound identifier accepted before one is generated instead.
REQUEST_ID_MAX_LENGTH = 64

#: Message of the record emitted for a throttled request.
THROTTLED_MESSAGE = "Request throttled"

# Characters an inbound request identifier may carry.
_REQUEST_ID_ALPHABET = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789-_."
)
#: Chunk size the message allowance is derived from. A body sent in
#: smaller pieces is refused once it passes that allowance.
MIN_CHUNK_BYTES = 512

#: Fewest body messages accepted whatever the configured byte cap.
MIN_BODY_MESSAGES = 64

#: Rejection reason: the declared ``content-length`` exceeds the cap.
REASON_DECLARED_SIZE = "declared_size"

#: Rejection reason: the streamed byte total exceeded the cap.
REASON_BYTE_COUNT = "byte_count"

#: Rejection reason: the body message count exceeded its allowance.
REASON_MESSAGE_COUNT = "message_count"

# Request header carrying the body size the client declares.
_CONTENT_LENGTH_HEADER = "content-length"

_HTTP_SCOPE = "http"

_REQUEST_MESSAGE = "http.request"

# Request-state attribute the limiter sets to the limit it evaluated.
_EVALUATED_LIMIT_ATTRIBUTE = "view_rate_limit"

# Request-state attribute marking a request already counted, which the
# endpoint decorators read so that one request is counted once.
_COUNTED_ATTRIBUTE = "_rate_limiting_complete"

# ASGI message type carrying the response status and headers.
_RESPONSE_START_MESSAGE = "http.response.start"

# ``limiter`` is defined by the credential endpoints and is bound to
# ``app.state.limiter`` below.
from backend.app.api.endpoints.auth import limiter  # noqa: E402
from backend.app.api.router import api_router  # noqa: E402
from backend.app.services.paypal_service import (  # noqa: E402
    close_http_client,
    open_http_client,
)


@asynccontextmanager
async def _lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Opens the shared outbound HTTP client for the process lifetime.

    The client the PayPal integration issues its calls through is opened
    before the first request is served and closed once the last one has
    completed. Any handler removed from a governed logging namespace is
    reported at startup, and the log queue is drained on the way out so
    no record is lost when the process stops.
    """
    removed = unredacted_handler_names()
    if removed:
        logger.warning(
            "Removed a log handler that would not have redacted records",
            extra={"handlers": list(removed)},
        )
    await open_http_client()
    try:
        yield
    finally:
        await close_http_client()
        flush_log_queue()


app = FastAPI(
    lifespan=_lifespan,
    docs_url=DOCS_PATH if DOCUMENTATION_ENABLED else None,
    redoc_url=REDOC_PATH if DOCUMENTATION_ENABLED else None,
    openapi_url=OPENAPI_PATH if DOCUMENTATION_ENABLED else None,
)
app.state.limiter = limiter


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Sets :data:`SECURITY_HEADERS` on every outgoing response."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response


def _accepted_request_id(scope: Scope) -> Optional[str]:
    """Returns the identifier the request supplies, if it supplies one.

    A value is accepted only when it is non-blank, no longer than
    :data:`REQUEST_ID_MAX_LENGTH` and drawn entirely from
    :data:`_REQUEST_ID_ALPHABET`, so a client cannot inject separators or
    control characters into a log record. Anything else returns ``None``
    and one is generated instead.
    """
    raw = Headers(scope=scope).get(REQUEST_ID_HEADER)
    if not raw:
        return None
    candidate = raw.strip()
    if not candidate or len(candidate) > REQUEST_ID_MAX_LENGTH:
        return None
    if not all(char in _REQUEST_ID_ALPHABET for char in candidate):
        return None
    return candidate


def _scoped_request_id(request: Request) -> Optional[str]:
    """Returns the identifier bound to ``request``, or ``None``.

    The value is read from the ASGI scope, where
    :class:`RequestIdMiddleware` records it, so it is still available to a
    handler that runs after the middleware has unbound it -- which is
    where an error that reached no handler is answered. The bound
    identifier is used when the scope carries none.
    """
    try:
        state = request.scope.get("state")
        if isinstance(state, dict):
            scoped = state.get(REQUEST_ID_FIELD)
            if scoped:
                return str(scoped)
    except Exception:
        return current_request_id()
    return current_request_id()


class RequestIdMiddleware:
    """Binds an identifier to the request and returns it on the response.

    The identifier is taken from :data:`REQUEST_ID_HEADER` when the
    request supplies an acceptable one and generated otherwise. It is
    bound for the duration of the request, so every structured record the
    request produces carries it, is placed on ``request.state`` and is set
    on :data:`REQUEST_ID_HEADER` of the outgoing response, whatever status
    that response carries.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != _HTTP_SCOPE:
            await self.app(scope, receive, send)
            return

        request_id = _accepted_request_id(scope) or uuid.uuid4().hex
        token = bind_request_id(request_id)
        scope.setdefault("state", {})
        scope["state"][REQUEST_ID_FIELD] = request_id

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == _RESPONSE_START_MESSAGE:
                headers = MutableHeaders(scope=message)
                headers[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            reset_request_id(token)


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
    return JSONResponse(
        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
        content={"detail": BODY_TOO_LARGE_DETAIL},
    )


def _message_allowance(max_body_bytes: int) -> int:
    """Returns how many body messages one request may send.

    A body arriving in chunks smaller than :data:`MIN_CHUNK_BYTES`, empty
    chunks included, would otherwise let a client send an unlimited
    number of messages while the byte total stays under the cap. The
    allowance is the number of minimum-size chunks the cap admits, never
    fewer than :data:`MIN_BODY_MESSAGES`.
    """
    chunks = -(-max_body_bytes // MIN_CHUNK_BYTES)
    return max(MIN_BODY_MESSAGES, chunks)


class BodySizeLimitMiddleware:
    """Rejects a request body above ``max_body_bytes`` with HTTP 413.

    A size declared by ``content-length`` is checked before any body is
    read. A request that declares no size, as a chunked request does, is
    counted as the application streams it: each chunk is passed straight
    through and only its length is retained, so the body is neither
    buffered nor replayed here, and the memory this layer holds does not
    follow the body's size. The number of body messages is bounded as
    well as the byte total, so a body sent as an unlimited run of tiny or
    empty chunks is refused too. ``max_messages`` defaults to the
    allowance :func:`_message_allowance` derives from the byte cap, so the
    application configures one setting rather than two.

    The cap applies to every request on every route, whatever content
    type the body carries. A size declared above the cap is answered
    before the application is called at all. A streamed body that passes
    a bound is refused as the chunk that passes it is read, by raising
    the ``413`` that :func:`http_exception_handler` renders -- the one
    exception type the framework re-raises out of its body-parsing step
    rather than reporting as a malformed body.
    """

    def __init__(
        self,
        app: ASGIApp,
        max_body_bytes: int,
        max_messages: Optional[int] = None,
    ) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes
        if max_messages is None:
            max_messages = _message_allowance(max_body_bytes)
        self.max_body_messages = max_messages

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != _HTTP_SCOPE:
            await self.app(scope, receive, send)
            return

        declared = _declared_body_size(scope)
        if declared is not None and declared > self.max_body_bytes:
            self._log_rejection(scope, REASON_DECLARED_SIZE, declared)
            response = _body_too_large_response()
            await response(scope, receive, send)
            return

        await self.app(scope, self._counting_receive(scope, receive), send)

    def _counting_receive(
        self, scope: Scope, receive: Receive
    ) -> Receive:
        """Returns ``receive`` wrapped in a byte and message counter.

        Each message is returned to the caller unchanged. The wrapper
        holds two integers and no chunk, and refuses the request instead
        of returning the message that carries either total past its
        bound.
        """
        received = 0
        messages = 0

        async def counting_receive() -> Message:
            nonlocal received, messages
            message = await receive()
            if message["type"] != _REQUEST_MESSAGE:
                return message
            received += len(message.get("body", b""))
            messages += 1
            if received > self.max_body_bytes:
                self._refuse(scope, REASON_BYTE_COUNT, received)
            if messages > self.max_body_messages:
                self._refuse(scope, REASON_MESSAGE_COUNT, received)
            return message

        return counting_receive

    def _refuse(self, scope: Scope, reason: str, received: int) -> None:
        """Records the rejection and raises the ``413`` for it."""
        self._log_rejection(scope, reason, received)
        raise StarletteHTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=BODY_TOO_LARGE_DETAIL,
        )

    def _log_rejection(
        self, scope: Scope, reason: str, received: Optional[int]
    ) -> None:
        logger.warning(
            "Request body exceeds the configured cap",
            extra={
                "path": scope.get("path"),
                "method": scope.get("method"),
                "reason": reason,
                "received_bytes": received,
                "max_bytes": self.max_body_bytes,
                "max_messages": self.max_body_messages,
            },
        )


def _matched_endpoint(scope: Scope) -> Optional[Callable]:
    """Returns the endpoint the request routes to, or ``None``.

    Only a full match, on path and method both, resolves an endpoint.
    """
    application = scope.get("app")
    if application is None:
        return None
    for candidate in getattr(application, "routes", ()):
        try:
            match, _ = candidate.matches(scope)
        except Exception:
            continue
        if match == Match.FULL:
            endpoint = getattr(candidate, "endpoint", None)
            if endpoint is not None:
                return endpoint
    return None


class RateLimitGateMiddleware:
    """Counts a request against its rate limit before the body is read.

    ``limiter`` holds the limits the credential endpoints declare. Those
    limits are attached to the endpoint functions, and the limiter's own
    middleware leaves a decorated endpoint to its decorator, which runs
    after the framework has parsed the request body. This layer counts
    the request at the transport boundary instead: the route is matched
    from the scope, the limit is evaluated, and a request over its limit
    is answered ``429`` without its body being read at all.

    A request that passes is marked as counted, so the decorator on the
    endpoint does not count it a second time. The mark is only applied
    once the evaluation has recorded which limit applies, which is what
    the decorator reads when it sets the rate-limit response headers.
    """

    def __init__(self, app: ASGIApp, limiter: Limiter) -> None:
        self.app = app
        self.limiter = limiter

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != _HTTP_SCOPE or not self.limiter.enabled:
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        endpoint = _matched_endpoint(scope)
        if endpoint is None:
            await self.app(scope, receive, send)
            return

        try:
            self.limiter._check_request_limit(request, endpoint, False)
        except RateLimitExceeded as exceeded:
            self._log_rejection(scope, exceeded)
            response = _rate_limit_exceeded_handler(request, exceeded)
            await response(scope, receive, send)
            return

        if hasattr(request.state, _EVALUATED_LIMIT_ATTRIBUTE):
            setattr(request.state, _COUNTED_ATTRIBUTE, True)
        await self.app(scope, receive, send)

    def _log_rejection(
        self, scope: Scope, exceeded: RateLimitExceeded
    ) -> None:
        """Records one request refused by its rate limit.

        The record carries :data:`THROTTLED_MESSAGE` and the same fields
        :func:`rate_limit_exceeded_handler` records, so one throttling
        decision reads the same whichever layer took it.
        """
        logger.warning(
            THROTTLED_MESSAGE,
            extra={
                "path": scope.get("path"),
                "method": scope.get("method"),
                "policy": _rate_limit_policy(exceeded),
            },
        )


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> Response:
    """Returns the status, detail and headers that ``exc`` carries.

    A deliberate rejection raised by endpoint code keeps its status code
    and its detail, so the messages those endpoints return are
    unchanged. Statuses that permit no body are answered without one.

    A rejection the raising code has already written to the audit trail
    is not recorded again here, so one refusal produces one record.
    """
    if not is_audited(exc):
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
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": INVALID_REQUEST_DETAIL},
    )


def _cors_headers(request: Request) -> Dict[str, str]:
    """Returns the cross-origin headers a response outside CORS needs.

    The request's ``Origin`` is matched against
    ``settings.ALLOWED_ORIGINS`` exactly, and then with letter case
    folded, which is how that list is stored. A match returns the single
    matching origin together with the credentialed-response header; no
    wildcard is ever returned, and an origin outside the list returns no
    origin header at all.

    ``Vary: Origin`` is returned whenever the request carried an origin,
    so a response is never cached across origins. An absent origin
    returns no headers, since the request is not a cross-origin one.
    """
    try:
        origin = request.headers.get(_ORIGIN_HEADER)
    except Exception:
        return {}
    if not origin:
        return {}

    headers = {_VARY_HEADER: _ORIGIN_HEADER.capitalize()}
    allowed = list(settings.ALLOWED_ORIGINS)
    if origin in allowed:
        matched = origin
    else:
        folded = origin.strip().lower()
        matched = next(
            (entry for entry in allowed if entry.lower() == folded),
            None,
        )
    if matched is None:
        return headers
    headers[CORS_ALLOW_ORIGIN_HEADER] = matched
    headers[CORS_ALLOW_CREDENTIALS_HEADER] = _CREDENTIALS_ALLOWED
    return headers


async def unhandled_exception_handler(
    request: Request, exc: Exception
) -> Response:
    """Returns a fixed detail for an error that reached no handler.

    The response carries no exception text, no traceback and no
    identifier of the code that raised. The error itself is recorded
    through the redacting logger. This handler runs outside the
    middleware stack, so it sets :data:`SECURITY_HEADERS` and the
    cross-origin headers of :func:`_cors_headers` on the response it
    builds.
    """
    request_id = _scoped_request_id(request)
    log_exception(
        logger,
        "Unhandled application error",
        exc,
        path=request.scope.get("path"),
        method=request.scope.get("method"),
        request_id=request_id,
    )
    headers = dict(SECURITY_HEADERS)
    headers.update(_cors_headers(request))
    if request_id:
        headers[REQUEST_ID_HEADER] = request_id
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": SERVER_ERROR_DETAIL,
            REQUEST_ID_FIELD: request_id,
        },
        headers=headers,
    )


async def rate_limit_exceeded_handler(
    request: Request, exc: RateLimitExceeded
) -> Response:
    """Records one throttling decision and returns the stock response.

    The record carries the request path and method and the policy that
    was exceeded. The response body, status and headers are the limiter's
    own, so the throttling contract is unchanged.
    """
    logger.warning(
        THROTTLED_MESSAGE,
        extra={
            "path": request.scope.get("path"),
            "method": request.scope.get("method"),
            "policy": _rate_limit_policy(exc),
        },
    )
    return _rate_limit_exceeded_handler(request, exc)


def _rate_limit_policy(exc: RateLimitExceeded) -> Optional[str]:
    """Returns the exceeded policy as text, or ``None``."""
    limit = getattr(exc, "limit", None)
    for attribute in ("limit", "error_message"):
        value = getattr(limit, attribute, None)
        if value:
            return str(value)
    if limit is not None:
        return str(limit)
    return None


app.add_exception_handler(
    StarletteHTTPException, http_exception_handler
)
app.add_exception_handler(
    RequestValidationError, validation_exception_handler
)
app.add_exception_handler(
    RateLimitExceeded, rate_limit_exceeded_handler
)
app.add_exception_handler(Exception, unhandled_exception_handler)

# Registered innermost first: the layer added last is the first to run
# on an inbound request. The resulting inbound order is request
# identifier, response headers, cross-origin policy, host validation,
# rate limiter, body-size cap, router. The rate limiter sits outside the
# body-size cap, so a request over its limit is refused before any chunk
# of its body is read, and the cross-origin layer encloses both the host
# check and those two, so the 400, 429 and 413 they return carry the same
# headers as any other response.
app.add_middleware(
    BodySizeLimitMiddleware,
    max_body_bytes=settings.MAX_REQUEST_BODY_BYTES,
    max_messages=settings.MAX_REQUEST_BODY_CHUNKS,
)
app.add_middleware(RateLimitGateMiddleware, limiter=limiter)
app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=list(CORS_ALLOW_METHODS),
    allow_headers=list(CORS_ALLOW_HEADERS),
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)

app.include_router(api_router)


@app.get("/health")
def health_check() -> Dict[str, str]:
    """Reports that the process is able to serve requests."""
    return {"status": HEALTH_STATUS}
