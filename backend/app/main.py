"""FastAPI application assembly, middleware, health checks, and
exception handling.
"""

import base64
import hashlib
import math
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager
from types import MappingProxyType
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Tuple,
)

import anyio
from anyio.lowlevel import RunVar
from fastapi import Depends, FastAPI, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.utils import is_body_allowed_for_status_code
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text
from sqlalchemy.exc import TimeoutError as PoolTimeout
from sqlalchemy.orm import Session
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

from backend.app.core.authorization import audit_failure_count
from backend.app.core.config import LOCAL_ENVIRONMENT, settings
from backend.app.core.logging import (
    QUEUE_DRAIN_TIMEOUT_SECONDS,
    SIGNAL_FIELD,
    SPAN_ID_FIELD,
    TRACEPARENT_HEADER,
    TRACE_ID_FIELD,
    bind_request_id,
    bind_trace_context,
    configure_logging,
    current_request_id,
    current_trace_context,
    current_traceparent,
    flush_log_queue,
    get_logger,
    is_audited,
    log_audit_fallback,
    log_exception,
    logging_failure_count,
    parse_traceparent,
    reset_request_id,
    reset_trace_context,
    unredacted_handler_names,
)
from backend.app.core.rate_limit import (
    RATE_LIMIT_HEADERS,
    RETRY_AFTER_HEADER,
)

__all__ = [
    "ADMISSION_BOUND_MESSAGE",
    "ADMISSION_REFUSED_MESSAGE",
    "BODY_NOT_RECEIVED_DETAIL",
    "BODY_NOT_RECEIVED_MESSAGE",
    "BODY_TOO_LARGE_DETAIL",
    "BODYLESS_METHODS",
    "CAPACITY_DETAIL",
    "CORS_ALLOW_CREDENTIALS_HEADER",
    "CORS_ALLOW_HEADERS",
    "CORS_ALLOW_METHODS",
    "CORS_ALLOW_ORIGIN_HEADER",
    "CORS_EXPOSE_HEADERS",
    "DOCS_PATH",
    "DOCUMENTATION_ENABLED",
    "DOCUMENTATION_FONT_ORIGIN",
    "DOCUMENTATION_FONT_STYLE_ORIGIN",
    "DOCUMENTATION_ICON_ORIGIN",
    "DOCUMENTATION_MARK_ORIGIN",
    "DOCUMENTATION_PATHS",
    "DOCUMENTATION_VIEWER_ORIGIN",
    "DOCUMENTATION_WORKER_SOURCE",
    "ERROR_RESPONSE_COMPONENT",
    "GENERATED_VALIDATION_COMPONENTS",
    "HEALTH_PATH",
    "HEALTH_STATUS",
    "INVALID_HOST_DETAIL",
    "INVALID_REQUEST_DETAIL",
    "LOG_DRAIN_INCOMPLETE_MESSAGE",
    "NOT_READY_STATUS",
    "OAUTH2_REDIRECT_PATH",
    "OPENAPI_PATH",
    "POOL_EXHAUSTED_MESSAGE",
    "PUBLISHED_REFUSAL_STATUS",
    "READINESS_BOUND_DIALECTS",
    "READINESS_BOUND_STATEMENTS",
    "READINESS_CONCURRENT_MESSAGE",
    "READINESS_FAILURE_MESSAGE",
    "READINESS_PATH",
    "READINESS_STATEMENT",
    "READINESS_STATUS",
    "REDOC_PATH",
    "REFUSAL_DETAIL_FIELD",
    "REQUEST_ID_FIELD",
    "REQUEST_ID_HEADER",
    "REQUEST_ID_MAX_LENGTH",
    "RETRY_AFTER_FIELD",
    "SINK_DEGRADED_MESSAGE",
    "SINK_DEGRADED_SIGNAL",
    "MIN_BODY_MESSAGES",
    "MIN_CHUNK_BYTES",
    "REASON_BYTE_COUNT",
    "REASON_CHUNK_DEADLINE",
    "REASON_DECLARED_SIZE",
    "REASON_MESSAGE_COUNT",
    "REASON_TOTAL_DEADLINE",
    "SECURITY_HEADERS",
    "SERVER_ERROR_DETAIL",
    "THROTTLED_MESSAGE",
    "TOO_MANY_REQUESTS_DETAIL",
    "UNGATED_PATHS",
    "BodyPrefetchMiddleware",
    "BodySizeLimitMiddleware",
    "RequestAdmissionMiddleware",
    "RequestIdMiddleware",
    "RateLimitGateMiddleware",
    "SecurityHeadersMiddleware",
    "TrustedHostGateMiddleware",
    "api_schema",
    "app",
    "capacity_retry_after_seconds",
    "health_check",
    "http_exception_handler",
    "limiter",
    "pool_timeout_handler",
    "rate_limit_exceeded_handler",
    "readiness_check",
    "readiness_outcome",
    "reset_readiness_cache",
    "unhandled_exception_handler",
    "validation_exception_handler",
]

# The configured level is applied before the first record is emitted, so
# every record this process writes -- including the ones the assembly
# below produces -- is filtered at the level the deployment set.
configure_logging(settings.LOG_LEVEL)

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
        # Every feature named here is one a browser recognises, so the header
        # denies each without also reporting an unrecognised token.
        "Permissions-Policy": (
            "accelerometer=(), autoplay=(), "
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

#: Response headers a cross-origin caller's own code may read. The set is
#: the throttle policy a refused request is answered with: the window's
#: allowance, what remains of it, when it resets, and how long to wait.
CORS_EXPOSE_HEADERS: Tuple[str, ...] = RATE_LIMIT_HEADERS + (
    RETRY_AFTER_HEADER,
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

#: Detail returned when a request exceeds its rate limit.
TOO_MANY_REQUESTS_DETAIL = "Too many requests"

#: Detail returned when the connection pool had no connection to give a
#: request within ``settings.DB_POOL_TIMEOUT_SECONDS``. It names a
#: capacity limit rather than a fault, and carries no pool figure.
CAPACITY_DETAIL = "Service temporarily unavailable"

#: Message of the record emitted for a request refused for capacity.
POOL_EXHAUSTED_MESSAGE = "Database connection pool exhausted"

#: Message of the record emitted for a request the admission gate
#: refused, having waited its whole allowance for a slot.
ADMISSION_REFUSED_MESSAGE = "Request not admitted within its allowance"

#: Message reporting the admission bound in force at startup.
ADMISSION_BOUND_MESSAGE = "Bounded the requests admitted to the database"

#: Detail returned when the request names a host outside
#: ``settings.ALLOWED_HOSTS``.
INVALID_HOST_DETAIL = "Invalid host header"

HEALTH_STATUS = "ok"

#: Path the liveness probe is published at. It answers as soon as the
#: process serves requests and reads no dependency, so it reports that the
#: process is alive rather than that it can serve traffic.
HEALTH_PATH = "/health"

#: Path the readiness probe is published at. It is prefixed by
#: :data:`HEALTH_PATH`, so a caller matching on a prefix would reach
#: either one and the full path is named wherever a probe is configured.
READINESS_PATH = "/health/ready"

#: Routes the admission gate does not hold. Both are read by an
#: orchestrator, which acts on a probe that does not answer, so neither
#: may wait behind the requests the gate is bounding. The readiness route
#: reads the database, and the connections the gate leaves unclaimed are
#: what it draws on.
UNGATED_PATHS: Tuple[str, ...] = (HEALTH_PATH, READINESS_PATH)

#: Status reported when every dependency the probe reads answered.
READINESS_STATUS = "ready"

#: Status reported when a dependency the probe reads did not answer.
NOT_READY_STATUS = "unavailable"

#: Statement the readiness probe reads the database with.
READINESS_STATEMENT = text("SELECT 1")

#: Statements that bound the probe's own transaction on PostgreSQL. Each
#: calls ``set_config`` with its local flag set, so the bound lasts for
#: that transaction only and no other caller of the shared engine --
#: including the Alembic revisions -- inherits it. ``:milliseconds`` is
#: bound from ``settings.READINESS_TIMEOUT_SECONDS``, and is passed as a
#: parameter rather than interpolated because ``SET`` accepts no
#: parameter while ``set_config`` does.
READINESS_BOUND_STATEMENTS = (
    text("SELECT set_config('statement_timeout', :milliseconds, true)"),
    text("SELECT set_config('lock_timeout', :milliseconds, true)"),
)

#: Dialect names :data:`READINESS_BOUND_STATEMENTS` is issued against.
READINESS_BOUND_DIALECTS = frozenset(("postgresql",))

#: Message recorded when the readiness probe cannot read the database.
READINESS_FAILURE_MESSAGE = "readiness probe could not read the database"

#: Message recorded when a record-writing sink this process depends on
#: has degraded. The readiness probe emits it; the response body carries
#: the readiness outcome only.
SINK_DEGRADED_MESSAGE = "A record-writing sink degraded"

#: Value carried on :data:`backend.app.core.logging.SIGNAL_FIELD` of the
#: degradation record, so an alerting rule can select it by field rather
#: than by matching the message text.
SINK_DEGRADED_SIGNAL = "record_sink_degraded"
#: Message recorded when a probe answers from the last recorded outcome
#: because another probe already holds the one database read this route
#: performs at a time.
READINESS_CONCURRENT_MESSAGE = (
    "readiness probe answered from the last recorded outcome"
)

#: Path the interactive documentation is published at.
DOCS_PATH = "/docs"

#: Path the alternative documentation viewer is published at.
REDOC_PATH = "/redoc"

#: Path the documentation viewer publishes its OAuth2 redirection at.
OAUTH2_REDIRECT_PATH = DOCS_PATH + "/oauth2-redirect"

#: Path the OpenAPI schema is published at.
OPENAPI_PATH = "/openapi.json"

#: Name of the published component describing a refusal body.
ERROR_RESPONSE_COMPONENT = "ErrorResponse"

#: Status the schema generator publishes a refusal body for, as the
#: string form a published document keys its responses by.
PUBLISHED_REFUSAL_STATUS = str(status.HTTP_422_UNPROCESSABLE_CONTENT)

#: Components the generator publishes for a refusal body carrying a list
#: of per-field failures, which no route of this application returns.
GENERATED_VALIDATION_COMPONENTS: Tuple[str, ...] = (
    "HTTPValidationError",
    "ValidationError",
)

#: Body field a refusal carries its fixed detail under.
REFUSAL_DETAIL_FIELD = "detail"

# Media type a published response body is described under.
_JSON_MEDIA_TYPE = "application/json"

# Reference expression naming ERROR_RESPONSE_COMPONENT.
_ERROR_RESPONSE_REFERENCE = (
    "#/components/schemas/" + ERROR_RESPONSE_COMPONENT
)

#: Paths answering with a documentation page rather than with API data,
#: so :func:`_documentation_policy` governs them in place of the policy
#: in :data:`SECURITY_HEADERS`.
DOCUMENTATION_PATHS: Tuple[str, ...] = (
    DOCS_PATH,
    REDOC_PATH,
    OAUTH2_REDIRECT_PATH,
)

#: Origin the pinned documentation viewers and their stylesheets are
#: loaded from.
DOCUMENTATION_VIEWER_ORIGIN = "https://cdn.jsdelivr.net"

#: Origin one viewer declares its web fonts through.
DOCUMENTATION_FONT_STYLE_ORIGIN = "https://fonts.googleapis.com"

#: Origin those web fonts are served from.
DOCUMENTATION_FONT_ORIGIN = "https://fonts.gstatic.com"

#: Origin the documentation favicon is served from.
DOCUMENTATION_ICON_ORIGIN = "https://fastapi.tiangolo.com"

#: Origin one viewer serves its own mark from.
DOCUMENTATION_MARK_ORIGIN = "https://cdn.redoc.ly"

#: Source a viewer builds its own worker from, which one of them uses to
#: index the schema for its search.
DOCUMENTATION_WORKER_SOURCE = "blob:"

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

#: Body field carrying the wait a throttled caller owes, in whole
#: seconds. It restates the ``Retry-After`` header, which a caller
#: reading only the body never sees.
RETRY_AFTER_FIELD = "retry_after_seconds"

#: Message of the record emitted for a throttled request.
THROTTLED_MESSAGE = "Request throttled"

#: Message reported when the log queue still holds records after the
#: shutdown drain timeout elapsed. It is written directly to standard
#: error rather than through the queue.
LOG_DRAIN_INCOMPLETE_MESSAGE = "Log queue did not drain before shutdown"

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

#: Rejection reason: the whole body did not arrive within its deadline.
REASON_TOTAL_DEADLINE = "body_read_deadline"

#: Rejection reason: one further chunk of the body did not arrive within
#: its deadline.
REASON_CHUNK_DEADLINE = "body_chunk_deadline"

#: Detail returned when a request body did not arrive within its
#: deadline. It names the body rather than the deadline's value, so no
#: response reveals how long a client may stall for.
BODY_NOT_RECEIVED_DETAIL = "Request body not received in time"

#: Message of the record emitted for a body refused for its deadline.
BODY_NOT_RECEIVED_MESSAGE = "Request body did not arrive within its deadline"

#: Methods that carry no request body, so a request using one is passed
#: to the layers below without a body being read for it.
BODYLESS_METHODS: Tuple[str, ...] = ("GET", "HEAD", "OPTIONS", "TRACE")

#: Failures a route raises for a scope it cannot read, such as one
#: carrying no method or no path, or a candidate that answers no match
#: call at all. Each is recorded and the candidate skipped. Anything else
#: propagates, so a caller relying on the match fails closed.
UNMATCHABLE_ROUTE_ERRORS = (
    AttributeError,
    KeyError,
    TypeError,
    ValueError,
)

# Request header carrying the body size the client declares.
_CONTENT_LENGTH_HEADER = "content-length"

# Response header naming the media type the body carries.
_CONTENT_TYPE_HEADER = "content-type"

# Response header carrying the content-security policy.
_CSP_HEADER = "content-security-policy"

# Media type a documentation page is served as.
_HTML_MEDIA_TYPE = "text/html"

# Script elements written into a page rather than fetched: those are the
# ones a policy admits by the digest of their content.
_INLINE_SCRIPT_PATTERN = re.compile(
    r"<script(?![^>]*\ssrc\s*=)[^>]*>(.*?)</script>",
    re.DOTALL | re.IGNORECASE,
)

# Request header carrying the host the client addressed.
_HOST_HEADER = "host"

_HTTP_SCOPE = "http"

# Scope types the host check applies to, as the base middleware defines.
_HOST_CHECKED_SCOPES = ("http", "websocket")

_REQUEST_MESSAGE = "http.request"

# Request-state attribute the limiter sets to the limit it evaluated.
_EVALUATED_LIMIT_ATTRIBUTE = "view_rate_limit"

# Request-state attribute marking a request already counted, which the
# endpoint decorators read. One request is counted once.
_COUNTED_ATTRIBUTE = "_rate_limiting_complete"

# ASGI message type carrying the response status and headers.
_RESPONSE_START_MESSAGE = "http.response.start"

# ``limiter`` is defined by the credential endpoints and is bound to
# ``app.state.limiter`` below.
from backend.app.api.endpoints.auth import limiter  # noqa: E402
from backend.app.api.router import api_router  # noqa: E402
from backend.app.core.rate_limit import RETRY_AFTER_HEADER  # noqa: E402
from backend.app.db.database import (  # noqa: E402
    admitted_concurrency,
    get_db,
    pool_capacity,
)
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
    no record is lost when the process stops. A queue that still holds
    records once the drain timeout elapses is reported on standard error,
    which does not travel through the queue.

    The admission bound in force is reported at startup, so a deployment
    can see how many requests it will run against its database at once.
    """
    removed = unredacted_handler_names()
    if removed:
        logger.warning(
            "Removed a log handler that would not have redacted records",
            extra={"handlers": list(removed)},
        )
    admitted = admitted_concurrency(settings.DATABASE_URL)
    logger.info(
        ADMISSION_BOUND_MESSAGE,
        extra={
            "admitted_concurrency": admitted,
            "pool_capacity": pool_capacity(settings.DATABASE_URL),
            "admission_wait_seconds": settings.DB_POOL_TIMEOUT_SECONDS,
        },
    )
    await open_http_client()
    try:
        yield
    finally:
        await close_http_client()
        if not flush_log_queue():
            log_audit_fallback(
                LOG_DRAIN_INCOMPLETE_MESSAGE,
                {"timeout_seconds": QUEUE_DRAIN_TIMEOUT_SECONDS},
            )


app = FastAPI(
    lifespan=_lifespan,
    docs_url=DOCS_PATH if DOCUMENTATION_ENABLED else None,
    redoc_url=REDOC_PATH if DOCUMENTATION_ENABLED else None,
    openapi_url=OPENAPI_PATH if DOCUMENTATION_ENABLED else None,
)
app.state.limiter = limiter


def _inline_script_sources(body: bytes) -> Tuple[str, ...]:
    """Returns one policy source expression per inline script in ``body``.

    Each expression is the base64 SHA-256 digest of one script element's
    own content, in the form a policy names it.
    """
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return ()
    sources = []
    for script in _INLINE_SCRIPT_PATTERN.findall(text):
        digest = hashlib.sha256(script.encode("utf-8")).digest()
        encoded = base64.b64encode(digest).decode("ascii")
        sources.append("'sha256-" + encoded + "'")
    return tuple(sources)


def _documentation_policy(body: bytes) -> str:
    """Returns the content-security policy for one documentation page.

    Every directive stays denied by default. Script and stylesheet are
    admitted from the pinned viewer origin, and an inline script only by
    the digest of its own content, so a script the page did not itself
    carry does not run. Inline style is admitted, the worker source
    admits the blob a viewer builds from the page, and connections are
    admitted same-origin only. Framing, base URI and form submission
    stay denied exactly as they are on an API response.
    """
    script_sources = " ".join(
        (DOCUMENTATION_VIEWER_ORIGIN,) + _inline_script_sources(body)
    )
    style_sources = " ".join(
        (
            "'unsafe-inline'",
            DOCUMENTATION_VIEWER_ORIGIN,
            DOCUMENTATION_FONT_STYLE_ORIGIN,
        )
    )
    image_sources = " ".join(
        (
            DOCUMENTATION_ICON_ORIGIN,
            DOCUMENTATION_MARK_ORIGIN,
            "data:",
        )
    )
    return "; ".join(
        (
            "default-src 'none'",
            "script-src " + script_sources,
            "style-src " + style_sources,
            "font-src " + DOCUMENTATION_FONT_ORIGIN,
            "img-src " + image_sources,
            "worker-src " + DOCUMENTATION_WORKER_SOURCE,
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'none'",
        )
    )


def _is_documentation_page(
    request: Request, response: Response
) -> bool:
    """Reports whether ``response`` is a published documentation page."""
    if not DOCUMENTATION_ENABLED:
        return False
    if request.scope.get("path") not in DOCUMENTATION_PATHS:
        return False
    if response.status_code != status.HTTP_200_OK:
        return False
    media_type = response.headers.get(_CONTENT_TYPE_HEADER, "")
    return media_type.startswith(_HTML_MEDIA_TYPE)


async def _with_documentation_policy(response: Response) -> Response:
    """Returns ``response`` carrying the documentation policy.

    The body is read so the policy can name the digest of each inline
    script the page carries, and is returned byte-for-byte as it was.
    """
    iterator = getattr(response, "body_iterator", None)
    if iterator is None:
        body = getattr(response, "body", b"")
    else:
        chunks = []
        async for chunk in iterator:
            chunks.append(chunk)
        body = b"".join(chunks)
    headers = {
        name: value
        for name, value in response.headers.items()
        if name.lower() not in (_CONTENT_LENGTH_HEADER, _CSP_HEADER)
    }
    headers[_CSP_HEADER] = _documentation_policy(body)
    return Response(
        content=body,
        status_code=response.status_code,
        headers=headers,
    )


def _drop_orphan_credentials_header(response: Response) -> None:
    """Removes :data:`CORS_ALLOW_CREDENTIALS_HEADER` when no origin is
    shared.

    That header is read only beside :data:`CORS_ALLOW_ORIGIN_HEADER`, so
    a response carrying it without one names no origin it applies to and
    has it removed before it leaves.
    """
    headers = response.headers
    if CORS_ALLOW_CREDENTIALS_HEADER not in headers:
        return
    if CORS_ALLOW_ORIGIN_HEADER in headers:
        return
    del headers[CORS_ALLOW_CREDENTIALS_HEADER]


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Sets :data:`SECURITY_HEADERS` on every outgoing response.

    The credentialed-response header is then dropped from any response
    that names no shared origin, which is what
    :func:`_drop_orphan_credentials_header` does. It runs before the
    documentation branch below, because that branch rebuilds a response
    from the headers this one leaves.

    A response on one of :data:`DOCUMENTATION_PATHS` then has its policy
    replaced by the one :func:`_documentation_policy` builds, so the
    viewer this application publishes in a local run loads its own assets
    while every API response keeps the policy that denies everything.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        _drop_orphan_credentials_header(response)
        if _is_documentation_page(request, response):
            return await _with_documentation_policy(response)
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


def _stated_request_id(scope: Scope) -> Optional[str]:
    """Returns the identifier recorded in ``scope``, or ``None``.

    The value is read from the ASGI scope, where
    :class:`RequestIdMiddleware` records it, so it is still available to a
    handler that runs after the middleware has unbound it -- which is
    where an error that reached no handler is answered. The bound
    identifier is used when the scope carries none.
    """
    try:
        state = scope.get("state")
        if isinstance(state, dict):
            scoped = state.get(REQUEST_ID_FIELD)
            if scoped:
                return str(scoped)
    except Exception:
        return current_request_id()
    return current_request_id()


def _scoped_request_id(request: Request) -> Optional[str]:
    """Returns the identifier bound to ``request``, or ``None``."""
    return _stated_request_id(request.scope)


def _accepted_trace_id(scope: Scope) -> Optional[str]:
    """Returns the trace the request asks to be correlated with.

    The value is read from :data:`TRACEPARENT_HEADER` and parsed as W3C
    trace context. A header that is absent, malformed, carries the
    invalid version or names an all-zero identifier yields ``None``, and
    a fresh trace is started instead. Only the trace identifier is
    adopted: the caller's span identifier is its own and this process
    mints a new one beneath it.
    """
    raw = Headers(scope=scope).get(TRACEPARENT_HEADER)
    parsed = parse_traceparent(raw)
    if parsed is None:
        return None
    return parsed[0]


class RequestIdMiddleware:
    """Binds the correlation identifiers and returns them on the response.

    The request identifier is taken from :data:`REQUEST_ID_HEADER` when
    the request supplies an acceptable one and generated otherwise. The
    trace identifier is taken from :data:`TRACEPARENT_HEADER` when the
    request carries valid W3C trace context and generated otherwise, and
    a span identifier is minted for this process's own work either way.

    All three are bound for the duration of the request, so every
    structured record the request produces carries them, and all three
    are placed on ``request.state``. :data:`REQUEST_ID_HEADER` and
    :data:`TRACEPARENT_HEADER` are set on the outgoing response, whatever
    status that response carries, so a caller can correlate its own
    records with this process's.
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
        trace_token = bind_trace_context(_accepted_trace_id(scope))
        traceparent = current_traceparent()
        context = current_trace_context()
        scope.setdefault("state", {})
        scope["state"][REQUEST_ID_FIELD] = request_id
        if context is not None:
            scope["state"][TRACE_ID_FIELD] = context[0]
            scope["state"][SPAN_ID_FIELD] = context[1]

        async def send_with_correlation(message: Message) -> None:
            if message["type"] == _RESPONSE_START_MESSAGE:
                headers = MutableHeaders(scope=message)
                headers[REQUEST_ID_HEADER] = request_id
                if traceparent:
                    headers[TRACEPARENT_HEADER] = traceparent
            await send(message)

        try:
            await self.app(scope, receive, send_with_correlation)
        finally:
            reset_trace_context(trace_token)
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
    """Reject request bodies that exceed configured byte or
    message-count limits.
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


class _BodyDeadlineExpired(Exception):
    """Raised inside the prefetch layer when a body deadline elapsed."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _body_not_received_response() -> JSONResponse:
    """Returns the answer given to a body that did not arrive in time."""
    return JSONResponse(
        status_code=status.HTTP_408_REQUEST_TIMEOUT,
        content={"detail": BODY_NOT_RECEIVED_DETAIL},
    )


class BodyPrefetchMiddleware:
    """Read a request body to completion, under deadlines, before the
    layers below it are entered.

    The layer below this one is :class:`RequestAdmissionMiddleware`, whose
    slot is held for the whole of the routed request. A route reads its
    body inside that request, so a client that opens a connection,
    declares a body and then sends one byte of it used to hold an
    admission slot for as long as it kept the socket open: enough such
    connections held every slot, and unrelated requests -- including the
    public listings read -- waited the whole admission allowance and were
    then refused, while both probes stayed green because their paths are
    ungated.

    Reading the body here moves that wait outside the gate. A stalled body
    occupies no admission slot at all, so capacity is unaffected by how
    long a client takes to send one, and the two deadlines bound how long
    the connection itself is held: the whole body must arrive within
    ``total_seconds`` and each further chunk of it within
    ``chunk_seconds``. A body that misses either deadline is answered
    :data:`BODY_NOT_RECEIVED_DETAIL` with status 408.

    The bytes held are bounded by the cap :class:`BodySizeLimitMiddleware`
    applies, which sits immediately outside this layer, so the messages
    counted through its receive channel are the messages buffered here and
    a body over the cap is refused rather than held. Requests using a
    method in ``bodyless_methods`` are passed straight through.
    """

    def __init__(
        self,
        app: ASGIApp,
        total_seconds: float,
        chunk_seconds: float,
        bodyless_methods: Tuple[str, ...] = BODYLESS_METHODS,
    ) -> None:
        self.app = app
        self.total_seconds = total_seconds
        self.chunk_seconds = chunk_seconds
        self.bodyless_methods = tuple(
            method.upper() for method in bodyless_methods
        )

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != _HTTP_SCOPE or self._carries_no_body(scope):
            await self.app(scope, receive, send)
            return

        try:
            body = await self._read_body(scope, receive)
        except _BodyDeadlineExpired as expired:
            self._log_rejection(scope, expired.reason)
            await _body_not_received_response()(scope, receive, send)
            return
        except StarletteHTTPException as refused:
            # The receive channel outside this layer refuses a body past
            # its cap by raising, and this layer sits outside the handler
            # that renders such a refusal, so it is rendered here. The
            # refusal is already recorded by the layer that raised it.
            await JSONResponse(
                status_code=refused.status_code,
                content={"detail": refused.detail},
            )(scope, receive, send)
            return

        await self.app(scope, self._replayed(body, receive), send)

    def _carries_no_body(self, scope: Scope) -> bool:
        """Returns whether the request's method carries no body."""
        method = scope.get("method")
        if not isinstance(method, str):
            return True
        return method.upper() in self.bodyless_methods

    async def _read_body(
        self, scope: Scope, receive: Receive
    ) -> Tuple[Message, ...]:
        """Returns every body message the request sent, in order.

        Reading stops at the message that completes the body, or at a
        disconnect. Each individual wait is bounded by ``chunk_seconds``
        and the whole read by ``total_seconds``; whichever elapses first
        raises :class:`_BodyDeadlineExpired` naming that deadline.
        """
        messages: List[Message] = []
        try:
            with anyio.fail_after(self.total_seconds):
                while True:
                    try:
                        with anyio.fail_after(self.chunk_seconds):
                            message = await receive()
                    except TimeoutError:
                        raise _BodyDeadlineExpired(REASON_CHUNK_DEADLINE)
                    messages.append(message)
                    if message["type"] != _REQUEST_MESSAGE:
                        break
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            raise _BodyDeadlineExpired(REASON_TOTAL_DEADLINE) from None
        return tuple(messages)

    @staticmethod
    def _replayed(body: Tuple[Message, ...], receive: Receive) -> Receive:
        """Returns a channel that hands ``body`` on and then defers.

        The buffered messages are returned once each, in order, and every
        call after them is answered by the request's own channel, so a
        disconnect is still delivered by the server rather than
        manufactured here.
        """
        remaining = list(body)

        async def replayed() -> Message:
            if remaining:
                return remaining.pop(0)
            return await receive()

        return replayed

    def _log_rejection(self, scope: Scope, reason: str) -> None:
        logger.warning(
            BODY_NOT_RECEIVED_MESSAGE,
            extra={
                "path": scope.get("path"),
                "method": scope.get("method"),
                "reason": reason,
                "body_timeout_seconds": self.total_seconds,
                "body_chunk_timeout_seconds": self.chunk_seconds,
            },
        )


def capacity_retry_after_seconds() -> int:
    """Returns the seconds a capacity refusal asks a client to wait.

    The value is the configured wait for a pooled connection, rounded up
    to whole seconds, which is the form the ``Retry-After`` header takes
    in seconds and the longest a request already in flight can still be
    holding one.
    """
    return max(1, int(math.ceil(settings.DB_POOL_TIMEOUT_SECONDS)))


def _capacity_response(request_id: Optional[str]) -> JSONResponse:
    """Returns the answer given to a request refused for capacity.

    Both refusals -- the admission gate's and
    :func:`pool_timeout_handler`'s -- return this, so a caller sees one
    answer whichever refused it: the status says the service is
    unavailable for now, ``Retry-After`` says for how long, and the body
    carries :data:`CAPACITY_DETAIL` and the request identifier and nothing
    else. No pool figure, no admission bound, no exception text and no
    traceback reach the client.
    """
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "detail": CAPACITY_DETAIL,
            REQUEST_ID_FIELD: request_id,
        },
        headers={RETRY_AFTER_HEADER: str(capacity_retry_after_seconds())},
    )


#: The admission bound in force, held per event loop. A process serving
#: on one loop shares one bound across every request on it, and a second
#: loop -- which each test client builds -- gets its own.
_ADMISSION_LIMITER: RunVar = RunVar("_admission_limiter")


class RequestAdmissionMiddleware:
    """Bounds how many requests reach the router at once.

    Every route that reads the database holds one pooled connection for
    as long as its session is open, and the framework closes that session
    inside the routed request -- before the router's own call returns and
    therefore before this layer releases the slot. Holding the number of
    requests inside this layer at or below :func:`admitted_concurrency`
    therefore holds the number of connections wanted below the pool's
    ceiling, so a request that reaches a route finds a connection rather
    than waiting for one.

    A request that does not get a slot within ``wait_seconds`` is
    answered by :func:`_capacity_response`, which is the same answer
    :func:`pool_timeout_handler` returns, so a caller cannot tell which
    of the two refused it and both carry ``Retry-After``.

    Paths in ``ungated_paths`` are passed straight through. The bound is
    held per event loop, so a process serving on one loop shares one
    bound across every request on it.

    ``bound`` of ``None`` installs the layer as a pass-through, which is
    what a backend whose pool has no ceiling gets.
    """

    def __init__(
        self,
        app: ASGIApp,
        bound: Optional[int],
        wait_seconds: float,
        ungated_paths: Tuple[str, ...] = UNGATED_PATHS,
    ) -> None:
        self.app = app
        self.bound = bound
        self.wait_seconds = wait_seconds
        self.ungated_paths = tuple(ungated_paths)

    def _limiter(self) -> "anyio.Semaphore":
        """Returns this event loop's admission bound, creating it once."""
        try:
            return _ADMISSION_LIMITER.get()
        except LookupError:
            limiter = anyio.Semaphore(int(self.bound))
            _ADMISSION_LIMITER.set(limiter)
            return limiter

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if (
            self.bound is None
            or scope["type"] != _HTTP_SCOPE
            or scope.get("path") in self.ungated_paths
        ):
            await self.app(scope, receive, send)
            return

        limiter = self._limiter()
        admitted = False
        with anyio.move_on_after(self.wait_seconds):
            await limiter.acquire()
            admitted = True
        if not admitted:
            await self._refuse(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        finally:
            limiter.release()

    async def _refuse(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Answers one request that waited its whole allowance."""
        request_id = _stated_request_id(scope)
        logger.warning(
            ADMISSION_REFUSED_MESSAGE,
            extra={
                "path": scope.get("path"),
                "method": scope.get("method"),
                REQUEST_ID_FIELD: request_id,
                "admitted_concurrency": self.bound,
                "admission_wait_seconds": self.wait_seconds,
            },
        )
        await _capacity_response(request_id)(scope, receive, send)


def _matched_endpoint(scope: Scope) -> Optional[Callable]:
    """Returns the endpoint the request routes to, or ``None``.

    Only a full match, on path and method both, resolves an endpoint.

    A candidate that cannot answer the question is skipped and recorded:
    :data:`UNMATCHABLE_ROUTE_ERRORS` names the failures a route raises for
    a scope it cannot read, such as one carrying no method. Any other
    failure propagates, so the caller fails closed.
    """
    application = scope.get("app")
    if application is None:
        return None
    for candidate in getattr(application, "routes", ()):
        try:
            match, _ = candidate.matches(scope)
        except UNMATCHABLE_ROUTE_ERRORS as error:
            logger.warning(
                "Route candidate could not be matched",
                extra={
                    "path": scope.get("path"),
                    "method": scope.get("method"),
                    "candidate": getattr(
                        candidate, "name", type(candidate).__name__
                    ),
                    "candidate_type": type(candidate).__name__,
                    "error": type(error).__name__,
                },
            )
            continue
        if match == Match.FULL:
            endpoint = getattr(candidate, "endpoint", None)
            if endpoint is not None:
                return endpoint
    return None


class RateLimitGateMiddleware:
    """Evaluate endpoint rate limits before request-body parsing."""

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
            response = _throttled_response(request, exceeded)
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


class TrustedHostGateMiddleware(TrustedHostMiddleware):
    """Host validation answered in this application's error envelope.

    An accepted host and the ``www.`` redirect are left to the base
    middleware, which decides both. A host outside ``allowed_hosts`` is
    answered here with :data:`INVALID_HOST_DETAIL` under ``detail`` and
    ``application/json``, the same shape as every other rejection this
    application returns.
    """

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if not self._is_refused(scope):
            await super().__call__(scope, receive, send)
            return
        response = JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": INVALID_HOST_DETAIL},
        )
        await response(scope, receive, send)

    def _is_refused(self, scope: Scope) -> bool:
        """Reports whether the base middleware would refuse this request.

        The host is matched exactly and against a ``*.`` suffix pattern,
        as the base middleware matches it, and a host it would redirect
        to the ``www.`` form counts as not refused, and the redirect is
        still the base middleware's to issue.
        """
        if (
            self.allow_any
            or scope["type"] not in _HOST_CHECKED_SCOPES
        ):
            return False
        host = Headers(scope=scope).get(_HOST_HEADER, "").split(":")[0]
        for pattern in self.allowed_hosts:
            if host == pattern or (
                pattern.startswith("*") and host.endswith(pattern[1:])
            ):
                return False
            if self.www_redirect and "www." + host == pattern:
                return False
        return True


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
    through the redacting logger as its class, the module that defines
    it, the route and method that reached it and the request identifier
    that correlates the two; ``exception_message`` is suppressed, so no
    message text travels with the record. The formatted traceback is
    still emitted at ``DEBUG``, which production levels suppress. This
    handler runs outside the middleware stack, so it sets
    :data:`SECURITY_HEADERS` and the cross-origin headers of
    :func:`_cors_headers` on the response it builds.
    """
    request_id = _scoped_request_id(request)
    log_exception(
        logger,
        "Unhandled application error",
        exc,
        exception_message=None,
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


async def pool_timeout_handler(
    request: Request, exc: PoolTimeout
) -> Response:
    """Answers a request the connection pool had no connection for.

    The pool raises this when a request has waited
    ``settings.DB_POOL_TIMEOUT_SECONDS`` and no connection became free.
    :class:`RequestAdmissionMiddleware` holds the number of requests that
    can want one below the pool's ceiling, so this is reached by a route
    that layer does not hold or by one whose demand it does not predict,
    and the answer is the same either way: a capacity limit rather than a
    fault, with ``Retry-After`` saying how long to wait, so a client or a
    load balancer can retry rather than treating the answer as a failed
    request. The body carries :data:`CAPACITY_DETAIL` and the request
    identifier and nothing else -- no pool size, no exception text and no
    traceback.

    This handler is registered for the pool's own exception class, so it
    is reached inside the middleware stack and the response it returns
    carries :data:`SECURITY_HEADERS`, the cross-origin headers and
    :data:`REQUEST_ID_HEADER` from the layers it travels back out
    through.
    """
    request_id = _scoped_request_id(request)
    log_exception(
        logger,
        POOL_EXHAUSTED_MESSAGE,
        exc,
        exception_message=None,
        path=request.scope.get("path"),
        method=request.scope.get("method"),
        request_id=request_id,
        pool_timeout_seconds=settings.DB_POOL_TIMEOUT_SECONDS,
        retry_after_seconds=capacity_retry_after_seconds(),
    )
    return _capacity_response(request_id)


def _throttled_response(
    request: Request, exc: RateLimitExceeded
) -> Response:
    """Returns the response one request refused by its rate limit gets.

    The body carries :data:`TOO_MANY_REQUESTS_DETAIL` under ``detail``,
    the key every other rejection this application returns uses, and the
    policy that was exceeded is reported through headers rather than in
    the body. The limiter writes those headers onto the response it is
    handed, so the reply carries ``Retry-After`` in seconds together with
    the request count the window admits, the count remaining and the
    time the window resets. The wait that header names is also carried in
    the body under :data:`RETRY_AFTER_FIELD`, so a caller reading only
    the body is told how long to wait and not merely that it must.
    """
    response = JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": TOO_MANY_REQUESTS_DETAIL},
    )
    evaluated = getattr(
        request.state, _EVALUATED_LIMIT_ATTRIBUTE, None
    )
    response = limiter._inject_headers(response, evaluated)
    return _with_retry_window(response)


def _with_retry_window(response: Response) -> Response:
    """Restates a throttled response's ``Retry-After`` wait in its body.

    The limiter writes the header after the body has been rendered, so
    the body is rendered a second time here once the value is known, and
    ``Content-Length`` is corrected to the new body. The header carries
    whole seconds rather than an HTTP date, which
    :data:`backend.app.core.rate_limit.RETRY_AFTER_FORMAT` fixes. A
    header that is absent, non-numeric or negative leaves the body at the
    shape :func:`_throttled_response` built, so the ``detail`` key is
    present on every throttled reply whatever the limiter reported.
    """
    raw = response.headers.get(RETRY_AFTER_HEADER)
    if raw is None:
        return response
    try:
        seconds = int(raw)
    except (TypeError, ValueError):
        return response
    if seconds < 0:
        return response
    body = response.render(
        {
            "detail": TOO_MANY_REQUESTS_DETAIL,
            RETRY_AFTER_FIELD: seconds,
        }
    )
    response.body = body
    response.headers["content-length"] = str(len(body))
    return response


async def rate_limit_exceeded_handler(
    request: Request, exc: RateLimitExceeded
) -> Response:
    """Records one throttling decision and returns its response.

    The record carries the request path and method and the policy that
    was exceeded. The response is the one :func:`_throttled_response`
    builds, so a refusal taken here reads exactly like one taken by
    :class:`RateLimitGateMiddleware`.
    """
    logger.warning(
        THROTTLED_MESSAGE,
        extra={
            "path": request.scope.get("path"),
            "method": request.scope.get("method"),
            "policy": _rate_limit_policy(exc),
        },
    )
    return _throttled_response(request, exc)


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


def _error_response_schema() -> Dict[str, Any]:
    """Returns the schema of the body a refusal carries.

    It is the shape :func:`validation_exception_handler` and every other
    refusal in this module return: an object carrying a single fixed
    string under :data:`REFUSAL_DETAIL_FIELD`.
    """
    return {
        "title": ERROR_RESPONSE_COMPONENT,
        "type": "object",
        "properties": {
            REFUSAL_DETAIL_FIELD: {
                "title": REFUSAL_DETAIL_FIELD.capitalize(),
                "type": "string",
            }
        },
        "required": [REFUSAL_DETAIL_FIELD],
    }


def _aligned_refusal_bodies(document: Dict[str, Any]) -> Dict[str, Any]:
    """Publishes the refusal body the routes in ``document`` return.

    :data:`ERROR_RESPONSE_COMPONENT` is added and named by every
    published :data:`PUBLISHED_REFUSAL_STATUS` response, and the
    :data:`GENERATED_VALIDATION_COMPONENTS` that naming leaves
    unreferenced are removed. Only that status is rewritten, and the
    document is returned rather than copied, so calling this twice on one
    document leaves it as the first call did.
    """
    components = document.setdefault("components", {})
    schemas = components.setdefault("schemas", {})
    schemas[ERROR_RESPONSE_COMPONENT] = _error_response_schema()
    for name in GENERATED_VALIDATION_COMPONENTS:
        schemas.pop(name, None)
    for operations in document.get("paths", {}).values():
        for operation in operations.values():
            if not isinstance(operation, dict):
                continue
            responses = operation.get("responses")
            if not isinstance(responses, dict):
                continue
            refusal = responses.get(PUBLISHED_REFUSAL_STATUS)
            if not isinstance(refusal, dict):
                continue
            refusal["content"] = {
                _JSON_MEDIA_TYPE: {
                    "schema": {"$ref": _ERROR_RESPONSE_REFERENCE}
                }
            }
    return document


_generated_api_schema = app.openapi


def api_schema() -> Dict[str, Any]:
    """Returns the published OpenAPI document, generating it once.

    The generated document is passed through
    :func:`_aligned_refusal_bodies` before it is published, and the
    result is held on the application, so a later call returns the
    document the first call aligned.
    """
    published = app.openapi_schema
    if published is None:
        published = _aligned_refusal_bodies(_generated_api_schema())
        app.openapi_schema = published
    return published


app.openapi = api_schema

app.add_exception_handler(
    StarletteHTTPException, http_exception_handler
)
app.add_exception_handler(
    RequestValidationError, validation_exception_handler
)
app.add_exception_handler(
    RateLimitExceeded, rate_limit_exceeded_handler
)
# Registered for the pool's own class rather than left to the catch-all
# below, which answers 500 and re-raises so the failure also reaches the
# server as an unhandled error.
app.add_exception_handler(PoolTimeout, pool_timeout_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

# Registered innermost first: the layer added last is the first to run
# on an inbound request. The resulting inbound order is request
# identifier, response headers, cross-origin policy, host validation,
# rate limiter, body-size cap, body prefetch, admission gate, router. The
# rate limiter sits outside the body-size cap, so a request over its
# limit is refused before any chunk of its body is read, and the
# cross-origin layer encloses both the host check and those two, so the
# 400, 429 and 413 they return carry the same headers as any other
# response. The admission gate is innermost, so it encloses the router
# and nothing else: a request the limiter or the body cap refuses never
# takes an admission slot, and every slot it does hand out is held for
# the whole of the routed request, including the session teardown FastAPI
# runs before the router returns. The 503 it returns travels back out
# through the layers above it, so it carries the same headers too.
#
# The prefetch layer sits between the body cap and the gate, so a body is
# read under the cap's counting channel and under its own deadlines
# before a slot is taken: a client that stalls part-way through sending
# one is answered 408 and never occupies capacity the routes need.
app.add_middleware(
    RequestAdmissionMiddleware,
    bound=admitted_concurrency(settings.DATABASE_URL),
    wait_seconds=settings.DB_POOL_TIMEOUT_SECONDS,
)
app.add_middleware(
    BodyPrefetchMiddleware,
    total_seconds=settings.REQUEST_BODY_TIMEOUT_SECONDS,
    chunk_seconds=settings.REQUEST_BODY_CHUNK_TIMEOUT_SECONDS,
)
app.add_middleware(
    BodySizeLimitMiddleware,
    max_body_bytes=settings.MAX_REQUEST_BODY_BYTES,
    max_messages=settings.MAX_REQUEST_BODY_CHUNKS,
)
app.add_middleware(RateLimitGateMiddleware, limiter=limiter)
app.add_middleware(
    TrustedHostGateMiddleware, allowed_hosts=settings.ALLOWED_HOSTS
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=list(CORS_ALLOW_METHODS),
    allow_headers=list(CORS_ALLOW_HEADERS),
    expose_headers=list(CORS_EXPOSE_HEADERS),
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)

app.include_router(api_router)


#: Guards the recorded outcome below, for the length of one assignment
#: or one read.
_readiness_state_lock = threading.Lock()

#: Guards the one database read the readiness route performs at a time.
#: It is held for the length of that read and is never held while
#: :data:`_readiness_state_lock` is.
_readiness_probe_lock = threading.Lock()

#: The last recorded readiness outcome and the monotonic instant it stops
#: being reused, or ``None`` while no outcome has been recorded.
_readiness_cache: Optional[Tuple[bool, float]] = None


def reset_readiness_cache() -> None:
    """Discards the recorded readiness outcome.

    The next call to :func:`readiness_outcome` reads the database again.
    """
    global _readiness_cache
    with _readiness_state_lock:
        _readiness_cache = None


def _recorded_readiness() -> Optional[Tuple[bool, float]]:
    """Returns the recorded outcome and its expiry, or ``None``."""
    with _readiness_state_lock:
        return _readiness_cache


def _record_readiness(ready: bool) -> None:
    """Records one outcome and the instant it stops being reused."""
    global _readiness_cache
    expiry = time.monotonic() + settings.READINESS_CACHE_SECONDS
    with _readiness_state_lock:
        _readiness_cache = (ready, expiry)


def _reusable_readiness() -> Optional[bool]:
    """Returns the recorded outcome while it may still be reused."""
    recorded = _recorded_readiness()
    if recorded is not None and time.monotonic() < recorded[1]:
        return recorded[0]
    return None


def _bound_readiness_transaction(db: Session) -> None:
    """Bounds the probe's own transaction where the dialect supports it.

    Each bound is set with its local flag, so it applies to this
    transaction alone and no other user of the shared engine inherits it.
    A dialect outside :data:`READINESS_BOUND_DIALECTS` is left alone.
    """
    if db.get_bind().dialect.name not in READINESS_BOUND_DIALECTS:
        return
    milliseconds = str(int(settings.READINESS_TIMEOUT_SECONDS * 1000))
    for statement in READINESS_BOUND_STATEMENTS:
        db.execute(statement, {"milliseconds": milliseconds})


def _read_database(db: Session) -> bool:
    """Reads :data:`READINESS_STATEMENT` under a bounded transaction."""
    try:
        _bound_readiness_transaction(db)
        db.execute(READINESS_STATEMENT)
    except Exception as error:
        log_exception(logger, READINESS_FAILURE_MESSAGE, error)
        return False
    finally:
        try:
            db.rollback()
        except Exception as error:  # pragma: no cover - driver dependent
            log_exception(logger, READINESS_FAILURE_MESSAGE, error)
    return True


def readiness_outcome(db: Session) -> bool:
    """Returns whether the database answered, reading it at most once.

    A recorded outcome younger than ``settings.READINESS_CACHE_SECONDS``
    is returned without touching the database, so a burst of probes costs
    one read rather than one read each. The session is opened lazily, so a
    reused outcome checks out no connection at all.

    Only one caller performs the read. A caller arriving while that read
    is in flight answers from the last recorded outcome, and refuses when
    there is none, so the number of connections this route holds never
    exceeds one however many callers arrive.
    """
    reusable = _reusable_readiness()
    if reusable is not None:
        return reusable

    if not _readiness_probe_lock.acquire(blocking=False):
        logger.warning(READINESS_CONCURRENT_MESSAGE)
        recorded = _recorded_readiness()
        return recorded[0] if recorded is not None else False

    try:
        reusable = _reusable_readiness()
        if reusable is not None:
            return reusable
        ready = _read_database(db)
        _record_readiness(ready)
    finally:
        _readiness_probe_lock.release()
    return ready


@app.get(HEALTH_PATH)
async def health_check() -> Dict[str, str]:
    """Reports that the process is able to serve requests.

    Answered on the event loop rather than in a worker thread. It reads
    nothing and waits on nothing, and this path is exempt from the
    admission bound, so the liveness reading is independent of how many
    database-bound requests are in flight or waiting for admission.
    """
    return {"status": HEALTH_STATUS}


def _report_degraded_sinks() -> None:
    """Records the counts of records a sink failed to write, if any.

    Two counters are read: the refusals the audit sink rejected, and the
    records the logging handler could not emit. Each is a count of
    records this process produced and could not write through its
    primary sink, so a non-zero value means the evidence trail is
    incomplete even though the process is serving. When both are zero
    nothing is recorded.

    The record carries the counts as discrete fields and no request
    content. It is emitted rather than returned, so the readiness
    response body is unchanged.
    """
    audit_failures = audit_failure_count()
    emit_failures = logging_failure_count()
    if not audit_failures and not emit_failures:
        return
    logger.warning(
        SINK_DEGRADED_MESSAGE,
        extra={
            SIGNAL_FIELD: SINK_DEGRADED_SIGNAL,
            "audit_failures": audit_failures,
            "log_emit_failures": emit_failures,
        },
    )


@app.get(READINESS_PATH)
@limiter.limit(settings.RATE_LIMIT_READINESS)
def readiness_check(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> Dict[str, str]:
    """Return bounded database readiness, reusing cached outcomes and
    reporting degraded log sinks.
    """
    _report_degraded_sinks()
    if readiness_outcome(db):
        return {"status": READINESS_STATUS}
    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": NOT_READY_STATUS}
