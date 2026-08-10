"""Bounded PayPal REST order, capture, and webhook-verification
operations.
"""

import asyncio
import json
import math
import re
import threading
import time
from contextlib import asynccontextmanager
from typing import (
    Any,
    AsyncIterator,
    Dict,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Tuple,
)
from urllib.parse import urlsplit

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from backend.app.core.authorization import load_owned
from backend.app.core.config import TLS_SCHEME, settings
from backend.app.core.logging import (
    exception_fields,
    get_logger,
    outbound_trace_headers,
    register_required_secret_values,
)
from backend.app.core.plans import format_amount, get_plan
from backend.app.db.models import Subscription

__all__ = [
    "APPROVAL_HOSTS",
    "APPROVAL_REL",
    "AUTH_ALGO_HEADER",
    "CAPTURE_COMPLETED_STATUS",
    "CATEGORY_AUTHENTICATION",
    "CATEGORY_MALFORMED_RESPONSE",
    "CATEGORY_PROVIDER_CLIENT",
    "CATEGORY_PROVIDER_SERVER",
    "CATEGORY_RATE_LIMITED",
    "CATEGORY_TIMEOUT",
    "CATEGORY_TRANSPORT",
    "CERT_URL_HEADER",
    "DEBUG_ID_HEADER",
    "ERROR_CATEGORIES",
    "EXPIRY_MARGIN_SECONDS",
    "IDEMPOTENCY_HEADER",
    "ISSUE_ORDER_ALREADY_CAPTURED",
    "REASON_AMOUNT_MISMATCH",
    "FAILURE_BACKOFF_SECONDS",
    "KEEPALIVE_EXPIRY_SECONDS",
    "MAX_CONNECTIONS",
    "MAX_KEEPALIVE_CONNECTIONS",
    "MAX_PROVIDER_ISSUE_DETAILS",
    "MAX_RESPONSE_BYTES",
    "PROVIDER_ISSUE_FIELDS",
    "PROVIDER_ISSUE_PATTERN",
    "PREFER_HEADER",
    "PREFER_REPRESENTATION",
    "REASON_CERTIFICATE_HOST",
    "REASON_CURRENCY_MISMATCH",
    "REASON_MALFORMED_BODY",
    "REASON_RESPONSE_TOO_LARGE",
    "REASON_MALFORMED_CAPTURE",
    "REASON_MISSING_HEADER",
    "REASON_NOT_COMPLETED",
    "REASON_ORDER_MISMATCH",
    "REASON_SIGNATURE",
    "REASON_VERIFIER_UNAVAILABLE",
    "REQUIRED_WEBHOOK_HEADERS",
    "RETRYABLE_CATEGORIES",
    "TRANSMISSION_ID_HEADER",
    "TRANSMISSION_SIG_HEADER",
    "TRANSMISSION_TIME_HEADER",
    "VERIFICATION_FAILURE",
    "VERIFICATION_STATUSES",
    "VERIFICATION_SUCCESS",
    "VERIFICATION_STATUS_FIELD",
    "WEBHOOK_EVENT_FIELD",
    "CaptureOutcome",
    "OrderOwnershipError",
    "PayPalAPIError",
    "PayPalError",
    "WebhookVerification",
    "approval_url",
    "capture_order",
    "capture_request_id",
    "fetch_order",
    "close_http_client",
    "create_order",
    "open_http_client",
    "order_request_id",
    "read_capture",
    "reset_access_token_cache",
    "verify_settled_order",
    "verify_webhook_signature",
    "webhook_body_object",
]

PAYPAL_CLIENT_ID = settings.PAYPAL_CLIENT_ID
PAYPAL_CLIENT_SECRET = settings.PAYPAL_CLIENT_SECRET

logger = get_logger(__name__)

# Replaces the provider credentials wherever they appear in a record,
# including in text that names no key such as provider error prose.
register_required_secret_values(
    PAYPAL_CLIENT_SECRET, settings.PAYPAL_WEBHOOK_ID
)

#: Header naming the signature algorithm, mapped to ``auth_algo``.
AUTH_ALGO_HEADER = "PAYPAL-AUTH-ALGO"

#: Header naming the signing certificate, mapped to ``cert_url``.
CERT_URL_HEADER = "PAYPAL-CERT-URL"

#: Header naming the delivery, mapped to ``transmission_id``.
TRANSMISSION_ID_HEADER = "PAYPAL-TRANSMISSION-ID"

#: Header carrying the signature, mapped to ``transmission_sig``.
TRANSMISSION_SIG_HEADER = "PAYPAL-TRANSMISSION-SIG"

#: Header carrying the send time, mapped to ``transmission_time``.
TRANSMISSION_TIME_HEADER = "PAYPAL-TRANSMISSION-TIME"

#: Request header asking the provider for a complete representation of
#: the resource a mutating call produced.
PREFER_HEADER = "Prefer"

#: Value sent as :data:`PREFER_HEADER` on the capture call, which is what
#: makes the response carry the settled amount, currency and capture
#: identifier rather than only an identifier and a status.
PREFER_REPRESENTATION = "return=representation"

#: Relation naming the hosted approval target among an order's links.
APPROVAL_REL = "approve"

#: Domains a hosted approval target may address. A host equal to one of
#: these, or a subdomain of one of them, is accepted.
APPROVAL_HOSTS = frozenset({"paypal.com"})

#: Every header a notification must carry to be checked at all.
REQUIRED_WEBHOOK_HEADERS = (
    AUTH_ALGO_HEADER,
    CERT_URL_HEADER,
    TRANSMISSION_ID_HEADER,
    TRANSMISSION_SIG_HEADER,
    TRANSMISSION_TIME_HEADER,
)

#: The only ``verification_status`` treated as a passing check.
VERIFICATION_SUCCESS = "SUCCESS"

#: The only ``verification_status`` treated as a rejected signature.
VERIFICATION_FAILURE = "FAILURE"

#: Every ``verification_status`` the verifier is understood to report.
#: A value outside this set, a value of another type and an absent value
#: are each treated as a check that could not be completed.
VERIFICATION_STATUSES = (VERIFICATION_SUCCESS, VERIFICATION_FAILURE)

#: Rejection reason: the certificate host is outside the allowlist.
REASON_CERTIFICATE_HOST = "certificate_host_not_allowlisted"

#: Rejection reason: at least one required header is absent or blank.
REASON_MISSING_HEADER = "required_header_missing"

#: Rejection reason: the raw body does not decode to a JSON object.
REASON_MALFORMED_BODY = "malformed_body"

#: Field of the postback document that carries the notification.
WEBHOOK_EVENT_FIELD = "webhook_event"

#: Field of the verifier's response that carries its outcome.
VERIFICATION_STATUS_FIELD = "verification_status"

#: Rejection reason: PayPal reported :data:`VERIFICATION_FAILURE`.
REASON_SIGNATURE = "signature_not_verified"

#: Rejection reason: the check could not be completed. Covers a verifier
#: that could not be reached or did not answer, and a verifier answer
#: that does not carry a :data:`VERIFICATION_STATUSES` value.
REASON_VERIFIER_UNAVAILABLE = "verifier_unavailable"

#: Response header carrying the provider's support correlation handle.
DEBUG_ID_HEADER = "PayPal-Debug-Id"

#: Request header carrying the idempotency key of a mutating call.
IDEMPOTENCY_HEADER = "PayPal-Request-Id"

#: Failure category: the call did not complete within the timeout.
CATEGORY_TIMEOUT = "timeout"

#: Failure category: the call did not reach the provider.
CATEGORY_TRANSPORT = "transport"

#: Failure category: the provider answered a server error.
CATEGORY_PROVIDER_SERVER = "provider_server"

#: Failure category: the provider rejected the request as sent.
CATEGORY_PROVIDER_CLIENT = "provider_client"

#: Failure category: the provider throttled the call.
CATEGORY_RATE_LIMITED = "rate_limited"

#: Failure category: the provider rejected the credentials or the token.
CATEGORY_AUTHENTICATION = "authentication"

#: Failure category: the provider's body was not usable.
CATEGORY_MALFORMED_RESPONSE = "malformed_response"

#: Every category a :class:`PayPalAPIError` may carry.
ERROR_CATEGORIES = (
    CATEGORY_TIMEOUT,
    CATEGORY_TRANSPORT,
    CATEGORY_PROVIDER_SERVER,
    CATEGORY_PROVIDER_CLIENT,
    CATEGORY_RATE_LIMITED,
    CATEGORY_AUTHENTICATION,
    CATEGORY_MALFORMED_RESPONSE,
)

#: The categories whose failure may resolve on a later attempt.
RETRYABLE_CATEGORIES = frozenset(
    {
        CATEGORY_TIMEOUT,
        CATEGORY_TRANSPORT,
        CATEGORY_PROVIDER_SERVER,
        CATEGORY_RATE_LIMITED,
    }
)

#: The only capture status treated as a settled payment.
CAPTURE_COMPLETED_STATUS = "COMPLETED"

#: Capture rejection: the response names a different order.
REASON_ORDER_MISMATCH = "order_id_mismatch"

#: Capture rejection: the provider did not report completion.
REASON_NOT_COMPLETED = "capture_not_completed"

#: Capture rejection: the captured amount is not the plan's amount.
REASON_AMOUNT_MISMATCH = "captured_amount_mismatch"

#: Capture rejection: the captured currency is not the plan's currency.
REASON_CURRENCY_MISMATCH = "captured_currency_mismatch"

#: Capture rejection: the response could not be read.
REASON_MALFORMED_CAPTURE = "capture_response_malformed"

#: Provider issue reporting that the order named by a capture call has
#: already been settled. It is the one issue a caller may treat as a
#: settlement to be read back rather than as a failed call.
ISSUE_ORDER_ALREADY_CAPTURED = "ORDER_ALREADY_CAPTURED"

#: Fields of a provider error body the issue code is read from, in the
#: order they are consulted. ``details`` is a list whose entries carry
#: ``issue``; ``name`` is the error's own identifier. No other field of
#: the body is read, and no value from any other field is retained.
PROVIDER_ISSUE_FIELDS = ("details", "name")

#: Entries of ``details`` this many deep are examined; a longer list is
#: read no further, so the work one error body can cause is bounded.
MAX_PROVIDER_ISSUE_DETAILS = 16

#: Shape an issue code must have to be carried. A value that is not an
#: upper-case identifier of at most 64 characters is discarded rather
#: than retained, so nothing a provider body carries reaches a caller or
#: a log record except a code of this shape.
PROVIDER_ISSUE_PATTERN = re.compile(r"\A[A-Z][A-Z0-9_]{0,63}\Z")

#: Prefix of the idempotency key sent when an order is opened.
_ORDER_KEY_PREFIX = "sub-order-"

#: Prefix of the idempotency key sent when an order is captured.
_CAPTURE_KEY_PREFIX = "sub-capture-"

#: Seconds trimmed from the reported lifetime before a token is reused.
EXPIRY_MARGIN_SECONDS = 60.0

#: Seconds a failed credential exchange is not repeated for.
FAILURE_BACKOFF_SECONDS = 5.0

#: Bytes of a provider response body that are decoded. A body declaring
#: or carrying more is refused before it is decoded, so the memory one
#: response can be made to occupy is bounded whatever the provider sends.
MAX_RESPONSE_BYTES = 1048576

#: Field naming the provider order a record is about. It is emitted
#: alongside the request identifier the logger binds and the provider's
#: own debug identifier, so one record carries the local identifier and
#: both provider identifiers for the same call.
PROVIDER_ORDER_FIELD = "provider_order_id"

#: Rejection reason: the response body exceeds :data:`MAX_RESPONSE_BYTES`.
REASON_RESPONSE_TOO_LARGE = "response_body_too_large"

#: Response header declaring the body length.
CONTENT_LENGTH_HEADER = "Content-Length"

#: Connections the shared client keeps open at once.
MAX_CONNECTIONS = 20

#: Idle connections the shared client keeps for reuse.
MAX_KEEPALIVE_CONNECTIONS = 10

#: Seconds an idle pooled connection is kept before it is dropped.
KEEPALIVE_EXPIRY_SECONDS = 30.0

# Path of the OAuth2 client-credentials grant.
_OAUTH_PATH = "/v1/oauth2/token"

_ORDERS_PATH = "/v2/checkout/orders"

_CAPTURE_SUFFIX = "/capture"

_VERIFY_PATH = "/v1/notifications/verify-webhook-signature"

_GRANT_TYPE = "client_credentials"

_ORDER_INTENT = "CAPTURE"

_ORDER_DESCRIPTION = "Subscription Payment"

# Payer experience settings carried on the created order.
_USER_ACTION = "PAY_NOW"
_SHIPPING_PREFERENCE = "NO_SHIPPING"
_PAYMENT_METHOD_PREFERENCE = "IMMEDIATE_PAYMENT_REQUIRED"

# Link relations that carry the payer-approval target, most specific
# first.
_APPROVAL_RELATIONS = ("payer-action", "approve")

# Operation names recorded on a provider call.
_OPERATION_TOKEN = "oauth_token"
_OPERATION_CREATE = "create_order"
_OPERATION_CAPTURE = "capture_order"
_OPERATION_FETCH = "fetch_order"
_OPERATION_VERIFY = "verify_webhook_signature"

# Provider status that retires the cached access token.
_UNAUTHORIZED_STATUS = 401

# Provider status that marks the call as throttled.
_TOO_MANY_REQUESTS_STATUS = 429

# Lowest provider status treated as a provider-side error.
_SERVER_ERROR_STATUS = 500

# Provider status that marks the call as forbidden.
_FORBIDDEN_STATUS = 403

# Message returned for every refused capture. One message covers an
# order that resolves to no row and an order owned by another principal.
_CAPTURE_REFUSED = "The order is not available to the requesting user."

# No response body, URL or credential reaches this message.
_CALL_FAILED = "The PayPal REST API call did not succeed."

# Request method named in the record of a read call.
_GET_METHOD = "GET"

# Request method every write call is issued with.
_POST_METHOD = "POST"

# Failures translated into a module error. httpx.InvalidURL,
# httpx.CookieConflict and httpx.StreamError sit outside the
# httpx.HTTPError hierarchy, and ValueError covers the JSON decode
# error raised while a body is parsed.
_TRANSPORT_ERRORS = (
    httpx.HTTPError,
    httpx.InvalidURL,
    httpx.CookieConflict,
    httpx.StreamError,
    ValueError,
)

# Guards the cached token, the refresh flag and the backoff deadline, and
# carries the notification that a refresh has finished. Held only while
# those values are read or written, never while a request is in flight.
_CACHE_STATE = threading.Condition()

_cached_access = None  # type: Optional[str]

_cached_deadline = 0.0

# Instant before which no further credential exchange is attempted, and
# the failure that set it. Both are cleared by a successful exchange and
# by reset_access_token_cache.
_backoff_deadline = 0.0

_backoff_failure = None  # type: Optional[Tuple[str, Optional[int], bool]]

# Generation of the token cache. reset_access_token_cache advances it, and
# an exchange started under an earlier generation stores neither its token
# nor its failure, so a rotation is never undone by a call already in
# flight when it happened.
_cache_generation = 0

# Client shared by every call issued on the event loop that opened it,
# with the loop it belongs to, or None when the application has not
# opened one.
_shared_client = None  # type: Optional[httpx.AsyncClient]

_shared_client_loop = None  # type: Optional[Any]

# Single-flight token-refresh lock, with the loop it was created on. An
# asyncio lock belongs to one loop, so it is replaced when the running
# loop is not the one it was created on.
_refresh_lock_object = None  # type: Optional["asyncio.Lock"]

_refresh_lock_loop = None  # type: Optional[Any]


def _running_loop() -> Optional[Any]:
    """Returns the event loop this call is running on, or ``None``."""
    try:
        return asyncio.get_event_loop()
    except RuntimeError:
        return None


def _refresh_lock() -> "asyncio.Lock":
    """Returns the single-flight token-refresh lock for this loop.

    A lock created on another loop is replaced, so the lock returned is
    always one the awaiting caller's own loop can hold. At most one lock
    is held at a time, so a loop that has ended leaves nothing behind.
    """
    global _refresh_lock_object, _refresh_lock_loop
    loop = _running_loop()
    with _CACHE_STATE:
        if _refresh_lock_object is None or _refresh_lock_loop is not loop:
            _refresh_lock_object = asyncio.Lock()
            _refresh_lock_loop = loop
        return _refresh_lock_object


def _build_client() -> "httpx.AsyncClient":
    """Creates an asynchronous client carrying the configured timeout.

    The connection pool is bounded by :data:`MAX_CONNECTIONS` and
    :data:`MAX_KEEPALIVE_CONNECTIONS`, capped in turn by
    ``settings.PAYPAL_MAX_CONNECTIONS``, so a burst of concurrent calls
    queues on the pool rather than opening an unbounded number of
    sockets against the provider.
    """
    ceiling = settings.PAYPAL_MAX_CONNECTIONS
    return httpx.AsyncClient(
        timeout=settings.HTTP_TIMEOUT_SECONDS,
        limits=httpx.Limits(
            max_connections=min(MAX_CONNECTIONS, ceiling),
            max_keepalive_connections=min(
                MAX_KEEPALIVE_CONNECTIONS, ceiling
            ),
            keepalive_expiry=KEEPALIVE_EXPIRY_SECONDS,
        ),
    )


async def open_http_client() -> None:
    """Opens the client every call on this event loop shares.

    Called once while the application starts. The client is recorded
    against the loop it was opened on, and :func:`_client` yields it only
    to a call running on that same loop. Calling this again while a client
    is already open leaves that client in place.
    """
    global _shared_client, _shared_client_loop
    if _shared_client is not None:
        return
    _shared_client = _build_client()
    _shared_client_loop = _running_loop()


async def close_http_client() -> None:
    """Closes the shared client and releases its connections.

    Called once while the application stops. Calling it when no client is
    open does nothing.
    """
    global _shared_client, _shared_client_loop
    client = _shared_client
    _shared_client = None
    _shared_client_loop = None
    if client is None:
        return
    await client.aclose()


@asynccontextmanager
async def _client() -> "AsyncIterator[httpx.AsyncClient]":
    """Yields the client a single call should be issued through.

    The shared client is yielded to a call running on the loop that
    opened it. A call made outside the application's lifetime -- from a
    task or a test driving a function directly -- or on any other loop
    gets a client of its own, which is closed when the block ends.
    """
    shared = _shared_client
    if shared is not None and _shared_client_loop is _running_loop():
        yield shared
        return
    async with _build_client() as temporary:
        yield temporary


class PayPalError(Exception):
    """Base class for every error raised by this module."""


class OrderOwnershipError(PayPalError):
    """Raised when an order is not owned by the requesting principal.

    Raised both when the order identifier resolves to no stored row and
    when it resolves to a row held by another user. The two cases carry
    the same message and are not distinguished.
    """


class PayPalAPIError(PayPalError):
    """Provider failure with sanitized category, status, debug
    identifier, issue code, and retryability metadata.
    """

    def __init__(
        self,
        message: str,
        category: str = CATEGORY_TRANSPORT,
        status_code: Optional[int] = None,
        debug_id: Optional[str] = None,
        retryable: Optional[bool] = None,
        operation: Optional[str] = None,
        issue: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.status_code = status_code
        self.debug_id = debug_id
        self.operation = operation
        self.issue = issue
        if retryable is None:
            self.retryable = category in RETRYABLE_CATEGORIES
        else:
            self.retryable = bool(retryable)

    def audit_fields(self) -> Dict[str, Any]:
        """Returns the fields describing this failure for a log record."""
        return {
            "provider_category": self.category,
            "provider_status": self.status_code,
            "paypal_debug_id": self.debug_id,
            "provider_operation": self.operation,
            "provider_issue": self.issue,
            "provider_retryable": self.retryable,
        }


class WebhookVerification(NamedTuple):
    """Outcome of one webhook signature check.

    ``verified`` is True only when PayPal reported a passing check.
    ``transmission_id`` and ``event_type`` are populated only on that
    outcome, and ``reason`` is populated only on a rejection.
    ``retryable`` is True when the check itself could not be completed,
    so the notification may be delivered again.
    """

    verified: bool
    transmission_id: Optional[str] = None
    event_type: Optional[str] = None
    reason: Optional[str] = None
    retryable: bool = False


class CaptureOutcome(NamedTuple):
    """What a capture response reports about the payment it settled.

    ``completed`` is True only when the response names the expected
    order, reports :data:`CAPTURE_COMPLETED_STATUS`, carries the
    expected amount and currency, and carries a provider identifier for
    the settlement. ``capture_id`` is that identifier and is populated on
    every completed outcome. No column holds it: the caller writes it to
    the activation audit record, under ``paypal_capture_id``, and the
    ``subscriptions`` row retains only ``paypal_order_id``. ``reason``
    names the first check that failed and is ``None`` on a completed
    capture.
    """

    completed: bool
    order_id: Optional[str] = None
    status: Optional[str] = None
    amount: Optional[str] = None
    currency: Optional[str] = None
    capture_id: Optional[str] = None
    reason: Optional[str] = None


def _declared_length(response: Any) -> Optional[int]:
    """Returns the body length a response declares, or ``None``."""
    try:
        value = response.headers.get(CONTENT_LENGTH_HEADER)
    except Exception:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _refuse_size(
    measured: int, operation: Optional[str], response: Any
) -> None:
    """Records a body refused for its size, with the cap it passed.

    The record names the operation, the reason, the size measured, the cap
    and the provider's debug identifier. No part of the body is recorded.
    """
    logger.error(
        "PayPal REST call returned a body past the accepted size",
        extra={
            "provider_operation": operation,
            "reason": REASON_RESPONSE_TOO_LARGE,
            "response_bytes": measured,
            "max_response_bytes": MAX_RESPONSE_BYTES,
            "paypal_debug_id": _debug_id(response),
        },
    )


async def _bounded_body(
    response: Any, operation: Optional[str]
) -> Optional[bytes]:
    """Returns the streamed body, or ``None`` when it passes the cap.

    The declared length is read first, so a body announcing itself as past
    :data:`MAX_RESPONSE_BYTES` is refused before any of it is read. The
    bytes received are then accumulated one chunk at a time and the read
    stops as soon as they pass that cap, so a body declaring no length, or
    under-declaring one, is bounded as well. At most
    :data:`MAX_RESPONSE_BYTES` plus one chunk is ever held.
    """
    declared = _declared_length(response)
    if declared is not None and declared > MAX_RESPONSE_BYTES:
        _refuse_size(declared, operation, response)
        return None
    received = 0
    chunks = []
    async for chunk in response.aiter_bytes():
        received += len(chunk)
        if received > MAX_RESPONSE_BYTES:
            _refuse_size(received, operation, response)
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _oversized(response: Any, operation: Optional[str]) -> bool:
    """Report whether a response body is past :data:`MAX_RESPONSE_BYTES`.

    Applies to a response whose body is already held in memory, which is
    the error responses :func:`_provider_issue` is handed when no streamed
    body was captured. The declared length is read first, so a body that
    announces itself as oversized is refused without its bytes being
    examined. The bytes actually received are measured next, which covers
    a body that declares no length or under-declares one.
    """
    for measured in (_declared_length(response), _body_length(response)):
        if measured is not None and measured > MAX_RESPONSE_BYTES:
            _refuse_size(measured, operation, response)
            return True
    return False


def _body_length(response: Any) -> Optional[int]:
    """Returns the number of bytes a response carries, or ``None``.

    ``None`` is returned for a response whose body has not been read,
    which is the state of a streamed response before its chunks are
    taken. Reading the attribute raises in that state, so the failure is
    answered with ``None`` and the declared length carries the check.
    """
    try:
        body = getattr(response, "content", None)
    except Exception:
        return None
    if isinstance(body, (bytes, bytearray)):
        return len(body)
    return None


def _without_declared_length(headers: Any) -> List[Tuple[str, str]]:
    """Returns ``headers`` without the length of the original body.

    The reconstructed response carries fewer bytes than the transfer
    declared whenever the read was stopped, so the declared length is
    dropped and the client states the length of what is actually held.
    """
    return [
        (name, value)
        for name, value in headers.items()
        if name.lower() != CONTENT_LENGTH_HEADER.lower()
    ]


async def _read_bounded(
    client: Any,
    method: str,
    url: str,
    operation: Optional[str] = None,
    **arguments: Any
) -> Any:
    """Stream a response only up to MAX_RESPONSE_BYTES and raise a
    malformed-response error when exceeded.
    """
    opener = getattr(client, "stream", None)
    if opener is None:
        verb = getattr(client, method.lower(), None)
        if verb is not None:
            return await verb(url, **arguments)
        return await client.request(method, url, **arguments)

    limit = MAX_RESPONSE_BYTES + 1
    async with opener(method, url, **arguments) as streamed:
        if _oversized(streamed, operation):
            raise PayPalAPIError(
                _CALL_FAILED,
                category=CATEGORY_MALFORMED_RESPONSE,
                status_code=getattr(streamed, "status_code", None),
                debug_id=_debug_id(streamed),
                operation=operation,
            )
        chunks = []  # type: List[bytes]
        held = 0
        async for chunk in streamed.aiter_bytes():
            chunks.append(chunk)
            held += len(chunk)
            if held >= limit:
                break
        return httpx.Response(
            status_code=streamed.status_code,
            headers=_without_declared_length(streamed.headers),
            content=b"".join(chunks)[:limit],
            request=streamed.request,
        )


def _decoded_object(
    response: Any, operation: Optional[str], body: Optional[bytes]
) -> Dict[str, Any]:
    """Returns the decoded object a response carries.

    ``body`` is the bytes a bounded reader accumulated for this response,
    so nothing is decoded that was not measured first. ``None`` means
    :func:`_bounded_body` refused the body for its size, and raises
    :class:`PayPalAPIError` carrying
    :data:`CATEGORY_MALFORMED_RESPONSE` rather than anything being
    parsed.

    The bytes handed over are measured again before they are parsed, which
    is what refuses the body :func:`_read_bounded` stops mid-transfer: that
    reader keeps one byte past :data:`MAX_RESPONSE_BYTES` precisely so the
    excess is provable here. Whichever reader produced the bytes, a body
    past the cap is therefore never parsed. A body that decodes to
    anything other than an object raises the same error.
    """
    if body is None:
        raise PayPalAPIError(
            _CALL_FAILED,
            category=CATEGORY_MALFORMED_RESPONSE,
            status_code=getattr(response, "status_code", None),
            debug_id=_debug_id(response),
            operation=operation,
        )
    if len(body) > MAX_RESPONSE_BYTES:
        _refuse_size(len(body), operation, response)
        raise PayPalAPIError(
            _CALL_FAILED,
            category=CATEGORY_MALFORMED_RESPONSE,
            status_code=getattr(response, "status_code", None),
            debug_id=_debug_id(response),
            operation=operation,
        )
    payload = json.loads(bytes(body).decode("utf-8"))
    if not isinstance(payload, dict):
        logger.error(
            "PayPal REST call returned a body that is not an object",
            extra={
                "provider_operation": operation,
                "provider_status": getattr(response, "status_code", None),
                "paypal_debug_id": _debug_id(response),
                "body_type": type(payload).__name__,
            },
        )
        raise PayPalAPIError(
            _CALL_FAILED,
            category=CATEGORY_MALFORMED_RESPONSE,
            status_code=getattr(response, "status_code", None),
            debug_id=_debug_id(response),
            operation=operation,
        )
    return payload


def _debug_id(response: Any) -> Optional[str]:
    """Returns the ``PayPal-Debug-Id`` a response carries, or ``None``."""
    try:
        value = response.headers.get(DEBUG_ID_HEADER)
    except Exception:
        return None
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _status_category(status_code: int) -> str:
    """Returns the failure category a provider status belongs to."""
    if status_code in (_UNAUTHORIZED_STATUS, _FORBIDDEN_STATUS):
        return CATEGORY_AUTHENTICATION
    if status_code == _TOO_MANY_REQUESTS_STATUS:
        return CATEGORY_RATE_LIMITED
    if status_code >= _SERVER_ERROR_STATUS:
        return CATEGORY_PROVIDER_SERVER
    return CATEGORY_PROVIDER_CLIENT


def _issue_code(value: Any) -> Optional[str]:
    """Returns ``value`` as an issue code, or ``None``.

    A value is returned only when it is a string whose stripped form
    matches :data:`PROVIDER_ISSUE_PATTERN`, so a code is either an
    upper-case identifier of bounded length or nothing at all.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not PROVIDER_ISSUE_PATTERN.match(candidate):
        return None
    return candidate


def _provider_issue(
    response: Any,
    operation: Optional[str] = None,
    body: Optional[bytes] = None,
) -> Optional[str]:
    """Returns the provider's issue code for a failed call, or ``None``.

    ``body``, when supplied, is the bytes :func:`_bounded_body` already
    measured and accumulated for this response, and is decoded in place of
    reading the response again. Without it the body is decoded through the
    response, and only when it is within :data:`MAX_RESPONSE_BYTES`.

    Only the fields named by :data:`PROVIDER_ISSUE_FIELDS` are consulted:
    the first :data:`MAX_PROVIDER_ISSUE_DETAILS` entries of ``details``
    for their ``issue``, then the body's own ``name``. Every candidate is
    passed through :func:`_issue_code`, so no other field, and no value of
    any other shape, is retained or returned. Any failure to read the body
    returns ``None``.
    """
    if response is None:
        return None
    try:
        if body is not None:
            payload = json.loads(bytes(body).decode("utf-8"))
        else:
            if _oversized(response, operation):
                return None
            payload = response.json()
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    details = payload.get("details")
    if isinstance(details, list):
        for entry in details[:MAX_PROVIDER_ISSUE_DETAILS]:
            if not isinstance(entry, dict):
                continue
            code = _issue_code(entry.get("issue"))
            if code is not None:
                return code
    return _issue_code(payload.get("name"))


def _api_error(
    error: Exception,
    path: str,
    operation: Optional[str],
    body: Optional[bytes] = None,
    order_id: Optional[str] = None,
) -> PayPalAPIError:
    """Classifies ``error`` and records it as one structured failure.

    ``body``, when supplied, is the bytes :func:`_bounded_body` measured
    for the failing response, and is what the provider's issue code is
    read from, so a failure carries its issue code without the response
    being read a second time or without a bound.

    The record carries the path, the operation, the failure category, the
    provider status, the provider's debug identifier, the provider's issue
    code and, when the call named one, the provider order the call was
    about. The bound request identifier is added by the logger. No response
    body, no URL and no credential is recorded, and the returned exception
    carries the same fields for its caller to translate.
    """
    status_code = None  # type: Optional[int]
    debug_id = None  # type: Optional[str]
    issue = None  # type: Optional[str]
    if isinstance(error, httpx.TimeoutException):
        category = CATEGORY_TIMEOUT
    elif isinstance(error, httpx.HTTPStatusError):
        status_code = error.response.status_code
        debug_id = _debug_id(error.response)
        issue = _provider_issue(error.response, operation, body)
        category = _status_category(status_code)
    elif isinstance(error, ValueError):
        category = CATEGORY_MALFORMED_RESPONSE
    else:
        category = CATEGORY_TRANSPORT
    failure = PayPalAPIError(
        _CALL_FAILED,
        category=category,
        status_code=status_code,
        debug_id=debug_id,
        operation=operation,
        issue=issue,
    )
    fields = failure.audit_fields()
    fields["path"] = path
    fields[PROVIDER_ORDER_FIELD] = order_id
    fields.update(exception_fields(error))
    logger.error("PayPal REST call failed", extra=fields)
    return failure


def order_request_id(subscription_id: Any) -> str:
    """Returns the idempotency key for opening a subscription's order.

    The key is derived from the identifier of the already-persisted
    ``subscriptions`` row, so a repeat of an uncertain call presents the
    same key and resolves to the same order.
    """
    return _ORDER_KEY_PREFIX + str(subscription_id)


def capture_request_id(subscription_id: Any) -> str:
    """Returns the idempotency key for capturing a subscription's order.

    Derived from the same persisted identifier as
    :func:`order_request_id`, so a repeated capture resolves to the
    capture already performed rather than to a second charge.
    """
    return _CAPTURE_KEY_PREFIX + str(subscription_id)


def _cache_lifetime(reported: Any) -> float:
    """Return the seconds a token may be reused for.

    The reported lifetime is trimmed by :data:`EXPIRY_MARGIN_SECONDS`.
    A missing, non-numeric, non-finite or already-exhausted lifetime
    returns 0.0, which holds no token back for reuse.
    """
    try:
        seconds = float(reported)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(seconds):
        return 0.0
    remaining = seconds - EXPIRY_MARGIN_SECONDS
    return remaining if remaining > 0.0 else 0.0


async def _exchange_credentials() -> Tuple[str, float]:
    """Return a fresh access token and the seconds it may be reused.

    The client identifier and secret are sent as HTTP Basic credentials
    and appear in no return value, no exception message and no log
    record. The response is streamed and measured against
    :data:`MAX_RESPONSE_BYTES` before any of it is decoded. Raises
    :class:`PayPalAPIError` when the grant does not return a usable token.
    """
    response_body = None  # type: Optional[bytes]
    grant_headers = {"Accept": "application/json"}
    grant_headers.update(outbound_trace_headers())
    try:
        async with _client() as client:
            async with client.stream(
                _POST_METHOD,
                settings.PAYPAL_API_BASE + _OAUTH_PATH,
                data={"grant_type": _GRANT_TYPE},
                auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
                headers=grant_headers,
                timeout=settings.HTTP_TIMEOUT_SECONDS,
            ) as response:
                response_body = await _bounded_body(response, _OPERATION_TOKEN)
                response.raise_for_status()
        payload = _decoded_object(response, _OPERATION_TOKEN, response_body)
    except PayPalAPIError:
        raise
    except _TRANSPORT_ERRORS as error:
        raise _api_error(
            error, _OAUTH_PATH, _OPERATION_TOKEN, response_body
        ) from None

    granted = payload.get("access_token")
    if not isinstance(granted, str) or not granted:
        logger.error(
            "PayPal credential exchange returned no usable grant",
            extra={
                "path": _OAUTH_PATH,
                "provider_operation": _OPERATION_TOKEN,
                "provider_status": response.status_code,
                "paypal_debug_id": _debug_id(response),
            },
        )
        raise PayPalAPIError(
            _CALL_FAILED,
            category=CATEGORY_MALFORMED_RESPONSE,
            status_code=response.status_code,
            debug_id=_debug_id(response),
            operation=_OPERATION_TOKEN,
        )
    return granted, _cache_lifetime(payload.get("expires_in"))


def _read_cached_token() -> Optional[str]:
    """Returns the held access token while it may still be reused."""
    with _CACHE_STATE:
        if _cached_access is not None:
            if time.monotonic() < _cached_deadline:
                return _cached_access
    return None


def _current_generation() -> int:
    """Returns the generation the token cache is currently on."""
    with _CACHE_STATE:
        return _cache_generation


def _store_cached_token(
    granted: str, lifetime: float, generation: int
) -> bool:
    """Holds ``granted`` for ``lifetime`` seconds. Reports whether it did.

    The token is held only while ``generation`` is still the current
    generation of the cache. A token exchanged under an earlier generation
    is discarded and ``False`` is returned, so a credential rotation that
    ran while the exchange was in flight is not undone by its result.

    Any recorded exchange failure is cleared, so a successful exchange
    ends the backoff immediately.
    """
    global _cached_access, _cached_deadline
    global _backoff_deadline, _backoff_failure
    with _CACHE_STATE:
        if generation != _cache_generation:
            return False
        _cached_access = granted if lifetime > 0.0 else None
        _cached_deadline = time.monotonic() + lifetime
        _backoff_deadline = 0.0
        _backoff_failure = None
    return True


def _record_exchange_failure(
    error: PayPalAPIError, generation: int
) -> bool:
    """Holds ``error`` back for :data:`FAILURE_BACKOFF_SECONDS`.

    The category, provider status and retryability are held with the
    deadline, so a caller refused during the window is answered as the
    failure that caused it rather than as a different kind of failure.

    The failure is held only while ``generation`` is still the current
    generation of the cache, so a failure from an exchange that used
    credentials since rotated does not hold back a caller that would now
    use the new ones. Reports whether it was held.
    """
    global _backoff_deadline, _backoff_failure
    with _CACHE_STATE:
        if generation != _cache_generation:
            return False
        _backoff_deadline = time.monotonic() + FAILURE_BACKOFF_SECONDS
        _backoff_failure = (
            getattr(error, "category", CATEGORY_TRANSPORT),
            getattr(error, "status_code", None),
            bool(getattr(error, "retryable", True)),
        )
    return True


def _held_back_failure() -> Optional[PayPalAPIError]:
    """Returns the failure to raise while the backoff window holds.

    ``None`` is returned once the window has elapsed, or when no failure
    is recorded.
    """
    with _CACHE_STATE:
        if _backoff_failure is None:
            return None
        if time.monotonic() >= _backoff_deadline:
            return None
        category, status_code, retryable = _backoff_failure
    return PayPalAPIError(
        _CALL_FAILED,
        category=category,
        status_code=status_code,
        retryable=retryable,
        operation=_OPERATION_TOKEN,
    )


async def _bearer_credential() -> str:
    """Return a cached bearer token or perform one single-flight
    credential exchange.
    """
    cached = _read_cached_token()
    if cached is not None:
        return cached
    held_back = _held_back_failure()
    if held_back is not None:
        raise held_back
    async with _refresh_lock():
        cached = _read_cached_token()
        if cached is not None:
            return cached
        held_back = _held_back_failure()
        if held_back is not None:
            raise held_back
        generation = _current_generation()
        try:
            granted, lifetime = await _exchange_credentials()
        except PayPalAPIError as error:
            _record_exchange_failure(error, generation)
            raise
        _store_cached_token(granted, lifetime, generation)
        return granted


def reset_access_token_cache() -> None:
    """Discard the cached access token and any recorded failure.

    The next call performs a fresh credential exchange. Called after the
    grant credentials are rotated. The generation of the cache is advanced,
    so a refresh already in flight finishes and returns its grant to its
    own caller without storing it here.
    """
    global _cached_access, _cached_deadline
    global _backoff_deadline, _backoff_failure, _cache_generation
    with _CACHE_STATE:
        _cached_access = None
        _cached_deadline = 0.0
        _backoff_deadline = 0.0
        _backoff_failure = None
        _cache_generation += 1
        _CACHE_STATE.notify_all()


async def _post_json(
    path: str,
    body: Optional[Dict[str, Any]] = None,
    idempotency_key: Optional[str] = None,
    operation: Optional[str] = None,
    allow_refresh: bool = True,
    extra_headers: Optional[Mapping[str, str]] = None,
    document: Optional[bytes] = None,
    order_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Issue a bounded authenticated POST, retry one 401 after cache
    reset, and return a decoded object.
    """
    headers = {}  # type: Dict[str, str]
    if extra_headers:
        for name, value in extra_headers.items():
            if isinstance(name, str) and isinstance(value, str):
                headers[name] = value
    headers.update(outbound_trace_headers())
    headers["Authorization"] = "Bearer " + await _bearer_credential()
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"
    if idempotency_key:
        headers[IDEMPOTENCY_HEADER] = idempotency_key

    if document is None:
        content = {"json": body if body is not None else {}}
    else:
        content = {"content": document}

    response_body = None  # type: Optional[bytes]
    try:
        async with _client() as client:
            async with client.stream(
                _POST_METHOD,
                settings.PAYPAL_API_BASE + path,
                headers=headers,
                timeout=settings.HTTP_TIMEOUT_SECONDS,
                **content
            ) as response:
                retrying = (
                    response.status_code == _UNAUTHORIZED_STATUS
                    and allow_refresh
                )
                if not retrying:
                    response_body = await _bounded_body(response, operation)
                    response.raise_for_status()
        if retrying:
            reset_access_token_cache()
            logger.warning(
                "PayPal rejected the access token; repeating the call "
                "once with a fresh grant",
                extra={
                    "path": path,
                    "provider_operation": operation,
                    "provider_status": response.status_code,
                    "paypal_debug_id": _debug_id(response),
                    "paypal_request_id": idempotency_key,
                    PROVIDER_ORDER_FIELD: order_id,
                },
            )
            return await _post_json(
                path,
                body,
                idempotency_key=idempotency_key,
                operation=operation,
                allow_refresh=False,
                extra_headers=extra_headers,
                document=document,
                order_id=order_id,
            )
        payload = _decoded_object(response, operation, response_body)
    except PayPalAPIError:
        raise
    except _TRANSPORT_ERRORS as error:
        raise _api_error(
            error, path, operation, response_body, order_id
        ) from None

    debug_id = _debug_id(response)

    logger.debug(
        "PayPal REST call completed",
        extra={
            "path": path,
            "provider_operation": operation,
            "provider_status": response.status_code,
            "paypal_debug_id": debug_id,
            "paypal_request_id": idempotency_key,
            PROVIDER_ORDER_FIELD: order_id,
        },
    )
    return payload


async def _get_json(
    path: str,
    operation: Optional[str] = None,
    allow_refresh: bool = True,
    order_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Return the decoded object from a Bearer-authenticated GET.

    Reads a resource without changing it. ``path`` is appended to
    ``settings.PAYPAL_API_BASE`` and the call carries
    ``settings.HTTP_TIMEOUT_SECONDS``. The response is streamed and
    measured against :data:`MAX_RESPONSE_BYTES` before any of it is
    decoded. A ``401`` discards the cached access token and repeats the
    call once with a fresh grant; the repeat runs with ``allow_refresh``
    cleared, so it cannot recurse, and the body of the rejected call is
    closed without being read. Every other failure raises
    :class:`PayPalAPIError`. No response body, URL or credential reaches
    the raised message or a log record.
    """
    headers = {
        "Authorization": "Bearer " + await _bearer_credential(),
        "Accept": "application/json",
    }
    response_body = None  # type: Optional[bytes]
    headers.update(outbound_trace_headers())
    try:
        async with _client() as client:
            async with client.stream(
                _GET_METHOD,
                settings.PAYPAL_API_BASE + path,
                headers=headers,
                timeout=settings.HTTP_TIMEOUT_SECONDS,
            ) as response:
                retrying = (
                    response.status_code == _UNAUTHORIZED_STATUS
                    and allow_refresh
                )
                if not retrying:
                    response_body = await _bounded_body(response, operation)
                    response.raise_for_status()
        if retrying:
            reset_access_token_cache()
            logger.warning(
                "PayPal rejected the access token; repeating the read "
                "once with a fresh grant",
                extra={
                    "path": path,
                    "provider_operation": operation,
                    "provider_status": response.status_code,
                    "paypal_debug_id": _debug_id(response),
                    PROVIDER_ORDER_FIELD: order_id,
                },
            )
            return await _get_json(
                path,
                operation=operation,
                allow_refresh=False,
                order_id=order_id,
            )
        payload = _decoded_object(response, operation, response_body)
    except PayPalAPIError:
        raise
    except _TRANSPORT_ERRORS as error:
        raise _api_error(
            error, path, operation, response_body, order_id
        ) from None

    debug_id = _debug_id(response)

    logger.debug(
        "PayPal REST read completed",
        extra={
            "path": path,
            "provider_operation": operation,
            "provider_status": response.status_code,
            "paypal_debug_id": debug_id,
            PROVIDER_ORDER_FIELD: order_id,
        },
    )
    return payload


async def create_order(
    plan_id: str,
    return_url: str,
    cancel_url: str,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a catalog-priced PayPal order using configured
    hosted-return URLs and an idempotency key.
    """
    plan = get_plan(plan_id)
    body = {
        "intent": _ORDER_INTENT,
        "purchase_units": [
            {
                "amount": {
                    "currency_code": plan.currency,
                    "value": format_amount(plan.amount),
                },
                "description": _ORDER_DESCRIPTION,
            }
        ],
        "payment_source": {
            "paypal": {
                "experience_context": {
                    "return_url": return_url,
                    "cancel_url": cancel_url,
                    "user_action": _USER_ACTION,
                    "shipping_preference": _SHIPPING_PREFERENCE,
                    "payment_method_preference": (
                        _PAYMENT_METHOD_PREFERENCE
                    ),
                }
            }
        },
    }
    return await _post_json(
        _ORDERS_PATH,
        body,
        idempotency_key=idempotency_key,
        operation=_OPERATION_CREATE,
    )


def _approval_host_suffixes() -> Tuple[str, ...]:
    """Returns the registrable domains approval targets may sit under.

    Each suffix is the final two labels of an entry of
    ``settings.PAYPAL_CERT_HOST_ALLOWLIST``, so the accepted domains come
    from validated configuration.
    """
    suffixes = set()
    for entry in settings.PAYPAL_CERT_HOST_ALLOWLIST:
        labels = str(entry).strip().lower().rstrip(".").split(".")
        if len(labels) >= 2 and all(labels[-2:]):
            suffixes.add(".".join(labels[-2:]))
    return tuple(sorted(suffixes))


def _is_allowed_approval_url(value: Any) -> bool:
    """Returns True when ``value`` is an acceptable approval target.

    The value is accepted only when it parses, names the
    :data:`backend.app.core.config.TLS_SCHEME` scheme, carries no user
    information, and its parsed host equals or is a dot-boundary
    subdomain of one of :func:`_approval_host_suffixes`.
    """
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parts = urlsplit(value.strip())
        scheme = parts.scheme
        userinfo = parts.username or parts.password
        host = parts.hostname
    except ValueError:
        return False
    if scheme != TLS_SCHEME or userinfo or not host:
        return False
    candidate = host.strip().lower().rstrip(".")
    if not candidate:
        return False
    for suffix in _approval_host_suffixes():
        if candidate == suffix or candidate.endswith("." + suffix):
            return True
    return False


def approval_url(order: Any) -> Optional[str]:
    """Returns the payer-approval target ``order`` carries, or ``None``.

    The links are searched for :data:`_APPROVAL_RELATIONS` in order, and
    the target is returned only when :func:`_is_allowed_approval_url`
    accepts it, so a target outside PayPal's own domains is not handed
    back to a client. ``None`` is returned when the order carries no
    acceptable target.
    """
    if not isinstance(order, dict):
        return None
    links = order.get("links")
    if not isinstance(links, list):
        return None
    for relation in _APPROVAL_RELATIONS:
        for link in links:
            if not isinstance(link, dict):
                continue
            if str(link.get("rel", "")).strip().lower() != relation:
                continue
            target = link.get("href")
            if _is_allowed_approval_url(target):
                return str(target).strip()
    return None


async def capture_order(
    db: Session,
    order_id: str,
    current_user: Any,
    request: Optional[Any] = None,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Capture only an order owned by the current user and validate it
    against the catalog amount and currency.
    """
    subscription = await run_in_threadpool(
        _resolve_owned_order, db, order_id, current_user, request
    )
    # Read after the ownership check, so no attribute is loaded again.
    key = idempotency_key or capture_request_id(subscription.id)
    captured = await _post_json(
        _ORDERS_PATH + "/" + str(order_id) + _CAPTURE_SUFFIX,
        {},
        idempotency_key=key,
        operation=_OPERATION_CAPTURE,
        extra_headers={PREFER_HEADER: PREFER_REPRESENTATION},
        order_id=str(order_id),
    )
    if _first_capture(captured) is not None:
        return captured
    logger.info(
        "Reading a captured PayPal order back because its capture "
        "response carried no settled capture",
        extra={
            "provider_operation": _OPERATION_CAPTURE,
            "paypal_request_id": key,
            "capture_status": _capture_status(captured, None),
            PROVIDER_ORDER_FIELD: str(order_id),
        },
    )
    return await fetch_order(order_id)


async def fetch_order(order_id: str) -> Dict[str, Any]:
    """Reads an order back from the API without settling anything.

    Used to establish what an order already settled, so a repeated
    capture and a notification reporting a settled capture resolve to
    the same outcome as the call that settled it. Raises
    :class:`PayPalAPIError` when the read fails.
    """
    return await _get_json(
        _ORDERS_PATH + "/" + str(order_id),
        operation=_OPERATION_FETCH,
        order_id=str(order_id),
    )


async def verify_settled_order(
    db: Session,
    order_id: str,
    current_user: Any,
    expected_amount: Any,
    expected_currency: str,
    request: Optional[Any] = None,
) -> CaptureOutcome:
    """Read and validate an already-settled order after the same
    ownership check used for capture.
    """
    await run_in_threadpool(
        _resolve_owned_order, db, order_id, current_user, request
    )
    payload = await fetch_order(order_id)
    return read_capture(
        payload, order_id, expected_amount, expected_currency
    )


def _resolve_owned_order(
    db: Session,
    order_id: str,
    current_user: Any,
    request: Optional[Any],
) -> Subscription:
    """Returns the ``subscriptions`` row ``current_user`` owns.

    The lookup and the ownership decision are both performed by the
    centralized authorization path, and its refusal is re-raised as
    :class:`OrderOwnershipError` so this module keeps one error type. An
    order resolving to no row and an order resolving to another
    principal's row are not distinguished.
    """
    try:
        return load_owned(
            db,
            Subscription,
            current_user,
            request=request,
            paypal_order_id=order_id,
        )
    except HTTPException:
        raise OrderOwnershipError(_CAPTURE_REFUSED) from None


def read_capture(
    payload: Any,
    order_id: str,
    expected_amount: Any,
    expected_currency: str,
) -> CaptureOutcome:
    """Reports what a capture response settled.

    The response is a completed capture only when it names ``order_id``,
    reports :data:`CAPTURE_COMPLETED_STATUS` at the order or the capture
    level, carries an amount equal to ``expected_amount`` rendered to
    two decimal places in ``expected_currency``, and carries the
    provider's own identifier for the settlement. The first check that
    fails names the ``reason``, and no later check is applied.

    A completed outcome therefore always carries a non-blank
    ``capture_id``. The caller writes that identifier to its activation
    audit record; no column holds it.
    """
    if not isinstance(payload, dict):
        return CaptureOutcome(
            completed=False, reason=REASON_MALFORMED_CAPTURE
        )

    reported_id = payload.get("id")
    if not isinstance(reported_id, str) or reported_id != order_id:
        return CaptureOutcome(
            completed=False,
            order_id=reported_id if isinstance(reported_id, str) else None,
            reason=REASON_ORDER_MISMATCH,
        )

    capture = _first_capture(payload)
    status = _capture_status(payload, capture)
    if status != CAPTURE_COMPLETED_STATUS:
        return CaptureOutcome(
            completed=False,
            order_id=reported_id,
            status=status,
            reason=REASON_NOT_COMPLETED,
        )

    amount, currency = _capture_amount(capture)
    if amount is None or currency is None:
        return CaptureOutcome(
            completed=False,
            order_id=reported_id,
            status=status,
            amount=amount,
            currency=currency,
            reason=REASON_MALFORMED_CAPTURE,
        )
    try:
        expected = format_amount(expected_amount)
    except (TypeError, ValueError):
        return CaptureOutcome(
            completed=False,
            order_id=reported_id,
            status=status,
            amount=amount,
            currency=currency,
            reason=REASON_AMOUNT_MISMATCH,
        )
    if amount != expected:
        return CaptureOutcome(
            completed=False,
            order_id=reported_id,
            status=status,
            amount=amount,
            currency=currency,
            reason=REASON_AMOUNT_MISMATCH,
        )
    if currency != str(expected_currency):
        return CaptureOutcome(
            completed=False,
            order_id=reported_id,
            status=status,
            amount=amount,
            currency=currency,
            reason=REASON_CURRENCY_MISMATCH,
        )
    capture_id = _capture_identifier(capture)
    if capture_id is None:
        # Reports a settlement carrying no provider identifier as a
        # malformed capture rather than as a completed one.
        return CaptureOutcome(
            completed=False,
            order_id=reported_id,
            status=status,
            amount=amount,
            currency=currency,
            reason=REASON_MALFORMED_CAPTURE,
        )
    return CaptureOutcome(
        completed=True,
        order_id=reported_id,
        status=status,
        amount=amount,
        currency=currency,
        capture_id=capture_id,
    )


def _capture_identifier(capture: Any) -> Optional[str]:
    """Returns the provider's identifier for a settled capture."""
    if not isinstance(capture, dict):
        return None
    value = capture.get("id")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _first_capture(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Returns the first capture object a capture response carries."""
    units = payload.get("purchase_units")
    if not isinstance(units, list):
        return None
    for unit in units:
        if not isinstance(unit, dict):
            continue
        payments = unit.get("payments")
        if not isinstance(payments, dict):
            continue
        captures = payments.get("captures")
        if not isinstance(captures, list):
            continue
        for capture in captures:
            if isinstance(capture, dict):
                return capture
    return None


def _capture_status(
    payload: Dict[str, Any],
    capture: Optional[Dict[str, Any]],
) -> Optional[str]:
    """Returns the settled status the response reports, or ``None``.

    The capture object's own status is preferred; the order's status is
    used when the response carries no capture object.
    """
    if isinstance(capture, dict):
        status = capture.get("status")
        if isinstance(status, str) and status.strip():
            return status.strip()
    status = payload.get("status")
    if isinstance(status, str) and status.strip():
        return status.strip()
    return None


def _capture_amount(
    capture: Optional[Dict[str, Any]],
) -> Tuple[Optional[str], Optional[str]]:
    """Returns the captured amount and currency, or ``None`` for each."""
    if not isinstance(capture, dict):
        return None, None
    amount = capture.get("amount")
    if not isinstance(amount, dict):
        return None, None
    value = amount.get("value")
    currency = amount.get("currency_code")
    if not isinstance(value, str) or not value.strip():
        value = None
    if not isinstance(currency, str) or not currency.strip():
        currency = None
    if value is None or currency is None:
        return value, currency
    return value.strip(), currency.strip()


def _header_lookup(headers: Mapping[str, str]) -> Dict[str, str]:
    """Return the headers keyed by upper-case name.

    Values that are not strings are dropped, and each value is
    stripped, so a blank value is indistinguishable from an absent one.
    """
    resolved = {}  # type: Dict[str, str]
    try:
        items = list(headers.items())
    except AttributeError:
        return resolved
    for name, value in items:
        if isinstance(name, str) and isinstance(value, str):
            candidate = value.strip()
            if candidate:
                resolved[name.strip().upper()] = candidate
    return resolved


def _is_allowed_certificate_url(value: Optional[str]) -> bool:
    """Return True when ``value`` is an allowlisted certificate URL.

    The value is accepted only when it parses, names the
    :data:`backend.app.core.config.TLS_SCHEME` scheme, carries no user
    information, and its host equals an entry of
    ``settings.PAYPAL_CERT_HOST_ALLOWLIST`` or is a subdomain of one on
    a dot boundary. The host is compared as a parsed component, never as
    a substring of the whole value.
    """
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parts = urlsplit(value.strip())
        scheme = parts.scheme
        userinfo = parts.username or parts.password
        host = parts.hostname
    except ValueError:
        return False
    if scheme != TLS_SCHEME or userinfo or not host:
        return False
    candidate = host.strip().lower().rstrip(".")
    if not candidate:
        return False
    for entry in settings.PAYPAL_CERT_HOST_ALLOWLIST:
        allowed = str(entry).strip().lower().rstrip(".")
        if allowed and (
            candidate == allowed
            or candidate.endswith("." + allowed)
        ):
            return True
    return False


def _event_type(body: Any) -> Optional[str]:
    if isinstance(body, dict):
        value = body.get("event_type")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _rejected(
    reason: str, retryable: bool = False
) -> WebhookVerification:
    """Return a rejection carrying ``reason``.

    Nothing is recorded here: the caller holds the request context and
    records the outcome once, so one rejected notification produces one
    audit record. No header value, signature, certificate URL,
    notification body or response body leaves this function.
    """
    return WebhookVerification(
        verified=False, reason=reason, retryable=retryable
    )


def webhook_body_object(body: Any) -> Optional[Dict[str, Any]]:
    """Returns the notification ``body`` carries, or ``None``.

    ``body`` is the raw request bytes. ``None`` is returned when they are
    empty, are not UTF-8, do not decode as JSON, or decode to anything
    other than an object.
    """
    if isinstance(body, (bytes, bytearray)):
        if not body:
            return None
        try:
            text = bytes(body).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return None
    elif isinstance(body, str):
        text = body
    else:
        return None
    try:
        decoded = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded


def _raw_notification_bytes(body: Any) -> Optional[bytes]:
    """Returns the raw notification bytes ``body`` carries, or ``None``.

    A binary body is returned as ``bytes``, and text is encoded as UTF-8,
    so the decoded notification and the postback document are built from
    one representation of the same body. ``None`` is returned for a value
    of any other type and for text that does not encode.
    """
    if isinstance(body, str):
        try:
            return body.encode("utf-8")
        except (UnicodeEncodeError, ValueError):
            return None
    if isinstance(body, (bytes, bytearray, memoryview)):
        try:
            return bytes(body)
        except (TypeError, ValueError):
            return None
    return None


def _postback_document(
    lookup: Dict[str, str],
    certificate_url: str,
    transmission_id: str,
    body: bytes,
) -> bytes:
    """Returns the postback document PayPal's verifier is sent.

    Every field except ``webhook_event`` is serialised from a value read
    here, and ``webhook_event`` carries ``body`` verbatim, so the
    notification PayPal checks the signature against is byte-for-byte the
    one that arrived. ``webhook_id`` is a field of this document rather
    than of the notification, so a ``webhook_id`` inside the notification
    is nested under ``webhook_event`` and cannot displace it.
    """
    fields = json.dumps(
        {
            "auth_algo": lookup[AUTH_ALGO_HEADER],
            "cert_url": certificate_url,
            "transmission_id": transmission_id,
            "transmission_sig": lookup[TRANSMISSION_SIG_HEADER],
            "transmission_time": lookup[TRANSMISSION_TIME_HEADER],
            "webhook_id": settings.PAYPAL_WEBHOOK_ID,
        },
        ensure_ascii=False,
    ).encode("utf-8")
    return (
        fields[:-1]
        + b',"'
        + WEBHOOK_EVENT_FIELD.encode("utf-8")
        + b'":'
        + bytes(body)
        + b"}"
    )


async def verify_webhook_signature(
    headers: Mapping[str, str],
    body: bytes,
) -> WebhookVerification:
    """Validate required headers and certificate host, then submit the
    raw event bytes to PayPal's signature verifier.
    """
    lookup = _header_lookup(headers)

    certificate_url = lookup.get(CERT_URL_HEADER)
    if not _is_allowed_certificate_url(certificate_url):
        return _rejected(REASON_CERTIFICATE_HOST)

    if any(name not in lookup for name in REQUIRED_WEBHOOK_HEADERS):
        return _rejected(REASON_MISSING_HEADER)

    raw_body = _raw_notification_bytes(body)
    notification = (
        webhook_body_object(raw_body) if raw_body is not None else None
    )
    if notification is None:
        return _rejected(REASON_MALFORMED_BODY)

    transmission_id = lookup[TRANSMISSION_ID_HEADER]
    document = _postback_document(
        lookup, certificate_url, transmission_id, raw_body
    )

    try:
        payload = await _post_json(
            _VERIFY_PATH,
            None,
            operation=_OPERATION_VERIFY,
            document=document,
        )
    except PayPalError:
        return _rejected(REASON_VERIFIER_UNAVAILABLE, retryable=True)

    reported = _verification_status(payload)
    if reported == VERIFICATION_SUCCESS:
        return WebhookVerification(
            verified=True,
            transmission_id=transmission_id,
            event_type=_event_type(notification),
        )
    if reported == VERIFICATION_FAILURE:
        return _rejected(REASON_SIGNATURE)
    return _rejected(REASON_VERIFIER_UNAVAILABLE, retryable=True)


def _verification_status(payload: Any) -> Optional[str]:
    """Returns the outcome the verifier reported, or ``None``.

    ``None`` is returned unless ``payload`` is an object carrying
    :data:`VERIFICATION_STATUS_FIELD` as a string naming one of
    :data:`VERIFICATION_STATUSES`. An absent field, a field of another
    type and a value outside that set therefore all read as an outcome
    this service does not have, which is distinct from a reported
    rejection. Only the field named above is read; no other field of the
    response is examined and none is recorded.
    """
    if not isinstance(payload, dict):
        return None
    reported = payload.get(VERIFICATION_STATUS_FIELD)
    if not isinstance(reported, str):
        return None
    candidate = reported.strip()
    if candidate not in VERIFICATION_STATUSES:
        return None
    return candidate
