"""PayPal REST integration: order creation, capture and webhook checks.

Every call addresses the REST API base named by
``settings.PAYPAL_API_BASE``, carries a Bearer token obtained from the
OAuth2 client-credentials grant, and applies the timeout named by
``settings.HTTP_TIMEOUT_SECONDS``. The base and the grant credentials are
read from validated settings, and no environment name or host is written
here.

Three operations are published:

* :func:`create_order` opens an order whose amount and currency come from
  the plan catalog. It takes a plan identifier and the two hosted
  redirect URLs, and it takes no amount, currency, price or date.
* :func:`capture_order` resolves the stored order identifier to its
  ``subscriptions`` row and captures the order only when that row's
  ``user_id`` equals the authenticated principal. An order that does not
  resolve to an owned row is refused before anything is written and
  before any request leaves the process.
* :func:`verify_webhook_signature` checks an inbound notification
  against PayPal's verify-webhook-signature endpoint. The host named by
  the ``PAYPAL-CERT-URL`` header is checked against
  ``settings.PAYPAL_CERT_HOST_ALLOWLIST`` before that value is used,
  transmitted or logged, and all five ``PAYPAL-*`` headers are required.
  The function reads and writes no database state on any path and
  returns a :class:`WebhookVerification`; its caller records the
  returned ``transmission_id`` under the uniqueness constraint that
  rejects a replay.

The access token is held in a process-wide cache for the lifetime the
grant reports, less :data:`EXPIRY_MARGIN_SECONDS`, and
:func:`reset_access_token_cache` discards it. No credential, no token
and no ``Authorization`` value is written to a log record.

Usage::

    order = create_order("premium_monthly", return_url, cancel_url)
    captured = capture_order(db, order["id"], current_user.id)
    result = verify_webhook_signature(headers, payload)
"""

import math
import threading
import time
from typing import Any, Dict, Mapping, NamedTuple, Optional, Tuple
from urllib.parse import urlsplit

import httpx
from sqlalchemy.orm import Session

from backend.app.core.config import TLS_SCHEME, settings
from backend.app.core.logging import get_logger
from backend.app.core.plans import format_amount, get_plan
from backend.app.db.models import Subscription

__all__ = [
    "AUTH_ALGO_HEADER",
    "CERT_URL_HEADER",
    "EXPIRY_MARGIN_SECONDS",
    "REASON_CERTIFICATE_HOST",
    "REASON_MISSING_HEADER",
    "REASON_SIGNATURE",
    "REASON_VERIFIER_UNAVAILABLE",
    "REQUIRED_WEBHOOK_HEADERS",
    "TRANSMISSION_ID_HEADER",
    "TRANSMISSION_SIG_HEADER",
    "TRANSMISSION_TIME_HEADER",
    "VERIFICATION_SUCCESS",
    "OrderOwnershipError",
    "PayPalAPIError",
    "PayPalError",
    "WebhookVerification",
    "capture_order",
    "create_order",
    "reset_access_token_cache",
    "verify_webhook_signature",
]

PAYPAL_CLIENT_ID = settings.PAYPAL_CLIENT_ID
PAYPAL_CLIENT_SECRET = settings.PAYPAL_CLIENT_SECRET

logger = get_logger(__name__)

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

#: Rejection reason: the certificate host is outside the allowlist.
REASON_CERTIFICATE_HOST = "certificate_host_not_allowlisted"

#: Rejection reason: at least one required header is absent or blank.
REASON_MISSING_HEADER = "required_header_missing"

#: Rejection reason: PayPal did not report a passing check.
REASON_SIGNATURE = "signature_not_verified"

#: Rejection reason: the check could not be completed.
REASON_VERIFIER_UNAVAILABLE = "verifier_unavailable"

#: Seconds trimmed from the reported lifetime before a token is reused.
EXPIRY_MARGIN_SECONDS = 60.0

# Path of the OAuth2 client-credentials grant.
_OAUTH_PATH = "/v1/oauth2/token"

# Path of the orders collection.
_ORDERS_PATH = "/v2/checkout/orders"

# Suffix appended to an order path to capture it.
_CAPTURE_SUFFIX = "/capture"

# Path of the webhook signature check.
_VERIFY_PATH = "/v1/notifications/verify-webhook-signature"

# Grant type of the client-credentials exchange.
_GRANT_TYPE = "client_credentials"

# Order intent that settles the payment on capture.
_ORDER_INTENT = "CAPTURE"

# Description carried on the single purchase unit.
_ORDER_DESCRIPTION = "Subscription Payment"

# Message returned for every refused capture. One message covers an
# order that resolves to no row and an order owned by another principal.
_CAPTURE_REFUSED = "The order is not available to the requesting user."

# Message returned for every failed REST call. No response body, URL or
# credential reaches the message.
_CALL_FAILED = "The PayPal REST API call did not succeed."

# Failures translated into a module error. httpx.InvalidURL,
# httpx.CookieConflict and httpx.StreamError sit outside the
# httpx.HTTPError hierarchy, and ValueError covers the JSON decode
# error raised by Response.json().
_TRANSPORT_ERRORS = (
    httpx.HTTPError,
    httpx.InvalidURL,
    httpx.CookieConflict,
    httpx.StreamError,
    ValueError,
)

# Serialises reads and writes of the cached access token.
_CACHE_LOCK = threading.Lock()

# Cached access token, or None when no usable token is held.
_cached_access = None  # type: Optional[str]

# Monotonic deadline after which the cached token is not reused.
_cached_deadline = 0.0


class PayPalError(Exception):
    """Base class for every error raised by this module."""


class OrderOwnershipError(PayPalError):
    """Raised when an order is not owned by the requesting principal.

    Raised both when the order identifier resolves to no stored row and
    when it resolves to a row held by another user. The two cases carry
    the same message and are not distinguished.
    """


class PayPalAPIError(PayPalError):
    """Raised when a REST call fails or returns an unusable body."""


class WebhookVerification(NamedTuple):
    """Outcome of one webhook signature check.

    ``verified`` is True only when PayPal reported a passing check.
    ``transmission_id`` and ``event_type`` are populated only on that
    outcome, and ``reason`` is populated only on a rejection.
    """

    verified: bool
    transmission_id: Optional[str] = None
    event_type: Optional[str] = None
    reason: Optional[str] = None


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


def _exchange_credentials() -> Tuple[str, float]:
    """Return a fresh access token and the seconds it may be reused.

    The client identifier and secret are sent as HTTP Basic credentials
    and appear in no return value, no exception message and no log
    record. Raises :class:`PayPalAPIError` when the grant does not
    return a usable token.
    """
    try:
        response = httpx.post(
            settings.PAYPAL_API_BASE + _OAUTH_PATH,
            data={"grant_type": _GRANT_TYPE},
            auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
            headers={"Accept": "application/json"},
            timeout=settings.HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
    except _TRANSPORT_ERRORS:
        logger.exception("PayPal credential exchange failed")
        raise PayPalAPIError(_CALL_FAILED) from None

    granted = None
    if isinstance(payload, dict):
        granted = payload.get("access_token")
    if not isinstance(granted, str) or not granted:
        logger.error(
            "PayPal credential exchange returned no usable grant"
        )
        raise PayPalAPIError(_CALL_FAILED)
    return granted, _cache_lifetime(payload.get("expires_in"))


def _bearer_credential() -> str:
    """Return a cached access token, exchanging credentials if needed.

    A held token is reused until its trimmed lifetime elapses. A run of
    calls inside one lifetime performs one exchange.
    """
    global _cached_access, _cached_deadline
    with _CACHE_LOCK:
        now = time.monotonic()
        if _cached_access is not None and now < _cached_deadline:
            return _cached_access
        granted, lifetime = _exchange_credentials()
        _cached_access = granted if lifetime > 0.0 else None
        _cached_deadline = now + lifetime
        return granted


def reset_access_token_cache() -> None:
    """Discard the cached access token.

    The next call performs a fresh credential exchange. Called after the
    grant credentials are rotated.
    """
    global _cached_access, _cached_deadline
    with _CACHE_LOCK:
        _cached_access = None
        _cached_deadline = 0.0


def _post_json(path: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """Return the decoded object from a Bearer-authenticated POST.

    ``path`` is appended to ``settings.PAYPAL_API_BASE`` and the call
    carries ``settings.HTTP_TIMEOUT_SECONDS``. Raises
    :class:`PayPalAPIError` when the call fails or when the body does
    not decode to an object; no response body reaches the raised
    message.
    """
    try:
        response = httpx.post(
            settings.PAYPAL_API_BASE + path,
            json=body,
            headers={
                "Authorization": "Bearer " + _bearer_credential(),
                "Content-Type": "application/json",
            },
            timeout=settings.HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
    except PayPalAPIError:
        raise
    except _TRANSPORT_ERRORS:
        logger.exception(
            "PayPal REST call failed", extra={"path": path}
        )
        raise PayPalAPIError(_CALL_FAILED) from None

    if not isinstance(payload, dict):
        logger.error(
            "PayPal REST call returned a body that is not an object",
            extra={"path": path, "body_type": type(payload).__name__},
        )
        raise PayPalAPIError(_CALL_FAILED)
    return payload


def create_order(
    plan_id: str,
    return_url: str,
    cancel_url: str,
) -> Dict[str, Any]:
    """Open a PayPal order for the plan named by ``plan_id``.

    The charge amount and currency are read from the plan catalog and
    rendered by its two-decimal formatter. This function declares no
    amount, currency, total, price, start-date or end-date parameter.

    ``return_url`` and ``cancel_url`` are the hosted redirect targets
    handed back to the payer. No card number, verification value or
    expiry is accepted here or sent from here.

    Returns the created order object, whose ``id`` is the value stored
    on ``Subscription.paypal_order_id`` and whose ``links`` carry the
    approval target.

    Raises :class:`backend.app.core.plans.UnknownPlanError` when
    ``plan_id`` is not a catalog identifier, and :class:`PayPalAPIError`
    when the call fails.
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
        "application_context": {
            "return_url": return_url,
            "cancel_url": cancel_url,
        },
    }
    return _post_json(_ORDERS_PATH, body)


def capture_order(
    db: Session,
    order_id: str,
    current_user_id: int,
) -> Dict[str, Any]:
    """Capture ``order_id`` for the authenticated principal.

    ``order_id`` is resolved against the stored
    ``Subscription.paypal_order_id`` column, and the resolved row's
    ``user_id`` is compared with ``current_user_id``. The capture call
    is issued only after both steps pass.

    ``db`` is the caller's request-scoped session. Nothing is written,
    flushed or committed here, and an order that resolves to no row or
    to another user's row is refused with
    :class:`OrderOwnershipError` before any request leaves the process.

    Raises :class:`PayPalAPIError` when the capture call fails.
    """
    subscription = (
        db.query(Subscription)
        .filter(Subscription.paypal_order_id == order_id)
        .first()
    )
    if subscription is None or subscription.user_id != current_user_id:
        logger.warning(
            "Refused a PayPal capture for an order that does not "
            "belong to the requesting user",
            extra={"user_id": current_user_id},
        )
        raise OrderOwnershipError(_CAPTURE_REFUSED)

    return _post_json(
        _ORDERS_PATH + "/" + str(order_id) + _CAPTURE_SUFFIX, {}
    )


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
    """Return the event type named by ``body``, or None."""
    if isinstance(body, dict):
        value = body.get("event_type")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _rejected(reason: str) -> WebhookVerification:
    """Return a rejection carrying ``reason`` and record it.

    ``reason`` is the only value logged. No header value, signature,
    certificate URL, notification body or response body is recorded.
    """
    logger.warning(
        "Rejected an inbound PayPal webhook notification",
        extra={"reason": reason},
    )
    return WebhookVerification(verified=False, reason=reason)


def verify_webhook_signature(
    headers: Mapping[str, str],
    body: Any,
) -> WebhookVerification:
    """Check an inbound PayPal notification and report the outcome.

    ``headers`` is the inbound header mapping, matched without regard to
    letter case, and ``body`` is the already-decoded notification. The
    checks are applied in this order:

    1. the host of the ``PAYPAL-CERT-URL`` header is checked against
       ``settings.PAYPAL_CERT_HOST_ALLOWLIST``, before that value is
       used, transmitted or logged
    2. every header of :data:`REQUIRED_WEBHOOK_HEADERS` must be present
       and non-blank
    3. the assembled payload is posted to PayPal's
       verify-webhook-signature endpoint, and only
       :data:`VERIFICATION_SUCCESS` is treated as a passing check

    Reads and writes no database state on any path, and never raises:
    every rejection is returned as a :class:`WebhookVerification` whose
    ``verified`` is False and whose ``reason`` names the failed check.
    ``transmission_id`` is returned only on a passing check, and the
    caller records it under the uniqueness constraint that rejects a
    replayed notification.
    """
    lookup = _header_lookup(headers)

    # Validates the certificate host against the allowlist. First
    # statement to operate on the header value.
    certificate_url = lookup.get(CERT_URL_HEADER)
    if not _is_allowed_certificate_url(certificate_url):
        return _rejected(REASON_CERTIFICATE_HOST)

    if any(name not in lookup for name in REQUIRED_WEBHOOK_HEADERS):
        return _rejected(REASON_MISSING_HEADER)

    transmission_id = lookup[TRANSMISSION_ID_HEADER]
    postback = {
        "auth_algo": lookup[AUTH_ALGO_HEADER],
        "cert_url": certificate_url,
        "transmission_id": transmission_id,
        "transmission_sig": lookup[TRANSMISSION_SIG_HEADER],
        "transmission_time": lookup[TRANSMISSION_TIME_HEADER],
        "webhook_id": settings.PAYPAL_WEBHOOK_ID,
        "webhook_event": body,
    }

    try:
        payload = _post_json(_VERIFY_PATH, postback)
    except PayPalError:
        return _rejected(REASON_VERIFIER_UNAVAILABLE)

    if payload.get("verification_status") != VERIFICATION_SUCCESS:
        return _rejected(REASON_SIGNATURE)

    return WebhookVerification(
        verified=True,
        transmission_id=transmission_id,
        event_type=_event_type(body),
    )
