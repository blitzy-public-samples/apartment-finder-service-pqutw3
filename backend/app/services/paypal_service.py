import logging
import paypalrestsdk
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import Dict, Optional
from fastapi.concurrency import run_in_threadpool
from backend.app.core.config import settings

logger = logging.getLogger(__name__)

PAYPAL_CLIENT_ID = settings.PAYPAL_CLIENT_ID
PAYPAL_CLIENT_SECRET = settings.PAYPAL_CLIENT_SECRET

# SEC-09: states in which PayPal reports the funds for a reference as
# authorized; a payment carries the first set, a billing agreement the second
_APPROVED_PAYMENT_STATES = frozenset({"approved", "completed"})
_APPROVED_AGREEMENT_STATES = frozenset({"active"})
_AMOUNT_QUANTUM = Decimal("0.01")

# HUMAN ASSISTANCE NEEDED
# The following function has a confidence level below 0.8 and may need review
def create_payment(amount: float, currency: str, return_url: str, cancel_url: str) -> Dict:
    # SEC-09: reads the payment environment from validated configuration.
    paypalrestsdk.configure({
        "mode": settings.PAYPAL_MODE,
        "client_id": PAYPAL_CLIENT_ID,
        "client_secret": PAYPAL_CLIENT_SECRET
    })

    payment = paypalrestsdk.Payment({
        "intent": "sale",
        "payer": {
            "payment_method": "paypal"
        },
        "redirect_urls": {
            "return_url": return_url,
            "cancel_url": cancel_url
        },
        "transactions": [{
            "amount": {
                "total": str(amount),
                "currency": currency
            },
            "description": "Subscription Payment"
        }]
    })

    if payment.create():
        return payment.to_dict()
    else:
        return {"error": payment.error}

# HUMAN ASSISTANCE NEEDED
# The following function has a confidence level below 0.8 and may need review
def execute_payment(payment_id: str, payer_id: str) -> Dict:
    payment = paypalrestsdk.Payment.find(payment_id)
    
    if payment.execute({"payer_id": payer_id}):
        return payment.to_dict()
    else:
        return {"error": payment.error}


def _reference_marker(reference: str) -> str:
    # SEC-09: redacted reference for the audit record
    return sha256(reference.encode("utf-8")).hexdigest()[:16]


def _state_marker(resource: Dict) -> str:
    # SEC-09: provider-supplied state reduced to a log-safe token
    state = str(resource.get("state", ""))
    token = "".join(c for c in state if c.isalnum() or c in "-_")
    return token[:32] or "unknown"


def _to_decimal(value) -> Optional[Decimal]:
    try:
        return Decimal(str(value)).quantize(_AMOUNT_QUANTUM)
    except (InvalidOperation, TypeError, ValueError):
        return None


def _amount_value(entry, key: str) -> Optional[Decimal]:
    # SEC-09: reads one reported amount; None when PayPal did not supply the
    # expected shape
    if not isinstance(entry, dict):
        return None
    amount = entry.get("amount")
    if not isinstance(amount, dict):
        return None
    return _to_decimal(amount.get(key))


def _sum_amounts(entries, key: str) -> Optional[Decimal]:
    # SEC-09: total of the reported amounts; None when any entry is unreadable
    if not isinstance(entries, list) or not entries:
        return None
    total = Decimal("0")
    for entry in entries:
        reported = _amount_value(entry, key)
        if reported is None:
            return None
        total += reported
    return total


def _payment_total(resource: Dict) -> Optional[Decimal]:
    # SEC-09: sum of the transaction totals PayPal reports for a payment
    return _sum_amounts(resource.get("transactions"), "total")


def _agreement_total(resource: Dict) -> Optional[Decimal]:
    # SEC-09: sum of the payment-definition amounts PayPal reports for a
    # billing agreement
    plan = resource.get("plan")
    if not isinstance(plan, dict):
        return None
    return _sum_amounts(plan.get("payment_definitions"), "value")


def _resource_authorizes_amount(resource: Dict, amount: float) -> bool:
    # SEC-09: the reference must be in an authorized state and report a total
    # equal to the amount being charged
    expected = _to_decimal(amount)
    if expected is None:
        return False
    state = str(resource.get("state", "")).strip().lower()
    if state in _APPROVED_PAYMENT_STATES:
        return _payment_total(resource) == expected
    if state in _APPROVED_AGREEMENT_STATES:
        return _agreement_total(resource) == expected
    return False


def _find_payment_resource(reference: str) -> Optional[Dict]:
    # SEC-09: blocking provider lookup of the client-supplied reference,
    # tried as a payment and then as a billing agreement; returns None when
    # PayPal does not return a resource
    paypalrestsdk.configure({
        "mode": settings.PAYPAL_MODE,
        "client_id": PAYPAL_CLIENT_ID,
        "client_secret": PAYPAL_CLIENT_SECRET
    })
    for finder in (paypalrestsdk.Payment.find,
                   paypalrestsdk.BillingAgreement.find):
        try:
            resource = finder(reference)
        except Exception as exc:
            logger.warning(
                "paypal lookup failed reference=%s error=%s",
                _reference_marker(reference), type(exc).__name__)
            continue
        if resource is None:
            continue
        payload = resource.to_dict() if hasattr(resource, "to_dict") else None
        if isinstance(payload, dict):
            return payload
    return None


async def process_payment(payment_method: str, amount: float) -> bool:
    # SEC-09/F-01: approves only a reference PayPal confirms as authorized for
    # this exact amount; every unverified, malformed or failing path returns
    # False
    if not isinstance(payment_method, str) or not payment_method.strip():
        return False
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        return False
    if amount <= 0:
        return False
    reference = payment_method.strip()
    marker = _reference_marker(reference)
    try:
        resource = await run_in_threadpool(_find_payment_resource, reference)
    except Exception as exc:
        logger.warning(
            "payment verification failed reference=%s error=%s",
            marker, type(exc).__name__)
        return False
    if resource is None:
        logger.warning(
            "payment verification refused reference=%s reason=%s",
            marker, "not_retrievable")
        return False
    if not _resource_authorizes_amount(resource, amount):
        logger.warning(
            "payment verification refused reference=%s state=%s reason=%s",
            marker, _state_marker(resource), "state_or_amount_mismatch")
        return False
    return True