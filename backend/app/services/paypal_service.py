import logging
import threading

import paypalrestsdk
from collections import OrderedDict
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import Dict, Optional
from fastapi.concurrency import run_in_threadpool
from backend.app.core.config import settings

logger = logging.getLogger(__name__)

# SEC-09/SEC-12: caps the provider client's records, which carry the
# request URL, the authorization header and both bodies (CWE-532)
PROVIDER_LOG_LEVEL = logging.WARNING
_PROVIDER_LOGGER_NAME = "paypalrestsdk"
logging.getLogger(_PROVIDER_LOGGER_NAME).setLevel(PROVIDER_LOG_LEVEL)

PAYPAL_CLIENT_ID = settings.PAYPAL_CLIENT_ID
PAYPAL_CLIENT_SECRET = settings.PAYPAL_CLIENT_SECRET

# SEC-09: states in which PayPal reports the funds for a reference as
# authorized; a payment carries the first set, a billing agreement the second
_APPROVED_PAYMENT_STATES = frozenset({"approved", "completed"})
_APPROVED_AGREEMENT_STATES = frozenset({"active"})
_AMOUNT_QUANTUM = Decimal("0.01")

# SEC-09: the unit this application charges; a total reported in any other
# currency does not authorize the charge (CWE-863)
_EXPECTED_CURRENCY = "USD"

# SEC-09: upper bound in seconds on one provider call (CWE-400)
_REQUEST_TIMEOUT_SECONDS = 10.0

# SEC-09: spent-reference digests retained in this worker, oldest first;
# while retained, a verified reference authorizes no second charge
# (CWE-294). Eviction past the limit and worker restart both drop state
_CONSUMPTION_LIMIT = 4096
_consumed_references = OrderedDict()
_claimed_references = set()
_consumption_lock = threading.Lock()


class _BoundedTransport:
    # SEC-09: supplies the request timeout the provider SDK never sets
    def __init__(self, delegate, timeout: float):
        self._delegate = delegate
        self._timeout = timeout

    def request(self, *args, **kwargs):
        kwargs.setdefault("timeout", self._timeout)
        return self._delegate.request(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._delegate, name)


def _bind_request_timeout() -> None:
    # SEC-09: every provider call funnels through paypalrestsdk.api.requests
    transport = getattr(paypalrestsdk.api, "requests", None)
    if transport is None or isinstance(transport, _BoundedTransport):
        return
    paypalrestsdk.api.requests = _BoundedTransport(
        transport, _REQUEST_TIMEOUT_SECONDS)


_bind_request_timeout()

# HUMAN ASSISTANCE NEEDED
# The following function has a confidence level below 0.8 and may need review
def create_payment(amount: float, currency: str, return_url: str, cancel_url: str) -> Dict:
    paypalrestsdk.configure({
        # SEC-09: environment from validated configuration (CWE-1188)
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


def _amount_currency(entry) -> Optional[str]:
    # SEC-09: reads the unit PayPal reports beside one amount; None when the
    # unit is absent or not a string
    if not isinstance(entry, dict):
        return None
    amount = entry.get("amount")
    if not isinstance(amount, dict):
        return None
    currency = amount.get("currency")
    if not isinstance(currency, str) or not currency.strip():
        return None
    return currency.strip().upper()


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


def _charge_entries(resource: Dict):
    # SEC-09: the reported amount entries for either reference kind
    state = str(resource.get("state", "")).strip().lower()
    if state in _APPROVED_AGREEMENT_STATES:
        plan = resource.get("plan")
        if not isinstance(plan, dict):
            return None
        return plan.get("payment_definitions")
    return resource.get("transactions")


def _entries_carry_currency(entries, currency: str) -> bool:
    # SEC-09: every reported amount carries the expected unit (CWE-863)
    if not isinstance(entries, list) or not entries:
        return False
    return all(_amount_currency(entry) == currency for entry in entries)


def _payer_identity(resource: Dict) -> Optional[str]:
    # SEC-09: the payer PayPal attributes the reference to; None when the
    # provider names nobody (CWE-863)
    payer = resource.get("payer")
    if not isinstance(payer, dict):
        return None
    info = payer.get("payer_info")
    if not isinstance(info, dict):
        return None
    for key in ("payer_id", "email"):
        value = info.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _agreement_plan(resource: Dict) -> Optional[str]:
    # SEC-09: the billing plan a reusable agreement is bound to
    plan = resource.get("plan")
    if not isinstance(plan, dict):
        return None
    value = plan.get("id")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


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


def _resource_authorizes_charge(resource: Dict, amount: float, currency: str,
                                plan_id: Optional[str],
                                payer_id: Optional[str]) -> Optional[str]:
    # SEC-09: binds the full transaction identity - state, total, unit, payer
    # and, for a reusable agreement, the plan; returns the refusal reason, or
    # None when the reference authorizes this exact charge (CWE-863)
    if not _resource_authorizes_amount(resource, amount):
        return "state_or_amount_mismatch"
    if not _entries_carry_currency(_charge_entries(resource), currency):
        return "currency_mismatch"
    payer = _payer_identity(resource)
    if payer is None:
        return "payer_unidentified"
    if payer_id is not None and payer != payer_id.strip():
        return "payer_mismatch"
    state = str(resource.get("state", "")).strip().lower()
    if state in _APPROVED_AGREEMENT_STATES:
        if plan_id is None or not plan_id.strip():
            return "plan_unbound"
        if _agreement_plan(resource) != plan_id.strip():
            return "plan_mismatch"
    return None


def _reference_key(reference: str) -> str:
    # SEC-09: ledger key holding no provider reference in memory
    return sha256(reference.encode("utf-8")).hexdigest()


def _claim_reference(key: str) -> bool:
    # SEC-09: reserves one reference for this attempt; False when it is spent
    # already or in flight on another request (CWE-294)
    with _consumption_lock:
        if key in _consumed_references or key in _claimed_references:
            return False
        _claimed_references.add(key)
        return True


def _release_reference(key: str) -> None:
    # SEC-09: returns an unverified reference for a later attempt
    with _consumption_lock:
        _claimed_references.discard(key)


def _consume_reference(key: str) -> None:
    # SEC-09: records a verified reference in the bounded worker-local
    # ledger; while the digest remains there it authorizes no further
    # charge, and the oldest digest is evicted past the limit
    with _consumption_lock:
        _claimed_references.discard(key)
        _consumed_references[key] = True
        while len(_consumed_references) > _CONSUMPTION_LIMIT:
            _consumed_references.popitem(last=False)


def _find_payment_resource(reference: str) -> Optional[Dict]:
    # SEC-09: blocking provider lookup of the client-supplied reference,
    # tried as a payment and then as a billing agreement; returns None when
    # PayPal does not return a resource
    paypalrestsdk.configure({
        # SEC-09: environment from validated configuration (CWE-1188)
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


async def process_payment(payment_method: str, amount: float, *,
                          currency: Optional[str] = None,
                          plan_id: Optional[str] = None,
                          payer_id: Optional[str] = None) -> bool:
    # SEC-09: approves only a reference PayPal confirms as authorized for this
    # exact charge - amount, unit, payer and, for a reusable agreement, the
    # bound plan - and records it in the bounded worker-local ledger; every
    # unverified, malformed or failing path returns False, as does a replay
    # while the digest remains in that ledger
    if not isinstance(payment_method, str) or not payment_method.strip():
        return False
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        return False
    if amount <= 0:
        return False
    reference = payment_method.strip()
    marker = _reference_marker(reference)
    key = _reference_key(reference)
    expected = (currency or _EXPECTED_CURRENCY).strip().upper()
    if not _claim_reference(key):
        logger.warning(
            "payment verification refused reference=%s reason=%s",
            marker, "reference_already_used")
        return False
    authorized = False
    try:
        try:
            resource = await run_in_threadpool(
                _find_payment_resource, reference)
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
        refusal = _resource_authorizes_charge(
            resource, amount, expected, plan_id, payer_id)
        if refusal is not None:
            logger.warning(
                "payment verification refused reference=%s state=%s reason=%s",
                marker, _state_marker(resource), refusal)
            return False
        authorized = True
        return True
    finally:
        if authorized:
            _consume_reference(key)
        else:
            _release_reference(key)
