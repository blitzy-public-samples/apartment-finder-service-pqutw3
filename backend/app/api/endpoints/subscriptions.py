"""Subscription lifecycle and PayPal notification intake.

Three routes are published under the ``/subscriptions`` prefix that
:mod:`backend.app.api.router` already applies:

* ``POST /`` opens a PayPal order priced by the plan catalog, records the
  subscription that order belongs to as :data:`PENDING_STATUS`, and
  returns it together with the PayPal-hosted approval target the payer
  must be sent to. The addresses PayPal returns the payer to are
  ``settings.PAYPAL_RETURN_URL`` for an approval and
  ``settings.PAYPAL_CANCEL_URL`` for an abandoned checkout, each
  validated configuration of its own. The request contract carries a plan
  identifier only,
  and **no payment is captured here**: PayPal's own sequence is create,
  then payer approval, then capture. The row is committed *before* the
  order is opened, so the ownership the later capture is bound to is
  durable and a settled charge always has a stored row -- pending at
  worst -- that reconciliation can complete. A repeat of the request
  reuses the open row already recorded for that account and plan, and
  presents PayPal the idempotency key derived from that row's own
  identifier, so the repeat resolves to the order the first attempt
  opened.
* ``GET /`` returns the caller's own subscription carrying
  :data:`ACTIVE_STATUS` whose window is still open. A pending, failed,
  cancelled or refunded row grants nothing and is not returned.
* ``POST /webhook`` processes one verified PayPal notification exactly
  once, and is the single path that captures a payment and grants an
  entitlement. The signature is checked before any business field is
  read, and the delivery identifier is recorded under the uniqueness
  constraint that detects a repeated delivery.

No route accepts a PayPal identifier from a client. An order identifier
enters this service only as the value PayPal returns to the order this
service opened, and it is stored on the row that opened it.

The charge amount, the currency, the entitlement window, the stored
status, the PayPal order identifier and the role a subscriber holds are
all assigned here from the plan catalog, the server clock and PayPal's
own responses. No request field takes part in any of them.

Entitlement is granted by the webhook alone, and only once PayPal has
reported the order captured for the plan's exact amount and currency. A
notification reporting the payer's approval and one reporting a settled
capture both run through the same :func:`_activate`, which returns
without a second grant when the row already carries
:data:`ACTIVE_STATUS`, so the two notifications cannot entitle one row
twice. An order is captured under an idempotency key derived from the
identifier of the already-committed ``subscriptions`` row, so a repeated
delivery resolves to the capture already performed rather than to a
second charge, and an order PayPal reports as already captured is read
back and measured rather than settled again. A verified notification's
delivery record and the state transition it drives are written in one
transaction, so a failure part-way leaves neither behind and PayPal's
redelivery processes the event once.

A verified delivery already recorded is answered ``200`` without being
processed again, because PayPal redelivers every notification it is not
answered ``2xx``.

The row created by ``POST /`` carries :data:`PENDING_STATUS` and no end
date until a settlement is proven. A settlement that cannot be recorded
leaves that pending row in place and is answered ``503`` carrying
:data:`RECONCILIATION_DETAIL`, so a charge that PayPal took is never
silently forgotten; an order that could not be opened at all is marked
:data:`FAILED_STATUS`, which grants nothing, retains any provider
identifier already known for it, and stays open to a later attempt.

A row reaches :data:`ACTIVE_STATUS` only after its charge has settled,
and that status combined with an open window is the single condition
both ``GET /`` and
:func:`backend.app.core.authorization.entitled_role` read, so the
entitlement a plan grants lapses with the row and nothing has to demote
the account. The role this module writes onto the account records the
entitlement the row carries; it is not what grants it, because
:func:`backend.app.core.authorization.stored_credit` credits a stored
subscriber role at the baseline and every decision that turns on it
reads the unexpired row instead.

The two authenticated routes resolve their principal through
:func:`backend.app.core.authorization.require_role`, which reads the role
from the stored user row. ``POST /webhook`` declares no role dependency
and is admitted on its signature alone; the account whose entitlement it
grants is resolved from the stored order identifier, never from the
notification.

``POST /`` and ``POST /webhook`` are ``async`` routes that each await a
provider call, and the session they hold is the synchronous one
:func:`backend.app.db.database.get_db` yields. Every statement these two
routes issue therefore runs through :func:`_in_session`, which hands it
to a worker thread, so a statement waiting on a database lock never
occupies the event loop and the completion of a provider call awaited by
another request stays deliverable. The ownership resolution inside
:mod:`backend.app.services.paypal_service` runs on the same kind of
worker-thread boundary. The session is used by one thread at a time and
never by two at once.

A transition is applied to the row as it stands when the transition is
written, not as it stood when the notification arrived: :func:`_activate`
and :func:`_revoke` each re-read the row under a write lock held for the
rest of the transaction. A subscription already in one of
:data:`TERMINAL_STATUSES` is never moved out of it, so an approval whose
capture was still in flight when a refund or a cancellation was recorded
leaves that outcome in place.
"""

import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from typing import Any, Callable, Dict, Optional, Tuple, TypeVar

from backend.app.api.endpoints.auth import limiter
from backend.app.core.authorization import (
    Role,
    parse_role,
    require_role,
    resolve_role,
    role_satisfies,
)
from backend.app.core.config import settings
from backend.app.core.logging import get_logger, mark_audited
from backend.app.core.plans import (
    STATUS_ACTIVE,
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_REFUNDED,
    Plan,
    UnknownPlanError,
    get_plan,
)
from backend.app.db.database import get_db
from backend.app.schema.subscription import (
    Subscription,
    SubscriptionCreate,
    SubscriptionCreated,
)
from backend.app.db.models import (
    Subscription as SubscriptionModel,
    User,
    WebhookEvent,
)
from backend.app.services.paypal_service import (
    CATEGORY_PROVIDER_CLIENT,
    CATEGORY_RATE_LIMITED,
    CATEGORY_TIMEOUT,
    ISSUE_ORDER_ALREADY_CAPTURED,
    REASON_MALFORMED_BODY,
    REASON_VERIFIER_UNAVAILABLE,
    CaptureOutcome,
    PayPalAPIError,
    PayPalError,
    approval_url,
    capture_order,
    capture_request_id,
    create_order,
    order_request_id,
    read_capture,
    verify_settled_order,
    verify_webhook_signature,
    webhook_body_object,
)

router = APIRouter()

logger = get_logger(__name__)

#: Status stored on a subscription row whose payment was captured. Every
#: status this module writes is re-exported from the plan catalog, which
#: holds the complete set read both by the endpoint writing the column
#: and by the authorization module reading it.
ACTIVE_STATUS = STATUS_ACTIVE

#: Status stored on a row recorded before its payment is captured.
PENDING_STATUS = STATUS_PENDING

#: Status stored on a row whose payment did not settle, and on a
#: subscription whose order could not be opened.
FAILED_STATUS = STATUS_FAILED

#: Status stored on a subscription PayPal reports as not settled.
CANCELLED_STATUS = STATUS_CANCELLED

#: Status stored on a subscription whose payment was returned.
REFUNDED_STATUS = STATUS_REFUNDED

INVALID_SUBSCRIPTION_DETAIL = "Invalid subscription data"

PAYMENT_FAILED_DETAIL = "Payment processing failed"

#: Detail returned when PayPal could not be reached or did not answer.
PAYMENT_UNAVAILABLE_DETAIL = "Payment provider unavailable"

#: Detail returned when a settled charge could not be recorded.
RECONCILIATION_DETAIL = "Payment recorded for reconciliation"

#: Reason recorded when the order identifier is already stored.
REASON_DUPLICATE_ORDER = "duplicate_paypal_order_id"

#: Reason recorded when the pending row could not be committed.
REASON_PENDING_NOT_RECORDED = "pending_row_not_recorded"

#: Reason recorded when the failed mark could not be committed.
REASON_COMPENSATION_NOT_RECORDED = "compensation_not_recorded"

#: Reason recorded when a settled charge could not be activated.
REASON_ACTIVATION_NOT_RECORDED = "activation_not_recorded"

#: Detail returned for a notification that fails its signature check.
WEBHOOK_REJECTED_DETAIL = "Webhook verification failed"

#: Detail returned when a notification could not be checked at all.
WEBHOOK_UNVERIFIABLE_DETAIL = "Webhook verification unavailable"

UNTYPED_EVENT = "UNKNOWN"

#: Reason recorded for a delivery identifier already recorded.
REASON_REPLAY = "duplicate_transmission_id"

#: Rejection reason recorded for an order carrying no usable identifier
#: or no allowlisted approval target.
REASON_UNUSABLE_ORDER = "unusable_order"

#: Rejection reason recorded for an approval naming no stored order.
REASON_UNMATCHED_ORDER = "unmatched_order"

#: Rejection reason recorded for a row naming no catalog plan.
REASON_PLAN_UNAVAILABLE = "plan_unavailable"

#: Rejection reason recorded for a settled capture carrying no provider
#: capture identifier, which no row reaching :data:`ACTIVE_STATUS` may
#: lack.
REASON_UNRECONCILABLE_CAPTURE = "capture_identifier_missing"

ORDER_ID_KEY = "id"

#: Longest provider order identifier accepted. A longer value is refused
#: rather than stored, so what one provider response can place in a
#: column and in an outbound path is bounded.
MAX_PROVIDER_ORDER_ID_LENGTH = 64

#: Shape a provider order identifier must have to be stored and used. It
#: admits only characters that need no escaping in a URL path segment, so
#: the stored value is the value the provider path carries.
PROVIDER_ORDER_ID_PATTERN = re.compile(
    r"\A[A-Za-z0-9][A-Za-z0-9._~-]{0,%d}\Z"
    % (MAX_PROVIDER_ORDER_ID_LENGTH - 1)
)

#: Key carrying the object a notification reports on.
RESOURCE_KEY = "resource"

#: Notification reporting that the payer approved an order.
EVENT_ORDER_APPROVED = "CHECKOUT.ORDER.APPROVED"

#: Notification reporting that PayPal settled a capture.
EVENT_CAPTURE_COMPLETED = "PAYMENT.CAPTURE.COMPLETED"

#: Notifications reporting that a settled payment was undone.
REVOKING_EVENTS = (
    "PAYMENT.CAPTURE.DENIED",
    "PAYMENT.CAPTURE.REFUNDED",
    "PAYMENT.CAPTURE.REVERSED",
    "CHECKOUT.ORDER.DECLINED",
)

#: Outcome reported for a notification that drove a transition.
OUTCOME_PROCESSED = "processed"

#: Outcome reported for a delivery that had already been recorded.
OUTCOME_DUPLICATE = "duplicate"

#: Outcome reported for a notification no transition applies to.
OUTCOME_IGNORED = "ignored"

# Statuses each revoking notification maps the subscription to.
_REVOKED_STATUSES = {
    "PAYMENT.CAPTURE.DENIED": CANCELLED_STATUS,
    "PAYMENT.CAPTURE.REFUNDED": REFUNDED_STATUS,
    "PAYMENT.CAPTURE.REVERSED": REFUNDED_STATUS,
    "CHECKOUT.ORDER.DECLINED": CANCELLED_STATUS,
}

# Statuses a subscription may still be moved out of.
_OPEN_STATUSES = (PENDING_STATUS, FAILED_STATUS)

#: Statuses no notification moves a subscription out of. Each records a
#: settlement the provider has undone, and each closes the entitlement
#: window, so a later approval of the same order leaves them in place.
TERMINAL_STATUSES = frozenset(_REVOKED_STATUSES.values())

#: Reason recorded when a transition is abandoned because the row reached
#: a terminal status while the transition was being decided.
REASON_TERMINAL_STATUS = "subscription_already_terminal"

# Provider failure categories answered with a client-facing 4xx. Every
# other category is a dependency failure.
_CLIENT_STATE_CATEGORIES = (CATEGORY_PROVIDER_CLIENT,)

# Verification reasons that report a check which could not be completed
# rather than a notification the check rejected. Each is answered
# HTTP_503_SERVICE_UNAVAILABLE.
_UNCHECKED_REASONS = (REASON_VERIFIER_UNAVAILABLE,)

# Return type of the operation :func:`_in_session` is handed.
_Result = TypeVar("_Result")


async def _in_session(
    operation: "Callable[..., _Result]", *args: Any, **kwargs: Any
) -> "_Result":
    """Runs one synchronous session operation in a worker thread.

    Used by the two ``async`` routes of this module for every call that
    reaches the database, so no statement they issue runs on the event
    loop. The exception the operation raises is raised here unchanged, so
    a caller's ``except IntegrityError`` or ``except SQLAlchemyError``
    reads exactly as it would around a direct call.

    Successive calls run one after another and never overlap, so the
    session is held by one thread at a time.
    """
    return await run_in_threadpool(operation, *args, **kwargs)


def _provider_status(error: PayPalError) -> int:
    """Returns the status a provider failure is answered with.

    A timeout is answered ``504``, a throttled or otherwise transient
    dependency failure ``503``, any other dependency failure ``502``, and
    a request the provider rejected as sent ``400``.
    """
    category = getattr(error, "category", None)
    if category == CATEGORY_TIMEOUT:
        return status.HTTP_504_GATEWAY_TIMEOUT
    if category == CATEGORY_RATE_LIMITED:
        return status.HTTP_503_SERVICE_UNAVAILABLE
    if category in _CLIENT_STATE_CATEGORIES:
        return status.HTTP_400_BAD_REQUEST
    return status.HTTP_502_BAD_GATEWAY


def _provider_detail(response_status: int) -> str:
    """Returns the detail returned with ``response_status``."""
    if response_status == status.HTTP_400_BAD_REQUEST:
        return PAYMENT_FAILED_DETAIL
    return PAYMENT_UNAVAILABLE_DETAIL


def _provider_order_id(order: Any) -> Optional[str]:
    """Returns the identifier an opened order carries, or ``None``.

    The value is read from :data:`ORDER_ID_KEY`, stripped of surrounding
    whitespace, and returned only when the result is non-empty and
    matches :data:`PROVIDER_ORDER_ID_PATTERN`. A value that is not a
    string, one that is blank or whitespace only, one longer than
    :data:`MAX_PROVIDER_ORDER_ID_LENGTH` and one carrying a character
    outside that shape each return ``None``.

    The returned value is what is persisted, logged and appended to the
    provider path, so no other form of the identifier reaches a column or
    an outbound request.
    """
    if not isinstance(order, dict):
        return None
    value = order.get(ORDER_ID_KEY)
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not PROVIDER_ORDER_ID_PATTERN.match(candidate):
        return None
    return candidate


def _is_already_captured(error: PayPalError) -> bool:
    """Reports whether a provider refusal names an order already settled.

    True only when the failure sits in :data:`_CLIENT_STATE_CATEGORIES`
    **and** carries the issue code
    :data:`backend.app.services.paypal_service.ISSUE_ORDER_ALREADY_CAPTURED`.
    A refusal the provider answered with the same status under any other
    issue code, and one carrying no issue code at all, are both False.
    """
    if getattr(error, "category", None) not in _CLIENT_STATE_CATEGORIES:
        return False
    return getattr(error, "issue", None) == ISSUE_ORDER_ALREADY_CAPTURED


def _could_not_be_checked(verification: Any) -> bool:
    """Reports whether a notification's check did not complete.

    True when the outcome names a reason in :data:`_UNCHECKED_REASONS`,
    and also when it reports itself retryable. The reason is read first
    and on its own, so an outcome the verification function classified as
    unavailable is answered as unavailable whatever the retryability of
    the provider failure underneath it, and a rejected signature is the
    only outcome answered ``400``.
    """
    reason = getattr(verification, "reason", None)
    if reason in _UNCHECKED_REASONS:
        return True
    return bool(getattr(verification, "retryable", False))


def _provider_fields(error: PayPalError) -> Dict[str, Any]:
    """Returns the safe provider fields ``error`` carries."""
    reader = getattr(error, "audit_fields", None)
    if callable(reader):
        try:
            fields = reader()
        except Exception:
            return {}
        if isinstance(fields, dict):
            return dict(fields)
    return {}


def _refuse_provider(
    error: PayPalError,
    message: str,
    **context: Any
) -> HTTPException:
    """Records one provider failure and returns the response for it.

    The record carries the provider category, status, debug identifier
    and retryability. The returned response carries a generic detail and
    is marked audited, so it is not recorded a second time further out.
    """
    response_status = _provider_status(error)
    fields = _provider_fields(error)
    fields.update(context)
    fields["status_code"] = response_status
    logger.error(message, extra=fields)
    return mark_audited(
        HTTPException(
            status_code=response_status,
            detail=_provider_detail(response_status),
        )
    )


def _payment_failure(reason: str, current_user: User, plan: Plan) -> None:
    """Records one subscription that could not be completed.

    The reason, the principal and the plan are recorded. No order
    identifier, credential or PayPal response body is included.
    """
    logger.warning(
        "Refused a subscription that could not be completed",
        extra={
            "reason": reason,
            "user_id": current_user.id,
            "plan_id": plan.plan_id,
        },
    )


def _reject(
    request: Request,
    reason: Optional[str],
    response_status: Optional[int] = None,
    **context: Any
) -> None:
    """Records one rejected PayPal notification.

    ``reason`` and the request path are the only values recorded from the
    notification. No header value, signature, certificate URL or
    notification body is passed to the logger.
    """
    fields: Dict[str, Any] = {
        "reason": reason,
        "path": request.scope.get("path"),
        "method": request.scope.get("method"),
    }
    if response_status is not None:
        fields["status_code"] = response_status
    fields.update(context)
    logger.warning(
        "Rejected an inbound PayPal notification", extra=fields
    )


def _reject_webhook(
    request: Request,
    reason: Optional[str],
    response_status: int,
    detail: str,
    **context: Any
) -> HTTPException:
    """Records one rejected notification and returns the response for it.

    The record is the single one :func:`_reject` emits, so a rejection
    answered with a response and a rejection merely acknowledged are
    recorded the same way. The returned response is marked audited, so
    this record is the only one the rejection produces.
    """
    _reject(request, reason, response_status, **context)
    return mark_audited(
        HTTPException(status_code=response_status, detail=detail)
    )


@router.post('/')
async def create_subscription(
    subscription: SubscriptionCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(Role.REGISTERED))
) -> SubscriptionCreated:
    """Opens a subscription for the caller and returns its approval target.

    The request carries a plan identifier only. The amount, the currency
    and the entitlement period are read from the plan catalog.

    The subscription row is written and committed as
    :data:`PENDING_STATUS` **before** the PayPal order is opened, so the
    attempt is durably recorded whatever the provider then does, and the
    idempotency key the order is opened under is derived from that
    committed row's own identifier by
    :func:`backend.app.services.paypal_service.order_request_id`. A
    repeat of the request reuses the open row already recorded for this
    account and plan -- pending or failed -- and presents the key derived
    from it, so the repeat resolves to the order the first attempt opened
    rather than opening a second one. The order is not captured here and
    the caller holds no entitlement yet: the payer must approve the order
    at the returned ``approval_url``, and PayPal's notification of that
    approval is what captures the payment and grants the role.

    No ORM attribute is read between the commit that makes the row
    durable and the provider call, so the transaction is closed and its
    connection is back in the pool for the duration of that call. The row
    is read again afterwards. Each statement runs through
    :func:`_in_session`, so none of them occupies the event loop.

    The entitlement window is left empty until a settlement is proven, so
    the row that exists across the approval window entitles nothing by
    either the ``GET /`` predicate or
    :func:`backend.app.core.authorization.entitled_role`.

    A plan the catalog does not publish is answered ``400`` with
    :data:`INVALID_SUBSCRIPTION_DETAIL`. A row that cannot be committed
    before the provider is called at all, and an order identifier the
    uniqueness constraint rejects, are each answered ``400`` with
    :data:`PAYMENT_FAILED_DETAIL` after one record naming the reason --
    never with a database error reaching the caller. An order that cannot
    be opened is answered by :func:`_provider_status`, and the row it was
    opened for is left recorded as :data:`FAILED_STATUS` carrying
    whatever provider identifier is already known for it. An order
    carrying no usable identifier or no allowlisted approval target is
    answered ``400`` after one record naming
    :data:`REASON_UNUSABLE_ORDER`, with the row left
    :data:`FAILED_STATUS`, because neither can be carried through to a
    settlement. An opened order whose identifier cannot be stored is
    answered ``503`` carrying :data:`RECONCILIATION_DETAIL`, because the
    provider holds an order this service could not finish recording.
    """
    if not subscription.plan_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_SUBSCRIPTION_DETAIL,
        )

    try:
        plan = get_plan(subscription.plan_id)
    except UnknownPlanError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_SUBSCRIPTION_DETAIL,
        ) from None

    # Record the attempt durably before the provider is asked to do
    # anything, reusing the open attempt already recorded for this
    # account and plan.
    try:
        subscription_id, idempotency_key = await _in_session(
            _open_intent, db, current_user, plan
        )
    except SQLAlchemyError:
        await _in_session(db.rollback)
        _payment_failure(REASON_PENDING_NOT_RECORDED, current_user, plan)
        raise HTTPException(
            status_code=400, detail=PAYMENT_FAILED_DETAIL
        ) from None

    try:
        order = await create_order(
            plan.plan_id,
            settings.PAYPAL_RETURN_URL,
            settings.PAYPAL_CANCEL_URL,
            idempotency_key=idempotency_key,
        )
    except PayPalError as error:
        await _in_session(_mark_failed, db, subscription_id)
        raise _refuse_provider(
            error,
            "Could not open a PayPal order for a subscription",
            subscription_id=subscription_id,
            plan_id=plan.plan_id,
            paypal_request_id=idempotency_key,
        ) from None

    order_id = _provider_order_id(order)
    target = approval_url(order)
    if order_id is None or target is None:
        # An order with no acceptable identifier cannot be captured, and
        # one with no allowlisted approval target cannot be approved, so
        # neither is handed back as an opened subscription.
        await _in_session(_mark_failed, db, subscription_id)
        logger.error(
            "PayPal order carried no usable identifier or no allowlisted "
            "approval target",
            extra={
                "subscription_id": subscription_id,
                "plan_id": plan.plan_id,
                "paypal_request_id": idempotency_key,
                "reason": REASON_UNUSABLE_ORDER,
                "order_identifier_present": order_id is not None,
                "approval_target_present": target is not None,
            },
        )
        raise mark_audited(
            HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=PAYMENT_FAILED_DETAIL,
            )
        )

    pending = await _in_session(_stored, db, subscription_id)
    if pending is None:
        raise _refuse_reconciliation(
            "Opened a PayPal order whose subscription row could no "
            "longer be read",
            subscription_id=subscription_id,
            plan_id=plan.plan_id,
            paypal_request_id=idempotency_key,
        )

    pending.paypal_order_id = order_id
    try:
        await _in_session(db.commit)
    except IntegrityError:
        # The uniqueness constraint rejected the order identifier, so it
        # is already recorded against another row.
        await _in_session(db.rollback)
        await _in_session(_mark_failed, db, subscription_id)
        _payment_failure(REASON_DUPLICATE_ORDER, current_user, plan)
        raise HTTPException(
            status_code=400, detail=PAYMENT_FAILED_DETAIL
        ) from None
    except SQLAlchemyError:
        await _in_session(db.rollback)
        await _in_session(_mark_failed, db, subscription_id)
        raise _refuse_reconciliation(
            "Opened a PayPal order whose identifier could not be "
            "recorded",
            subscription_id=subscription_id,
            plan_id=plan.plan_id,
            paypal_request_id=idempotency_key,
        ) from None
    await _in_session(db.refresh, pending)

    logger.info(
        "Opened a PayPal order for a subscription",
        extra={
            "subscription_id": subscription_id,
            "plan_id": plan.plan_id,
            "paypal_order_id": order_id,
            "paypal_request_id": idempotency_key,
            "subscription_status": pending.status,
        },
    )
    created = Subscription.from_orm(pending).dict()
    return SubscriptionCreated(approval_url=target, **created)


def _reusable_intent(
    db: Session, current_user: User, plan: Plan
) -> Optional[SubscriptionModel]:
    """Returns the open attempt already recorded for this plan.

    An attempt is reusable while it belongs to the principal, names the
    same plan, carries a status in :data:`_OPEN_STATUSES` and has no
    entitlement window. The idempotency key its order was or will be
    opened under is derived from the row's own identifier, so every such
    row already carries one. The most recent one is returned, and
    ``None`` when the account holds no such attempt.
    """
    return (
        db.query(SubscriptionModel)
        .filter(
            SubscriptionModel.user_id == current_user.id,
            SubscriptionModel.plan_id == plan.plan_id,
            SubscriptionModel.status.in_(_OPEN_STATUSES),
            SubscriptionModel.end_date.is_(None),
        )
        .order_by(SubscriptionModel.id.desc())
        .first()
    )


def _open_intent(
    db: Session, current_user: User, plan: Plan
) -> "Tuple[int, str]":
    """Commits the attempt an order will be opened for and describes it.

    The open attempt already recorded for this account and plan is
    reused and returned to :data:`PENDING_STATUS`; otherwise a row is
    added and flushed to obtain its identifier. Either way the
    idempotency key is derived from that identifier, so the same key is
    presented on every attempt for the row, and the returned identifier
    and key are plain values, so no ORM attribute has to be read after
    the commit.

    Raises ``SQLAlchemyError`` when the attempt cannot be committed.
    """
    existing = _reusable_intent(db, current_user, plan)
    if existing is not None:
        subscription_id = existing.id
        idempotency_key = order_request_id(subscription_id)
        existing.status = PENDING_STATUS
        db.commit()
        return subscription_id, idempotency_key

    pending = SubscriptionModel(
        user_id=current_user.id,
        plan_id=plan.plan_id,
        amount=plan.amount,
        currency=plan.currency,
        status=PENDING_STATUS,
        start_date=datetime.now(timezone.utc),
        end_date=None,
        paypal_order_id=None,
    )
    db.add(pending)
    # The identifier the idempotency key is derived from is assigned by
    # the flush, so the key is available in that same transaction.
    db.flush()
    subscription_id = pending.id
    idempotency_key = order_request_id(subscription_id)
    db.commit()
    return subscription_id, idempotency_key


def _stored(
    db: Session, subscription_id: Any
) -> Optional[SubscriptionModel]:
    """Returns the subscription row ``subscription_id`` names."""
    return (
        db.query(SubscriptionModel)
        .filter(SubscriptionModel.id == subscription_id)
        .first()
    )


def _refuse_reconciliation(
    message: str, **context: Any
) -> HTTPException:
    """Records one settlement left for reconciliation and answers it.

    The response carries :data:`RECONCILIATION_DETAIL` and is marked
    audited, so the record emitted here is the only one it produces.
    """
    fields = dict(context)
    fields["reason"] = REASON_ACTIVATION_NOT_RECORDED
    fields["status_code"] = status.HTTP_503_SERVICE_UNAVAILABLE
    logger.error(message, extra=fields)
    return mark_audited(
        HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=RECONCILIATION_DETAIL,
        )
    )


def _mark_failed(db: Session, subscription_id: Any) -> None:
    """Records that a subscription's order could not be opened.

    The row stays in place carrying :data:`FAILED_STATUS` and no end
    date, so it grants no entitlement, the attempt stays visible to
    reconciliation, and the row remains open to a later attempt that
    reuses its idempotency key. Any PayPal order identifier already
    stored on the row is left as it is, so an order the provider holds
    stays joined to the attempt it belongs to. When the mark itself
    cannot be committed the row is left as it was, which is pending and
    equally without entitlement.
    """
    subscription = _stored(db, subscription_id)
    if subscription is None:
        return
    subscription.status = FAILED_STATUS
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.error(
            "Could not mark an unopened subscription failed; the "
            "pending row is left for reconciliation",
            extra={
                "subscription_id": subscription_id,
                "reason": REASON_COMPENSATION_NOT_RECORDED,
            },
        )


@router.get('/')
def get_user_subscription(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(Role.REGISTERED))
) -> Optional[Subscription]:
    """Returns the caller's own entitling subscription.

    The query is scoped to the authenticated principal's identifier, to
    :data:`ACTIVE_STATUS` and to a window that has not closed, which is
    the same set of conditions
    :func:`backend.app.core.authorization.entitled_role` resolves a role
    from -- so the row this route reports and the role that route grants
    cannot disagree. A row belonging to another account is not reachable
    here, and ``None`` is returned when the caller holds no such row --
    including when the only row they hold is awaiting payer approval,
    cancelled, refunded or failed, none of which entitles anything.

    The row whose entitlement runs longest is returned when several
    qualify, and the identifier breaks a tie, so the result is
    deterministic rather than whichever row the database happened to
    return first.

    A caller whose window has closed also has the role stored on its
    account lowered back to the baseline by :func:`_revoke_role` here,
    so the column stops naming an entitlement the caller no longer
    holds. That write only brings the record into line: the closed
    window already withdrew the entitlement itself, because
    :func:`backend.app.core.authorization.stored_credit` credits a
    stored subscriber role at the baseline and no authorization decision
    reads it as more. An administrator is never lowered, and a caller
    another subscription still entitles is left as it is.
    """
    subscription = db.query(SubscriptionModel).filter(
        SubscriptionModel.user_id == current_user.id,
        SubscriptionModel.status == ACTIVE_STATUS,
        SubscriptionModel.end_date.isnot(None),
        SubscriptionModel.end_date > datetime.now(timezone.utc),
    ).order_by(
        SubscriptionModel.end_date.desc(),
        SubscriptionModel.id.desc(),
    ).first()

    if subscription is None:
        _withdraw_expired_entitlement(db, current_user)
        return None

    return Subscription.from_orm(subscription)


def _withdraw_expired_entitlement(db: Session, user: User) -> None:
    """Lowers a subscriber whose entitlement window has closed.

    Nothing is written when :func:`_revoke_role` declines, and a write
    that cannot be committed is rolled back and recorded rather than
    reaching the caller, because the caller asked to read.
    """
    revoked = _revoke_role(db, user)
    if revoked is None:
        return
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.error(
            "Could not withdraw an expired entitlement; the stored role "
            "is left for reconciliation",
            extra={
                "user_id": user.id,
                "reason": REASON_COMPENSATION_NOT_RECORDED,
            },
        )
        return
    logger.info(
        "Withdrew an entitlement whose window had closed",
        extra={"user_id": user.id, "revoked_role": revoked},
    )


@router.post('/webhook')
@limiter.limit(settings.RATE_LIMIT_WEBHOOK)
async def receive_paypal_webhook(
    request: Request,
    db: Session = Depends(get_db)
) -> Dict[str, str]:
    """Processes one verified PayPal notification exactly once.

    The route declares no role dependency and is admitted on its
    signature alone, so it carries ``settings.RATE_LIMIT_WEBHOOK`` per
    caller address to bound the verification work an unauthenticated
    caller can start. The steps run in this order, and no later step runs
    before an earlier one passes.

    1. the raw request bytes are read, bounded by the request-body-size
       cap :mod:`backend.app.main` applies
    2. the notification is checked by the PayPal service, which is handed
       those bytes and transmits them verbatim, validates the host of the
       ``PAYPAL-CERT-URL`` header against
       ``settings.PAYPAL_CERT_HOST_ALLOWLIST`` before that value is used
       or transmitted, requires every ``PAYPAL-*`` header, and requires
       the bytes to decode to an object
    3. the bytes are decoded, which is the first time any field of the
       notification is read
    4. the delivery identifier is added to ``webhook_events`` and
       flushed, whose uniqueness constraint detects a repeated delivery
    5. the notification is applied to the subscription it names
    6. the delivery record and the transition are committed together

    Every statement of steps 4 to 6 runs through :func:`_in_session`, and
    the flush that waits on the uniqueness constraint while a concurrent
    delivery of the same identifier is still open waits in a worker
    thread, holding no event-loop time. That concurrent delivery is parked
    in the provider call of step 5 with its own delivery row uncommitted,
    and its completion is delivered by the event loop. The wait resolves
    either way: a commit raises ``IntegrityError`` and the repeat is
    acknowledged, a rollback lets the waiting insert succeed and the
    notification is still settled.

    A notification the check *rejects* -- a certificate host outside the
    allowlist, an absent header, a body that does not decode to an
    object, or an explicit
    :data:`backend.app.services.paypal_service.VERIFICATION_FAILURE`
    from PayPal -- is answered ``400``. A notification that could not be
    checked at all is answered ``503``: that covers a verifier which
    could not be reached or did not answer, and a verifier answer that
    carries no recognised status, and it is decided by
    :func:`_could_not_be_checked` from the reason itself rather than from
    the retryability of any provider failure beneath it. PayPal delivers
    a ``503`` again, as it redelivers every notification it is not
    answered ``2xx`` for. A delivery identifier already recorded is
    answered ``200`` and is **not** processed again. Nothing is written on
    any rejected path.

    A transition that cannot be committed is answered ``503`` carrying
    :data:`RECONCILIATION_DETAIL` after one record naming
    :data:`REASON_ACTIVATION_NOT_RECORDED`, and the notification is
    delivered again.

    Only the rejection reason, the request path and safe identifiers are
    recorded; no header value, signature or notification body reaches a
    log record. The record for a repeated delivery names the verified
    delivery identifier and the provider's order identifier, so it is
    correlated with the delivery that was processed.
    """
    raw_body = await request.body()

    # Check the signature against the bytes that arrived, before any
    # business field is read
    verification = await verify_webhook_signature(
        request.headers, raw_body
    )
    if not verification.verified:
        if _could_not_be_checked(verification):
            raise _reject_webhook(
                request,
                verification.reason,
                status.HTTP_503_SERVICE_UNAVAILABLE,
                WEBHOOK_UNVERIFIABLE_DETAIL,
            )
        raise _reject_webhook(
            request,
            verification.reason,
            status.HTTP_400_BAD_REQUEST,
            WEBHOOK_REJECTED_DETAIL,
        )

    notification = webhook_body_object(raw_body)
    if notification is None:
        raise _reject_webhook(
            request,
            REASON_MALFORMED_BODY,
            status.HTTP_400_BAD_REQUEST,
            WEBHOOK_REJECTED_DETAIL,
        )

    event_type = verification.event_type or UNTYPED_EVENT

    # Record the delivery under the uniqueness constraint
    db.add(
        WebhookEvent(
            transmission_id=verification.transmission_id,
            event_type=event_type,
        )
    )
    try:
        await _in_session(db.flush)
    except IntegrityError:
        await _in_session(db.rollback)
        logger.warning(
            "Acknowledged a repeated PayPal delivery without "
            "processing it again",
            extra={
                "reason": REASON_REPLAY,
                "path": request.scope.get("path"),
                "event_type": event_type,
                # Identity of the delivery, taken from the verified
                # headers, so the repeat is correlated with the delivery
                # that was processed. The order identifier is the
                # provider's own and is present when the notification
                # names one.
                "transmission_id": verification.transmission_id,
                "paypal_order_id": _order_id_from(notification),
            },
        )
        return {"status": OUTCOME_DUPLICATE}

    # Apply the notification, then commit the delivery record and the
    # transition together
    try:
        outcome = await _apply_notification(
            db, request, notification, event_type
        )
    except PayPalError as error:
        await _in_session(db.rollback)
        raise _refuse_provider(
            error,
            "Could not apply a verified PayPal notification",
            event_type=event_type,
        ) from None
    except Exception:
        await _in_session(db.rollback)
        raise

    try:
        await _in_session(db.commit)
    except SQLAlchemyError:
        await _in_session(db.rollback)
        raise _refuse_reconciliation(
            "Applied a verified PayPal notification whose transition "
            "could not be recorded",
            event_type=event_type,
        ) from None
    return {"status": outcome}


def _order_id_from(notification: Any) -> Optional[str]:
    """Returns the order identifier a notification names, or ``None``.

    An order notification names it directly on the resource. A payment
    notification names it under the resource's supplementary related
    identifiers.
    """
    if not isinstance(notification, dict):
        return None
    resource = notification.get(RESOURCE_KEY)
    if not isinstance(resource, dict):
        return None
    direct = resource.get(ORDER_ID_KEY)
    if isinstance(direct, str) and direct.strip():
        candidate = direct.strip()
    else:
        candidate = None
    supplementary = resource.get("supplementary_data")
    if isinstance(supplementary, dict):
        related = supplementary.get("related_ids")
        if isinstance(related, dict):
            linked = related.get("order_id")
            if isinstance(linked, str) and linked.strip():
                return linked.strip()
    return candidate


def _subscription_for(
    db: Session, order_id: str
) -> Optional[SubscriptionModel]:
    """Returns the subscription an order identifier belongs to."""
    return (
        db.query(SubscriptionModel)
        .filter(SubscriptionModel.paypal_order_id == order_id)
        .first()
    )


async def _apply_notification(
    db: Session,
    request: Request,
    notification: Any,
    event_type: str,
) -> str:
    """Applies one verified notification to the subscription it names.

    Returns :data:`OUTCOME_PROCESSED` when a transition was applied or
    the subscription already held the state the notification reports, and
    :data:`OUTCOME_IGNORED` when the notification names no supported
    event, no order identifier, or an order this service did not open.
    Nothing is committed here; the caller commits the transition and the
    delivery record together.

    Each step that reaches the database runs through :func:`_in_session`,
    so none of them occupies the event loop.
    """
    if event_type not in (
        EVENT_ORDER_APPROVED,
        EVENT_CAPTURE_COMPLETED,
    ) and event_type not in REVOKING_EVENTS:
        logger.info(
            "Acknowledged a PayPal notification no transition applies "
            "to",
            extra={"event_type": event_type},
        )
        return OUTCOME_IGNORED

    order_id = _order_id_from(notification)
    if order_id is None:
        logger.warning(
            "A verified PayPal notification named no order identifier",
            extra={"event_type": event_type},
        )
        return OUTCOME_IGNORED

    subscription = await _in_session(_subscription_for, db, order_id)
    if subscription is None:
        logger.warning(
            "A verified PayPal notification named an order this "
            "service did not open",
            extra={
                "event_type": event_type,
                "reason": REASON_UNMATCHED_ORDER,
            },
        )
        return OUTCOME_IGNORED

    if event_type in REVOKING_EVENTS:
        return await _in_session(_revoke, db, subscription, event_type)

    if subscription.status == ACTIVE_STATUS:
        logger.info(
            "A verified PayPal notification reported a subscription "
            "already active",
            extra={
                "event_type": event_type,
                "subscription_id": subscription.id,
                "subscription_status": subscription.status,
            },
        )
        return OUTCOME_PROCESSED

    if subscription.status not in _OPEN_STATUSES:
        logger.warning(
            "A verified PayPal notification could not move a "
            "subscription out of its stored status",
            extra={
                "event_type": event_type,
                "subscription_id": subscription.id,
                "subscription_status": subscription.status,
            },
        )
        return OUTCOME_IGNORED

    plan = _plan_for(subscription)
    if plan is None:
        logger.error(
            "A verified PayPal notification named a subscription whose "
            "plan the catalog no longer publishes",
            extra={
                "event_type": event_type,
                "subscription_id": subscription.id,
                "reason": REASON_PLAN_UNAVAILABLE,
            },
        )
        return OUTCOME_IGNORED

    if event_type == EVENT_ORDER_APPROVED:
        outcome = await _settle(
            db, request, subscription, plan, order_id
        )
    else:
        outcome = read_capture(
            _capture_envelope(order_id, notification.get(RESOURCE_KEY)),
            order_id,
            plan.amount,
            plan.currency,
        )

    return await _in_session(
        _activate, db, subscription, plan, outcome, event_type
    )


async def _settle(
    db: Session,
    request: Request,
    subscription: SubscriptionModel,
    plan: Plan,
    order_id: str,
) -> CaptureOutcome:
    """Captures an approved order and reports what it settled.

    The capture is issued through
    :func:`backend.app.services.paypal_service.capture_order`, which
    resolves ``order_id`` to the stored row it belongs to and compares
    that row's owner with the principal passed to it before the call
    leaves the process, under an idempotency key derived from the stored
    row's identifier. The capture is measured against the plan's own
    amount and currency.

    An order the provider rejects as already settled is read back through
    :func:`backend.app.services.paypal_service.verify_settled_order`,
    which repeats the same ownership resolution and issues no capture,
    and whose complete outcome is returned unchanged. A redelivery of an
    approval PayPal has already settled therefore resolves to that
    settlement rather than to a second charge or a refusal, recovered
    from the provider's own representation rather than a reconstructed
    one.

    That recovery is entered only for a refusal the provider identifies
    as :data:`ISSUE_ORDER_ALREADY_CAPTURED`, which
    :func:`_is_already_captured` decides from the failure's issue code
    rather than from its category. Every other provider failure --
    including every other refusal answered with the same status -- is
    raised for the caller to answer, and the caller discards the
    delivery record it had claimed, so the notification is delivered
    again rather than consumed as one nothing applied to.

    The owning account is loaded through :func:`_in_session`, so the read
    the relationship issues does not run on the event loop.
    """
    owner = await _in_session(_owner_of, subscription)
    try:
        captured = await capture_order(
            db,
            order_id,
            owner,
            request=request,
            idempotency_key=capture_request_id(subscription.id),
        )
    except PayPalAPIError as error:
        if not _is_already_captured(error):
            raise
        logger.warning(
            "Reading back an order the provider reported as already "
            "settled",
            extra={
                "subscription_id": subscription.id,
                "plan_id": plan.plan_id,
                "provider_category": error.category,
                "provider_status": error.status_code,
                "provider_issue": error.issue,
                "paypal_debug_id": error.debug_id,
            },
        )
        return await verify_settled_order(
            db,
            order_id,
            owner,
            plan.amount,
            plan.currency,
            request=request,
        )
    return read_capture(
        captured, order_id, plan.amount, plan.currency
    )


def _owner_of(subscription: SubscriptionModel) -> Optional[User]:
    """Returns the account a subscription belongs to."""
    return subscription.user


def _capture_envelope(order_id: str, resource: Any) -> Optional[Dict]:
    """Returns a notified capture in the shape the reader measures.

    A capture notification reports the capture itself, keyed by the
    capture identifier, while
    :func:`backend.app.services.paypal_service.read_capture` measures an
    order's capture response, keyed by the order identifier. Placing the
    resource under the order it settles means one reader validates the
    status, the amount and the currency for both continuations, so a
    notified capture is held to exactly the same conditions as a captured
    order.
    """
    if not isinstance(resource, dict):
        return None
    return {
        "id": order_id,
        "status": resource.get("status"),
        "purchase_units": [
            {"payments": {"captures": [resource]}}
        ],
    }


def _plan_for(subscription: SubscriptionModel) -> Optional[Plan]:
    """Returns the catalog entry a subscription was priced by."""
    try:
        return get_plan(subscription.plan_id)
    except UnknownPlanError:
        return None


def _lock_subscription(
    db: Session, subscription: SubscriptionModel
) -> Optional[SubscriptionModel]:
    """Returns the subscription row held under a write lock.

    The row is re-read inside the current transaction and the lock is held
    until that transaction ends, so two notifications naming the same
    subscription are applied one after the other rather than interleaved.
    ``populate_existing`` discards the copy loaded earlier, so the
    attributes read are the persisted ones. ``None`` is returned when the
    row is no longer there.
    """
    return (
        db.query(SubscriptionModel)
        .filter(SubscriptionModel.id == subscription.id)
        .populate_existing()
        .with_for_update()
        .one_or_none()
    )


def _abandon_terminal(
    subscription: SubscriptionModel, event_type: str
) -> str:
    """Records a transition abandoned against a terminal status."""
    logger.warning(
        "Left a subscription in the terminal status the provider "
        "recorded for it",
        extra={
            "event_type": event_type,
            "subscription_id": subscription.id,
            "subscription_status": subscription.status,
            "reason": REASON_TERMINAL_STATUS,
        },
    )
    return OUTCOME_IGNORED


def _activate(
    db: Session,
    subscription: SubscriptionModel,
    plan: Plan,
    outcome: CaptureOutcome,
    event_type: str,
) -> str:
    """Grants entitlement once the capture is confirmed complete.

    ``outcome`` is the complete measurement its caller made of what the
    provider settled, against the order identifier, the settled status
    and the plan's own amount and currency. An outcome that fails any of
    those leaves the subscription in the status it already held and grants
    no role, so a redelivery or a later attempt can still settle the row
    correctly.

    The row is re-read under a write lock before it is written, and the
    status read back decides the transition: a row now in one of
    :data:`TERMINAL_STATUSES` is left as it is, a row already in
    :data:`ACTIVE_STATUS` is reported as processed without being written
    again, and a row in any other status outside :data:`_OPEN_STATUSES` is
    left as it is. A concurrent revocation recorded while the capture was
    in flight therefore stands.

    The provider's own capture identifier is recorded in the activation
    record, and a settled capture carrying none activates nothing, so
    every row reaching :data:`ACTIVE_STATUS` can be reconciled against
    the provider afterwards.
    """
    if not outcome.completed:
        logger.warning(
            "Refused to activate a subscription whose capture PayPal "
            "did not report as complete for the plan's own amount",
            extra={
                "event_type": event_type,
                "subscription_id": subscription.id,
                "subscription_status": subscription.status,
                "capture_reason": outcome.reason,
                "capture_status": outcome.status,
                "captured_currency": outcome.currency,
            },
        )
        return OUTCOME_IGNORED

    if not outcome.capture_id:
        logger.error(
            "Refused to activate a subscription whose settled capture "
            "carried no provider capture identifier",
            extra={
                "event_type": event_type,
                "subscription_id": subscription.id,
                "subscription_status": subscription.status,
                "reason": REASON_UNRECONCILABLE_CAPTURE,
                "capture_status": outcome.status,
                "captured_currency": outcome.currency,
            },
        )
        return OUTCOME_IGNORED

    locked = _lock_subscription(db, subscription)
    if locked is None:
        logger.warning(
            "A verified PayPal notification named a subscription that "
            "is no longer stored",
            extra={
                "event_type": event_type,
                "subscription_id": subscription.id,
                "reason": REASON_UNMATCHED_ORDER,
            },
        )
        return OUTCOME_IGNORED
    if locked.status in TERMINAL_STATUSES:
        return _abandon_terminal(locked, event_type)
    if locked.status == ACTIVE_STATUS:
        logger.info(
            "A verified PayPal notification reported a subscription "
            "already active",
            extra={
                "event_type": event_type,
                "subscription_id": locked.id,
                "subscription_status": locked.status,
            },
        )
        return OUTCOME_PROCESSED
    if locked.status not in _OPEN_STATUSES:
        logger.warning(
            "A verified PayPal notification could not move a "
            "subscription out of its stored status",
            extra={
                "event_type": event_type,
                "subscription_id": locked.id,
                "subscription_status": locked.status,
            },
        )
        return OUTCOME_IGNORED

    started = datetime.now(timezone.utc)
    locked.status = ACTIVE_STATUS
    locked.start_date = started
    locked.end_date = started + timedelta(days=plan.period_days)
    granted = _grant_role(locked.user, plan.required_role)
    db.flush()
    logger.info(
        "Activated a subscription against a confirmed PayPal capture",
        extra={
            "event_type": event_type,
            "subscription_id": locked.id,
            "plan_id": plan.plan_id,
            "paypal_order_id": locked.paypal_order_id,
            "paypal_capture_id": outcome.capture_id,
            "subscription_status": locked.status,
            "capture_status": outcome.status,
            "granted_role": granted,
        },
    )
    return OUTCOME_PROCESSED


def _revoke(
    db: Session,
    subscription: SubscriptionModel,
    event_type: str,
) -> str:
    """Ends an entitlement PayPal reports as undone.

    The row is re-read under the same write lock the activation path takes.
    A row already in one of :data:`TERMINAL_STATUSES` is left as it is,
    which covers a second revoking notification for the same order.
    Otherwise the subscription is moved to the status the notification maps
    to, its entitlement window is closed at the server clock, and the
    principal is demoted when it holds the subscriber role and no other
    subscription still entitles it.
    """
    locked = _lock_subscription(db, subscription)
    if locked is None:
        logger.warning(
            "A verified PayPal notification named a subscription that "
            "is no longer stored",
            extra={
                "event_type": event_type,
                "subscription_id": subscription.id,
                "reason": REASON_UNMATCHED_ORDER,
            },
        )
        return OUTCOME_IGNORED
    if locked.status in TERMINAL_STATUSES:
        return _abandon_terminal(locked, event_type)
    locked.status = _REVOKED_STATUSES.get(event_type, CANCELLED_STATUS)
    locked.end_date = datetime.now(timezone.utc)
    db.flush()
    revoked = _revoke_role(db, locked.user)
    db.flush()
    logger.warning(
        "Ended a subscription PayPal reported as undone",
        extra={
            "event_type": event_type,
            "subscription_id": locked.id,
            "subscription_status": locked.status,
            "revoked_role": revoked,
        },
    )
    return OUTCOME_PROCESSED


def _grant_role(user: Optional[User], required_role: str) -> Optional[str]:
    """Raises a principal to the role its plan carries, if it is higher.

    The stored role is only ever raised: a principal already holding that
    role or a higher one is left as it is. Returns the role now stored, or
    ``None`` when nothing changed.

    The stored value records which plan role the account holds. It does
    not itself entitle the account: what
    :func:`backend.app.core.authorization.entitled_role` reads is the row
    this write accompanies, and a stored subscriber role no unexpired row
    supports is credited at the baseline.
    """
    if user is None:
        return None
    target = parse_role(required_role)
    if target is None:
        return None
    if role_satisfies(resolve_role(user), target):
        return None
    user.role = target.value
    return target.value


def _revoke_role(db: Session, user: Optional[User]) -> Optional[str]:
    """Lowers a subscriber back to the registered role.

    Only a principal whose stored role is exactly the subscriber role is
    lowered, so an administrator is never demoted here, and only when no
    other subscription still entitles it. Returns the role now stored, or
    ``None`` when nothing changed.

    The write keeps the stored value in step with the rows; it is not the
    revocation itself, which the closing of the entitlement window
    already performed.
    """
    if user is None:
        return None
    if resolve_role(user) is not Role.PREMIUM:
        return None
    remaining = (
        db.query(SubscriptionModel)
        .filter(
            SubscriptionModel.user_id == user.id,
            SubscriptionModel.status == ACTIVE_STATUS,
            SubscriptionModel.end_date > datetime.now(timezone.utc),
        )
        .first()
    )
    if remaining is not None:
        return None
    user.role = Role.REGISTERED.value
    return Role.REGISTERED.value
