"""Subscription lifecycle and PayPal notification intake.

Four routes are published under the ``/subscriptions`` prefix that
:mod:`backend.app.api.router` already applies:

* ``POST /`` opens a PayPal order priced by the plan catalog, records the
  subscription that order belongs to as :data:`PENDING_STATUS`, and
  returns it together with the PayPal-hosted approval target the payer
  must be sent to. The request contract carries a plan identifier only,
  and **no payment is captured here**: PayPal's own sequence is create,
  then payer approval, then capture. The row is committed *before* the
  order is opened, so the ownership a later capture is bound to is
  durable and a settled charge always has a stored row -- pending at
  worst -- that reconciliation can complete.
* ``POST /capture`` settles an approved order the caller owns and opens
  the entitlement it paid for. Ownership is resolved server-side from the
  stored order identifier, and an order the provider reports as already
  captured is read back and measured rather than settled a second time.
* ``GET /`` returns the caller's own subscription carrying
  :data:`ACTIVE_STATUS` whose window is still open. A pending, failed,
  cancelled or refunded row grants nothing and is not returned.
* ``POST /webhook`` processes one verified PayPal notification exactly
  once. The signature is checked before any business field is read, and
  the delivery identifier is recorded under the uniqueness constraint
  that detects a repeated delivery.

The charge amount, the currency, the entitlement window, the stored
status, the PayPal order identifier and the role a subscriber holds are
all assigned here from the plan catalog, the server clock and PayPal's
own responses. No request field takes part in any of them.

Entitlement is granted by ``POST /capture`` and by the webhook, and by
either one only once PayPal has reported the order captured for the
plan's exact amount and currency. Both continuations run through the same
:func:`_activate`, which returns without a second grant when the row
already carries :data:`ACTIVE_STATUS`, so the two paths cannot entitle
one row twice. An order is captured under an idempotency key derived from
the identifier of the already-committed ``subscriptions`` row, so a
repeated delivery or a repeated attempt resolves to the capture already
performed rather than to a second charge. A verified notification's
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
:data:`FAILED_STATUS`, which grants nothing and stays open to a later
attempt.

A row reaches :data:`ACTIVE_STATUS` only after its charge has settled,
and that status combined with an open window is the single condition
both ``GET /`` and
:func:`backend.app.core.authorization.entitled_role` read, so the
entitlement a plan grants lapses with the row and nothing has to demote
the account.

The three authenticated routes resolve their principal through
:func:`backend.app.core.authorization.require_role`, which reads the role
from the stored user row. ``POST /webhook`` declares no role dependency
and is admitted on its signature alone.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from typing import Any, Dict, Optional

from backend.app.api.endpoints.auth import limiter
from backend.app.core.authorization import (
    Role,
    load_owned,
    parse_role,
    require_role,
    resolve_role,
    role_satisfies,
)
from backend.app.core.config import settings
from backend.app.core.logging import get_logger, mark_audited
from backend.app.core.plans import (
    STATUS_ACTIVE,
    STATUS_FAILED,
    STATUS_PENDING,
    Plan,
    UnknownPlanError,
    get_plan,
)
from backend.app.db.database import get_db
from backend.app.schema.subscription import (
    Subscription,
    SubscriptionCapture,
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
)

router = APIRouter()

logger = get_logger(__name__)

#: Status stored on a subscription row whose payment was captured. The
#: three status values are re-exported from the plan catalog, which
#: holds them so that the endpoint writing the column and the
#: authorization module reading it cannot drift apart.
ACTIVE_STATUS = STATUS_ACTIVE

#: Status stored on a row recorded before its payment is captured.
PENDING_STATUS = STATUS_PENDING

#: Status stored on a row whose payment did not settle, and on a
#: subscription whose order could not be opened.
FAILED_STATUS = STATUS_FAILED

#: Status stored on a subscription PayPal reports as not settled.
CANCELLED_STATUS = "cancelled"

#: Status stored on a subscription whose payment was returned.
REFUNDED_STATUS = "refunded"

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

#: Rejection reason recorded for a body that does not decode, or that
#: decodes to something other than an object.
REASON_MALFORMED_BODY = "malformed_body"

#: Reason recorded for a delivery identifier already recorded.
REASON_REPLAY = "duplicate_transmission_id"

#: Rejection reason recorded for an order carrying no usable identifier
#: or no allowlisted approval target.
REASON_UNUSABLE_ORDER = "unusable_order"

#: Rejection reason recorded for an approval naming no stored order.
REASON_UNMATCHED_ORDER = "unmatched_order"

#: Rejection reason recorded for a row naming no catalog plan.
REASON_PLAN_UNAVAILABLE = "plan_unavailable"

#: Rejection reason recorded for a capture that did not settle.
REASON_CAPTURE_FAILED = "capture_failed"

#: Frontend path the PayPal hosted redirect returns the payer to.
HOSTED_REDIRECT_PATH = "/subscription"

#: Continuation appended to :data:`HOSTED_REDIRECT_PATH` for a payer who
#: approved the order at PayPal.
HOSTED_RETURN_PATH = "/return"

#: Continuation appended to :data:`HOSTED_REDIRECT_PATH` for a payer who
#: abandoned the hosted checkout.
HOSTED_CANCEL_PATH = "/cancel"

ORDER_ID_KEY = "id"

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

#: Event label recorded for an activation driven by the payer's return
#: through the capture continuation rather than by a notification.
CAPTURE_CONTINUATION = "CAPTURE.CONTINUATION"

# Provider failure categories answered with a client-facing 4xx. Every
# other category is a dependency failure.
_CLIENT_STATE_CATEGORIES = (CATEGORY_PROVIDER_CLIENT,)


def _hosted_redirect_url(continuation: str) -> str:
    """Returns one hosted-redirect target handed to PayPal.

    The target is :data:`HOSTED_REDIRECT_PATH` followed by
    ``continuation`` under ``settings.PAYPAL_RETURN_BASE_URL``, which is
    validated configuration of its own so that the CORS origin list
    cannot govern where a payer is sent. ``continuation`` is
    :data:`HOSTED_RETURN_PATH` for a payer who approved the order and
    :data:`HOSTED_CANCEL_PATH` for one who abandoned the checkout, so the
    frontend can tell the two outcomes apart.
    """
    return (
        settings.PAYPAL_RETURN_BASE_URL
        + HOSTED_REDIRECT_PATH
        + continuation
    )


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
    committed row's identifier and stored on it, so a repeat of an
    uncertain call presents the same key rather than opening a second
    order. The order is not captured here and the
    caller holds no entitlement yet: the payer must approve the order at
    the returned ``approval_url``, and either ``POST /capture`` or
    PayPal's notification of that approval is what captures the payment
    and grants the role.

    The entitlement window is left empty until a settlement is proven, so
    the row that exists across the approval window entitles nothing by
    either the ``GET /`` predicate or
    :func:`backend.app.core.authorization.entitled_role`.

    A plan the catalog does not publish is answered ``400`` with
    :data:`INVALID_SUBSCRIPTION_DETAIL`. An order that cannot be opened
    is answered by :func:`_provider_status`, and the row it was opened for
    is left recorded as :data:`FAILED_STATUS`. An order carrying no
    usable identifier or no allowlisted approval target is answered
    ``400`` after one record naming :data:`REASON_UNUSABLE_ORDER`, with
    the row left :data:`FAILED_STATUS`, because neither can be carried
    through to a settlement. A row that cannot be
    committed at all, and an order identifier the uniqueness constraint
    rejects, are each answered ``400`` with
    :data:`PAYMENT_FAILED_DETAIL` after one record naming the reason --
    never with a database error reaching the caller.
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
    # anything
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
    try:
        # The identifier the idempotency key is derived from is assigned
        # by the flush, and the key is stored with the row that same
        # transaction, so the committed row already carries the key the
        # order will be opened under.
        db.flush()
        pending.paypal_request_id = order_request_id(pending.id)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        _payment_failure(REASON_PENDING_NOT_RECORDED, current_user, plan)
        raise HTTPException(
            status_code=400, detail=PAYMENT_FAILED_DETAIL
        ) from None
    db.refresh(pending)

    idempotency_key = pending.paypal_request_id
    try:
        order = await create_order(
            plan.plan_id,
            _hosted_redirect_url(HOSTED_RETURN_PATH),
            _hosted_redirect_url(HOSTED_CANCEL_PATH),
            idempotency_key=idempotency_key,
        )
    except PayPalError as error:
        _mark_failed(db, pending)
        raise _refuse_provider(
            error,
            "Could not open a PayPal order for a subscription",
            subscription_id=pending.id,
            plan_id=plan.plan_id,
            paypal_request_id=idempotency_key,
        ) from None

    order_id = order.get(ORDER_ID_KEY) if isinstance(order, dict) else None
    target = approval_url(order)
    if not isinstance(order_id, str) or not order_id or target is None:
        # An order with no identifier cannot be captured, and one with no
        # allowlisted approval target cannot be approved, so neither is
        # handed back as an opened subscription.
        _mark_failed(db, pending)
        logger.error(
            "PayPal order carried no usable identifier or no allowlisted "
            "approval target",
            extra={
                "subscription_id": pending.id,
                "plan_id": plan.plan_id,
                "paypal_request_id": idempotency_key,
                "reason": REASON_UNUSABLE_ORDER,
                "order_identifier_present": bool(order_id),
                "approval_target_present": target is not None,
            },
        )
        raise mark_audited(
            HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=PAYMENT_FAILED_DETAIL,
            )
        )

    pending.paypal_order_id = order_id
    try:
        db.commit()
    except IntegrityError:
        # The uniqueness constraint rejected the order identifier, so it
        # is already recorded against another row.
        db.rollback()
        _mark_failed(db, pending)
        _payment_failure(REASON_DUPLICATE_ORDER, current_user, plan)
        raise HTTPException(
            status_code=400, detail=PAYMENT_FAILED_DETAIL
        ) from None
    except SQLAlchemyError:
        db.rollback()
        _mark_failed(db, pending)
        _payment_failure(REASON_PENDING_NOT_RECORDED, current_user, plan)
        raise HTTPException(
            status_code=400, detail=PAYMENT_FAILED_DETAIL
        ) from None
    db.refresh(pending)

    logger.info(
        "Opened a PayPal order for a subscription",
        extra={
            "subscription_id": pending.id,
            "plan_id": plan.plan_id,
            "paypal_order_id": order_id,
            "paypal_request_id": idempotency_key,
            "subscription_status": pending.status,
        },
    )
    created = Subscription.from_orm(pending).dict()
    return SubscriptionCreated(approval_url=target, **created)


def _mark_failed(db: Session, subscription: SubscriptionModel) -> None:
    """Records that a subscription's order could not be opened.

    The row stays in place carrying :data:`FAILED_STATUS` and no end
    date, so it grants no entitlement, the attempt stays visible to
    reconciliation, and the row remains open to a later attempt. When the
    mark itself cannot be committed the row is left as it was, which is
    pending and equally without entitlement.
    """
    subscription_id = subscription.id
    subscription.status = FAILED_STATUS
    subscription.paypal_order_id = None
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


@router.post('/capture')
async def capture_subscription(
    capture: SubscriptionCapture,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(Role.REGISTERED))
) -> Subscription:
    """Settles an approved order and grants the entitlement it buys.

    This is the continuation the payer's browser reaches after the
    hosted approval. The order identifier is resolved to a stored row
    through :func:`backend.app.core.authorization.load_owned`, so an
    order matching no row and an order belonging to another account are
    both refused before anything is captured, and the service repeats
    that ownership comparison before the capture call leaves the
    process.

    The captured status, amount and currency are measured against the
    plan catalog, and the row reaches :data:`ACTIVE_STATUS` with the
    plan's role only once that measurement passes -- both in one
    transaction.

    A row already granting entitlement is returned unchanged with no
    call to the provider, so repeating the request settles nothing
    twice. An order the provider reports as already captured is read
    back and measured the same way. A row already closed, and an order
    that does not settle for the catalog price, are answered ``400``
    with :data:`PAYMENT_FAILED_DETAIL`.
    """
    subscription = load_owned(
        db,
        SubscriptionModel,
        current_user,
        request=request,
        paypal_order_id=capture.order_id,
    )

    if subscription.status == ACTIVE_STATUS:
        return Subscription.from_orm(subscription)

    if subscription.status not in _OPEN_STATUSES:
        logger.warning(
            "Refused a capture for a subscription already closed",
            extra={
                "user_id": current_user.id,
                "subscription_id": subscription.id,
                "subscription_status": subscription.status,
            },
        )
        raise HTTPException(
            status_code=400, detail=PAYMENT_FAILED_DETAIL
        )

    plan = _plan_for(subscription)
    if plan is None:
        logger.error(
            "Refused a capture for a subscription naming no catalog plan",
            extra={
                "user_id": current_user.id,
                "subscription_id": subscription.id,
            },
        )
        raise HTTPException(
            status_code=400, detail=PAYMENT_FAILED_DETAIL
        )

    order_id = capture.order_id
    try:
        captured = await capture_order(
            db,
            order_id,
            current_user,
            request=request,
            idempotency_key=capture_request_id(subscription.id),
        )
    except PayPalAPIError as error:
        if error.category in _CLIENT_STATE_CATEGORIES:
            # The provider already settled this order; read it back and
            # measure it rather than settling anything a second time.
            try:
                outcome = await verify_settled_order(
                    db,
                    order_id,
                    current_user,
                    plan.amount,
                    plan.currency,
                    request=request,
                )
            except PayPalError as read_error:
                raise _refuse_provider(
                    read_error,
                    "Refused a subscription capture whose settled order "
                    "could not be read back",
                    user_id=current_user.id,
                    subscription_id=subscription.id,
                ) from None
            if not outcome.completed:
                raise HTTPException(
                    status_code=400, detail=PAYMENT_FAILED_DETAIL
                )
            captured = {
                "id": order_id,
                "status": outcome.status,
            }
        else:
            raise _refuse_provider(
                error,
                "Refused a subscription capture the provider rejected",
                user_id=current_user.id,
                subscription_id=subscription.id,
            ) from None
    except PayPalError as error:
        raise _refuse_provider(
            error,
            "Refused a subscription capture the provider rejected",
            user_id=current_user.id,
            subscription_id=subscription.id,
        ) from None

    subscription = db.query(SubscriptionModel).filter(
        SubscriptionModel.id == subscription.id
    ).first()
    if subscription is None:
        raise HTTPException(
            status_code=400, detail=PAYMENT_FAILED_DETAIL
        )
    if subscription.status == ACTIVE_STATUS:
        return Subscription.from_orm(subscription)

    if _activate(
        db, subscription, plan, captured, order_id, CAPTURE_CONTINUATION
    ) != OUTCOME_PROCESSED:
        db.rollback()
        _payment_failure(REASON_CAPTURE_FAILED, current_user, plan)
        raise HTTPException(
            status_code=400, detail=PAYMENT_FAILED_DETAIL
        )
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.error(
            "Captured a PayPal order whose entitlement could not be "
            "recorded; the pending row is left for reconciliation",
            extra={
                "user_id": current_user.id,
                "plan_id": plan.plan_id,
                "paypal_order_id": order_id,
                "reason": REASON_ACTIVATION_NOT_RECORDED,
            },
        )
        raise HTTPException(
            status_code=503, detail=RECONCILIATION_DETAIL
        ) from None
    db.refresh(subscription)
    return Subscription.from_orm(subscription)


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

    A caller whose window has closed is lowered back to the baseline role
    by :func:`_revoke_role` here, since an expiry produces no
    notification of its own. An administrator is never lowered, and a
    caller another subscription still entitles is left as it is.
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

    1. the transport body is decoded, and must decode to an object
    2. the notification is checked by the PayPal service, which validates
       the host of the ``PAYPAL-CERT-URL`` header against
       ``settings.PAYPAL_CERT_HOST_ALLOWLIST`` before that value is used
       or transmitted, and requires every ``PAYPAL-*`` header
    3. the delivery identifier is added to ``webhook_events`` and
       flushed, whose uniqueness constraint detects a repeated delivery
    4. the notification is applied to the subscription it names
    5. the delivery record and the transition are committed together

    A body that does not decode to an object and a notification that
    fails the check are answered ``400``. A notification that could not
    be checked at all is answered ``503``, so PayPal delivers it again.
    A delivery
    identifier already recorded is answered ``200`` and is **not**
    processed again, because PayPal redelivers every notification it is
    not answered ``2xx``. Nothing is written on any rejected path.

    Only the rejection reason, the request path and safe identifiers are
    recorded; no header value, signature or notification body reaches a
    log record.
    """
    try:
        notification = await request.json()
    except ValueError:
        raise _reject_webhook(
            request,
            REASON_MALFORMED_BODY,
            status.HTTP_400_BAD_REQUEST,
            WEBHOOK_REJECTED_DETAIL,
        ) from None
    if not isinstance(notification, dict):
        # A body that decodes to a list, a string or a number is not a
        # notification, so it is refused before it is transmitted to the
        # verifier as one.
        raise _reject_webhook(
            request,
            REASON_MALFORMED_BODY,
            status.HTTP_400_BAD_REQUEST,
            WEBHOOK_REJECTED_DETAIL,
        )

    # Check the signature before any business field is read
    verification = await verify_webhook_signature(
        request.headers, notification
    )
    if not verification.verified:
        if verification.retryable:
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

    event_type = verification.event_type or UNTYPED_EVENT

    # Record the delivery under the uniqueness constraint
    db.add(
        WebhookEvent(
            transmission_id=verification.transmission_id,
            event_type=event_type,
        )
    )
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        logger.warning(
            "Acknowledged a repeated PayPal delivery without "
            "processing it again",
            extra={
                "reason": REASON_REPLAY,
                "path": request.scope.get("path"),
                "event_type": event_type,
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
        db.rollback()
        raise _refuse_provider(
            error,
            "Could not apply a verified PayPal notification",
            event_type=event_type,
        ) from None
    except Exception:
        db.rollback()
        raise

    db.commit()
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

    subscription = _subscription_for(db, order_id)
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
        return _revoke(db, subscription, event_type)

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
        captured = await capture_order(
            db,
            order_id,
            subscription.user,
            request=request,
            idempotency_key=capture_request_id(subscription.id),
        )
    else:
        captured = _capture_envelope(
            order_id, notification.get(RESOURCE_KEY)
        )

    return _activate(db, subscription, plan, captured, order_id,
                     event_type)


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


def _activate(
    db: Session,
    subscription: SubscriptionModel,
    plan: Plan,
    captured: Any,
    order_id: str,
    event_type: str,
) -> str:
    """Grants entitlement once the capture is confirmed complete.

    The capture is confirmed against the order identifier, the settled
    status and the plan's own amount and currency. A capture that fails
    any of those leaves the subscription in the status it already held
    and grants no role, so a redelivery or a later attempt can still
    settle the row correctly.

    The provider's own capture identifier is recorded on the row, so a
    settled charge can be reconciled against the provider afterwards.
    """
    outcome = read_capture(captured, order_id, plan.amount, plan.currency)
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

    started = datetime.now(timezone.utc)
    subscription.status = ACTIVE_STATUS
    subscription.start_date = started
    subscription.end_date = started + timedelta(days=plan.period_days)
    subscription.paypal_capture_id = outcome.capture_id
    granted = _grant_role(subscription.user, plan.required_role)
    db.flush()
    logger.info(
        "Activated a subscription against a confirmed PayPal capture",
        extra={
            "event_type": event_type,
            "subscription_id": subscription.id,
            "plan_id": plan.plan_id,
            "subscription_status": subscription.status,
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

    The subscription is moved to the status the notification maps to, its
    entitlement window is closed at the server clock, and the principal
    is demoted when it holds the subscriber role and no other
    subscription still entitles it.
    """
    subscription.status = _REVOKED_STATUSES.get(
        event_type, CANCELLED_STATUS
    )
    subscription.end_date = datetime.now(timezone.utc)
    db.flush()
    revoked = _revoke_role(db, subscription.user)
    db.flush()
    logger.warning(
        "Ended a subscription PayPal reported as undone",
        extra={
            "event_type": event_type,
            "subscription_id": subscription.id,
            "subscription_status": subscription.status,
            "revoked_role": revoked,
        },
    )
    return OUTCOME_PROCESSED


def _grant_role(user: Optional[User], required_role: str) -> Optional[str]:
    """Raises a principal to the role its plan carries, if it is higher.

    The stored role is only ever raised: a principal already holding that
    role or a higher one is left as it is. Returns the role now stored, or
    ``None`` when nothing changed.
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
