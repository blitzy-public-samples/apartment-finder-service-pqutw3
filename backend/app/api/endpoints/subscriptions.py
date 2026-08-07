"""Subscription creation, retrieval and PayPal notification intake.

Three routes are published under the ``/subscriptions`` prefix that
:mod:`backend.app.api.router` already applies:

* ``POST /`` opens a PayPal order priced by the plan catalog, records
  the subscription it belongs to and captures that order through the
  ownership-bound service lookup. The request contract carries a plan
  identifier only.
* ``GET /`` returns the caller's own active subscription.
* ``POST /webhook`` records one verified PayPal notification. The
  signature is checked before the notification is recorded, and the
  delivery identifier is stored under the uniqueness constraint that
  rejects a repeated delivery.

The charge amount, the currency, the entitlement window, the stored
status and the PayPal order identifier are all assigned here from the
plan catalog, the server clock and the PayPal response. No request
field takes part in any of them.

The two authenticated routes resolve their principal through
:func:`backend.app.core.authorization.require_role`, which reads the
role from the stored user row. ``POST /webhook`` declares no role
dependency and is admitted on its signature alone.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from typing import Dict, Optional

from backend.app.core.authorization import Role, require_role
from backend.app.core.config import settings
from backend.app.core.logging import get_logger
from backend.app.core.plans import UnknownPlanError, get_plan
from backend.app.db.database import get_db
from backend.app.schema.subscription import SubscriptionCreate, Subscription
from backend.app.db.models import (
    Subscription as SubscriptionModel,
    User,
    WebhookEvent,
)
from backend.app.services.paypal_service import (
    PayPalError,
    capture_order,
    create_order,
    verify_webhook_signature,
)

router = APIRouter()

logger = get_logger(__name__)

#: Status stored on a subscription row created here.
ACTIVE_STATUS = "active"

#: Detail returned for a plan the catalog does not publish.
INVALID_SUBSCRIPTION_DETAIL = "Invalid subscription data"

#: Detail returned when the PayPal order does not complete.
PAYMENT_FAILED_DETAIL = "Payment processing failed"

#: Detail returned for a notification that fails its signature check.
WEBHOOK_REJECTED_DETAIL = "Webhook verification failed"

#: Detail returned for a delivery identifier already recorded.
WEBHOOK_REPLAY_DETAIL = "Webhook already processed"

#: Event type stored when a verified notification names none.
UNTYPED_EVENT = "UNKNOWN"

#: Rejection reason recorded for a body that does not decode.
REASON_MALFORMED_BODY = "malformed_body"

#: Rejection reason recorded for a delivery already recorded.
REASON_REPLAY = "duplicate_transmission_id"

#: Frontend path the PayPal hosted redirect returns the payer to.
HOSTED_REDIRECT_PATH = "/subscription"

#: Key carrying the order identifier in a created PayPal order.
ORDER_ID_KEY = "id"


def _hosted_redirect_url() -> str:
    """Returns the hosted-redirect target handed to PayPal.

    The target is :data:`HOSTED_REDIRECT_PATH` under the first entry of
    ``settings.ALLOWED_ORIGINS``.
    """
    origins = settings.ALLOWED_ORIGINS
    origin = origins[0] if origins else ""
    return origin + HOSTED_REDIRECT_PATH


def _reject(request: Request, reason: Optional[str]) -> None:
    """Records one rejected PayPal notification.

    ``reason`` and the request path are the only values recorded. No
    header value, signature, certificate URL or notification body is
    passed to the logger.
    """
    logger.warning(
        "Rejected an inbound PayPal notification",
        extra={
            "reason": reason,
            "path": request.scope.get("path"),
        },
    )


@router.post('/')
async def create_subscription(
    subscription: SubscriptionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(Role.REGISTERED))
) -> Subscription:
    """Opens, records and captures a subscription for the caller.

    The request carries a plan identifier only. The amount, the
    currency and the entitlement period are read from the plan catalog,
    the entitlement window is computed from the server clock and the
    stored status is :data:`ACTIVE_STATUS`.

    A plan the catalog does not publish is answered ``400`` with
    :data:`INVALID_SUBSCRIPTION_DETAIL`. An order that cannot be opened
    or captured is answered ``400`` with :data:`PAYMENT_FAILED_DETAIL`,
    and the row prepared for it is rolled back.
    """
    # Validate subscription data
    if not subscription.plan_id:
        raise HTTPException(
            status_code=400, detail=INVALID_SUBSCRIPTION_DETAIL
        )

    # Read the amount, currency and period from the server-owned catalog
    try:
        plan = get_plan(subscription.plan_id)
    except UnknownPlanError:
        raise HTTPException(
            status_code=400, detail=INVALID_SUBSCRIPTION_DETAIL
        ) from None

    # Open the PayPal order the catalog prices
    redirect_url = _hosted_redirect_url()
    try:
        order = create_order(plan.plan_id, redirect_url, redirect_url)
    except PayPalError:
        raise HTTPException(
            status_code=400, detail=PAYMENT_FAILED_DETAIL
        ) from None

    order_id = order.get(ORDER_ID_KEY)
    if not isinstance(order_id, str) or not order_id:
        logger.error(
            "PayPal order carried no usable identifier",
            extra={
                "user_id": current_user.id,
                "plan_id": plan.plan_id,
            },
        )
        raise HTTPException(
            status_code=400, detail=PAYMENT_FAILED_DETAIL
        )

    # Compute the entitlement window from the server clock
    start_date = datetime.now(timezone.utc)
    end_date = start_date + timedelta(days=plan.period_days)

    # Create new subscription in database
    new_subscription = SubscriptionModel(
        user_id=current_user.id,
        plan_id=plan.plan_id,
        amount=plan.amount,
        currency=plan.currency,
        status=ACTIVE_STATUS,
        start_date=start_date,
        end_date=end_date,
        paypal_order_id=order_id
    )
    db.add(new_subscription)
    db.flush()

    # Capture the order against the row that owns it
    try:
        capture_order(db, order_id, current_user.id)
    except PayPalError:
        db.rollback()
        raise HTTPException(
            status_code=400, detail=PAYMENT_FAILED_DETAIL
        ) from None

    db.commit()
    db.refresh(new_subscription)

    # Return created subscription
    return Subscription.from_orm(new_subscription)


@router.get('/')
async def get_user_subscription(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(Role.REGISTERED))
) -> Optional[Subscription]:
    """Returns the caller's own subscription that has not yet ended.

    The query is scoped to the authenticated principal's identifier. A
    row belonging to another account is not reachable here, and
    ``None`` is returned when the caller holds no unexpired row.
    """
    # Query database for user's active subscription
    subscription = db.query(SubscriptionModel).filter(
        SubscriptionModel.user_id == current_user.id,
        SubscriptionModel.end_date > datetime.now(timezone.utc)
    ).first()

    # Return subscription if found, else return None
    return Subscription.from_orm(subscription) if subscription else None


@router.post('/webhook')
async def receive_paypal_webhook(
    request: Request,
    db: Session = Depends(get_db)
) -> Dict[str, str]:
    """Records one verified PayPal notification exactly once.

    The route declares no role dependency and is admitted on its
    signature alone. The steps run in this order, and no later step
    runs before an earlier one passes.

    1. the transport body is decoded
    2. the notification is checked by the PayPal service, which
       validates the host of the ``PAYPAL-CERT-URL`` header against
       ``settings.PAYPAL_CERT_HOST_ALLOWLIST`` before that value is
       used or transmitted, and requires every ``PAYPAL-*`` header
    3. the delivery identifier is inserted into ``webhook_events``,
       whose uniqueness constraint rejects a repeated delivery
    4. ``200`` is returned

    A body that does not decode and a notification that fails the
    check are answered ``400`` with :data:`WEBHOOK_REJECTED_DETAIL`. A
    repeated delivery identifier is answered ``409`` with
    :data:`WEBHOOK_REPLAY_DETAIL`. Nothing is written on any of those
    paths. Only the rejection reason and the request path are recorded;
    no header value, signature or notification body reaches a log
    record.
    """
    # Decode the transport body
    try:
        notification = await request.json()
    except ValueError:
        _reject(request, REASON_MALFORMED_BODY)
        raise HTTPException(
            status_code=400, detail=WEBHOOK_REJECTED_DETAIL
        ) from None

    # Check the signature before the notification is recorded
    verification = verify_webhook_signature(
        request.headers, notification
    )
    if not verification.verified:
        _reject(request, verification.reason)
        raise HTTPException(
            status_code=400, detail=WEBHOOK_REJECTED_DETAIL
        )

    # Record the delivery under the uniqueness constraint
    db.add(
        WebhookEvent(
            transmission_id=verification.transmission_id,
            event_type=verification.event_type or UNTYPED_EVENT,
        )
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        _reject(request, REASON_REPLAY)
        raise HTTPException(
            status_code=409, detail=WEBHOOK_REPLAY_DETAIL
        ) from None

    return {"status": "processed"}
