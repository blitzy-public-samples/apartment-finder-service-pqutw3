from pydantic import BaseModel, constr, validator
from datetime import datetime
from typing import Optional

from backend.app.core.plans import PLAN_IDS

_PLAN_ID_MAX_LENGTH = 64

_ORDER_ID_MAX_LENGTH = 64

# Accepted order-identifier shape: the letters, digits, hyphens and
# underscores a PayPal order identifier is made of.
_ORDER_ID_REGEX = r"^[A-Za-z0-9_-]+$"

_PlanIdField = constr(
    strip_whitespace=True,
    min_length=1,
    max_length=_PLAN_ID_MAX_LENGTH,
)

_OrderIdField = constr(
    strip_whitespace=True,
    min_length=1,
    max_length=_ORDER_ID_MAX_LENGTH,
    regex=_ORDER_ID_REGEX,
)


class Subscription(BaseModel):
    """Response contract for a stored ``subscriptions`` row.

    The declared fields are the complete projection returned to a
    client. The charge amount, the currency, the PayPal order identifier,
    the idempotency key and the capture identifier are held only
    server-side and are absent from this contract.

    The hosted-checkout address is not declared here. It belongs to the
    response that opens a subscription, and is carried by
    :class:`SubscriptionCreated`.
    """

    id: int
    user_id: int
    start_date: datetime
    end_date: Optional[datetime]
    status: str

    class Config:
        orm_mode = True


class SubscriptionCreate(BaseModel):
    """Request contract for subscription creation.

    ``plan_id`` is the only field a client may supply, and it must name an
    identifier the plan catalog publishes. Any other field in the body is
    rejected.
    """

    plan_id: _PlanIdField

    class Config:
        extra = "forbid"

    @validator("plan_id")
    def validate_plan_id(cls, value: str) -> str:
        """Require an identifier published by the plan catalog."""
        if value not in PLAN_IDS:
            accepted = ", ".join(sorted(PLAN_IDS))
            raise ValueError(f"plan_id must be one of: {accepted}")
        return value


class SubscriptionCreated(Subscription):
    """Response contract for a newly opened subscription.

    Carries every field of :class:`Subscription` and adds the hosted
    PayPal redirect the payer must visit to approve the order. The row is
    created with the pending status and carries no entitlement until the
    approved order has been captured and reconciled.
    """

    approval_url: Optional[str] = None


class SubscriptionCapture(BaseModel):
    """Request contract for capturing an approved PayPal order.

    The order identifier is the complete allowlist of values a client may
    supply. The amount, the currency, the plan, the entitlement dates and
    the owning account are all resolved server-side from the stored row
    the identifier names, and a request carrying any of them is rejected.
    """

    order_id: _OrderIdField

    class Config:
        extra = "forbid"
