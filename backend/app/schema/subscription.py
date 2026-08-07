from pydantic import BaseModel, constr, validator
from datetime import datetime
from typing import Optional

from backend.app.core.plans import PLAN_IDS

_PLAN_ID_MAX_LENGTH = 64

_PlanIdField = constr(
    strip_whitespace=True,
    min_length=1,
    max_length=_PLAN_ID_MAX_LENGTH,
)


class Subscription(BaseModel):
    """Response contract for a stored ``subscriptions`` row.

    The declared fields are the complete projection returned to a
    client. The charge amount, the currency and the PayPal order
    identifier are held only server-side and are absent from this
    contract.

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

    ``approval_url`` is required. An order carrying no allowlisted
    approval target is refused rather than returned, so this response is
    never produced without one and a generated client is told the
    continuation is always present.
    """

    approval_url: str
