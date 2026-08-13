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

    The hosted-checkout address is not declared here. It is carried by
    the response that opens a subscription, which adds that one field to
    the fields declared here.
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

    Carries every field of the stored subscription projection and adds
    the hosted PayPal redirect the payer visits to approve the order.
    ``approval_url`` is the only field this response adds. The row is
    created with the pending status and carries no entitlement until the
    approved order has been captured and reconciled.

    ``approval_url`` is required. An order carrying no allowlisted
    approval target is refused, and this response is never produced
    without one.
    """

    approval_url: str
