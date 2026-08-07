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
    client. The plan identifier, the charge amount, the currency and the
    PayPal order identifier are held only server-side and are absent
    from this contract.
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

    The plan identifier is the complete allowlist of values a client may
    supply. The charge amount, the currency, the payment method and the
    entitlement dates are server-assigned: they are absent from this
    contract, and a request carrying any of them is rejected.
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
