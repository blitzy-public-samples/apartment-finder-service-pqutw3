"""Request and response contracts for the subscription endpoints.

``SubscriptionCreate`` is the request body accepted when a subscription
is created. ``Subscription`` is the response projection of a stored
``subscriptions`` row.
"""

from pydantic import BaseModel, constr, validator
from datetime import datetime
from decimal import Decimal
from typing import Optional

from backend.app.core.plans import PLAN_IDS

# Maximum length of the plan identifier accepted in a request.
_PLAN_ID_MAX_LENGTH = 64

# Maximum length of the payment-method selector accepted in a request.
_PAYMENT_METHOD_MAX_LENGTH = 32

_PlanIdField = constr(
    strip_whitespace=True,
    min_length=1,
    max_length=_PLAN_ID_MAX_LENGTH,
)

_PaymentMethodField = constr(
    strip_whitespace=True,
    min_length=1,
    max_length=_PAYMENT_METHOD_MAX_LENGTH,
)


class Subscription(BaseModel):
    """Response contract for a stored ``subscriptions`` row."""

    id: int
    user_id: int
    plan_id: Optional[str]
    amount: Optional[Decimal]
    currency: str
    start_date: datetime
    end_date: Optional[datetime]
    status: str

    class Config:
        # Permits population from a SQLAlchemy row via
        # Subscription.from_orm.
        orm_mode = True


class SubscriptionCreate(BaseModel):
    """Request contract for subscription creation.

    The declared fields are the complete allowlist of values a client may
    supply. The charge amount, the currency and the entitlement dates are
    server-assigned and absent from this contract.
    """

    plan_id: _PlanIdField
    payment_method: _PaymentMethodField

    class Config:
        # Rejects any field outside the allowlist above.
        extra = "forbid"

    @validator("plan_id")
    def validate_plan_id(cls, value: str) -> str:
        """Require an identifier published by the plan catalog."""
        if value not in PLAN_IDS:
            accepted = ", ".join(sorted(PLAN_IDS))
            raise ValueError(f"plan_id must be one of: {accepted}")
        return value
