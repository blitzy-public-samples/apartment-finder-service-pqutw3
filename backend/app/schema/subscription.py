from pydantic import BaseModel, StrictStr, validator
from datetime import datetime
from typing import Optional


def _require_json_number(value):
    # SEC-05: accepts a JSON number only; rejects strings and booleans
    if value is None:
        return value
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("must be a JSON number")
    return value


def _require_iso_datetime_string(value):
    # SEC-05: accepts an ISO-8601 date-time string only; rejects numbers
    if value is None:
        return value
    if not isinstance(value, str):
        raise TypeError("must be an ISO-8601 date-time string")
    return value


# SEC-05: strictly typed writable-field allow-list for POST /subscriptions/
class SubscriptionCreate(BaseModel):
    plan_id: StrictStr
    payment_method: StrictStr
    amount: float
    start_date: datetime
    end_date: Optional[datetime] = None

    _require_number = validator(
        "amount", pre=True, allow_reuse=True)(_require_json_number)

    _require_iso_datetimes = validator(
        "start_date", "end_date", pre=True, allow_reuse=True
    )(_require_iso_datetime_string)

    class Config:
        # SEC-05: rejects unknown keys; closes the CWE-915 vector
        extra = "forbid"


class Subscription(BaseModel):
    id: int
    user_id: int
    start_date: datetime
    end_date: Optional[datetime]
    status: str

    class Config:
        orm_mode = True
