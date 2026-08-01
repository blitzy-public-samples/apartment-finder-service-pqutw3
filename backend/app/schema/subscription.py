import math

from pydantic import BaseModel, StrictStr, validator
from datetime import datetime
from typing import Optional


def _require_json_number(value):
    # SEC-05: accepts a finite JSON number only; rejects strings, booleans,
    # NaN, the two infinities and a magnitude no float holds (CWE-20)
    if value is None:
        return value
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("must be a JSON number")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError("must be a finite number")
    return value


def _require_positive(value):
    # SEC-05: a charged amount carries a value above zero (CWE-20)
    if value is None:
        return value
    if value <= 0:
        raise ValueError("must be greater than zero")
    return value


def _require_end_after_start(value, values):
    # SEC-05: a term ends after it begins (CWE-20)
    start = values.get("start_date")
    if value is None or start is None:
        return value
    if value <= start:
        raise ValueError("must be later than start_date")
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

    _require_positive_amount = validator(
        "amount", allow_reuse=True)(_require_positive)

    _require_iso_datetimes = validator(
        "start_date", "end_date", pre=True, allow_reuse=True
    )(_require_iso_datetime_string)

    _require_date_order = validator(
        "end_date", allow_reuse=True)(_require_end_after_start)

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
