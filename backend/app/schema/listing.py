import math

from pydantic import BaseModel, StrictInt, StrictStr, validator
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


def _require_iso_datetime_string(value):
    # SEC-05: accepts an ISO-8601 date-time string only; rejects numbers
    if value is None:
        return value
    if not isinstance(value, str):
        raise TypeError("must be an ISO-8601 date-time string")
    return value


class Listing(BaseModel):
    # SEC-05: matches the INTEGER primary key at models.py:22
    id: int
    created_at: datetime
    updated_at: datetime
    rent: float
    # optionality mirrors the nullable columns at models.py:26-32
    broker_fee: Optional[float] = None
    square_footage: Optional[float] = None
    bedrooms: Optional[int] = None
    bathrooms: Optional[int] = None
    available_date: Optional[datetime] = None
    street_address: Optional[str] = None
    zillow_url: Optional[str] = None

    class Config:
        # listings.py:15 builds this model with from_orm
        orm_mode = True


class ListingCreate(BaseModel):
    # SEC-05: writable-field allow-list for POST /listings/
    rent: float
    broker_fee: Optional[float] = None
    square_footage: Optional[float] = None
    bedrooms: Optional[StrictInt] = None
    bathrooms: Optional[StrictInt] = None
    available_date: Optional[datetime] = None
    street_address: Optional[StrictStr] = None
    zillow_url: Optional[StrictStr] = None

    _require_numbers = validator(
        "rent", "broker_fee", "square_footage",
        pre=True, allow_reuse=True)(_require_json_number)

    _require_iso_datetime = validator(
        "available_date", pre=True, allow_reuse=True
    )(_require_iso_datetime_string)

    class Config:
        # SEC-05: rejects unknown keys; closes the CWE-915 vector
        extra = "forbid"
