from pydantic import BaseModel, StrictInt, StrictStr, validator
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
    # SEC-05: accepts an ISO-8601 date-time string only; rejects numbers,
    # which pydantic would otherwise read as a Unix timestamp
    if value is None:
        return value
    if not isinstance(value, str):
        raise TypeError("must be an ISO-8601 date-time string")
    return value


class Listing(BaseModel):
    id: str
    created_at: datetime
    updated_at: datetime
    rent: float
    broker_fee: float
    square_footage: float
    bedrooms: int
    bathrooms: int
    available_date: datetime
    street_address: str
    zillow_url: str


class ListingCreate(BaseModel):
    # SEC-05: writable-field allow-list for listings.py:23, typed strictly so
    # a wrong JSON type is rejected rather than coerced
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
