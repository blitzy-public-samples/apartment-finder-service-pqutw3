from pydantic import BaseModel
from datetime import datetime
from typing import Optional

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
    # SEC-05: writable-field allow-list for listings.py:23
    rent: float
    broker_fee: Optional[float] = None
    square_footage: Optional[float] = None
    bedrooms: Optional[int] = None
    bathrooms: Optional[int] = None
    available_date: Optional[datetime] = None
    street_address: Optional[str] = None
    zillow_url: Optional[str] = None

    class Config:
        # SEC-05: rejects unknown keys; closes the CWE-915 vector
        extra = "forbid"
