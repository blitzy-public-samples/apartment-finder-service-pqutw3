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