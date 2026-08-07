from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional


class Listing(BaseModel):
    """Response contract for a listing record read from a ``listings`` row."""

    id: int
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

    class Config:
        orm_mode = True


class ListingCreate(BaseModel):
    """Request contract for listing creation.

    The declared fields are the complete allowlist of ``listings`` columns a
    client may supply. Unknown fields are rejected. ``id``, ``created_at`` and
    ``updated_at`` are server-assigned and absent from this contract.
    """

    rent: float = Field(..., ge=0)
    broker_fee: Optional[float] = Field(None, ge=0)
    square_footage: Optional[float] = Field(None, ge=0)
    bedrooms: Optional[int] = Field(None, ge=0)
    bathrooms: Optional[int] = Field(None, ge=0)
    available_date: Optional[datetime] = None
    street_address: Optional[str] = Field(None, max_length=255)
    zillow_url: Optional[str] = Field(None, max_length=2048)

    class Config:
        extra = "forbid"
