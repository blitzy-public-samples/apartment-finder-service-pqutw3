from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional


class Listing(BaseModel):
    """Response contract for a listing record read from a ``listings`` row.

    Field optionality mirrors column nullability: ``id``, ``created_at``,
    ``updated_at`` and ``rent`` are non-null columns and stay required;
    every other column is nullable and projects as ``None``.
    """

    id: int
    created_at: datetime
    updated_at: datetime
    rent: float
    broker_fee: Optional[float] = None
    square_footage: Optional[float] = None
    bedrooms: Optional[int] = None
    bathrooms: Optional[int] = None
    available_date: Optional[datetime] = None
    street_address: Optional[str] = None
    zillow_url: Optional[str] = None

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
