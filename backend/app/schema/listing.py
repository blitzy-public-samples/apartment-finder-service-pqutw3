from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import Optional
from urllib.parse import urlsplit

#: URL schemes a listing address may use. Any other scheme, and any
#: value that is not an absolute URL, is refused.
LISTING_URL_SCHEMES = ("https", "http")

#: Characters refused in a text field. A text column stores no NUL, so a
#: value carrying one cannot be written and is refused by the contract
#: instead of by the driver.
FORBIDDEN_TEXT_CHARACTERS = ("\x00",)


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

    Each text field is bounded in length and refuses
    :data:`FORBIDDEN_TEXT_CHARACTERS`, and ``zillow_url`` must be an
    absolute URL whose scheme is one of :data:`LISTING_URL_SCHEMES` and
    which carries a host and no user information. A refusal names the
    field and never repeats the value.
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

    @validator("street_address", "zillow_url")
    def _reject_forbidden_characters(cls, value):
        """Refuses a text value a text column cannot store."""
        if value is None:
            return value
        for character in FORBIDDEN_TEXT_CHARACTERS:
            if character in value:
                raise ValueError(
                    "value carries a character a text column cannot store"
                )
        return value

    @validator("zillow_url")
    def _require_absolute_web_url(cls, value):
        """Refuses an address that is not an absolute web URL."""
        if value is None:
            return value
        try:
            parts = urlsplit(value)
        except ValueError:
            raise ValueError("value is not a parsable URL") from None
        if parts.scheme.lower() not in LISTING_URL_SCHEMES:
            raise ValueError(
                "scheme must be one of " + ", ".join(LISTING_URL_SCHEMES)
            )
        if not parts.hostname:
            raise ValueError("value carries no host")
        if parts.username or parts.password:
            raise ValueError("value carries user information")
        return value
