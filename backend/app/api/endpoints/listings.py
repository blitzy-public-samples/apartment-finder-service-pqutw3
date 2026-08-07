from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone

from backend.app.core.authorization import Role, require_role
from backend.app.core.config import settings
from backend.app.db.database import get_db
from backend.app.schema.listing import ListingCreate, Listing
from backend.app.db.models import Listing as ListingModel, User

router = APIRouter()

#: Page size applied when a request names none.
DEFAULT_PAGE_SIZE = min(100, settings.MAX_PAGE_SIZE)


@router.get("/")
def get_listings(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(
        DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE
    ),
) -> List[Listing]:
    listings = db.query(ListingModel).offset(skip).limit(limit).all()
    return [Listing.from_orm(listing) for listing in listings]


@router.post("/")
def create_listing(
    listing: ListingCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN)),
) -> Listing:
    # Timestamps are taken from the server clock.
    recorded_at = datetime.now(timezone.utc)
    # Each column is named explicitly; no request field is unpacked.
    db_listing = ListingModel(
        created_at=recorded_at,
        updated_at=recorded_at,
        rent=listing.rent,
        broker_fee=listing.broker_fee,
        square_footage=listing.square_footage,
        bedrooms=listing.bedrooms,
        bathrooms=listing.bathrooms,
        available_date=listing.available_date,
        street_address=listing.street_address,
        zillow_url=listing.zillow_url,
    )
    db.add(db_listing)
    db.commit()
    db.refresh(db_listing)
    return Listing.from_orm(db_listing)
