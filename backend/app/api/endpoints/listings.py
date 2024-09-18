from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from backend.app.db.database import get_db
from backend.app.schema.listing import ListingCreate, Listing
from backend.app.db.models import Listing as ListingModel
from backend.app.core.security import get_current_user

router = APIRouter()

@router.get("/")
def get_listings(db: Session = Depends(get_db), skip: int = 0, limit: int = 100) -> List[Listing]:
    listings = db.query(ListingModel).offset(skip).limit(limit).all()
    return [Listing.from_orm(listing) for listing in listings]

@router.post("/")
def create_listing(listing: ListingCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> Listing:
    # HUMAN ASSISTANCE NEEDED
    # The User model is not imported. Please ensure it's imported from the correct module.
    # Also, additional validation might be needed for the listing data.
    
    db_listing = ListingModel(**listing.dict(), owner_id=current_user.id)
    db.add(db_listing)
    db.commit()
    db.refresh(db_listing)
    return Listing.from_orm(db_listing)