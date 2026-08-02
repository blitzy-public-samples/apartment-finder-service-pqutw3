from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from backend.app.db.database import get_db
from backend.app.schema.listing import ListingCreate, Listing
from backend.app.db.models import Listing as ListingModel, User
from backend.app.core.security import get_current_user

router = APIRouter()

@router.get("/")
def get_listings(db: Session = Depends(get_db), skip: int = 0, limit: int = 100) -> List[Listing]:
    listings = db.query(ListingModel).offset(skip).limit(limit).all()
    return [Listing.from_orm(listing) for listing in listings]

@router.post("/")
def create_listing(listing: ListingCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> Listing:
    # SEC-05: ListingCreate is the only source of writable fields, so an
    # unknown key is refused before this line (CWE-915)
    #
    # This route cannot persist a row: models.py declares no owner column on
    # Listing and two non-null timestamps this body never carries. The write
    # answers a sanitized 500 and leaves no row.
    # documentation/security/decision-log.md carries the disposition.
    db_listing = ListingModel(**listing.dict(), owner_id=current_user.id)
    db.add(db_listing)
    db.commit()
    db.refresh(db_listing)
    return Listing.from_orm(db_listing)