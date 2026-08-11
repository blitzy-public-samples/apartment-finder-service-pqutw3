from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone

from backend.app.core.authorization import Role, require_role
from backend.app.core.config import settings
from backend.app.core.logging import get_logger, log_exception
from backend.app.db.database import get_db
from backend.app.schema.listing import ListingCreate, Listing
from backend.app.db.models import Listing as ListingModel, User

router = APIRouter()

logger = get_logger(__name__)

DEFAULT_PAGE_SIZE = min(100, settings.MAX_PAGE_SIZE)

LISTING_NOT_STORED_DETAIL = "Listing could not be stored"

LISTING_NOT_PROJECTABLE_DETAIL = "Listing page could not be served"

REASON_UNPROJECTABLE_ROW = "listing_not_projectable"

LISTING_NOT_STORED_MESSAGE = "Failed to store a listing"

REASON_NOT_STORED = "listing_not_stored"


@router.get("/")
def get_listings(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0, le=settings.MAX_PAGINATION_OFFSET),
    limit: int = Query(
        DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE
    ),
) -> List[Listing]:
    """Return a bounded, ID-ordered public listings page; fail if any
    stored row violates the response schema.
    """
    listings = (
        db.query(ListingModel)
        .order_by(ListingModel.id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    page = []
    for listing in listings:
        try:
            page.append(Listing.from_orm(listing))
        except ValidationError as error:
            logger.error(
                "Refused a listing page because the response contract "
                "cannot carry a stored row",
                extra={
                    "listing_id": listing.id,
                    "reason": REASON_UNPROJECTABLE_ROW,
                    "failed_fields": _failed_fields(error),
                },
            )
            raise HTTPException(
                status_code=500,
                detail=LISTING_NOT_PROJECTABLE_DETAIL,
            ) from None
    return page


def _failed_fields(error: ValidationError) -> List[str]:
    """Returns the contract fields ``error`` reports, sorted and unique.

    A location part is kept only when it names a field :class:`Listing`
    declares, so the result carries contract names and never a stored
    value.
    """
    declared = set(Listing.__fields__)
    names = set()
    for entry in error.errors():
        for part in entry.get("loc", ()):
            if isinstance(part, str) and part in declared:
                names.add(part)
    return sorted(names)


@router.post("/")
def create_listing(
    listing: ListingCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN)),
) -> Listing:
    """Stores one listing for an administrator and returns it.

    Only the fields the request body below declares are written. A field
    outside it cannot reach the stored listing.

    A street address is not required to be unique, so a listing naming an
    address that is already stored is accepted rather than refused, and
    more than one listing may carry the same address.

    Any refusal from storage, including a constraint violation, rolls the
    write back and is answered with one fixed message, so no response
    reveals which constraint was refused.
    """
    recorded_at = datetime.now(timezone.utc)
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
    try:
        db.commit()
    except SQLAlchemyError as error:
        db.rollback()
        log_exception(
            logger,
            LISTING_NOT_STORED_MESSAGE,
            error,
            user_id=current_user.id,
            reason=REASON_NOT_STORED,
        )
        raise HTTPException(
            status_code=500, detail=LISTING_NOT_STORED_DETAIL
        ) from None
    db.refresh(db_listing)
    return Listing.from_orm(db_listing)
