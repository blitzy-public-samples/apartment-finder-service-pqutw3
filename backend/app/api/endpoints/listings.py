from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone

from backend.app.core.authorization import Role, require_role
from backend.app.core.config import MAX_PAGINATION_OFFSET, settings
from backend.app.core.logging import get_logger
from backend.app.db.database import get_db
from backend.app.schema.listing import ListingCreate, Listing
from backend.app.db.models import Listing as ListingModel, User

router = APIRouter()

logger = get_logger(__name__)

#: Page size applied when a request names none.
DEFAULT_PAGE_SIZE = min(100, settings.MAX_PAGE_SIZE)

#: Detail returned when a listing cannot be persisted.
LISTING_NOT_STORED_DETAIL = "Listing could not be stored"

#: Reason recorded for a stored row the response contract cannot carry.
REASON_UNPROJECTABLE_ROW = "listing_not_projectable"


@router.get("/")
def get_listings(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0, le=MAX_PAGINATION_OFFSET),
    limit: int = Query(
        DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE
    ),
) -> List[Listing]:
    """Returns one page of the listing corpus, reachable without a token.

    Ordered by the primary key, so a row keeps its position across pages
    while the corpus is being written to.

    Each row is projected on its own. A row carrying a value the response
    contract cannot represent -- which
    :class:`backend.app.schema.listing.ListingCreate` refuses at every
    write path, so only a row written outside this contract can carry one
    -- is recorded against its identifier and left out of the page,
    because a page is more useful than a refusal and the endpoint is
    reachable without a credential.
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
                "Left a stored listing out of a page because the "
                "response contract cannot carry it",
                extra={
                    "listing_id": listing.id,
                    "reason": REASON_UNPROJECTABLE_ROW,
                    "failed_fields": _failed_fields(error),
                },
            )
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
    except SQLAlchemyError:
        db.rollback()
        logger.exception(
            "Failed to store a listing",
            extra={"user_id": current_user.id},
        )
        raise HTTPException(
            status_code=500, detail=LISTING_NOT_STORED_DETAIL
        ) from None
    db.refresh(db_listing)
    return Listing.from_orm(db_listing)
