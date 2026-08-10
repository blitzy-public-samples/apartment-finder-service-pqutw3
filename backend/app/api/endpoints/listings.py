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

#: Page size applied when a request names none.
DEFAULT_PAGE_SIZE = min(100, settings.MAX_PAGE_SIZE)

#: Detail returned when a listing cannot be persisted, whatever the
#: database refused it for.
LISTING_NOT_STORED_DETAIL = "Listing could not be stored"

#: Detail returned for a page carrying a stored row the response contract
#: cannot represent.
LISTING_NOT_PROJECTABLE_DETAIL = "Listing page could not be served"

#: Reason recorded for a stored row the response contract cannot carry.
REASON_UNPROJECTABLE_ROW = "listing_not_projectable"

#: Message recorded when the database refuses a listing write.
LISTING_NOT_STORED_MESSAGE = "Failed to store a listing"

#: Reason recorded with that message.
REASON_NOT_STORED = "listing_not_stored"


@router.get("/")
def get_listings(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0, le=settings.MAX_PAGINATION_OFFSET),
    limit: int = Query(
        DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE
    ),
) -> List[Listing]:
    """Returns one page of the listing corpus, reachable without a token.

    Ordered by the primary key, so a row keeps its position across pages
    while the corpus is being written to. The page carries every row the
    named window selects, in that order, so a page shorter than ``limit``
    means the window reached the end of the corpus and nothing else.

    ``limit`` is bounded by ``settings.MAX_PAGE_SIZE`` and ``skip`` by
    ``settings.MAX_PAGINATION_OFFSET``, so the rows one anonymous request
    can make the database walk are bounded by configuration rather than
    by the range of the column type. An offset above the cap is refused
    by request validation.

    Each row is projected on its own. A row carrying a value the response
    contract cannot represent -- which
    :class:`backend.app.schema.listing.ListingCreate` refuses at every
    write path, so only a row written outside this contract can carry one
    -- fails the page it appears on. The row is recorded against its
    identifier and the failing contract fields, and the response is an
    error rather than a page with that row removed.
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

    The row is built from named columns, so no field outside
    :class:`backend.app.schema.listing.ListingCreate` reaches it.

    The provider address column carries no uniqueness, in the mapped
    table and in revision ``0001`` alike, so a listing repeating an
    address already stored is **stored** rather than refused, and two
    rows may carry one address.

    Every refusal the database raises -- an integrity violation included
    -- rolls the write back and is answered with one fixed detail, so no
    response distinguishes which constraint the database refused or
    otherwise discloses its internals.
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
    # Any refusal from the database rolls the session back, is recorded
    # against the caller, and is answered with one fixed detail.
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
