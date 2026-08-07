"""Scheduled ingestion of provider listings into the ``listings`` table.

One pass reads the postal codes stored on saved filters, asks the
provider for the listings covering them, maps each returned record onto
the listing creation contract, and reconciles it against the stored
corpus on :data:`IDENTITY_COLUMN`.

Every write goes through a mapped ORM instance and names its columns
explicitly: a record is either constructed as a new
:class:`backend.app.db.models.Listing` or assigned onto the declared
mutable columns of the row it matches. No attribute is copied
dynamically from a provider object, and the identity column and the
server-assigned ``id`` and ``created_at`` are never reassigned.

A record carrying no identity is discarded rather than recorded, because
it cannot be reconciled on a later pass and would otherwise be inserted
again on every one. A record that fails the contract is discarded the
same way. Both are counted and reported once per pass.

The pass owns one session, commits once, and rolls back and reports on
any failure rather than propagating it, so a failing provider or
database never ends the schedule.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from backend.app.db.database import SessionLocal
from backend.app.services.zillow_service import (
    ListingMappingError,
    fetch_listings,
    process_listing,
)
from backend.app.db.models import Listing, ZipCode
from backend.app.schema.listing import ListingCreate
from backend.app.core.logging import get_logger, log_exception

UPDATE_INTERVAL = timedelta(hours=1)

#: Column a provider record is reconciled against. It is the only
#: declared column carrying a value the provider assigns per listing.
IDENTITY_COLUMN = "zillow_url"

#: Provider query filters sent with every scheduled pass. The pass
#: narrows by postal code alone.
PROVIDER_FILTERS: Dict[str, str] = {}

#: Message recorded when one ingestion pass does not complete.
INGESTION_FAILED_MESSAGE = "An error occurred while updating listings"

logger = get_logger(__name__)


def tracked_zip_codes(db: Session) -> List[str]:
    """Returns the distinct postal codes saved filters name.

    Blank and non-string values are dropped, and the result is sorted so
    one pass sends the provider a stable list.
    """
    rows = db.query(ZipCode.code).distinct().all()
    return sorted(
        set(
            code
            for (code,) in rows
            if isinstance(code, str) and code
        )
    )


def _new_listing(
    processed: ListingCreate,
    moment: datetime,
) -> Listing:
    """Returns a mapped row carrying ``processed``.

    Every column is named explicitly. ``created_at`` and ``updated_at``
    are taken from ``moment`` and ``id`` is left to the database.
    """
    return Listing(
        created_at=moment,
        updated_at=moment,
        rent=processed.rent,
        broker_fee=processed.broker_fee,
        square_footage=processed.square_footage,
        bedrooms=processed.bedrooms,
        bathrooms=processed.bathrooms,
        available_date=processed.available_date,
        street_address=processed.street_address,
        zillow_url=processed.zillow_url,
    )


def _refresh_listing(
    row: Listing,
    processed: ListingCreate,
    moment: datetime,
) -> None:
    """Assigns ``processed`` onto the declared mutable columns of ``row``.

    ``id``, ``created_at`` and the identity column are not assigned.
    """
    row.rent = processed.rent
    row.broker_fee = processed.broker_fee
    row.square_footage = processed.square_footage
    row.bedrooms = processed.bedrooms
    row.bathrooms = processed.bathrooms
    row.available_date = processed.available_date
    row.street_address = processed.street_address
    row.updated_at = moment


def _mapped(raw_listing: Dict) -> Optional[ListingCreate]:
    """Returns ``raw_listing`` mapped, or ``None`` when it is unusable.

    A record that fails the contract and a record carrying no identity
    both return ``None``. Neither the record nor any provider value
    reaches the log line.
    """
    try:
        processed = process_listing(raw_listing)
    except ListingMappingError:
        logger.warning("Discarded a provider listing that failed the contract")
        return None
    if not getattr(processed, IDENTITY_COLUMN):
        logger.warning(
            "Discarded a provider listing that carried no identity",
            extra={"identity_column": IDENTITY_COLUMN},
        )
        return None
    return processed


@asyncio.coroutine
async def update_listings():
    """Run one ingestion cycle over the listings the provider returns.

    Opens its own session, upserts each fetched listing by its Zillow
    identifier -- copying the processed attributes onto an existing row
    or adding a new one -- and commits once at the end of the cycle.

    Any exception rolls the session back and is recorded through the
    redacting logger rather than propagated, so a failed cycle leaves no
    partial write behind and does not stop the caller. The session is
    closed on every path.
    """
    db: Session = SessionLocal()
    processed = 0
    try:
        zip_codes = tracked_zip_codes(db)
        if not zip_codes:
            logger.info(
                "Skipped an ingestion pass because no saved filter "
                "names a postal code"
            )
            return
        raw_listings = fetch_listings(zip_codes, PROVIDER_FILTERS)
        moment = datetime.now(timezone.utc)
        recorded = 0
        refreshed = 0
        discarded = 0
        for raw_listing in raw_listings:
            # Only the count is carried outside this loop, so a failure
            # record names how far the pass got and never a listing.
            mapped = _mapped(raw_listing)
            if mapped is None:
                discarded += 1
                continue
            processed += 1
            identity = getattr(mapped, IDENTITY_COLUMN)
            existing_listing = db.query(Listing).filter(
                getattr(Listing, IDENTITY_COLUMN) == identity
            ).first()
            if existing_listing is None:
                db.add(_new_listing(mapped, moment))
                recorded += 1
            else:
                _refresh_listing(existing_listing, mapped, moment)
                refreshed += 1
        db.commit()
        logger.info(
            "Completed an ingestion pass",
            extra={
                "zip_codes": len(zip_codes),
                "received": len(raw_listings),
                "recorded": recorded,
                "refreshed": refreshed,
                "discarded": discarded,
            },
        )
    except Exception as e:
        db.rollback()
        # Records the failure as the exception's class, module and
        # redacted message together with the pass metadata.
        log_exception(
            logger,
            INGESTION_FAILED_MESSAGE,
            e,
            processed_listings=processed,
        )
    finally:
        db.close()


async def run_listing_updater():
    """Run :func:`update_listings` forever, once per interval.

    Each cycle is awaited and then followed by a sleep of
    :data:`UPDATE_INTERVAL`, so cycles never overlap and the interval is
    measured between the end of one cycle and the start of the next.

    This coroutine does not return: it is meant to be scheduled as a
    background task and cancelled to stop it. Because
    :func:`update_listings` swallows its own errors, a failed cycle is
    followed by the next one after the same interval.
    """
    while True:
        await update_listings()
        await asyncio.sleep(UPDATE_INTERVAL.total_seconds())
