import asyncio
from datetime import datetime, timedelta
from pydantic import ValidationError
from sqlalchemy.orm import Session
from backend.app.db.database import SessionLocal
from backend.app.services.zillow_service import fetch_listings, process_listing
from backend.app.db.models import Listing, ZipCode

UPDATE_INTERVAL = timedelta(hours=1)

# The one column carrying the provider's own reference for a listing, so the
# column an ingested record is matched on. models.py declares no separate
# provider identifier and this work adds no column. DL-437
LISTING_IDENTITY_FIELD = "zillow_url"


def _tracked_zip_codes(db: Session):
    """Return the distinct zip codes the stored filters ask to be watched."""
    return [
        code
        for (code,) in db.query(ZipCode.code).distinct().all()
        if code
    ]


def _existing_listing(db: Session, identity):
    """Return the stored row one provider reference already occupies."""
    if not identity:
        return None
    return (
        db.query(Listing)
        .filter(Listing.zillow_url == identity)
        .first()
    )


async def update_listings():
    db: Session = SessionLocal()
    try:
        zip_codes = _tracked_zip_codes(db)
        if not zip_codes:
            # No stored filter names a zip code, so there is nothing to fetch
            return
        # fetch_listings and process_listing are synchronous; both are called
        # without await. DL-437
        new_listings = fetch_listings(zip_codes, {})
        stamped_at = datetime.utcnow()
        for listing_data in new_listings:
            try:
                processed_listing = process_listing(listing_data)
            except (ValidationError, ValueError) as rejected:
                # One unusable provider record is skipped; the remaining
                # records in the batch are still ingested
                print(
                    "Skipping an unusable Zillow listing: "
                    f"{type(rejected).__name__}"
                )
                continue
            # SEC-05: only the writable fields the provider actually supplied,
            # read back through the allow-list ListingCreate declares
            values = processed_listing.dict(exclude_unset=True)
            existing_listing = _existing_listing(
                db, values.get(LISTING_IDENTITY_FIELD)
            )
            if existing_listing:
                for key, value in values.items():
                    setattr(existing_listing, key, value)
                existing_listing.updated_at = stamped_at
            else:
                db.add(
                    Listing(
                        created_at=stamped_at,
                        updated_at=stamped_at,
                        **values
                    )
                )
        db.commit()
    except Exception as e:
        db.rollback()
        # Log the error here
        print(f"An error occurred while updating listings: {str(e)}")
    finally:
        db.close()


async def run_listing_updater():
    while True:
        await update_listings()
        await asyncio.sleep(UPDATE_INTERVAL.total_seconds())
