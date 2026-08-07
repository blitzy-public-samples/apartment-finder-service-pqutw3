import asyncio
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from backend.app.db.database import SessionLocal
from backend.app.services.zillow_service import fetch_listings, process_listing
from backend.app.db.models import Listing
from backend.app.core.logging import get_logger

UPDATE_INTERVAL = timedelta(hours=1)

logger = get_logger(__name__)

@asyncio.coroutine
async def update_listings():
    db: Session = SessionLocal()
    try:
        new_listings = await fetch_listings()
        for listing_data in new_listings:
            processed_listing = await process_listing(listing_data)
            existing_listing = db.query(Listing).filter(Listing.zillow_id == processed_listing.zillow_id).first()
            if existing_listing:
                for key, value in processed_listing.__dict__.items():
                    setattr(existing_listing, key, value)
            else:
                db.add(processed_listing)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error("An error occurred while updating listings", exc_info=e)
    finally:
        db.close()

async def run_listing_updater():
    while True:
        await update_listings()
        await asyncio.sleep(UPDATE_INTERVAL.total_seconds())