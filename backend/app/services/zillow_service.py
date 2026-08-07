import httpx
from typing import List, Dict
from backend.app.core.config import settings
from backend.app.core.logging import get_logger
from backend.app.schema.listing import Listing

ZILLOW_API_URL = settings.ZILLOW_API_URL
ZILLOW_API_KEY = settings.ZILLOW_API_KEY

logger = get_logger(__name__)


def fetch_listings(zip_codes: List[str], filters: Dict) -> List[Dict]:
    """
    Fetches apartment listings from Zillow API
    """
    params = {
        "zip_codes": ",".join(zip_codes),
        **filters
    }
    headers = {"X-API-Key": ZILLOW_API_KEY}

    try:
        response = httpx.get(
            ZILLOW_API_URL,
            params=params,
            headers=headers,
            timeout=settings.HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return response.json().get("listings", [])
    except httpx.HTTPError:
        logger.exception("Failed to fetch listings from Zillow API")
        return []


def process_listing(raw_listing: Dict) -> Listing:
    """
    Processes raw listing data into Listing schema
    """
    return Listing(
        id=raw_listing.get("id"),
        address=raw_listing.get("address"),
        price=float(raw_listing.get("price", 0)),
        bedrooms=int(raw_listing.get("bedrooms", 0)),
        bathrooms=float(raw_listing.get("bathrooms", 0)),
        square_feet=int(raw_listing.get("square_feet", 0)),
        description=raw_listing.get("description", ""),
        image_url=raw_listing.get("image_url"),
        listing_url=raw_listing.get("listing_url")
    )
