import httpx
from typing import List, Dict
from backend.app.core.config import (
    is_allowed_listing_provider_url,
    settings,
)
from backend.app.core.logging import get_logger
from backend.app.schema.listing import Listing

ZILLOW_API_URL = settings.ZILLOW_API_URL
ZILLOW_API_KEY = settings.ZILLOW_API_KEY

logger = get_logger(__name__)

# Failures translated into an empty result. httpx.InvalidURL,
# httpx.CookieConflict and httpx.StreamError sit outside the
# httpx.HTTPError hierarchy, and ValueError covers the JSON decode
# error raised by Response.json().
_PROVIDER_ERRORS = (
    httpx.HTTPError,
    httpx.InvalidURL,
    httpx.CookieConflict,
    httpx.StreamError,
    ValueError,
)


def fetch_listings(zip_codes: List[str], filters: Dict) -> List[Dict]:
    """
    Fetches apartment listings from Zillow API

    Returns the provider's listing objects, or an empty list when the
    request fails, when the response body is not decodable JSON, or when
    the decoded body does not carry a list of listing objects. Every
    failure is logged once and none propagates to the caller. A transient
    failure is not retried inside this call; the caller's schedule is the
    retry interval.
    """
    if not is_allowed_listing_provider_url(ZILLOW_API_URL):
        logger.error(
            "Refusing to call the listing provider because the "
            "configured endpoint is outside the provider allowlist"
        )
        return []

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
        payload = response.json()
    except ValueError:
        logger.exception("Zillow API returned an undecodable body")
        return []
    except _PROVIDER_ERRORS:
        logger.exception("Failed to fetch listings from Zillow API")
        return []

    if not isinstance(payload, dict):
        logger.error(
            "Zillow API response body was not an object",
            extra={"body_type": type(payload).__name__},
        )
        return []

    listings = payload.get("listings", [])
    if not isinstance(listings, list):
        logger.error(
            "Zillow API listings field was not a list",
            extra={"listings_type": type(listings).__name__},
        )
        return []

    accepted = [entry for entry in listings if isinstance(entry, dict)]
    if len(accepted) != len(listings):
        logger.error(
            "Discarded Zillow API listings that were not objects",
            extra={
                "received": len(listings),
                "discarded": len(listings) - len(accepted),
            },
        )
    return accepted


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
