import requests
from typing import List, Dict
from backend.app.core.config import settings
from backend.app.schema.listing import Listing

ZILLOW_API_URL = settings.ZILLOW_API_URL
ZILLOW_API_KEY = settings.ZILLOW_API_KEY

# HUMAN ASSISTANCE NEEDED
# The fetch_listings function needs review and potential adjustments for production readiness
def fetch_listings(zip_codes: List[str], filters: Dict) -> List[Dict]:
    """
    Fetches apartment listings from Zillow API
    """
    params = {
        "api_key": ZILLOW_API_KEY,
        "zip_codes": ",".join(zip_codes),
        **filters
    }
    
    try:
        response = requests.get(ZILLOW_API_URL, params=params)
        response.raise_for_status()
        return response.json().get("listings", [])
    except requests.RequestException as e:
        # TODO: Implement proper error handling and logging
        print(f"Error fetching listings from Zillow API: {str(e)}")
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