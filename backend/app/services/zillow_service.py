import requests
from typing import Dict, List, Optional
from backend.app.core.config import settings
from backend.app.schema.listing import ListingCreate

ZILLOW_API_URL = settings.ZILLOW_API_URL
ZILLOW_API_KEY = settings.ZILLOW_API_KEY

# Bounded outbound wait: (connect, read) seconds. A provider that accepts the
# connection and never answers cannot hold the ingestion worker open
# (CWE-1088, CWE-400). DL-438
CONNECT_TIMEOUT_SECONDS = 5
READ_TIMEOUT_SECONDS = 10
REQUEST_TIMEOUT = (CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS)

# The provider keys each writable Listing column is read from, in priority
# order. Every target name is a field of ListingCreate, which is the single
# writable-field allow-list for the listings table. DL-436
PROVIDER_FIELD_SOURCES = {
    "rent": ("rent", "price", "monthly_rent"),
    "broker_fee": ("broker_fee", "brokerFee"),
    "square_footage": ("square_footage", "square_feet", "livingArea"),
    "bedrooms": ("bedrooms", "beds"),
    "bathrooms": ("bathrooms", "baths"),
    "available_date": ("available_date", "availableDate", "date_available"),
    "street_address": ("street_address", "streetAddress", "address"),
    "zillow_url": ("zillow_url", "listing_url", "detailUrl", "url"),
}

# Columns declared NOT NULL at models.py:25 among the writable set, so a
# provider record missing one cannot be mapped
REQUIRED_PROVIDER_FIELDS = ("rent",)


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
        response = requests.get(
            ZILLOW_API_URL, params=params, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return response.json().get("listings", [])
    except requests.Timeout as timeout:
        # Bounded wait elapsed: the attempt is abandoned rather than held
        # open (CWE-1088). DL-438
        print(f"Timed out fetching listings from Zillow API: {str(timeout)}")
        return []
    except requests.RequestException as e:
        # TODO: Implement proper error handling and logging
        print(f"Error fetching listings from Zillow API: {str(e)}")
        return []


def _first_present(raw_listing: Dict, provider_keys) -> Optional[object]:
    """Return the first non-null value the provider supplies for one column."""
    for key in provider_keys:
        if key in raw_listing and raw_listing[key] is not None:
            return raw_listing[key]
    return None


def _as_number(value):
    """Return a JSON number for a provider value, or None when absent."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        # Provider numerics arrive quoted and formatted; the currency and
        # grouping characters are removed before conversion
        cleaned = value.replace(",", "").replace("$", "").strip()
        if not cleaned:
            return None
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


def _as_whole_number(value) -> Optional[int]:
    """Return a whole JSON number for a provider value, or None."""
    number = _as_number(value)
    if number is None:
        return None
    try:
        rounded = int(round(number))
    except (OverflowError, ValueError):
        return None
    return rounded


def _as_text(value) -> Optional[str]:
    """Return a non-empty string for a provider value, or None."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


# SEC-05: every mapped value passes the writable-field allow-list, so a
# provider key outside it is rejected rather than absorbed (CWE-915). DL-436
_PROVIDER_VALUE_READERS = {
    "rent": _as_number,
    "broker_fee": _as_number,
    "square_footage": _as_number,
    "bedrooms": _as_whole_number,
    "bathrooms": _as_whole_number,
    "available_date": _as_text,
    "street_address": _as_text,
    "zillow_url": _as_text,
}


def process_listing(raw_listing: Dict) -> ListingCreate:
    """
    Processes raw listing data into Listing schema
    """
    mapped = {}
    for field, provider_keys in PROVIDER_FIELD_SOURCES.items():
        value = _PROVIDER_VALUE_READERS[field](
            _first_present(raw_listing, provider_keys)
        )
        if value is not None:
            mapped[field] = value

    missing = [
        field for field in REQUIRED_PROVIDER_FIELDS if field not in mapped
    ]
    if missing:
        raise ValueError(
            "provider record supplies no value for: " + ", ".join(missing)
        )

    return ListingCreate(**mapped)
