import json
import httpx
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Tuple
from pydantic import ValidationError
from backend.app.core.config import (
    is_allowed_listing_provider_url,
    settings,
)
from backend.app.core.logging import (
    get_logger,
    register_required_secret_values,
)
from backend.app.schema.listing import ListingCreate

ZILLOW_API_URL = settings.ZILLOW_API_URL
ZILLOW_API_KEY = settings.ZILLOW_API_KEY

logger = get_logger(__name__)

# Replaces the provider credential wherever it appears in a record,
# including in text that names no key such as provider error prose.
register_required_secret_values(ZILLOW_API_KEY)


class ListingMappingError(ValueError):
    """Raised when a provider record cannot be mapped to a listing.

    ``fields`` names the contract fields that failed, and a caller reads
    it to report which field a systematic discard comes from. Only names
    declared by :class:`backend.app.schema.listing.ListingCreate` are
    carried, and no provider value ever is.
    """

    def __init__(self, message: str, fields: Tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.fields = tuple(fields)


#: Listing columns a provider record may set, and the provider keys read
#: for each. Keys are tried in order and the first one carrying a value
#: wins. Any key the provider sends that appears in no entry is ignored.
PROVIDER_FIELD_SOURCES: Mapping[str, Tuple[str, ...]] = MappingProxyType(
    {
        "rent": ("rent", "price"),
        "broker_fee": ("broker_fee",),
        "square_footage": ("square_footage", "square_feet"),
        "bedrooms": ("bedrooms",),
        "bathrooms": ("bathrooms",),
        "available_date": ("available_date",),
        "street_address": ("street_address", "address"),
        "zillow_url": ("zillow_url", "listing_url"),
    }
)

# Failures translated into an empty result. httpx.InvalidURL,
# httpx.CookieConflict and httpx.StreamError sit outside the
# httpx.HTTPError hierarchy, and ValueError covers the JSON decode error
# and the decoding error raised while reading the body.
_PROVIDER_ERRORS = (
    httpx.HTTPError,
    httpx.InvalidURL,
    httpx.CookieConflict,
    httpx.StreamError,
    ValueError,
)

#: Largest provider response body read into memory, in bytes.
MAX_PROVIDER_RESPONSE_BYTES = 1048576

#: Most listing objects one provider response contributes.
MAX_PROVIDER_LISTINGS = 1000

#: Response header a provider declares its body length in.
CONTENT_LENGTH_HEADER = "Content-Length"

#: Rejection reason: the body is past :data:`MAX_PROVIDER_RESPONSE_BYTES`.
REASON_RESPONSE_TOO_LARGE = "response_body_too_large"

#: Truncation reason: the body carried more listing objects than
#: :data:`MAX_PROVIDER_LISTINGS`.
REASON_TOO_MANY_LISTINGS = "listing_count_past_cap"

#: Method the provider endpoint is read with.
_GET_METHOD = "GET"


def _client() -> "httpx.Client":
    """Returns the client one provider call is issued on.

    The configured timeout is carried by the client as well as by the
    call, so connecting is bounded alongside reading.
    """
    return httpx.Client(timeout=settings.HTTP_TIMEOUT_SECONDS)


def _declared_length(response: Any) -> Optional[int]:
    """Returns the body length a response declares, or ``None``."""
    try:
        value = response.headers.get(CONTENT_LENGTH_HEADER)
    except Exception:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _refuse_size(measured: int) -> None:
    """Records a body refused for its size, with the cap it passed."""
    logger.error(
        "Refused a Zillow API response body past the accepted size",
        extra={
            "reason": REASON_RESPONSE_TOO_LARGE,
            "response_bytes": measured,
            "max_response_bytes": MAX_PROVIDER_RESPONSE_BYTES,
        },
    )


def _bounded_body(response: Any) -> Optional[bytes]:
    """Returns the response body, or ``None`` when it is past the cap.

    The declared length is read first, so a body announcing itself as
    past :data:`MAX_PROVIDER_RESPONSE_BYTES` is refused before any of it
    is read. The bytes received are then accumulated and the read stops
    as soon as they pass that cap, so a body declaring no length is
    bounded as well.
    """
    declared = _declared_length(response)
    if declared is not None and declared > MAX_PROVIDER_RESPONSE_BYTES:
        _refuse_size(declared)
        return None
    received = 0
    chunks = []
    for chunk in response.iter_bytes():
        received += len(chunk)
        if received > MAX_PROVIDER_RESPONSE_BYTES:
            _refuse_size(received)
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _provider_failure_fields(
    error: BaseException,
) -> Dict[str, Optional[str]]:
    """Returns the class-level description of a provider failure.

    The exception's class and defining module are reported. No message
    text is included: the HTTP library renders the full request target in
    its messages, and that target carries the postal codes and filter
    values the caller searched for.
    """
    return {
        "exception_type": type(error).__name__,
        "exception_module": getattr(type(error), "__module__", None),
    }


def fetch_listings(zip_codes: List[str], filters: Dict) -> List[Dict]:
    """
    Fetches apartment listings from Zillow API

    Returns the provider's listing objects, or an empty list when the
    request fails, when the response body is past
    :data:`MAX_PROVIDER_RESPONSE_BYTES`, when it is not decodable JSON,
    or when the decoded body does not carry a list of listing objects.
    At most :data:`MAX_PROVIDER_LISTINGS` objects are returned.

    Every failure is logged once, as the failing exception's class and
    defining module with no message text and no request target, and none
    propagates to the caller. The call issues one request and performs no
    retry.
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
        with _client() as client:
            with client.stream(
                _GET_METHOD,
                ZILLOW_API_URL,
                params=params,
                headers=headers,
                timeout=settings.HTTP_TIMEOUT_SECONDS,
            ) as response:
                response.raise_for_status()
                body = _bounded_body(response)
        if body is None:
            return []
        payload = json.loads(body.decode("utf-8"))
    except ValueError as error:
        logger.error(
            "Zillow API returned an undecodable body",
            extra=_provider_failure_fields(error),
        )
        return []
    except _PROVIDER_ERRORS as error:
        logger.error(
            "Failed to fetch listings from Zillow API",
            extra=_provider_failure_fields(error),
        )
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
    if len(accepted) > MAX_PROVIDER_LISTINGS:
        logger.error(
            "Truncated the Zillow API listings at the accepted count",
            extra={
                "reason": REASON_TOO_MANY_LISTINGS,
                "received": len(accepted),
                "max_listings": MAX_PROVIDER_LISTINGS,
            },
        )
        accepted = accepted[:MAX_PROVIDER_LISTINGS]
    return accepted


def _first_present(raw_listing: Dict, names: Tuple[str, ...]) -> Any:
    """Returns the value of the first name ``raw_listing`` carries.

    Names are tried in order and a ``None`` value is treated as absent.
    ``None`` is returned when no name carries a value.
    """
    for name in names:
        value = raw_listing.get(name)
        if value is not None:
            return value
    return None


def _failed_fields(error: ValidationError) -> Tuple[str, ...]:
    """Returns the contract fields ``error`` reports, sorted and unique.

    A location part is kept only when it names a field
    :class:`ListingCreate` declares, so the result carries contract names
    and never a provider key or value.
    """
    declared = set(ListingCreate.__fields__)
    names = set()
    for entry in error.errors():
        for part in entry.get("loc", ()):
            if isinstance(part, str) and part in declared:
                names.add(part)
    return tuple(sorted(names))


def process_listing(raw_listing: Dict) -> ListingCreate:
    """Maps one provider record onto the listing creation contract.

    :data:`PROVIDER_FIELD_SOURCES` is the complete allowlist of the
    columns a provider record may set, and each entry names the provider
    keys read for it, in order. A key outside that allowlist is ignored,
    so nothing the provider sends can reach a column the contract does
    not declare. ``id``, ``created_at`` and ``updated_at`` are assigned
    by the caller and are not read here.

    The mapped values are validated by
    :class:`backend.app.schema.listing.ListingCreate`, which bounds each
    one. Raises :class:`ListingMappingError` when ``raw_listing`` is not
    a mapping or when the mapped values fail that validation; the raised
    error names the contract fields that failed under ``fields``.
    """
    if not isinstance(raw_listing, dict):
        raise ListingMappingError(
            "A provider listing must be an object, not "
            + type(raw_listing).__name__
        )
    mapped = dict(
        (column, _first_present(raw_listing, sources))
        for column, sources in PROVIDER_FIELD_SOURCES.items()
    )
    try:
        return ListingCreate(**mapped)
    except ValidationError as error:
        raise ListingMappingError(
            "A provider listing did not satisfy the listing contract: "
            + str(error),
            _failed_fields(error),
        ) from None
