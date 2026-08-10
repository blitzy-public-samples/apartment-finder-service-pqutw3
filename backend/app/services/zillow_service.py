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
    current_request_id,
    get_logger,
    outbound_trace_headers,
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


class ListingProviderError(RuntimeError):
    """Raised when one provider read produced no usable response.

    ``reason`` is the stable identifier of what failed, drawn from the
    ``REASON_*`` constants in this module, so a caller and a log query
    both select the cause by field rather than by matching prose. The
    message names the cause and never a provider value, a search value or
    the request target.

    This is distinct from a provider that answered correctly and reported
    no listings: that is an empty result, not a failure, and
    :func:`fetch_listings` returns an empty list for it.
    """

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


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

# Failures raised as a ListingProviderError. httpx.InvalidURL,
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

REASON_RESPONSE_TOO_LARGE = "response_body_too_large"

#: Rejection reason: the configured endpoint is outside the provider
#: allowlist, so no request may be issued to it.
REASON_ENDPOINT_NOT_ALLOWED = "provider_endpoint_not_allowed"

#: Rejection reason: the request could not be completed, or the provider
#: answered with a status it refuses with.
REASON_REQUEST_FAILED = "provider_request_failed"

#: Rejection reason: the body was not decodable as UTF-8 JSON.
REASON_BODY_NOT_DECODABLE = "response_body_not_decodable"

#: Rejection reason: the decoded body was not a JSON object, so the
#: declared collection key could not be read from it.
REASON_BODY_NOT_OBJECT = "response_body_not_object"

#: Rejection reason: the declared collection key did not carry a list.
REASON_COLLECTION_NOT_LIST = "response_collection_not_list"

#: Truncation reason: the body carried more listing objects than
#: :data:`MAX_PROVIDER_LISTINGS`.
REASON_TOO_MANY_LISTINGS = "listing_count_past_cap"

REASON_CHUNK_TOO_LARGE = "zip_code_chunk_past_cap"

REQUEST_CHUNK_REFUSED_MESSAGE = (
    "Refused to call the listing provider with more postal codes than "
    "one request accepts"
)
REASON_LISTING_NOT_OBJECT = "listing_not_object"

_GET_METHOD = "GET"

#: Request header the provider credential travels in, so it appears in no
#: URL, no query string, no proxy log and no referrer.
API_KEY_HEADER = "X-API-Key"

#: Request header the bound request identifier is sent to the provider in.
#: A provider-side record and the local record for the same call then
#: carry the same identifier.
REQUEST_ID_HEADER = "X-Request-ID"

#: Query parameter one request names its postal codes in, comma joined.
ZIP_CODES_PARAMETER = "zip_codes"

#: Key the response object carries its listing collection under.
LISTINGS_COLLECTION_KEY = "listings"

#: Every element of the wire contract this adapter reads and writes,
#: gathered so that the whole of it is enumerable from one object.
#:
#: This is the contract as *declared here*. It has not been verified
#: against a listing provider, and the register at
#: ``docs/security/RESIDUAL_RISK.md`` carries that as an open item.
#: Re-pointing this adapter at a provider whose contract is known means
#: changing these five entries and :data:`PROVIDER_FIELD_SOURCES`, and
#: nothing else in this module.
DECLARED_PROVIDER_CONTRACT: Mapping[str, Any] = MappingProxyType(
    {
        "method": _GET_METHOD,
        "credential_header": API_KEY_HEADER,
        "zip_codes_parameter": ZIP_CODES_PARAMETER,
        "listings_collection_key": LISTINGS_COLLECTION_KEY,
        "record_fields": PROVIDER_FIELD_SOURCES,
    }
)


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


def _refuse(
    message: str, reason: str, **fields: Any
) -> ListingProviderError:
    """Records a provider read that produced nothing, and returns the
    error to raise for it.

    The record carries ``reason`` and ``fields``, so a query selects the
    cause by field rather than by matching prose. Neither the record nor
    the returned error carries a provider value, a search value or the
    request target.
    """
    logger.error(message, extra=dict(fields, reason=reason))
    return ListingProviderError(message, reason)


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
    """Fetch one bounded postal-code chunk of provider listings.

    ``zip_codes`` is one chunk, not a whole corpus: a list longer than
    ``settings.INGESTION_ZIP_CODE_CHUNK`` is refused before any request.
    Returns at most :data:`MAX_PROVIDER_LISTINGS` provider objects; an
    empty list is a result rather than a failure.

    Raises :class:`ListingProviderError`, carrying the ``reason`` its log
    record carries, when the read produced no response this adapter can
    use: an endpoint outside the allowlist, a chunk past the cap, a failed
    or refused request, an oversized body, or a body that does not satisfy
    :data:`DECLARED_PROVIDER_CONTRACT`.
    """
    if not is_allowed_listing_provider_url(ZILLOW_API_URL):
        raise _refuse(
            "Refusing to call the listing provider because the "
            "configured endpoint is outside the provider allowlist",
            REASON_ENDPOINT_NOT_ALLOWED,
        )

    chunk_ceiling = int(settings.INGESTION_ZIP_CODE_CHUNK)
    if len(zip_codes) > chunk_ceiling:
        raise _refuse(
            REQUEST_CHUNK_REFUSED_MESSAGE,
            REASON_CHUNK_TOO_LARGE,
            setting="INGESTION_ZIP_CODE_CHUNK",
            zip_codes=len(zip_codes),
            max_zip_codes=chunk_ceiling,
        )

    params = {
        ZIP_CODES_PARAMETER: ",".join(zip_codes),
        **filters
    }
    headers = {API_KEY_HEADER: ZILLOW_API_KEY}
    correlation = current_request_id()
    if correlation:
        headers[REQUEST_ID_HEADER] = correlation
    headers.update(outbound_trace_headers())

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
            # _bounded_body has already recorded the size it refused.
            raise ListingProviderError(
                "Refused a Zillow API response body past the accepted "
                "size",
                REASON_RESPONSE_TOO_LARGE,
            )
        payload = json.loads(body.decode("utf-8"))
    except ValueError as error:
        raise _refuse(
            "Zillow API returned an undecodable body",
            REASON_BODY_NOT_DECODABLE,
            **_provider_failure_fields(error)
        ) from None
    except _PROVIDER_ERRORS as error:
        raise _refuse(
            "Failed to fetch listings from Zillow API",
            REASON_REQUEST_FAILED,
            **_provider_failure_fields(error)
        ) from None

    if not isinstance(payload, dict):
        raise _refuse(
            "Zillow API response body was not an object",
            REASON_BODY_NOT_OBJECT,
            body_type=type(payload).__name__,
        )

    # An absent key is a shape the declared contract does not describe,
    # so it is reported here rather than defaulted to an empty list: a
    # provider reporting no listings sends the key carrying no entries.
    listings = payload.get(LISTINGS_COLLECTION_KEY)
    if not isinstance(listings, list):
        raise _refuse(
            "Zillow API listings field was not a list",
            REASON_COLLECTION_NOT_LIST,
            listings_key=LISTINGS_COLLECTION_KEY,
            listings_type=type(listings).__name__,
        )

    accepted = [entry for entry in listings if isinstance(entry, dict)]
    if len(accepted) != len(listings):
        logger.warning(
            "Discarded Zillow API listings that were not objects",
            extra={
                "reason": REASON_LISTING_NOT_OBJECT,
                "received": len(listings),
                "discarded": len(listings) - len(accepted),
            },
        )
    if len(accepted) > MAX_PROVIDER_LISTINGS:
        logger.warning(
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
