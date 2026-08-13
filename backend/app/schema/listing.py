import math

from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import Optional
from urllib.parse import urlsplit

#: URL schemes a listing address may use. Any other scheme, plaintext
#: ``http`` included, and any value that is not an absolute URL, is
#: refused.
LISTING_URL_SCHEMES = ("https",)

#: Registrable domains a listing address may address. A host equal to one
#: of these, or a subdomain of one of them, is accepted; every other host
#: is refused. The comparison is made on a parsed host at a dot boundary,
#: so a host that merely ends with one of these names does not match.
LISTING_URL_DOMAINS = ("zillow.com",)

#: Characters refused in every text field. A text column stores no NUL.
FORBIDDEN_TEXT_CHARACTERS = ("\x00",)

#: Names of the fields carrying a measurement stored in a floating-point
#: column. Each refuses a value outside the finite range of that type.
MEASUREMENT_FIELDS = ("rent", "broker_fee", "square_footage")

#: Names of the fields carrying a count stored in an integer column.
COUNT_FIELDS = ("bedrooms", "bathrooms")

#: Largest value an integer column holds. Each field in
#: :data:`COUNT_FIELDS` refuses a value above it.
MAX_COUNT = 2 ** 31 - 1

#: Every field carrying a number, measurements and counts together. A
#: boolean is refused on each of them.
NUMERIC_FIELDS = MEASUREMENT_FIELDS + COUNT_FIELDS

#: Refusal reported for a value that is not a finite number, which no
#: JSON response can carry.
NON_FINITE_DETAIL = "value must be a finite number"

#: Refusal reported for a value whose magnitude no floating-point column
#: can represent.
UNREPRESENTABLE_DETAIL = "value is too large to be measured"

#: Refusal reported for a boolean supplied where a number is declared. A
#: boolean is a numeric type in Python, so a declared numeric field
#: converts ``true`` to 1 and ``false`` to 0 unless it is refused first.
BOOLEAN_DETAIL = "value must be a number, not a boolean"


def _numeric_value(value):
    """Returns ``value`` when it is not a boolean, else refuses it."""
    if isinstance(value, bool):
        raise ValueError(BOOLEAN_DETAIL)
    return value


def _allowlisted_host(hostname):
    """Reports whether ``hostname`` falls under an allowlisted domain.

    A host matches when it equals a domain in
    :data:`LISTING_URL_DOMAINS` or ends with that domain preceded by a
    dot, so ``zillow.com`` and ``www.zillow.com`` match while
    ``notzillow.com`` and ``zillow.com.example.net`` do not. A trailing
    root label and letter case are both normalised away first.
    """
    candidate = hostname.strip().rstrip(".").lower()
    for domain in LISTING_URL_DOMAINS:
        if candidate == domain or candidate.endswith("." + domain):
            return True
    return False


def _finite_measurement(value):
    """Returns ``value`` when it is a finite number, else refuses it.

    A boolean is refused. A value that no numeric conversion accepts is
    returned unchanged, so the declared field type reports it. A value
    that converts to an infinity, to a NaN, or that overflows the
    conversion is refused.
    """
    if value is None:
        return value
    _numeric_value(value)
    try:
        measured = float(value)
    except OverflowError:
        raise ValueError(UNREPRESENTABLE_DETAIL) from None
    except (TypeError, ValueError):
        return value
    if not math.isfinite(measured):
        raise ValueError(NON_FINITE_DETAIL)
    return value


class Listing(BaseModel):
    """Response contract for a listing record read from a ``listings`` row.

    Field optionality mirrors column nullability: ``id``, ``created_at``,
    ``updated_at`` and ``rent`` are non-null columns and stay required;
    every other column is nullable and projects as ``None``.

    ``rent``, ``broker_fee`` and ``square_footage`` must each be a finite
    number, and none of those three nor ``bedrooms`` or ``bathrooms``
    accepts a boolean. A stored row carrying a value this contract cannot
    represent fails to project.
    """

    id: int
    created_at: datetime
    updated_at: datetime
    rent: float
    broker_fee: Optional[float] = None
    square_footage: Optional[float] = None
    bedrooms: Optional[int] = None
    bathrooms: Optional[int] = None
    available_date: Optional[datetime] = None
    street_address: Optional[str] = None
    zillow_url: Optional[str] = None

    class Config:
        orm_mode = True

    @validator(*MEASUREMENT_FIELDS, pre=True)
    def _require_finite_measurement(cls, value):
        """Refuses a stored measurement a JSON response cannot carry."""
        return _finite_measurement(value)

    @validator(*COUNT_FIELDS, pre=True)
    def _require_numeric_count(cls, value):
        """Refuses a boolean where a count is declared."""
        return _numeric_value(value)


class ListingCreate(BaseModel):
    """Request contract for listing creation.

    The declared fields are the complete allowlist of ``listings`` columns a
    client may supply. Unknown fields are rejected. ``id``, ``created_at`` and
    ``updated_at`` are server-assigned and absent from this contract.

    Each text field is bounded in length, published with the field below,
    and refuses a NUL character. ``zillow_url`` must be an absolute
    ``https`` address on ``zillow.com`` or a subdomain of it, and must
    carry no user information. A refusal names the field and never
    repeats the value.

    ``rent``, ``broker_fee`` and ``square_footage`` must each be a finite
    number the stored column can represent: an infinity, a NaN or a
    magnitude beyond that range is refused. ``bedrooms`` and
    ``bathrooms`` are bounded at the maximum published with each of them,
    and none of these five fields accepts a boolean.
    """

    rent: float = Field(..., ge=0)
    broker_fee: Optional[float] = Field(None, ge=0)
    square_footage: Optional[float] = Field(None, ge=0)
    bedrooms: Optional[int] = Field(None, ge=0, le=MAX_COUNT)
    bathrooms: Optional[int] = Field(None, ge=0, le=MAX_COUNT)
    available_date: Optional[datetime] = None
    street_address: Optional[str] = Field(None, max_length=255)
    zillow_url: Optional[str] = Field(None, max_length=2048)

    class Config:
        extra = "forbid"

    @validator(*MEASUREMENT_FIELDS, pre=True)
    def _require_finite_measurement(cls, value):
        """Refuses a measurement outside the finite range of its column.

        Runs before the declared type is applied, so a whole number too
        large to convert to that type is refused.
        """
        return _finite_measurement(value)

    @validator(*COUNT_FIELDS, pre=True)
    def _require_numeric_count(cls, value):
        """Refuses a boolean where a count is declared."""
        return _numeric_value(value)

    @validator("street_address", "zillow_url")
    def _reject_forbidden_characters(cls, value):
        """Refuses a text value a text column cannot store."""
        if value is None:
            return value
        for character in FORBIDDEN_TEXT_CHARACTERS:
            if character in value:
                raise ValueError(
                    "value carries a character a text column cannot store"
                )
        return value

    @validator("zillow_url")
    def _require_absolute_web_url(cls, value):
        """Refuses an address that is not a provider listing URL.

        The value must parse as an absolute URL, use a scheme in
        :data:`LISTING_URL_SCHEMES`, carry no user information, and
        address a host that falls under :data:`LISTING_URL_DOMAINS`. The
        host is taken from the parsed URL, so an address carrying an
        allowlisted name anywhere other than in its host is refused.
        """
        if value is None:
            return value
        try:
            parts = urlsplit(value)
        except ValueError:
            raise ValueError("value is not a parsable URL") from None
        if parts.scheme.lower() not in LISTING_URL_SCHEMES:
            raise ValueError(
                "scheme must be one of " + ", ".join(LISTING_URL_SCHEMES)
            )
        if not parts.hostname:
            raise ValueError("value carries no host")
        if parts.username or parts.password:
            raise ValueError("value carries user information")
        if not _allowlisted_host(parts.hostname):
            raise ValueError(
                "host must be, or be a subdomain of, one of "
                + ", ".join(LISTING_URL_DOMAINS)
            )
        return value
