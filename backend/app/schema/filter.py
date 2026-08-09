from pydantic import BaseModel, conlist, constr, validator
from datetime import datetime
from typing import List, Optional

# Maximum number of postal codes accepted in one request. Creation is
# the only path that writes zip_codes rows, so this is also the number a
# stored filter carries and the number the Filter response projects.
MAX_ZIP_CODES = 5

# Bounds on the number of predicates accepted in one request. Creation is
# the only path that writes criteria rows, so the maximum is also the most
# a stored filter carries and the most the Filter response projects.
MIN_CRITERIA = 1
MAX_CRITERIA = 5

# Largest number of child rows one Filter response can project, which
# bounds the rows a page of filters loads at MAX_PAGE_SIZE times this.
MAX_CHILDREN_PER_FILTER = MAX_ZIP_CODES + MAX_CRITERIA

# Comparison operators accepted in a predicate. Matching ignores letter
# case and an accepted operator is stored in lower case.
ACCEPTED_CRITERIA_OPERATORS = frozenset(
    {
        "<",
        "<=",
        ">",
        ">=",
        "=",
        "==",
        "!=",
        "lt",
        "lte",
        "gt",
        "gte",
        "eq",
        "ne",
    }
)

# Accepted postal-code shape: five digits, optionally followed by a
# hyphen and a four-digit extension.
_ZIP_CODE_REGEX = r"^\d{5}(?:-\d{4})?$"

# Accepted predicate-field shape: a letter followed by letters, digits
# or underscores.
_CRITERIA_FIELD_REGEX = r"^[A-Za-z][A-Za-z0-9_]*$"

# Characters refused in a text field. A text column stores no NUL, so a
# value carrying one cannot be written and is refused by the contract
# instead of by the driver. This set is held equal to the one
# backend.app.schema.listing declares.
FORBIDDEN_TEXT_CHARACTERS = ("\x00",)

# Refusal reported for a text value a text column cannot store.
UNSTORABLE_TEXT_DETAIL = (
    "value carries a character a text column cannot store"
)


def _storable_text(value):
    """Returns ``value`` when a text column can store it, else refuses it.

    Every character in :data:`FORBIDDEN_TEXT_CHARACTERS` is refused. The
    refusal names neither the character nor the value.
    """
    if value is None:
        return value
    for character in FORBIDDEN_TEXT_CHARACTERS:
        if character in value:
            raise ValueError(UNSTORABLE_TEXT_DETAIL)
    return value


_NameField = constr(strip_whitespace=True, min_length=1, max_length=120)

_ZipCodeField = constr(
    strip_whitespace=True,
    min_length=1,
    max_length=16,
    regex=_ZIP_CODE_REGEX,
)

_CriteriaFieldField = constr(
    strip_whitespace=True,
    min_length=1,
    max_length=64,
    regex=_CRITERIA_FIELD_REGEX,
)

_CriteriaOperatorField = constr(
    strip_whitespace=True,
    min_length=1,
    max_length=32,
)

_CriteriaValueField = constr(
    strip_whitespace=True,
    min_length=1,
    max_length=256,
)


class ZipCode(BaseModel):
    # Projection of a zip_codes row.
    code: str

    class Config:
        orm_mode = True


class Criteria(BaseModel):
    # Projection of a criteria row.
    field: str
    operator: str
    value: str

    class Config:
        orm_mode = True


class Filter(BaseModel):
    id: int
    user_id: int
    name: str
    created_at: datetime
    last_used: Optional[datetime]
    zip_codes: List[ZipCode]
    criteria: List[Criteria]

    class Config:
        orm_mode = True


class ZipCodeCreate(BaseModel):
    """Postal code accepted inside a filter-creation request."""

    code: _ZipCodeField

    class Config:
        # Rejects any field outside the allowlist above.
        extra = "forbid"


class CriteriaCreate(BaseModel):
    """Predicate accepted inside a filter-creation request."""

    field: _CriteriaFieldField
    operator: _CriteriaOperatorField
    value: _CriteriaValueField

    class Config:
        # Rejects any field outside the allowlist above.
        extra = "forbid"

    @validator("operator")
    def validate_operator(cls, value: str) -> str:
        """Require one of the accepted comparison operators."""
        candidate = value.lower()
        if candidate not in ACCEPTED_CRITERIA_OPERATORS:
            accepted = ", ".join(sorted(ACCEPTED_CRITERIA_OPERATORS))
            raise ValueError(f"operator must be one of: {accepted}")
        return candidate

    @validator("value")
    def validate_value(cls, value: str) -> str:
        """Refuse a text value a text column cannot store."""
        return _storable_text(value)


class FilterCreate(BaseModel):
    # Allowlist of client-settable fields. This contract carries no id,
    # user_id, created_at or last_used.
    name: _NameField
    zip_codes: conlist(ZipCodeCreate, max_items=MAX_ZIP_CODES) = []
    criteria: conlist(
        CriteriaCreate, min_items=MIN_CRITERIA, max_items=MAX_CRITERIA
    )

    class Config:
        extra = "forbid"

    @validator("name")
    def validate_name(cls, value: str) -> str:
        """Refuse a text value a text column cannot store."""
        return _storable_text(value)
