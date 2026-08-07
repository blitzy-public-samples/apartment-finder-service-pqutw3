from pydantic import BaseModel, conlist, constr, validator
from datetime import datetime
from typing import List, Optional

# Maximum number of postal codes accepted in one request.
MAX_ZIP_CODES = 5

# Number of predicates accepted in one request.
MIN_CRITERIA = 1
MAX_CRITERIA = 1

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
