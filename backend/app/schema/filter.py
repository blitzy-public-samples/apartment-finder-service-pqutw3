from pydantic import BaseModel, StrictStr, conlist, constr, validator
from datetime import datetime
from typing import List, Optional

# SEC-05: bounds on what one POST /filters/ can store (CWE-770)
MAX_CRITERIA = 25
MAX_CRITERION_FIELD = 64
MAX_CRITERION_OPERATOR = 16
MAX_CRITERION_VALUE = 256
MAX_FILTER_NAME = 120


def _reject_nul_character(value: str) -> str:
    # SEC-05: the text type refuses a NUL byte at commit (CWE-20)
    if "\x00" in value:
        raise ValueError("must not contain a NUL character")
    return value


class ZipCode(BaseModel):
    code: str

    class Config:
        orm_mode = True

class Criteria(BaseModel):
    # SEC-05: strict strings reject a wrong JSON type; no coercion (CWE-20)
    field: StrictStr
    operator: StrictStr
    value: StrictStr

    # SEC-05: refuses the byte the driver cannot store (CWE-20)
    _reject_nul = validator(
        "field", "operator", "value", allow_reuse=True
    )(_reject_nul_character)

    class Config:
        extra = "forbid"   # SEC-05: rejects unknown keys in nested criteria
        orm_mode = True    # SEC-05: reads the mapped criteria rows on response


# SEC-05: bounded twin of Criteria for the write path
class CriteriaCreate(Criteria):
    field: constr(strict=True, max_length=MAX_CRITERION_FIELD)
    operator: constr(strict=True, max_length=MAX_CRITERION_OPERATOR)
    value: constr(strict=True, max_length=MAX_CRITERION_VALUE)

# SEC-05: writable-field allow-list for POST /filters/
class FilterCreate(BaseModel):
    name: constr(strict=True, max_length=MAX_FILTER_NAME)
    criteria: conlist(CriteriaCreate, max_items=MAX_CRITERIA)

    # SEC-05: refuses the byte the driver cannot store (CWE-20)
    _reject_nul_name = validator(
        "name", allow_reuse=True
    )(_reject_nul_character)

    class Config:
        # SEC-05: rejects unknown keys; closes the CWE-915 vector
        extra = "forbid"

class Filter(BaseModel):
    # SEC-05: matches the INTEGER key and foreign key
    id: int
    user_id: int
    name: str
    created_at: datetime
    last_used: Optional[datetime]
    zip_codes: List[ZipCode]
    criteria: List[Criteria]

    class Config:
        orm_mode = True
