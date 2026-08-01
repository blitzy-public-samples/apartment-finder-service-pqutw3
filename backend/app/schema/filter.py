from pydantic import BaseModel, StrictStr, validator
from datetime import datetime
from typing import List, Optional


def _reject_nul_character(value: str) -> str:
    # SEC-05: a NUL byte is refused by the PostgreSQL text type and aborts the
    # transaction at commit (filters.py:39)
    if "\x00" in value:
        raise ValueError("must not contain a NUL character")
    return value


class ZipCode(BaseModel):
    code: str

    class Config:
        orm_mode = True

class Criteria(BaseModel):
    # SEC-05: strict strings reject a wrong JSON type instead of coercing it
    field: StrictStr
    operator: StrictStr
    value: StrictStr

    # SEC-05: refuses the byte the driver cannot store; an authenticated
    # caller can no longer force a 500 out of db.commit() (CWE-20)
    _reject_nul = validator(
        "field", "operator", "value", allow_reuse=True
    )(_reject_nul_character)

    class Config:
        extra = "forbid"   # SEC-05: rejects unknown keys in nested criteria
        orm_mode = True    # SEC-05: reads the mapped criteria rows on response

# SEC-05: writable-field allow-list for POST /filters/
class FilterCreate(BaseModel):
    name: StrictStr
    criteria: List[Criteria]

    # SEC-05: refuses the byte the driver cannot store; an authenticated
    # caller can no longer force a 500 out of db.commit() (CWE-20)
    _reject_nul_name = validator(
        "name", allow_reuse=True
    )(_reject_nul_character)

    class Config:
        # SEC-05: rejects unknown keys; closes the CWE-915 vector
        extra = "forbid"

class Filter(BaseModel):
    id: str
    user_id: str
    name: str
    created_at: datetime
    last_used: Optional[datetime]
    zip_codes: List[ZipCode]
    criteria: List[Criteria]

    class Config:
        orm_mode = True