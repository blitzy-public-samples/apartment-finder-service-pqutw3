from pydantic import BaseModel, StrictStr
from datetime import datetime
from typing import List, Optional

class ZipCode(BaseModel):
    code: str

    class Config:
        orm_mode = True

class Criteria(BaseModel):
    # SEC-05: strict types; a non-string nested value is refused, never
    # coerced into the mapped varchar columns (CWE-20)
    field: StrictStr
    operator: StrictStr
    value: StrictStr

    class Config:
        extra = "forbid"   # SEC-05: rejects unknown keys in nested criteria
        orm_mode = True

# SEC-05: writable-field allow-list for POST /filters/
class FilterCreate(BaseModel):
    name: StrictStr
    criteria: List[Criteria]

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