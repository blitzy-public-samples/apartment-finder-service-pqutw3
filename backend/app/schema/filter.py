from pydantic import BaseModel, StrictStr
from datetime import datetime
from typing import List, Optional

class ZipCode(BaseModel):
    code: str

    class Config:
        orm_mode = True

class Criteria(BaseModel):
    field: str
    operator: str
    value: str

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