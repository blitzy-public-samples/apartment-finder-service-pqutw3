from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional

class ZipCode(BaseModel):
    code: str

class Criteria(BaseModel):
    field: str
    operator: str
    value: str

# SEC-05: writable-field allow-list for POST /filters/
class FilterCreate(BaseModel):
    name: str
    criteria: List[Criteria]

    class Config:
        extra = "forbid"   # SEC-05: rejects unknown keys; closes the CWE-915 vector

class Filter(BaseModel):
    id: str
    user_id: str
    name: str
    created_at: datetime
    last_used: Optional[datetime]
    zip_codes: List[ZipCode]
    criteria: List[Criteria]