from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional

class ZipCode(BaseModel):
    code: str

class Criteria(BaseModel):
    field: str
    operator: str
    value: str

class Filter(BaseModel):
    id: str
    user_id: str
    name: str
    created_at: datetime
    last_used: Optional[datetime]
    zip_codes: List[ZipCode]
    criteria: List[Criteria]