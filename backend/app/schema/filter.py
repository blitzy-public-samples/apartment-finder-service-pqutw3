from pydantic import BaseModel, conlist, constr
from datetime import datetime
from typing import List, Optional

class ZipCode(BaseModel):
    # Maximum length of a postal code accepted or returned.
    code: constr(max_length=16)

    class Config:
        # Permits population from a SQLAlchemy row via Filter.from_orm.
        orm_mode = True

class Criteria(BaseModel):
    # Maximum length of each predicate component accepted or returned.
    field: constr(max_length=64)
    operator: constr(max_length=32)
    value: constr(max_length=256)

    class Config:
        # Permits population from a SQLAlchemy row via Filter.from_orm.
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
        # Permits population from a SQLAlchemy row via Filter.from_orm.
        orm_mode = True

class FilterCreate(BaseModel):
    # Allowlist of client-settable fields. This contract carries no id,
    # user_id, created_at or last_used.
    name: constr(min_length=1, max_length=120)
    # Maximum number of postal codes accepted in one request.
    zip_codes: conlist(ZipCode, max_items=50) = []
    # Minimum and maximum number of predicates accepted in one request.
    criteria: conlist(Criteria, min_items=1, max_items=25)

    class Config:
        # Rejects any field outside the allowlist above.
        extra = "forbid"
