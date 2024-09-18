from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class User(BaseModel):
    id: str
    email: str
    hashed_password: str
    created_at: datetime
    last_login: Optional[datetime]