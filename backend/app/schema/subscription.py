from pydantic import BaseModel
from datetime import datetime
from typing import Optional


# SEC-05: writable-field allow-list for POST /subscriptions/
class SubscriptionCreate(BaseModel):
    plan_id: str
    payment_method: str
    amount: float
    start_date: datetime
    end_date: Optional[datetime] = None

    class Config:
        # SEC-05: rejects unknown keys; closes the CWE-915 vector
        extra = "forbid"


class Subscription(BaseModel):
    id: int
    user_id: int
    start_date: datetime
    end_date: Optional[datetime]
    status: str

    class Config:
        orm_mode = True
