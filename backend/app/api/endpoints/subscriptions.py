from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional

from backend.app.core.authorization import Role, require_role
from backend.app.core.plans import get_plan
from backend.app.db.database import get_db
from backend.app.schema.subscription import SubscriptionCreate, Subscription
from backend.app.db.models import Subscription as SubscriptionModel, User

router = APIRouter()

#: Status stored on a subscription row created here.
ACTIVE_STATUS = "active"


@router.post('/')
async def create_subscription(
    subscription: SubscriptionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(Role.REGISTERED))
) -> Subscription:
    # Validate subscription data
    if not subscription.plan_id:
        raise HTTPException(
            status_code=400, detail="Invalid subscription data"
        )

    # Read the amount, currency and period from the server-owned catalog
    plan = get_plan(subscription.plan_id)

    # Compute the entitlement window from the server clock
    start_date = datetime.now(timezone.utc)
    end_date = start_date + timedelta(days=plan.period_days)

    # Create new subscription in database
    new_subscription = SubscriptionModel(
        user_id=current_user.id,
        plan_id=plan.plan_id,
        amount=plan.amount,
        currency=plan.currency,
        status=ACTIVE_STATUS,
        start_date=start_date,
        end_date=end_date
    )
    db.add(new_subscription)
    db.commit()
    db.refresh(new_subscription)

    # Return created subscription
    return Subscription.from_orm(new_subscription)


@router.get('/')
async def get_user_subscription(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(Role.REGISTERED))
) -> Optional[Subscription]:
    # Query database for user's active subscription
    subscription = db.query(SubscriptionModel).filter(
        SubscriptionModel.user_id == current_user.id,
        SubscriptionModel.end_date > datetime.now(timezone.utc)
    ).first()

    # Return subscription if found, else return None
    return Subscription.from_orm(subscription) if subscription else None
