from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.db.database import get_db
from backend.app.schema.subscription import SubscriptionCreate, Subscription
from backend.app.db.models import Subscription as SubscriptionModel, User
from backend.app.core.security import get_current_user
from backend.app.services.paypal_service import process_payment

router = APIRouter()

# HUMAN ASSISTANCE NEEDED
# The confidence level for this function is below 0.8. Please review and adjust as necessary.
@router.post('/')
async def create_subscription(
    subscription: SubscriptionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Subscription:
    # Validate subscription data
    if not subscription.plan_id or not subscription.payment_method:
        raise HTTPException(status_code=400, detail="Invalid subscription data")

    # Process payment through PayPal
    payment_successful = await process_payment(subscription.payment_method, subscription.amount)
    if not payment_successful:
        raise HTTPException(status_code=400, detail="Payment processing failed")

    # Create new subscription in database
    new_subscription = SubscriptionModel(
        user_id=current_user.id,
        plan_id=subscription.plan_id,
        start_date=subscription.start_date,
        end_date=subscription.end_date
    )
    db.add(new_subscription)
    db.commit()
    db.refresh(new_subscription)

    # Associate subscription with current user
    current_user.subscription_id = new_subscription.id
    db.commit()

    # Return created subscription
    return Subscription.from_orm(new_subscription)

@router.get('/')
async def get_user_subscription(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Subscription:
    # Query database for user's active subscription
    subscription = db.query(SubscriptionModel).filter(
        SubscriptionModel.user_id == current_user.id,
        SubscriptionModel.end_date > datetime.utcnow()
    ).first()

    # Return subscription if found, else return None
    return Subscription.from_orm(subscription) if subscription else None