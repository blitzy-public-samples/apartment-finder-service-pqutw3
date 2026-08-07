from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.db.database import get_db
from backend.app.schema.filter import FilterCreate, Filter
from backend.app.db.models import (
    Criteria as CriteriaModel,
    Filter as FilterModel,
    User,
)
from backend.app.core.authorization import Role, require_role
from backend.app.core.config import settings
from datetime import datetime, timezone
from typing import List

router = APIRouter()

@router.post('/', response_model=Filter)
def create_filter(filter: FilterCreate, db: Session = Depends(get_db), current_user: User = Depends(require_role(Role.REGISTERED))):
    # Validate filter data
    if not filter.name or not filter.criteria:
        raise HTTPException(status_code=400, detail="Filter name and criteria are required")

    # Each validated predicate becomes one criteria row on the filter.
    criteria_rows = [
        CriteriaModel(field=c.field, operator=c.operator, value=c.value)
        for c in filter.criteria
    ]

    # Create new filter in database
    new_filter = FilterModel(
        name=filter.name,
        criteria=criteria_rows,
        created_at=datetime.now(timezone.utc),
        user_id=current_user.id
    )
    db.add(new_filter)
    db.commit()
    db.refresh(new_filter)

    # Return created filter
    return Filter.from_orm(new_filter)

@router.get('/', response_model=List[Filter])
def get_user_filters(db: Session = Depends(get_db), current_user: User = Depends(require_role(Role.REGISTERED))):
    # Query database for user's filters
    filters = db.query(FilterModel).filter(FilterModel.user_id == current_user.id).limit(settings.MAX_PAGE_SIZE).all()

    # Return list of filters
    return [Filter.from_orm(filter) for filter in filters]