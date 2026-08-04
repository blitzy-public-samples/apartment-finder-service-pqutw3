from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload
from backend.app.db.database import get_db
from backend.app.schema.filter import FilterCreate, Filter
from backend.app.db.models import (
    Filter as FilterModel,
    Criteria as CriteriaModel,
    User,
)
from backend.app.core.security import get_current_user
from datetime import datetime
from typing import List

router = APIRouter()

@router.post('/', response_model=Filter)
def create_filter(filter: FilterCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Validate filter data
    if not filter.name or not filter.criteria:
        raise HTTPException(status_code=400, detail="Filter name and criteria are required")

    # Create new filter in database
    # SEC-05: only the validated allow-list fields are copied onto mapped
    # Criteria children; created_at stays server-owned (CWE-915)
    new_filter = FilterModel(
        name=filter.name,
        criteria=[
            CriteriaModel(
                field=item.field,
                operator=item.operator,
                value=item.value,
            )
            for item in filter.criteria
        ],
        created_at=datetime.utcnow(),
        user_id=current_user.id
    )
    db.add(new_filter)
    db.commit()
    db.refresh(new_filter)

    # Return created filter
    return Filter.from_orm(new_filter)

@router.get('/', response_model=List[Filter])
def get_user_filters(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Query database for user's filters
    # SEC-05: both declared collections are loaded in a fixed number of
    # statements, so one caller's own row count cannot multiply the round
    # trips this read costs (CWE-770)
    filters = (
        db.query(FilterModel)
        .filter(FilterModel.user_id == current_user.id)
        .options(
            selectinload(FilterModel.zip_codes),
            selectinload(FilterModel.criteria),
        )
        .all()
    )

    # Return list of filters
    return [Filter.from_orm(filter) for filter in filters]