from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.db.database import get_db
from backend.app.schema.filter import FilterCreate, Filter
from backend.app.db.models import Filter as FilterModel, User
from backend.app.core.security import get_current_user
from typing import List

router = APIRouter()

@router.post('/', response_model=Filter)
def create_filter(filter: FilterCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Validate filter data
    if not filter.name or not filter.criteria:
        raise HTTPException(status_code=400, detail="Filter name and criteria are required")

    # Create new filter in database
    new_filter = FilterModel(
        name=filter.name,
        criteria=filter.criteria,
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
    filters = db.query(FilterModel).filter(FilterModel.user_id == current_user.id).all()

    # Return list of filters
    return [Filter.from_orm(filter) for filter in filters]