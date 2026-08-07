"""Saved-filter creation and retrieval.

Two routes are published under the ``/filters`` prefix that
:mod:`backend.app.api.router` already applies. Both resolve their
principal through :func:`backend.app.core.authorization.require_role`,
which reads the role from the stored user row, and both scope every row
they touch to that principal's identifier.

A filter is stored with its children: each accepted predicate becomes one
``criteria`` row and each accepted postal code becomes one ``zip_codes``
row, so every value the request contract admits is persisted and read
back by the response model. A filter that cannot be persisted is rolled
back, recorded through the redacting logger and answered ``500`` carrying
:data:`FILTER_NOT_STORED_DETAIL`.

Retrieval is paged in SQL and its page size is bounded by
``settings.MAX_PAGE_SIZE``, and the children of a whole page are loaded
by two further statements rather than by two per filter.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload
from backend.app.core.logging import get_logger, log_exception
from backend.app.db.database import get_db
from backend.app.schema.filter import FilterCreate, Filter
from backend.app.db.models import (
    Criteria as CriteriaModel,
    Filter as FilterModel,
    User,
    ZipCode as ZipCodeModel,
)
from backend.app.core.authorization import Role, require_role
from backend.app.core.config import settings
from datetime import datetime, timezone
from typing import List

router = APIRouter()

logger = get_logger(__name__)

#: Page size applied when a request names none.
DEFAULT_PAGE_SIZE = min(100, settings.MAX_PAGE_SIZE)

#: Detail returned when a filter cannot be persisted.
FILTER_NOT_STORED_DETAIL = "Filter could not be stored"


@router.post('/', response_model=Filter)
def create_filter(
    filter: FilterCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(Role.REGISTERED)),
):
    # Validate filter data
    if not filter.name or not filter.criteria:
        raise HTTPException(
            status_code=400,
            detail="Filter name and criteria are required",
        )

    criteria_rows = [
        CriteriaModel(field=c.field, operator=c.operator, value=c.value)
        for c in filter.criteria
    ]

    # Each validated postal code becomes one zip_codes row on the filter.
    zip_code_rows = [
        ZipCodeModel(code=z.code) for z in filter.zip_codes
    ]

    # Create new filter in database
    new_filter = FilterModel(
        name=filter.name,
        criteria=criteria_rows,
        zip_codes=zip_code_rows,
        created_at=datetime.now(timezone.utc),
        user_id=current_user.id
    )
    db.add(new_filter)
    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        log_exception(
            logger,
            "Failed to store a filter",
            exc,
            user_id=current_user.id,
        )
        raise HTTPException(
            status_code=500, detail=FILTER_NOT_STORED_DETAIL
        ) from None
    db.refresh(new_filter)

    return Filter.from_orm(new_filter)


@router.get('/', response_model=List[Filter])
def get_user_filters(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(Role.REGISTERED)),
    skip: int = Query(0, ge=0),
    limit: int = Query(
        DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE
    ),
):
    """Return one page of the caller's own filters.

    ``skip`` and ``limit`` are applied in SQL, and ``limit`` is bounded
    by ``settings.MAX_PAGE_SIZE``. The postal codes and the predicates
    of the returned filters are loaded by two further statements for the
    whole page rather than by two per filter, so the number of
    statements does not follow the page size. The number of children per
    filter is bounded by the creation contract in
    :mod:`backend.app.schema.filter`.
    """
    # Query database for user's filters
    filters = (
        db.query(FilterModel)
        .options(
            selectinload(FilterModel.zip_codes),
            selectinload(FilterModel.criteria),
        )
        .filter(FilterModel.user_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )

    # Return list of filters
    return [Filter.from_orm(filter) for filter in filters]
