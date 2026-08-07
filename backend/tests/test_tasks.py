from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.models import Base, Filter, Listing, User, ZipCode
from backend.app.tasks.listing_updater import (
    IDENTITY_COLUMN,
    UPDATE_INTERVAL,
    tracked_zip_codes,
    update_listings,
)

TASK_MODULE = 'backend.app.tasks.listing_updater'

ZIP_CODE = '12345'

LISTING_URL = 'https://www.zillow.com/homedetails/1'


@pytest.fixture
def mock_db_session():
    return MagicMock()


@pytest.fixture
def session_factory():
    engine = create_engine(
        'sqlite://',
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db(session_factory):
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def saved_zip_code(db):
    """A saved filter naming one postal code, which is what a pass reads."""
    user = User(
        email='ingest@example.com',
        hashed_password='x',
        created_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.flush()
    saved_filter = Filter(
        user_id=user.id,
        name='Test filter',
        created_at=datetime.now(timezone.utc),
        zip_codes=[ZipCode(code=ZIP_CODE)],
    )
    db.add(saved_filter)
    db.commit()
    return ZIP_CODE


def _provider_listing(**overrides):
    record = {
        'listing_url': LISTING_URL,
        'address': '123 Main St',
        'price': 2400,
        'bedrooms': 2,
        'bathrooms': 1,
        'square_feet': 850,
    }
    record.update(overrides)
    return record


@pytest.mark.asyncio
async def test_update_listings_completes_without_raising(
    mock_db_session,
):
    """The ingestion pass reports failures rather than propagating."""
    with patch(
        TASK_MODULE + '.SessionLocal', return_value=mock_db_session
    ):
        with patch(
            TASK_MODULE + '.tracked_zip_codes', return_value=[ZIP_CODE]
        ):
            with patch(TASK_MODULE + '.fetch_listings') as mock_fetch:
                mock_fetch.return_value = []
                await update_listings()

    assert mock_db_session.close.call_count == 1


@pytest.mark.asyncio
async def test_update_listings_closes_the_session_on_failure(
    mock_db_session,
):
    with patch(
        TASK_MODULE + '.SessionLocal', return_value=mock_db_session
    ):
        with patch(
            TASK_MODULE + '.tracked_zip_codes', return_value=[ZIP_CODE]
        ):
            with patch(
                TASK_MODULE + '.fetch_listings',
                side_effect=RuntimeError('provider unavailable'),
            ):
                await update_listings()

    assert mock_db_session.rollback.call_count == 1
    assert mock_db_session.close.call_count == 1


def test_update_interval_is_positive():
    assert UPDATE_INTERVAL.total_seconds() > 0


def test_tracked_zip_codes_reads_saved_filters(db, saved_zip_code):
    assert tracked_zip_codes(db) == [ZIP_CODE]


def test_tracked_zip_codes_is_empty_without_a_saved_filter(db):
    assert tracked_zip_codes(db) == []


@pytest.mark.asyncio
async def test_a_pass_is_skipped_when_no_filter_names_a_postal_code(
    session_factory,
):
    """No postal code means the provider is not called at all."""
    with patch(
        TASK_MODULE + '.SessionLocal', session_factory
    ):
        with patch(TASK_MODULE + '.fetch_listings') as mock_fetch:
            await update_listings()

    assert mock_fetch.call_count == 0


@pytest.mark.asyncio
async def test_a_provider_listing_is_persisted_as_a_mapped_orm_row(
    session_factory, db, saved_zip_code
):
    """The pass writes a real listings row, mapping provider names."""
    with patch(TASK_MODULE + '.SessionLocal', session_factory):
        with patch(
            TASK_MODULE + '.fetch_listings',
            return_value=[_provider_listing()],
        ) as mock_fetch:
            await update_listings()

    # The provider is called synchronously with the stored postal codes.
    assert mock_fetch.call_args.args[0] == [ZIP_CODE]

    rows = db.query(Listing).all()
    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, Listing)
    assert getattr(row, IDENTITY_COLUMN) == LISTING_URL
    assert row.rent == 2400
    assert row.street_address == '123 Main St'
    assert row.square_footage == 850
    assert row.bedrooms == 2
    assert row.created_at is not None
    assert row.updated_at is not None


@pytest.mark.asyncio
async def test_a_second_pass_refreshes_rather_than_duplicates(
    session_factory, db, saved_zip_code
):
    """The identity column reconciles a record seen twice."""
    for rent in (2400, 2500):
        with patch(TASK_MODULE + '.SessionLocal', session_factory):
            with patch(
                TASK_MODULE + '.fetch_listings',
                return_value=[_provider_listing(price=rent)],
            ):
                await update_listings()

    rows = db.query(Listing).all()
    assert len(rows) == 1
    assert rows[0].rent == 2500


@pytest.mark.asyncio
async def test_a_record_carrying_no_identity_is_discarded(
    session_factory, db, saved_zip_code
):
    """A record with no identity cannot be reconciled, so it is dropped."""
    record = _provider_listing()
    del record['listing_url']

    with patch(TASK_MODULE + '.SessionLocal', session_factory):
        with patch(
            TASK_MODULE + '.fetch_listings', return_value=[record]
        ):
            await update_listings()

    assert db.query(Listing).count() == 0


@pytest.mark.asyncio
async def test_a_record_failing_the_contract_is_discarded(
    session_factory, db, saved_zip_code
):
    """An unusable record is dropped without failing the whole pass."""
    good = _provider_listing()
    bad = _provider_listing(listing_url='https://www.zillow.com/2')
    del bad['price']

    with patch(TASK_MODULE + '.SessionLocal', session_factory):
        with patch(
            TASK_MODULE + '.fetch_listings', return_value=[bad, good]
        ):
            await update_listings()

    rows = db.query(Listing).all()
    assert len(rows) == 1
    assert getattr(rows[0], IDENTITY_COLUMN) == LISTING_URL


@pytest.mark.asyncio
async def test_a_provider_field_outside_the_allowlist_is_ignored(
    session_factory, db, saved_zip_code
):
    """Nothing the provider sends can reach an undeclared column."""
    record = _provider_listing(id=99, owner_id=7, description='ignored')

    with patch(TASK_MODULE + '.SessionLocal', session_factory):
        with patch(
            TASK_MODULE + '.fetch_listings', return_value=[record]
        ):
            await update_listings()

    row = db.query(Listing).one()
    assert row.id != 99
    assert not hasattr(row, 'owner_id')
    assert not hasattr(row, 'description')
