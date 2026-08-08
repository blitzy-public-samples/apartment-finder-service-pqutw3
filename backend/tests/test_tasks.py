import asyncio
import contextlib
import logging as stdlib_logging
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.logging import flush_log_queue
from backend.app.db.models import Base, Filter, Listing, User, ZipCode
from backend.app.tasks import listing_updater
from backend.app.tasks.listing_updater import (
    IDENTITY_COLUMN,
    INGESTION_FAILED_MESSAGE,
    RECORD_REFUSED_MESSAGE,
    UPDATE_INTERVAL,
    tracked_zip_codes,
    update_listings,
)

TASK_MODULE = 'backend.app.tasks.listing_updater'

ZIP_CODE = '12345'

LISTING_URL = 'https://www.zillow.com/homedetails/1'

SECOND_LISTING_URL = 'https://www.zillow.com/homedetails/2'

# Message the pass records when it completes. It is asserted absent from
# the cases where a failure must end the pass instead.
PASS_COMPLETED_MESSAGE = 'Completed an ingestion pass'

# Value placed in the numeric rent column to make the flush raise for one
# statement. The type layer cannot prepare it as a parameter.
UNBINDABLE_RENT = 'not-a-number'

# Detail carried by the stand-in defect below.
DEFECT_DETAIL = 'a defect in the row builder'

# Longest a stand-in provider call waits to be released. It bounds the
# case below so a pass that blocked the loop fails instead of hanging.
BLOCKED_FETCH_TIMEOUT = 5.0

# Detail carried by the stand-in provider failure below. The value is
# plain prose holding no credential shape, which the redacting
# formatter leaves unchanged.
PROVIDER_FAILURE_DETAIL = 'the listing provider was unreachable'

# Stream signature the cases below assert is absent from stdout and
# stderr: the ingestion failure message followed by the failure detail.
BARE_PRINT_SIGNATURE = (
    INGESTION_FAILED_MESSAGE + ': ' + PROVIDER_FAILURE_DETAIL
)

# Longest the assertions below wait for the queue-backed log listener to
# write every record one pass produced.
LOG_DRAIN_TIMEOUT = 5.0


class _RecordCollector(stdlib_logging.Handler):
    """Holds every record the logger it is attached to emits."""

    def __init__(self):
        super().__init__(level=stdlib_logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


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


def _unbindable_then_valid():
    """Returns a stand-in for the row builder, failing the first row.

    The first row it returns carries text in a numeric column, which the
    type layer cannot prepare as a parameter, so the flush raises
    ``StatementError`` for that one statement. Every later row is built
    as the module builds it.
    """
    real_builder = listing_updater._new_listing
    calls = {'count': 0}

    def build(mapped, moment):
        row = real_builder(mapped, moment)
        calls['count'] += 1
        if calls['count'] == 1:
            row.rent = UNBINDABLE_RENT
        return row

    return build


@contextlib.contextmanager
def _collected_task_records():
    """Collects the records the ingestion module's logger emits."""
    collector = _RecordCollector()
    logger = stdlib_logging.getLogger(TASK_MODULE)
    logger.addHandler(collector)
    try:
        yield collector.records
    finally:
        logger.removeHandler(collector)


def _record_named(records, message):
    """Returns the one collected record carrying ``message``."""
    matching = [
        record for record in records if record.getMessage() == message
    ]
    assert len(matching) == 1, message
    return matching[0]


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

    assert mock_fetch.call_count == 1
    assert mock_db_session.commit.call_count == 1
    assert mock_db_session.rollback.call_count == 0
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
    assert mock_db_session.commit.call_count == 0


@pytest.mark.asyncio
async def test_a_failed_pass_is_reported_through_the_module_logger(
    mock_db_session,
):
    failure = RuntimeError(PROVIDER_FAILURE_DETAIL)

    with patch(
        TASK_MODULE + '.SessionLocal', return_value=mock_db_session
    ):
        with patch(
            TASK_MODULE + '.tracked_zip_codes', return_value=[ZIP_CODE]
        ):
            with patch(
                TASK_MODULE + '.fetch_listings', side_effect=failure
            ):
                with patch(
                    TASK_MODULE + '.log_exception'
                ) as mock_log_exception:
                    await update_listings()

    assert mock_log_exception.call_count == 1
    reported_logger, message, error = mock_log_exception.call_args.args[:3]
    assert reported_logger.name == TASK_MODULE
    assert message == INGESTION_FAILED_MESSAGE
    assert error is failure
    assert mock_log_exception.call_args.kwargs['exception_message'] is None

    assert mock_db_session.rollback.call_count == 1
    assert mock_db_session.commit.call_count == 0
    assert mock_db_session.close.call_count == 1


@pytest.mark.asyncio
async def test_a_failed_pass_writes_no_failure_detail_to_a_stream(
    mock_db_session, capsys
):
    with patch(
        TASK_MODULE + '.SessionLocal', return_value=mock_db_session
    ):
        with patch(
            TASK_MODULE + '.tracked_zip_codes', return_value=[ZIP_CODE]
        ):
            with patch(
                TASK_MODULE + '.fetch_listings',
                side_effect=RuntimeError(PROVIDER_FAILURE_DETAIL),
            ):
                await update_listings()

    flush_log_queue(LOG_DRAIN_TIMEOUT)
    captured = capsys.readouterr()

    for stream in (captured.out, captured.err):
        assert BARE_PRINT_SIGNATURE not in stream
        assert PROVIDER_FAILURE_DETAIL not in stream

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

    # The provider receives the stored postal codes.
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
async def test_a_value_the_database_cannot_bind_is_a_record_refusal(
    session_factory, db, saved_zip_code
):
    """A parameter that cannot be prepared discards that record only.

    The failure is raised for one statement before the database receives
    it, so it names the record being written. The pass is asserted to
    complete, to record the refusal, and to store the other record.
    """
    refused = _provider_listing()
    accepted = _provider_listing(listing_url=SECOND_LISTING_URL)

    with patch(TASK_MODULE + '.SessionLocal', session_factory):
        with patch(
            TASK_MODULE + '.fetch_listings',
            return_value=[refused, accepted],
        ):
            with patch(
                TASK_MODULE + '._new_listing',
                side_effect=_unbindable_then_valid(),
            ):
                with _collected_task_records() as records:
                    await update_listings()

    rows = db.query(Listing).all()
    assert [getattr(row, IDENTITY_COLUMN) for row in rows] == [
        SECOND_LISTING_URL
    ]

    messages = [record.getMessage() for record in records]
    assert RECORD_REFUSED_MESSAGE in messages
    assert INGESTION_FAILED_MESSAGE not in messages
    assert PASS_COMPLETED_MESSAGE in messages
    refusal = _record_named(records, RECORD_REFUSED_MESSAGE)
    assert refusal.exception_type == 'StatementError'
    assert getattr(refusal, 'identity_column') == IDENTITY_COLUMN


@pytest.mark.asyncio
async def test_a_defect_raising_value_error_ends_the_pass(
    session_factory, db, saved_zip_code
):
    """A bare ``ValueError`` is a defect, not a record the database refused.

    The pass is asserted to roll back, to store nothing, to report the
    failure through the ingestion failure path, and to report no
    completion, so a defect can never be counted as a refused record on a
    pass that reported success.
    """
    with patch(TASK_MODULE + '.SessionLocal', session_factory):
        with patch(
            TASK_MODULE + '.fetch_listings',
            return_value=[_provider_listing()],
        ):
            with patch(
                TASK_MODULE + '._new_listing',
                side_effect=ValueError(DEFECT_DETAIL),
            ):
                with _collected_task_records() as records:
                    await update_listings()

    assert db.query(Listing).count() == 0

    messages = [record.getMessage() for record in records]
    assert INGESTION_FAILED_MESSAGE in messages
    assert RECORD_REFUSED_MESSAGE not in messages
    assert PASS_COMPLETED_MESSAGE not in messages
    failure = _record_named(records, INGESTION_FAILED_MESSAGE)
    assert failure.exception_type == 'ValueError'


@pytest.mark.asyncio
async def test_a_lost_connection_ends_the_pass(
    session_factory, db, saved_zip_code
):
    """A driver error that describes the session ends the pass.

    ``OperationalError`` applies to every record equally, so it is
    asserted to reach the ingestion failure path rather than the
    record-refusal path.
    """
    with patch(TASK_MODULE + '.SessionLocal', session_factory):
        with patch(
            TASK_MODULE + '.fetch_listings',
            return_value=[_provider_listing()],
        ):
            with patch(
                TASK_MODULE + '._new_listing',
                side_effect=OperationalError(
                    'INSERT INTO listings', {}, Exception('gone')
                ),
            ):
                with _collected_task_records() as records:
                    await update_listings()

    assert db.query(Listing).count() == 0

    messages = [record.getMessage() for record in records]
    assert INGESTION_FAILED_MESSAGE in messages
    assert RECORD_REFUSED_MESSAGE not in messages
    assert PASS_COMPLETED_MESSAGE not in messages


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


@pytest.mark.asyncio
async def test_the_provider_call_runs_off_the_event_loop(
    session_factory, saved_zip_code
):
    """The synchronous provider call is made on a worker thread."""
    loop_thread = threading.get_ident()
    calling_threads = []

    def recording_fetch(zip_codes, filters):
        calling_threads.append(threading.get_ident())
        return []

    with patch(TASK_MODULE + '.SessionLocal', session_factory):
        with patch(TASK_MODULE + '.fetch_listings', new=recording_fetch):
            await update_listings()

    assert len(calling_threads) == 1
    assert calling_threads[0] != loop_thread


@pytest.mark.asyncio
async def test_the_event_loop_runs_while_the_provider_is_waiting(
    session_factory, saved_zip_code
):
    """A concurrent task progresses before the provider call returns.

    The stand-in provider call blocks until the other task releases it,
    so it can only return once the loop has run that task.
    """
    released = threading.Event()
    release_observed = []

    def blocked_fetch(zip_codes, filters):
        release_observed.append(released.wait(BLOCKED_FETCH_TIMEOUT))
        return []

    async def release_after_yielding():
        for _ in range(3):
            await asyncio.sleep(0)
        released.set()

    with patch(TASK_MODULE + '.SessionLocal', session_factory):
        with patch(TASK_MODULE + '.fetch_listings', new=blocked_fetch):
            await asyncio.gather(
                update_listings(), release_after_yielding()
            )

    assert release_observed == [True]
