import pytest
from unittest.mock import MagicMock, patch

from backend.app.tasks.listing_updater import (
    UPDATE_INTERVAL,
    update_listings,
)

TASK_MODULE = 'backend.app.tasks.listing_updater'


@pytest.fixture
def mock_db_session():
    return MagicMock()


@pytest.mark.asyncio
async def test_update_listings_completes_without_raising(
    mock_db_session,
):
    """The ingestion pass reports failures rather than propagating."""
    with patch(
        TASK_MODULE + '.SessionLocal', return_value=mock_db_session
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
            TASK_MODULE + '.fetch_listings',
            side_effect=RuntimeError('provider unavailable'),
        ):
            await update_listings()

    assert mock_db_session.rollback.call_count == 1
    assert mock_db_session.close.call_count == 1


def test_update_interval_is_positive():
    assert UPDATE_INTERVAL.total_seconds() > 0
