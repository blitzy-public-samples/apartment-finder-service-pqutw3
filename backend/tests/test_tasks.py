import pytest
from unittest.mock import patch, MagicMock
from app.tasks import update_listings, process_and_validate_data

@pytest.fixture
def mock_db_session():
    return MagicMock()

@pytest.mark.asyncio
async def test_update_listings(mock_db_session):
    with patch('app.tasks.fetch_new_listings') as mock_fetch:
        mock_fetch.return_value = [
            {'id': 1, 'title': 'Test Listing 1'},
            {'id': 2, 'title': 'Test Listing 2'}
        ]
        
        await update_listings(mock_db_session)
        
        mock_fetch.assert_called_once()
        assert mock_db_session.add_all.call_count == 1
        assert mock_db_session.commit.call_count == 1

@pytest.mark.asyncio
async def test_process_and_validate_data(mock_db_session):
    test_data = [
        {'id': 1, 'name': 'Valid Item', 'price': 10.99},
        {'id': 2, 'name': 'Invalid Item', 'price': -5.00}
    ]
    
    with patch('app.tasks.validate_item') as mock_validate:
        mock_validate.side_effect = [True, False]
        
        result = await process_and_validate_data(test_data, mock_db_session)
        
        assert len(result['valid']) == 1
        assert len(result['invalid']) == 1
        assert result['valid'][0]['id'] == 1
        assert result['invalid'][0]['id'] == 2
        assert mock_db_session.add.call_count == 1
        assert mock_db_session.commit.call_count == 1

# HUMAN ASSISTANCE NEEDED
# The following test cases might need to be expanded or modified based on the actual implementation of the tasks:
# - Add more specific assertions for the data being added to the database
# - Include tests for error handling scenarios
# - Add tests for any additional functionality in the tasks that are not covered here