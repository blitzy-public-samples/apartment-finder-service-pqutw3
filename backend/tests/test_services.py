import unittest
from unittest.mock import MagicMock, patch

from backend.app.services.email_service import send_email
from backend.app.services.zillow_service import fetch_listings

ZILLOW_MODULE = 'backend.app.services.zillow_service'
EMAIL_MODULE = 'backend.app.services.email_service'


def _provider_response(payload):
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


class TestZillowService(unittest.TestCase):
    def test_fetch_listings(self):
        response = _provider_response({
            'listings': [
                {'id': 1, 'address': '123 Main St', 'price': 300000},
                {'id': 2, 'address': '456 Elm St', 'price': 250000}
            ]
        })

        with patch(ZILLOW_MODULE + '.httpx.get', return_value=response):
            listings = fetch_listings(zip_codes=['12345'], filters={})

        self.assertEqual(len(listings), 2)
        self.assertEqual(listings[0]['address'], '123 Main St')
        self.assertEqual(listings[1]['price'], 250000)

    def test_api_key_travels_in_a_header_never_in_the_url(self):
        response = _provider_response({'listings': []})

        with patch(
            ZILLOW_MODULE + '.httpx.get', return_value=response
        ) as mock_get:
            fetch_listings(zip_codes=['12345'], filters={})

        args, kwargs = mock_get.call_args
        from backend.app.core.config import settings

        key = settings.ZILLOW_API_KEY
        self.assertEqual(kwargs['headers']['X-API-Key'], key)
        self.assertNotIn(key, str(args))
        self.assertNotIn(key, str(kwargs['params']))
        self.assertNotIn('api_key', kwargs['params'])

    def test_every_request_carries_a_timeout(self):
        response = _provider_response({'listings': []})

        with patch(
            ZILLOW_MODULE + '.httpx.get', return_value=response
        ) as mock_get:
            fetch_listings(zip_codes=['12345'], filters={})

        self.assertIn('timeout', mock_get.call_args.kwargs)
        self.assertGreater(mock_get.call_args.kwargs['timeout'], 0)

    def test_provider_failure_yields_an_empty_list(self):
        import httpx

        with patch(
            ZILLOW_MODULE + '.httpx.get',
            side_effect=httpx.ConnectError('unreachable'),
        ):
            self.assertEqual(
                fetch_listings(zip_codes=['12345'], filters={}), []
            )

    def test_api_key_is_absent_from_every_log_record(self):
        import httpx

        from backend.app.core.config import settings
        from backend.app.core.logging import BASE_LOGGER_NAME

        key = settings.ZILLOW_API_KEY
        records = []

        import logging

        class Collector(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = Collector(level=logging.DEBUG)
        logger = logging.getLogger(BASE_LOGGER_NAME)
        logger.addHandler(handler)
        try:
            with patch(
                ZILLOW_MODULE + '.httpx.get',
                side_effect=httpx.ConnectError(
                    'unreachable ' + settings.ZILLOW_API_URL
                ),
            ):
                fetch_listings(zip_codes=['12345'], filters={})
        finally:
            logger.removeHandler(handler)

        self.assertTrue(records)
        for record in records:
            self.assertNotIn(key, repr(vars(record)))


class TestEmailService(unittest.TestCase):
    def test_send_email_reports_a_delivered_message(self):
        client = MagicMock()
        client.send.return_value = MagicMock(status_code=202)

        with patch(
            EMAIL_MODULE + '.SendGridAPIClient', return_value=client
        ):
            delivered = send_email(
                'test@example.com',
                'Test Notification',
                'This is a test notification.',
            )

        self.assertTrue(delivered)
        client.send.assert_called_once()

    def test_send_email_reports_a_rejected_message(self):
        client = MagicMock()
        client.send.return_value = MagicMock(status_code=400)

        with patch(
            EMAIL_MODULE + '.SendGridAPIClient', return_value=client
        ):
            self.assertFalse(
                send_email('test@example.com', 'Subject', 'Body')
            )

    def test_send_email_swallows_a_transport_failure(self):
        with patch(
            EMAIL_MODULE + '.SendGridAPIClient',
            side_effect=RuntimeError('transport down'),
        ):
            self.assertFalse(
                send_email('test@example.com', 'Subject', 'Body')
            )


if __name__ == '__main__':
    unittest.main()
