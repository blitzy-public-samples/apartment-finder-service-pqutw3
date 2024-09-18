import unittest
from unittest.mock import patch, MagicMock
from services.zillow_service import ZillowService
from services.paypal_service import PayPalService
from services.email_service import EmailService

class TestZillowService(unittest.TestCase):
    def setUp(self):
        self.zillow_service = ZillowService()

    @patch('services.zillow_service.requests.get')
    def test_fetch_listings(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'listings': [
                {'id': 1, 'address': '123 Main St', 'price': 300000},
                {'id': 2, 'address': '456 Elm St', 'price': 250000}
            ]
        }
        mock_get.return_value = mock_response

        listings = self.zillow_service.fetch_listings(zip_code='12345')

        self.assertEqual(len(listings), 2)
        self.assertEqual(listings[0]['address'], '123 Main St')
        self.assertEqual(listings[1]['price'], 250000)

class TestPayPalService(unittest.TestCase):
    def setUp(self):
        self.paypal_service = PayPalService()

    @patch('services.paypal_service.paypalrestsdk.Payment.create')
    def test_process_payment(self, mock_create):
        mock_create.return_value = True
        payment_data = {
            'amount': 100,
            'currency': 'USD',
            'description': 'Test payment'
        }

        result = self.paypal_service.process_payment(payment_data)

        self.assertTrue(result)
        mock_create.assert_called_once()

class TestEmailService(unittest.TestCase):
    def setUp(self):
        self.email_service = EmailService()

    @patch('services.email_service.smtplib.SMTP')
    def test_send_notification(self, mock_smtp):
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        recipient = 'test@example.com'
        subject = 'Test Notification'
        body = 'This is a test notification.'

        self.email_service.send_notification(recipient, subject, body)

        mock_server.send_message.assert_called_once()
        args, kwargs = mock_server.send_message.call_args
        self.assertIn(recipient, args[0]['To'])
        self.assertEqual(args[0]['Subject'], subject)
        self.assertIn(body, args[0].get_payload())

if __name__ == '__main__':
    unittest.main()