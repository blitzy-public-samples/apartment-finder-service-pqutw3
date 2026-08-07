import asyncio
import functools
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.plans import format_amount, get_plan
from backend.app.db.models import Base, Subscription, User
from backend.app.services import paypal_service
from backend.app.services.email_service import send_email
from backend.app.services.zillow_service import fetch_listings

ZILLOW_MODULE = 'backend.app.services.zillow_service'
EMAIL_MODULE = 'backend.app.services.email_service'

PLAN_ID = 'premium_monthly'
ORDER_ID = 'ORDER-SERVICE-1'
APPROVAL_URL = 'https://www.sandbox.paypal.com/checkoutnow?token=1'


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


def _run(coroutine):
    """Runs ``coroutine`` on a fresh event loop and returns its result."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coroutine)
    finally:
        loop.close()


def _order(
    status='COMPLETED',
    value=None,
    currency=None,
    captured=True,
    capture_status=None,
):
    """Returns a PayPal order object for the premium monthly plan."""
    plan = get_plan(PLAN_ID)
    amount = {
        'currency_code': currency or plan.currency,
        'value': value if value is not None else str(plan.amount),
    }
    body = {
        'id': ORDER_ID,
        'status': status,
        'links': [
            {'rel': 'self', 'href': 'https://api.example/o/1'},
            {'rel': 'payer-action', 'href': APPROVAL_URL},
        ],
    }
    if captured:
        body['purchase_units'] = [{
            'payments': {
                'captures': [{
                    'id': 'CAP-1',
                    'status': capture_status or status,
                    'amount': amount,
                }],
            },
        }]
    return body


class _Recorder:
    """Answers PayPal REST calls and records every request made."""

    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    @staticmethod
    def _path(sent):
        """Returns the request path of one outbound httpx request."""
        return sent.url.path

    def handle(self, sent):
        self.requests.append(sent)
        for suffix, status, payload in self.responses:
            if self._path(sent).endswith(suffix):
                return httpx.Response(status, json=payload)
        return httpx.Response(404, json={'name': 'NOT_FOUND'})

    def paths(self):
        return [self._path(sent) for sent in self.requests]

    def matching(self, suffix):
        return [
            sent
            for sent in self.requests
            if self._path(sent).endswith(suffix)
        ]


class TestPayPalService(unittest.TestCase):
    """The payment chain settles in the order PayPal documents."""

    def setUp(self):
        paypal_service.reset_access_token_cache()
        self.engine = create_engine(
            'sqlite://',
            connect_args={'check_same_thread': False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()
        owner = User(
            email='payer@example.com',
            hashed_password='x',
            created_at=datetime.now(timezone.utc),
            role='registered',
        )
        self.db.add(owner)
        self.db.commit()
        self.db.refresh(owner)
        self.owner = owner
        self.owner_id = owner.id
        stranger = User(
            email='stranger@example.com',
            hashed_password='x',
            created_at=datetime.now(timezone.utc),
            role='registered',
        )
        self.db.add(stranger)
        self.db.commit()
        self.db.refresh(stranger)
        self.stranger = stranger
        plan = get_plan(PLAN_ID)
        subscription = Subscription(
            user_id=owner.id,
            plan_id=PLAN_ID,
            amount=plan.amount,
            currency=plan.currency,
            status='pending',
            start_date=datetime.now(timezone.utc),
            paypal_order_id=ORDER_ID,
        )
        self.db.add(subscription)
        self.db.commit()
        self.db.refresh(subscription)
        self.subscription_id = subscription.id

    def _settlement(self, payload):
        """Returns what the service reports ``payload`` settled."""
        plan = get_plan(PLAN_ID)
        return paypal_service.read_capture(
            payload, ORDER_ID, plan.amount, plan.currency
        )

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()
        paypal_service.reset_access_token_cache()

    def _transport(self, responses):
        """Patches the service's client onto a recording transport."""
        recorder = _Recorder(
            [('/v1/oauth2/token', 200, {
                'access_token': 'grant-token', 'expires_in': 3600,
            })] + responses
        )
        factory = functools.partial(
            httpx.AsyncClient,
            transport=httpx.MockTransport(recorder.handle),
        )
        return recorder, patch.object(
            paypal_service.httpx, 'AsyncClient', factory
        )

    def test_create_order_prices_from_the_catalog_and_returns_a_link(self):
        recorder, transport = self._transport(
            [('/v2/checkout/orders', 201, _order(
                status='PAYER_ACTION_REQUIRED', captured=False
            ))]
        )
        with transport:
            order = _run(paypal_service.create_order(
                PLAN_ID, 'https://app.example/r', 'https://app.example/c'
            ))
        self.assertEqual(
            paypal_service.approval_url(order), APPROVAL_URL
        )
        created = recorder.matching('/v2/checkout/orders')[0]
        body = created.read().decode('utf-8')
        plan = get_plan(PLAN_ID)
        self.assertIn(str(plan.amount), body)
        self.assertIn(plan.currency, body)
        self.assertIn('"intent":"CAPTURE"', body.replace(' ', ''))

    def test_capture_requires_a_completed_and_reconciled_settlement(self):
        """A settlement that does not match the catalog is not complete.

        The measurement is reported rather than raised, so the caller
        decides what to do with the row it holds.
        """
        read_back = ('/v2/checkout/orders/' + ORDER_ID, 200,
                     _order(captured=False))
        for label, payload, extra in (
            (
                'neither level reports completion',
                _order(status='APPROVED'),
                [],
            ),
            (
                'the capture itself did not complete',
                _order(capture_status='PENDING'),
                [],
            ),
            ('no capture present', _order(captured=False), [read_back]),
            ('amount below the plan', _order(value='0.01'), []),
            ('foreign currency', _order(currency='EUR'), []),
        ):
            with self.subTest(label):
                _recorder, transport = self._transport(
                    [('/capture', 201, payload)] + extra
                )
                with transport:
                    captured = _run(paypal_service.capture_order(
                        self.db, ORDER_ID, self.owner
                    ))
                outcome = self._settlement(captured)
                self.assertFalse(outcome.completed)
                self.assertTrue(outcome.reason)

    def test_the_capture_asks_for_a_complete_representation(self):
        """The capture call requests the full settled representation.

        Without it PayPal answers with an identifier and a status alone,
        which carries neither the amount nor the capture identifier the
        settlement is measured by.
        """
        recorder, transport = self._transport(
            [('/capture', 201, _order())]
        )
        with transport:
            _run(paypal_service.capture_order(
                self.db, ORDER_ID, self.owner
            ))
        sent = recorder.matching('/capture')[0]
        self.assertEqual(
            sent.headers[paypal_service.PREFER_HEADER],
            paypal_service.PREFER_REPRESENTATION,
        )

    def test_a_minimal_capture_response_is_read_back_before_measuring(
        self,
    ):
        """A charge is never reported as unsettled for want of a body.

        PayPal may answer a capture with an identifier and a status only.
        The order is read back so the settlement is measured against the
        provider's own complete representation.
        """
        recorder, transport = self._transport([
            ('/capture', 201, {'id': ORDER_ID, 'status': 'COMPLETED'}),
            ('/v2/checkout/orders/' + ORDER_ID, 200, _order()),
        ])
        with transport:
            captured = _run(paypal_service.capture_order(
                self.db, ORDER_ID, self.owner
            ))
        plan = get_plan(PLAN_ID)
        outcome = self._settlement(captured)
        self.assertTrue(outcome.completed)
        self.assertEqual(outcome.amount, format_amount(plan.amount))
        self.assertEqual(outcome.currency, plan.currency)
        self.assertEqual(outcome.capture_id, 'CAP-1')
        self.assertEqual(
            len(recorder.matching('/v2/checkout/orders/' + ORDER_ID)), 1
        )

    def test_a_complete_capture_response_is_not_read_back(self):
        """A response already carrying the capture costs no extra call."""
        recorder, transport = self._transport(
            [('/capture', 201, _order())]
        )
        with transport:
            _run(paypal_service.capture_order(
                self.db, ORDER_ID, self.owner
            ))
        self.assertEqual(
            recorder.matching('/v2/checkout/orders/' + ORDER_ID), []
        )

    def test_a_settled_capture_is_reconciled_against_the_plan(self):
        recorder, transport = self._transport(
            [('/capture', 201, _order())]
        )
        with transport:
            captured = _run(paypal_service.capture_order(
                self.db, ORDER_ID, self.owner
            ))
        plan = get_plan(PLAN_ID)
        outcome = self._settlement(captured)
        self.assertTrue(outcome.completed)
        self.assertIsNone(outcome.reason)
        self.assertEqual(outcome.amount, format_amount(plan.amount))
        self.assertEqual(outcome.currency, plan.currency)
        self.assertEqual(outcome.capture_id, 'CAP-1')

        # The capture carries a request identifier derived from the row,
        # so a repeat of an uncertain call resolves to the same capture.
        sent = recorder.matching('/capture')[0]
        self.assertEqual(
            sent.headers['PayPal-Request-Id'],
            paypal_service.capture_request_id(self.subscription_id),
        )

    def test_capture_refuses_an_order_owned_by_another_user(self):
        recorder, transport = self._transport(
            [('/capture', 201, _order())]
        )
        with transport, self.assertRaises(
            paypal_service.OrderOwnershipError
        ):
            _run(paypal_service.capture_order(
                self.db, ORDER_ID, self.stranger
            ))
        # Nothing left the process.
        self.assertEqual(recorder.requests, [])

    def test_capture_refuses_an_order_with_no_stored_row(self):
        recorder, transport = self._transport(
            [('/capture', 201, _order())]
        )
        with transport, self.assertRaises(
            paypal_service.OrderOwnershipError
        ):
            _run(paypal_service.capture_order(
                self.db, 'ORDER-UNKNOWN', self.owner
            ))
        self.assertEqual(recorder.requests, [])

    def test_an_already_captured_order_is_reconciled_by_reading_it_back(
        self,
    ):
        """Recovers the case where a capture settled but was not recorded.

        The provider reports the order as already captured, which is a
        provider-state failure, and the settled order is then read back
        and measured without a second charge being issued.
        """
        recorder, transport = self._transport([
            ('/capture', 422, {'name': 'UNPROCESSABLE_ENTITY', 'details': [
                {'issue': 'ORDER_ALREADY_CAPTURED'},
            ]}),
            ('/v2/checkout/orders/' + ORDER_ID, 200, _order()),
        ])
        plan = get_plan(PLAN_ID)
        with transport:
            with self.assertRaises(
                paypal_service.PayPalAPIError
            ) as refused:
                _run(paypal_service.capture_order(
                    self.db, ORDER_ID, self.owner
                ))
            self.assertEqual(
                refused.exception.category,
                paypal_service.CATEGORY_PROVIDER_CLIENT,
            )
            outcome = _run(paypal_service.verify_settled_order(
                self.db, ORDER_ID, self.owner, plan.amount, plan.currency
            ))
        self.assertTrue(outcome.completed)
        self.assertEqual(outcome.amount, format_amount(plan.amount))
        self.assertTrue(
            any(path.endswith('/capture') for path in recorder.paths())
        )
        self.assertTrue(any(
            path.endswith('/v2/checkout/orders/' + ORDER_ID)
            for path in recorder.paths()
        ))

    def test_the_access_token_is_exchanged_once_per_lifetime(self):
        recorder, transport = self._transport(
            [('/capture', 201, _order())]
        )
        with transport:
            for _ in range(3):
                _run(paypal_service.capture_order(
                    self.db, ORDER_ID, self.owner
                ))
        exchanges = recorder.matching('/v1/oauth2/token')
        self.assertEqual(len(exchanges), 1)

    def test_every_call_is_made_through_the_async_client(self):
        """A synchronous httpx call would bypass this patch and fail."""
        recorder, transport = self._transport(
            [('/capture', 201, _order())]
        )
        with transport, patch.object(
            paypal_service.httpx,
            'post',
            side_effect=AssertionError('blocking call'),
        ):
            _run(paypal_service.capture_order(
                self.db, ORDER_ID, self.owner
            ))
        self.assertTrue(recorder.requests)

    def test_a_certificate_host_outside_the_allowlist_is_refused(self):
        recorder, transport = self._transport(
            [('/verify-webhook-signature', 200, {
                'verification_status': 'SUCCESS',
            })]
        )
        headers = {
            'PAYPAL-AUTH-ALGO': 'SHA256withRSA',
            'PAYPAL-CERT-URL': 'https://attacker.example.com/cert.pem',
            'PAYPAL-TRANSMISSION-ID': 'tx-1',
            'PAYPAL-TRANSMISSION-SIG': 'sig',
            'PAYPAL-TRANSMISSION-TIME': '2026-01-01T00:00:00Z',
        }
        with transport:
            result = _run(
                paypal_service.verify_webhook_signature(headers, {})
            )
        self.assertFalse(result.verified)
        self.assertEqual(
            result.reason, paypal_service.REASON_CERTIFICATE_HOST
        )
        # The certificate URL was never fetched or forwarded.
        self.assertEqual(recorder.requests, [])

    def test_an_allowlisted_notification_is_verified(self):
        _recorder, transport = self._transport(
            [('/verify-webhook-signature', 200, {
                'verification_status': 'SUCCESS',
            })]
        )
        headers = {
            'PAYPAL-AUTH-ALGO': 'SHA256withRSA',
            'PAYPAL-CERT-URL': 'https://api.sandbox.paypal.com/c.pem',
            'PAYPAL-TRANSMISSION-ID': 'tx-2',
            'PAYPAL-TRANSMISSION-SIG': 'sig',
            'PAYPAL-TRANSMISSION-TIME': '2026-01-01T00:00:00Z',
        }
        raw = b'{"event_type": "PAYMENT.CAPTURE.COMPLETED"}'
        with transport:
            result = _run(paypal_service.verify_webhook_signature(
                headers, raw
            ))
        self.assertTrue(result.verified)
        self.assertEqual(result.transmission_id, 'tx-2')
        self.assertEqual(
            result.event_type, 'PAYMENT.CAPTURE.COMPLETED'
        )
        # The bytes that arrived are what the verifier transmitted.
        posted = _recorder.matching('/verify-webhook-signature')[0]
        self.assertIn(raw, posted.content)
        self.assertEqual(
            json.loads(posted.content.decode('utf-8'))['webhook_event'],
            {'event_type': 'PAYMENT.CAPTURE.COMPLETED'},
        )


if __name__ == '__main__':
    unittest.main()
