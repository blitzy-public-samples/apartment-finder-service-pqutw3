import asyncio
import contextlib
import functools
import inspect
import logging
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.config import settings
from backend.app.core.logging import (
    BASE_LOGGER_NAME,
    REDACTION_PLACEHOLDER,
    RedactingFilter,
    RedactingJsonFormatter,
)
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

#: Header the listing provider credential is carried in.
API_KEY_HEADER = 'X-API-Key'

#: Query parameter name the credential was previously carried in.
LEGACY_KEY_PARAM = 'api_key'


def _provider_response(payload):
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


class _LogCollector(logging.Handler):
    """Holds every record the application logger emits while attached."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


def _rendered_log_lines(collector):
    """Returns each collected record as the line the process would emit.

    The application's redacting filter and formatter are applied, giving
    the fully rendered text -- message, ``extra`` context and formatted
    exception traceback included.
    """
    log_filter = RedactingFilter()
    formatter = RedactingJsonFormatter()
    lines = []
    for record in collector.records:
        log_filter.filter(record)
        lines.append(formatter.format(record))
    return lines


@contextlib.contextmanager
def _collecting_application_logs():
    """Collects the records the application logger emits in the block.

    The handler is attached to the ``backend`` logger, which owns the
    application's records, and is removed on exit.
    """
    collector = _LogCollector()
    logger = logging.getLogger(BASE_LOGGER_NAME)
    logger.addHandler(collector)
    try:
        yield collector
    finally:
        logger.removeHandler(collector)


def _outbound_request(mock_get):
    """Rebuilds the provider call ``mock_get`` recorded as a real request.

    The recorded target, query parameters and headers are assembled into
    an ``httpx.Request`` carrying the target and query string the
    provider would have received.
    """
    args, kwargs = mock_get.call_args
    return httpx.Request(
        'GET',
        args[0] if args else kwargs['url'],
        params=kwargs.get('params'),
        headers=kwargs.get('headers'),
    )


def _fetch_recording_the_call():
    """Runs one provider fetch and returns the mock that recorded it."""
    response = _provider_response({'listings': []})
    with patch(
        ZILLOW_MODULE + '.httpx.get', return_value=response
    ) as mock_get:
        fetch_listings(zip_codes=['12345'], filters={})
    return mock_get


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

    def test_api_key_travels_in_a_request_header(self):
        """The credential is carried in the provider request's headers."""
        built = _outbound_request(_fetch_recording_the_call())

        self.assertEqual(
            built.headers[API_KEY_HEADER], settings.ZILLOW_API_KEY
        )

    def test_api_key_is_absent_from_the_request_target(self):
        """The credential appears nowhere in the assembled target."""
        built = _outbound_request(_fetch_recording_the_call())
        target = str(built.url)

        self.assertNotIn(settings.ZILLOW_API_KEY, target)

    def test_api_key_is_absent_from_the_query_string(self):
        """The credential appears in no query parameter, by name or value.

        The parameter name the credential previously travelled under is
        asserted absent alongside the value itself.
        """
        mock_get = _fetch_recording_the_call()
        built = _outbound_request(mock_get)
        query = built.url.query.decode('utf-8')
        sent_params = mock_get.call_args.kwargs['params']

        self.assertNotIn(settings.ZILLOW_API_KEY, query)
        self.assertNotIn(LEGACY_KEY_PARAM, query)
        self.assertNotIn(LEGACY_KEY_PARAM, sent_params)
        self.assertNotIn(settings.ZILLOW_API_KEY, str(sent_params))

    def test_every_request_carries_a_timeout(self):
        """The provider call is bounded by the configured timeout."""
        mock_get = _fetch_recording_the_call()

        self.assertIn('timeout', mock_get.call_args.kwargs)
        self.assertEqual(
            mock_get.call_args.kwargs['timeout'],
            settings.HTTP_TIMEOUT_SECONDS,
        )
        self.assertGreater(mock_get.call_args.kwargs['timeout'], 0)

    def test_provider_failure_yields_an_empty_list(self):
        with patch(
            ZILLOW_MODULE + '.httpx.get',
            side_effect=httpx.ConnectError('unreachable'),
        ):
            self.assertEqual(
                fetch_listings(zip_codes=['12345'], filters={}), []
            )

    def test_api_key_is_absent_from_every_log_record(self):
        """The credential reaches no rendered log line.

        Two failure messages are driven. The first is the shape the HTTP
        library produces, naming the full request target, which places
        the credential beside a credential-shaped parameter name. The
        second quotes the credential in free prose, with no key name
        beside it. Each case asserts the raw record carries the
        credential and that no rendered line does.
        """
        key = settings.ZILLOW_API_KEY
        keyed_target = (
            settings.ZILLOW_API_URL + '?' + LEGACY_KEY_PARAM + '=' + key
        )
        for label, message in (
            ('the provider target names the credential',
             'failed for url ' + keyed_target),
            ('provider prose quotes the credential',
             'the credential ' + key + ' was rejected upstream'),
        ):
            with self.subTest(label):
                with _collecting_application_logs() as collector:
                    with patch(
                        ZILLOW_MODULE + '.httpx.get',
                        side_effect=httpx.ConnectError(message),
                    ):
                        self.assertEqual(
                            fetch_listings(
                                zip_codes=['12345'], filters={}
                            ),
                            [],
                        )

                self.assertTrue(collector.records)
                self.assertTrue(any(
                    key in repr(record.exc_info)
                    for record in collector.records
                ))
                rendered = _rendered_log_lines(collector)
                for line in rendered:
                    self.assertNotIn(key, line)
                self.assertTrue(any(
                    REDACTION_PLACEHOLDER in line for line in rendered
                ))


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
    """Answers PayPal REST calls and records every outbound call made."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    @staticmethod
    def _path(sent):
        """Returns the path of one outbound httpx call."""
        return sent.url.path

    def handle(self, sent):
        self.calls.append(sent)
        for suffix, status, payload in self.responses:
            if self._path(sent).endswith(suffix):
                return httpx.Response(status, json=payload)
        return httpx.Response(404, json={'name': 'NOT_FOUND'})

    def paths(self):
        return [self._path(sent) for sent in self.calls]

    def matching(self, suffix):
        return [
            sent
            for sent in self.calls
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

    def _transport(self, responses, access_token='grant-token'):
        """Patches the service's client onto a recording transport.

        ``access_token`` is the value the credential exchange grants.
        """
        recorder = _Recorder(
            [('/v1/oauth2/token', 200, {
                'access_token': access_token, 'expires_in': 3600,
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

        The outcome is reported to the caller rather than raised, and
        carries a reason naming the mismatch.
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
        """The capture call asks for the full settled representation.

        The ``Prefer`` header carries the representation preference the
        service declares.
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
        """A capture answered with an identifier and a status settles.

        The order is read back exactly once, and the settlement is then
        measured against the provider's complete representation.
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

        # The capture carries the idempotency identifier derived from
        # the stored row.
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
        self.assertEqual(recorder.calls, [])

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
        self.assertEqual(recorder.calls, [])

    def test_an_already_captured_order_is_reconciled_by_reading_it_back(
        self,
    ):
        """An order the provider reports as already captured settles.

        The refusal is categorised as a provider-state failure, the
        settled order is read back, and no second charge is issued.
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
        """No call is issued through the module's synchronous entrypoint.

        The synchronous entrypoint is made to raise, and the capture
        still reaches the recording transport.
        """
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
        self.assertTrue(recorder.calls)

    def test_create_order_accepts_no_parameter_that_can_set_the_total(
        self,
    ):
        """Order creation exposes no parameter able to set the charge.

        The signature is asserted to be exactly the plan identifier, the
        two hosted redirect targets and the idempotency key, and to carry
        no name through which an amount or a currency could be supplied.
        """
        accepted = tuple(
            inspect.signature(paypal_service.create_order).parameters
        )

        self.assertEqual(
            accepted,
            ('plan_id', 'return_url', 'cancel_url', 'idempotency_key'),
        )
        for forbidden in (
            'amount', 'total', 'price', 'value', 'currency', 'sum',
        ):
            for name in accepted:
                self.assertNotIn(forbidden, name.lower())

    def test_every_paypal_call_carries_an_explicit_timeout(self):
        """Every outbound provider call is bounded by the timeout.

        The credential exchange, the order creation and the capture are
        each asserted to carry the configured timeout on every phase of
        the connection.
        """
        recorder, transport = self._transport([
            ('/v2/checkout/orders', 201, _order(
                status='PAYER_ACTION_REQUIRED', captured=False
            )),
            ('/capture', 201, _order()),
        ])
        with transport:
            _run(paypal_service.create_order(
                PLAN_ID, 'https://app.example/r', 'https://app.example/c'
            ))
            _run(paypal_service.capture_order(
                self.db, ORDER_ID, self.owner
            ))

        self.assertTrue(recorder.matching('/v1/oauth2/token'))
        self.assertTrue(recorder.matching('/v2/checkout/orders'))
        self.assertTrue(recorder.matching('/capture'))
        for sent in recorder.calls:
            bounds = sent.extensions.get('timeout')
            self.assertIsNotNone(bounds)
            for phase in ('connect', 'read', 'write', 'pool'):
                self.assertEqual(
                    bounds[phase], settings.HTTP_TIMEOUT_SECONDS
                )

    def test_no_credential_or_token_reaches_a_log_record(self):
        """No provider credential reaches a rendered log line.

        A successful order and a refused one are both driven, and every
        rendered line is asserted free of the client identifier, the
        client secret and the granted access token.
        """
        granted = 'AccessTokenGrantedByTheProvider0123456789'
        recorder, transport = self._transport(
            [
                ('/v2/checkout/orders', 201, _order(
                    status='PAYER_ACTION_REQUIRED', captured=False
                )),
                ('/capture', 500, {'name': 'INTERNAL_SERVER_ERROR'}),
            ],
            access_token=granted,
        )
        with _collecting_application_logs() as collector:
            with transport:
                _run(paypal_service.create_order(
                    PLAN_ID,
                    'https://app.example/r',
                    'https://app.example/c',
                ))
                with self.assertRaises(paypal_service.PayPalAPIError):
                    _run(paypal_service.capture_order(
                        self.db, ORDER_ID, self.owner
                    ))

        self.assertTrue(recorder.matching('/v1/oauth2/token'))
        self.assertTrue(collector.records)
        for line in _rendered_log_lines(collector):
            self.assertNotIn(granted, line)
            self.assertNotIn(settings.PAYPAL_CLIENT_SECRET, line)
            self.assertNotIn(settings.PAYPAL_CLIENT_ID, line)


if __name__ == '__main__':
    unittest.main()
