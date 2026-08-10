import asyncio
import contextlib
import copy
import functools
import inspect
import io
import json
import logging
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import httpx
from python_http_client.client import Client as HttpClient
from python_http_client.exceptions import BadRequestsError, HTTPError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from conftest import (
    PAYPAL_OAUTH_PATH,
    PAYPAL_ORDERS_PATH,
    PAYPAL_ROUTE_CAPTURE_ORDER,
    PAYPAL_VERIFY_FIELDS,
    PAYPAL_VERIFY_PATH,
    PayPalContractError,
    assert_capture_body,
    assert_create_order_body,
    assert_paypal_contract,
    assert_paypal_request,
)

from backend.app.core.config import (
    PROVIDER_SECRET_SETTINGS,
    settings,
)
from backend.app.core.logging import (
    BASE_LOGGER_NAME,
    CONTEXT_FIELD,
    MIN_SECRET_VALUE_LENGTH,
    REDACTION_PLACEHOLDER,
    REQUEST_ID_FIELD,
    TRACEPARENT_HEADER,
    RedactingFilter,
    RedactingJsonFormatter,
    bind_request_id,
    bind_trace_context,
    current_traceparent,
    redact,
    register_required_secret_values,
    reset_request_id,
    reset_trace_context,
    flush_log_queue,
)
from backend.app.api.endpoints import (
    subscriptions as subscriptions_module,
)
from backend.app.core.plans import PLAN_IDS, format_amount, get_plan
from backend.app.db.models import Base, Subscription, User
from backend.app.services import email_service as email_service_module
from backend.app.services import paypal_service
from backend.app.services import zillow_service
from backend.app.services import zillow_service as zillow_service_module
from backend.app.services.email_service import send_email
from backend.app.services.zillow_service import (
    CONTENT_LENGTH_HEADER,
    ListingProviderError,
    fetch_listings,
)
from backend.app.tasks import (
    listing_updater as listing_updater_module,
)
from backend.tests.support import enforce_sqlite_foreign_keys

ZILLOW_MODULE = 'backend.app.services.zillow_service'
EMAIL_MODULE = 'backend.app.services.email_service'

PLAN_ID = 'premium_monthly'
ORDER_ID = 'ORDER-SERVICE-1'

ORDER_PATH = PAYPAL_ORDERS_PATH + '/' + ORDER_ID

STAND_IN_GRANT = 'contract-case-access-token'
APPROVAL_URL = 'https://www.sandbox.paypal.com/checkoutnow?token=1'

API_KEY_HEADER = 'X-API-Key'

LEGACY_KEY_PARAM = 'api_key'

SENDGRID_SEND_URL = 'https://api.sendgrid.com/v3/mail/send'

SENDGRID_URL_PATH = ['mail', 'send']

RECIPIENT_EMAIL = 'test@example.com'

EMAIL_SUBJECT = 'Test Notification'

EMAIL_CONTENT = '<p>This is a test notification.</p>'

EMAIL_ACCEPTED_STATUS = 202

EMAIL_DELIVERED_STATUSES = (EMAIL_ACCEPTED_STATUS,)

EMAIL_UNEXPECTED_SUCCESS_STATUSES = (200, 201, 203, 204)

EMAIL_REJECTED_STATUS = 400

EMAIL_UNAVAILABLE_STATUS = 503

EMAIL_REJECTION_BODY = b'{"errors":[{"message":"bad request"}]}'

EMAIL_FAILURE_MESSAGE = email_service_module.EMAIL_FAILURE_MESSAGE

REASON_SEND_FAILED = email_service_module.REASON_SEND_FAILED

PROVIDER_UNREACHABLE_DETAIL = 'the listing provider was unreachable'

BOUND_REQUEST_ID = 'caller0trace0provider1'

EMAIL_RECIPIENT = 'notified@example.com'

EMAIL_BODY = 'Three listings match your saved search.'

EMAIL_FAILURE_DETAIL = (
    'the provider rejected the credential '
    + settings.SENDGRID_API_KEY
)

EMAIL_KEYED_FAILURE_DETAIL = (
    'unauthorized: api_key=' + settings.SENDGRID_API_KEY
)

BARE_PRINT_SIGNATURE = EMAIL_FAILURE_DETAIL

LOG_DRAIN_TIMEOUT = 5.0

BARE_OUTPUT_FREE_MODULES = (
    email_service_module,
    zillow_service_module,
    listing_updater_module,
)


def _send_failing_with(detail):
    with patch(
        EMAIL_MODULE + '.SendGridAPIClient',
        side_effect=RuntimeError(detail),
    ):
        return send_email(EMAIL_RECIPIENT, EMAIL_SUBJECT, EMAIL_BODY)


def _structured_entries(lines):
    """Returns each non-blank line of ``lines`` decoded as an object.

    A line that is not a JSON object raises, which is how a bare write is
    told apart from a record the logger emitted.
    """
    decoded = []
    for line in lines:
        if not line.strip():
            continue
        entry = json.loads(line)
        if not isinstance(entry, dict):
            raise AssertionError(
                'emitted line is not a record: {0!r}'.format(line)
            )
        decoded.append(entry)
    return decoded


@contextlib.contextmanager
def _collecting_emitted_lines():
    """Collects the lines the redacting handler writes in the block.

    The handler the governed loggers dispatch to is given a buffer of its
    own for the duration, and the queue is drained before the buffer is
    installed and again before it is read, so the lines collected are the
    ones this block produced. The handler's own stream is restored on
    exit.
    """
    dispatcher = logging.getLogger(BASE_LOGGER_NAME).handlers[0]
    handler = dispatcher.target
    flush_log_queue(LOG_DRAIN_TIMEOUT)
    buffer = io.StringIO()
    original = handler.setStream(buffer)
    lines = []
    try:
        yield lines
    finally:
        flush_log_queue(LOG_DRAIN_TIMEOUT)
        lines.extend(buffer.getvalue().splitlines())
        handler.setStream(original)


def _provider_response(payload):
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


class _LogCollector(logging.Handler):

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


class _ProviderRecorder:

    def __init__(self, responder):
        self._responder = responder
        self.requests = []

    def handle(self, request):
        self.requests.append(request)
        return self._responder(request)

    @property
    def sent(self):
        if len(self.requests) != 1:
            raise AssertionError(
                "expected one provider call, got %d" % len(self.requests)
            )
        return self.requests[0]


@contextlib.contextmanager
def _provider(responder):
    """Runs the block with provider calls answered by ``responder``.

    The service's own client factory is replaced by one built on an
    ``httpx.MockTransport``, so the request the provider receives is
    assembled, sent and streamed by the real HTTP library.
    """
    recorder = _ProviderRecorder(responder)
    transport = httpx.MockTransport(recorder.handle)

    def build_client():
        return httpx.Client(
            transport=transport, timeout=settings.HTTP_TIMEOUT_SECONDS
        )

    with patch(ZILLOW_MODULE + '._client', new=build_client):
        yield recorder


def _answering(payload, status_code=200):

    def responder(request):
        return httpx.Response(status_code, json=payload)

    return responder


def _answering_bytes(body, status_code=200, declared=None):
    """Returns a responder answering with ``body`` verbatim.

    ``declared`` overrides the declared body length, so a body that
    announces itself as larger than it is can be served.
    """

    def responder(request):
        response = httpx.Response(status_code, content=body)
        if declared is not None:
            response.headers[CONTENT_LENGTH_HEADER] = str(declared)
        return response

    return responder


def _answering_in_chunks(chunk, count, produced):
    """Returns a responder streaming ``count`` copies of ``chunk``.

    No body length is declared, so the accumulated-byte cap is the only
    bound. Each chunk handed to the client is counted in ``produced``, so
    a read that stops early is visible.
    """

    def responder(request):
        def stream():
            for _ in range(count):
                produced.append(chunk)
                yield chunk

        return httpx.Response(200, content=stream())

    return responder


def _raising(error_factory):

    def responder(request):
        raise error_factory(request)

    return responder


def _fetch(zip_codes=('12345',), filters=None):
    return fetch_listings(
        zip_codes=list(zip_codes), filters=dict(filters or {})
    )


def _refused(case, reason, zip_codes=('12345',), filters=None):
    """Runs one fetch that must be refused, and returns the error.

    The refusal is asserted to be a ``ListingProviderError`` carrying
    ``reason``, so the case states which cause it expects rather than
    only that nothing came back. An empty list is never accepted here:
    that value means the provider answered and reported no listings.
    """
    with case.assertRaises(ListingProviderError) as raised:
        _fetch(zip_codes=zip_codes, filters=filters)
    case.assertEqual(raised.exception.reason, reason)
    return raised.exception


class TestTheDeclaredListingProviderContract(unittest.TestCase):
    """The listing adapter's wire contract, and how it fails.

    **These cases are written against the contract this repository
    declares, not against one verified with a listing provider.** The
    payloads below are the shape
    ``zillow_service.DECLARED_PROVIDER_CONTRACT`` describes; no provider
    specification was available to derive them from, and
    ``docs/security/RESIDUAL_RISK.md`` carries that as an open item. What
    they therefore establish is not that the adapter matches a provider,
    but that it matches its own declaration -- and, more importantly, that
    a response which does **not** match that declaration is reported as a
    failure naming the element that did not match, rather than read as a
    corpus with nothing in it. That is the property that makes a contract
    difference discoverable on the first live call.
    """

    def test_the_whole_declared_contract_is_enumerable(self):
        """Every element of the contract is reachable from one object.

        An operator re-pointing this adapter at a provider whose contract
        is known has one place to look, and a change to any element is
        visible here rather than buried in a call site.
        """
        contract = zillow_service.DECLARED_PROVIDER_CONTRACT

        self.assertEqual(
            set(contract),
            {
                'method',
                'credential_header',
                'zip_codes_parameter',
                'listings_collection_key',
                'record_fields',
            },
        )
        self.assertEqual(contract['method'], 'GET')
        self.assertEqual(contract['credential_header'], API_KEY_HEADER)
        self.assertEqual(
            contract['zip_codes_parameter'],
            zillow_service.ZIP_CODES_PARAMETER,
        )
        self.assertEqual(
            contract['listings_collection_key'],
            zillow_service.LISTINGS_COLLECTION_KEY,
        )
        self.assertEqual(
            contract['record_fields'],
            zillow_service.PROVIDER_FIELD_SOURCES,
        )
        with self.assertRaises(TypeError):
            contract['method'] = 'POST'

    def test_the_request_is_assembled_from_the_declared_contract(self):
        """The sent request names the declared parameter and header."""
        contract = zillow_service.DECLARED_PROVIDER_CONTRACT

        with _provider(_answering({'listings': []})) as recorder:
            _fetch(zip_codes=('11111', '22222'))

        sent = recorder.sent
        self.assertEqual(sent.method, contract['method'])
        self.assertIn(contract['credential_header'], sent.headers)
        self.assertEqual(
            sent.url.params[contract['zip_codes_parameter']],
            '11111,22222',
        )

    def test_a_provider_reporting_no_listings_is_not_a_failure(self):
        """An empty collection is a result the pass completes on."""
        key = zillow_service.LISTINGS_COLLECTION_KEY

        with _provider(_answering({key: []})):
            self.assertEqual(_fetch(), [])

    def test_a_body_that_is_not_an_object_names_that_element(self):
        with _provider(_answering(['not', 'an', 'object'])):
            _refused(self, zillow_service.REASON_BODY_NOT_OBJECT)

    def test_a_collection_that_is_not_a_list_names_that_element(self):
        key = zillow_service.LISTINGS_COLLECTION_KEY

        with _provider(_answering({key: {'unexpected': 'shape'}})):
            _refused(self, zillow_service.REASON_COLLECTION_NOT_LIST)

    def test_a_body_carrying_no_collection_names_that_element(self):
        """A missing key is a contract difference, not an empty corpus.

        This is the shape a provider with a different response contract
        answers with, and reading it as zero listings is what made an
        unverified contract indistinguishable from a quiet corpus.
        """
        with _collecting_application_logs() as collector:
            with _provider(_answering({'results': [{'id': 1}]})):
                _refused(self, zillow_service.REASON_COLLECTION_NOT_LIST)

        contexts = _contexts(collector)
        self.assertIn(
            zillow_service.REASON_COLLECTION_NOT_LIST,
            [context.get('reason') for context in contexts],
        )

    def test_an_endpoint_outside_the_allowlist_names_that_reason(self):
        """A refusal to call at all is a failure, not an empty corpus."""
        with patch.object(
            zillow_service,
            'ZILLOW_API_URL',
            'https://attacker.invalid/collect',
        ):
            with _provider(_answering({'listings': []})) as recorder:
                _refused(
                    self, zillow_service.REASON_ENDPOINT_NOT_ALLOWED
                )

        self.assertEqual(recorder.requests, [])

    def test_every_refusal_reason_is_distinct(self):
        """No two causes share an identifier, so a query separates them."""
        reasons = [
            zillow_service.REASON_ENDPOINT_NOT_ALLOWED,
            zillow_service.REASON_CHUNK_TOO_LARGE,
            zillow_service.REASON_REQUEST_FAILED,
            zillow_service.REASON_RESPONSE_TOO_LARGE,
            zillow_service.REASON_BODY_NOT_DECODABLE,
            zillow_service.REASON_BODY_NOT_OBJECT,
            zillow_service.REASON_COLLECTION_NOT_LIST,
        ]

        self.assertEqual(len(set(reasons)), len(reasons))
        for reason in reasons:
            self.assertTrue(reason)

    def test_a_refusal_is_not_confusable_with_a_mapping_failure(self):
        """The two error kinds are separate types, caught separately."""
        self.assertFalse(
            issubclass(
                ListingProviderError, zillow_service.ListingMappingError
            )
        )
        self.assertFalse(
            issubclass(
                zillow_service.ListingMappingError, ListingProviderError
            )
        )


class TestZillowService(unittest.TestCase):
    def test_fetch_listings(self):
        payload = {
            'listings': [
                {'id': 1, 'address': '123 Main St', 'price': 300000},
                {'id': 2, 'address': '456 Elm St', 'price': 250000},
            ]
        }

        with _provider(_answering(payload)):
            listings = _fetch()

        self.assertEqual(len(listings), 2)
        self.assertEqual(listings[0]['address'], '123 Main St')
        self.assertEqual(listings[1]['price'], 250000)

    def test_api_key_travels_in_a_request_header(self):
        with _provider(_answering({'listings': []})) as recorder:
            _fetch()

        self.assertEqual(
            recorder.sent.headers[API_KEY_HEADER],
            settings.ZILLOW_API_KEY,
        )

    def test_api_key_is_absent_from_the_request_target(self):
        with _provider(_answering({'listings': []})) as recorder:
            _fetch()

        self.assertNotIn(
            settings.ZILLOW_API_KEY, str(recorder.sent.url)
        )

    def test_the_bound_request_identifier_is_sent_to_the_provider(self):
        token = bind_request_id('req-corr-1')
        try:
            with _provider(_answering({'listings': []})) as recorder:
                _fetch()
        finally:
            reset_request_id(token)

        self.assertEqual(
            recorder.sent.headers[zillow_service_module.REQUEST_ID_HEADER],
            'req-corr-1',
        )

    def test_no_correlation_header_is_sent_when_none_is_bound(self):
        token = bind_request_id(None)
        try:
            with _provider(_answering({'listings': []})) as recorder:
                _fetch()
        finally:
            reset_request_id(token)

        self.assertNotIn(
            zillow_service_module.REQUEST_ID_HEADER,
            recorder.sent.headers,
        )

    def test_the_correlation_header_carries_no_credential(self):
        token = bind_request_id('req-corr-2')
        try:
            with _provider(_answering({'listings': []})) as recorder:
                _fetch()
        finally:
            reset_request_id(token)

        sent = recorder.sent.headers[
            zillow_service_module.REQUEST_ID_HEADER
        ]
        self.assertNotIn(settings.ZILLOW_API_KEY, sent)

    def test_the_configured_endpoint_is_not_a_reserved_example_host(self):
        from backend.app.core.config import (
            LOCAL_ENVIRONMENT,
            Settings,
            _is_reserved_host,
            _value_host,
        )

        shipped = Settings.__fields__['ZILLOW_API_URL'].default
        host = _value_host(shipped)

        self.assertIsNotNone(host)
        self.assertTrue(_is_reserved_host(host))
        self.assertEqual(settings.ENVIRONMENT, LOCAL_ENVIRONMENT)

    def test_api_key_is_absent_from_the_query_string(self):
        with _provider(_answering({'listings': []})) as recorder:
            _fetch()

        query = recorder.sent.url.query.decode('utf-8')

        self.assertNotIn(settings.ZILLOW_API_KEY, query)
        self.assertNotIn(LEGACY_KEY_PARAM, query)

    def test_the_search_values_reach_the_provider(self):
        with _provider(_answering({'listings': []})) as recorder:
            _fetch(zip_codes=('90210', '10001'), filters={'max_rent': 3000})

        query = recorder.sent.url.query.decode('utf-8')

        self.assertIn('90210', query)
        self.assertIn('10001', query)
        self.assertIn('3000', query)

    def test_every_request_carries_a_timeout(self):
        with _provider(_answering({'listings': []})) as recorder:
            _fetch()

        timeout = recorder.sent.extensions['timeout']

        self.assertEqual(timeout['connect'], settings.HTTP_TIMEOUT_SECONDS)
        self.assertEqual(timeout['read'], settings.HTTP_TIMEOUT_SECONDS)
        self.assertGreater(settings.HTTP_TIMEOUT_SECONDS, 0)

    def test_the_client_factory_carries_the_configured_timeout(self):
        with zillow_service._client() as client:
            self.assertEqual(
                client.timeout.read, settings.HTTP_TIMEOUT_SECONDS
            )
            self.assertEqual(
                client.timeout.connect, settings.HTTP_TIMEOUT_SECONDS
            )

    def test_a_chunk_past_the_configured_size_is_refused_unsent(self):
        ceiling = int(settings.INGESTION_ZIP_CODE_CHUNK)
        oversized = [
            '9{0:04d}'.format(index) for index in range(ceiling + 1)
        ]

        with _collecting_application_logs() as collector:
            with _provider(_answering({'listings': []})) as recorder:
                _refused(
                    self,
                    zillow_service.REASON_CHUNK_TOO_LARGE,
                    zip_codes=oversized,
                )

        self.assertEqual(recorder.requests, [])
        self.assertIn(
            zillow_service.REASON_CHUNK_TOO_LARGE, _reasons(collector)
        )

    def test_a_chunk_at_the_configured_size_is_sent(self):
        ceiling = int(settings.INGESTION_ZIP_CODE_CHUNK)
        allowed = ['9{0:04d}'.format(index) for index in range(ceiling)]

        with _provider(_answering({'listings': []})) as recorder:
            self.assertEqual(_fetch(zip_codes=allowed), [])

        self.assertEqual(len(recorder.requests), 1)

    def test_a_refused_chunk_carries_no_credential_into_the_record(self):
        ceiling = int(settings.INGESTION_ZIP_CODE_CHUNK)
        oversized = [
            '9{0:04d}'.format(index) for index in range(ceiling + 1)
        ]

        with _collecting_application_logs() as collector:
            with _provider(_answering({'listings': []})):
                _refused(
                    self,
                    zillow_service.REASON_CHUNK_TOO_LARGE,
                    zip_codes=oversized,
                )

        for line in _rendered_log_lines(collector):
            self.assertNotIn(settings.ZILLOW_API_KEY, line)

    def test_provider_failure_is_raised_rather_than_returned(self):
        """A transport failure reaches the caller as a failure."""
        with _provider(
            _raising(
                lambda request: httpx.ConnectError(
                    'unreachable', request=request
                )
            )
        ):
            _refused(self, zillow_service.REASON_REQUEST_FAILED)

    def test_a_rejected_status_is_raised_rather_than_returned(self):
        """A status the provider refuses with is not an empty corpus."""
        with _provider(_answering({'listings': []}, status_code=503)):
            _refused(self, zillow_service.REASON_REQUEST_FAILED)

    def test_an_undecodable_body_is_raised_rather_than_returned(self):
        with _provider(_answering_bytes(b'not json at all')):
            _refused(self, zillow_service.REASON_BODY_NOT_DECODABLE)

    def test_a_declared_length_past_the_cap_is_refused_unread(self):
        cap = zillow_service.MAX_PROVIDER_RESPONSE_BYTES
        with _collecting_application_logs() as collector:
            with _provider(
                _answering_bytes(
                    b'{"listings": [{"id": 1}]}', declared=cap + 1
                )
            ):
                _refused(
                    self, zillow_service.REASON_RESPONSE_TOO_LARGE
                )

        self.assertIn(
            zillow_service.REASON_RESPONSE_TOO_LARGE,
            _reasons(collector),
        )
        self.assertIn(cap + 1, _measured_sizes(collector))

    def test_a_body_past_the_cap_stops_being_read(self):
        cap = zillow_service.MAX_PROVIDER_RESPONSE_BYTES
        chunk = b'x' * 65536
        produced = []
        with _collecting_application_logs() as collector:
            with _provider(
                _answering_in_chunks(chunk, 64, produced)
            ):
                _refused(
                    self, zillow_service.REASON_RESPONSE_TOO_LARGE
                )

        self.assertIn(
            zillow_service.REASON_RESPONSE_TOO_LARGE,
            _reasons(collector),
        )
        self.assertLess(len(produced) * len(chunk), 2 * cap)
        self.assertGreater(len(produced) * len(chunk), cap)

    def test_a_body_at_the_cap_is_accepted(self):
        cap = zillow_service.MAX_PROVIDER_RESPONSE_BYTES
        entry = {'id': 1, 'address': ''}
        empty = len(json.dumps({'listings': [entry]}).encode('utf-8'))
        entry['address'] = 'p' * (cap - empty)
        body = json.dumps({'listings': [entry]}).encode('utf-8')
        self.assertEqual(len(body), cap)

        with _provider(_answering_bytes(body)):
            listings = _fetch()

        self.assertEqual(len(listings), 1)

    def test_more_listings_than_the_cap_are_truncated(self):
        limit = zillow_service.MAX_PROVIDER_LISTINGS
        payload = {
            'listings': [{'id': index} for index in range(limit + 5)]
        }
        with _collecting_application_logs() as collector:
            with _provider(_answering(payload)):
                listings = _fetch()

        self.assertEqual(len(listings), limit)
        self.assertIn(
            zillow_service.REASON_TOO_MANY_LISTINGS, _reasons(collector)
        )

    def test_listings_at_the_cap_are_all_returned(self):
        limit = zillow_service.MAX_PROVIDER_LISTINGS
        payload = {'listings': [{'id': index} for index in range(limit)]}
        with _provider(_answering(payload)):
            self.assertEqual(len(_fetch()), limit)

    def test_no_search_value_reaches_a_log_record(self):
        postal_code = '90210'
        neighbourhood = 'PRIVATEFILTERVALUE'
        target = '%s?zip_codes=%s&neighborhood=%s' % (
            settings.ZILLOW_API_URL, postal_code, neighbourhood
        )
        self.assertIn(postal_code, target)
        self.assertIn(neighbourhood, target)
        with _collecting_application_logs() as collector:
            with _provider(
                _raising(
                    lambda request: httpx.ConnectError(
                        'failed for url ' + target,
                        request=request,
                    )
                )
            ):
                refusal = _refused(
                    self,
                    zillow_service.REASON_REQUEST_FAILED,
                    zip_codes=(postal_code,),
                    filters={'neighborhood': neighbourhood},
                )

        # The raised message travels to the caller, so it is held to the
        # same rule as the record: it names neither search value.
        self.assertNotIn(postal_code, str(refusal))
        self.assertNotIn(neighbourhood, str(refusal))
        self.assertTrue(collector.records)
        for record in collector.records:
            self.assertIsNone(record.exc_info)
        for line in _rendered_log_lines(collector):
            self.assertNotIn(postal_code, line)
            self.assertNotIn(neighbourhood, line)
            self.assertNotIn(settings.ZILLOW_API_KEY, line)
            self.assertNotIn(settings.ZILLOW_API_URL, line)

    def test_a_failure_is_recorded_as_its_class(self):
        with _collecting_application_logs() as collector:
            with _provider(
                _raising(
                    lambda request: httpx.ReadTimeout(
                        'timed out for %s?zip_codes=90210'
                        % settings.ZILLOW_API_URL,
                        request=request,
                    )
                )
            ):
                _refused(self, zillow_service.REASON_REQUEST_FAILED)

        contexts = _contexts(collector)
        self.assertTrue(contexts)
        self.assertEqual(contexts[0]['exception_type'], 'ReadTimeout')
        self.assertEqual(contexts[0]['exception_module'], 'httpx')

    def test_api_key_is_absent_from_every_log_record(self):
        key = settings.ZILLOW_API_KEY
        with _collecting_application_logs() as collector:
            with _provider(
                _raising(
                    lambda request: httpx.ConnectError(
                        'the credential ' + key + ' was rejected',
                        request=request,
                    )
                )
            ):
                refusal = _refused(
                    self, zillow_service.REASON_REQUEST_FAILED
                )

        self.assertNotIn(key, str(refusal))
        self.assertTrue(collector.records)
        for line in _rendered_log_lines(collector):
            self.assertNotIn(key, line)

    def test_the_credential_is_registered_for_replacement(self):
        key = settings.ZILLOW_API_KEY
        rendered = redact('provider rejected ' + key + ' upstream')

        self.assertNotIn(key, rendered)
        self.assertIn(REDACTION_PLACEHOLDER, rendered)


CONTEXT_FIELDS = (
    'reason',
    'response_bytes',
    'max_response_bytes',
    'received',
    'max_listings',
    'exception_type',
    'exception_module',
)


def _contexts(collector):
    """Returns the context each collected record carries.

    ``extra`` keys are set as attributes on the record itself, so each
    one is read back by name.
    """
    contexts = []
    for record in collector.records:
        context = dict(
            (name, getattr(record, name))
            for name in CONTEXT_FIELDS
            if hasattr(record, name)
        )
        if context:
            contexts.append(context)
    return contexts


def _reasons(collector):
    return [
        context['reason']
        for context in _contexts(collector)
        if context.get('reason')
    ]


def _measured_sizes(collector):
    return [
        context['response_bytes']
        for context in _contexts(collector)
        if context.get('response_bytes') is not None
    ]


class _SendGridResponse(object):

    def __init__(self, status_code=EMAIL_ACCEPTED_STATUS, body=b''):
        self.status_code = status_code
        self.body = body

    def getcode(self):
        return self.status_code

    def read(self):
        return self.body

    def info(self):
        return {}


class _SendGridBoundary(object):

    def __init__(self, error=None, status_code=EMAIL_ACCEPTED_STATUS):
        self.error = error
        self.status_code = status_code
        self.calls = []

    def install(self):
        boundary = self

        def _make_request(client, opener, request, timeout=None):
            boundary.calls.append({
                'method': request.get_method(),
                'url': request.full_url,
                'headers': dict(request.header_items()),
                'body': request.data,
                'timeout': timeout,
                'client_timeout': client.timeout,
                'url_path': list(client._url_path),
            })
            if boundary.error is not None:
                raise boundary.error
            return _SendGridResponse(boundary.status_code)

        return patch.object(HttpClient, '_make_request', _make_request)

    def one_call(self):
        assert len(self.calls) == 1, self.calls
        return self.calls[0]


class TestEmailService(unittest.TestCase):

    def test_send_email_transmits_the_documented_request(self):
        boundary = _SendGridBoundary()

        with boundary.install():
            delivered = send_email(
                RECIPIENT_EMAIL,
                EMAIL_SUBJECT,
                EMAIL_CONTENT,
            )

        self.assertTrue(delivered)
        call = boundary.one_call()
        self.assertEqual(call['method'], 'POST')
        self.assertEqual(call['url'], SENDGRID_SEND_URL)
        self.assertEqual(call['url_path'], SENDGRID_URL_PATH)
        self.assertEqual(
            call['headers']['Authorization'],
            'Bearer ' + settings.SENDGRID_API_KEY,
        )
        self.assertEqual(
            call['headers']['Content-type'], 'application/json'
        )
        self.assertEqual(
            call['client_timeout'], settings.HTTP_TIMEOUT_SECONDS
        )

        message = json.loads(call['body'].decode('utf-8'))
        self.assertEqual(
            message['from']['email'], settings.FROM_EMAIL
        )
        self.assertEqual(
            message['personalizations'][0]['to'][0]['email'],
            RECIPIENT_EMAIL,
        )
        self.assertEqual(message['subject'], EMAIL_SUBJECT)
        self.assertEqual(
            message['content'][0]['value'], EMAIL_CONTENT
        )
        self.assertEqual(
            message['content'][0]['type'], 'text/html'
        )

    def test_send_email_reports_a_status_the_provider_accepts(self):
        for status_code in EMAIL_DELIVERED_STATUSES:
            with self.subTest(status_code):
                boundary = _SendGridBoundary(status_code=status_code)
                with boundary.install():
                    self.assertTrue(send_email(
                        RECIPIENT_EMAIL, EMAIL_SUBJECT, EMAIL_CONTENT
                    ))

    def test_the_accepted_status_is_the_one_the_endpoint_reports(self):
        self.assertEqual(email_service_module.ACCEPTED_STATUS, 202)
        self.assertEqual(
            EMAIL_DELIVERED_STATUSES, (email_service_module.ACCEPTED_STATUS,)
        )

    def test_send_email_refuses_another_success_status(self):
        for status_code in EMAIL_UNEXPECTED_SUCCESS_STATUSES:
            with self.subTest(status_code):
                boundary = _SendGridBoundary(status_code=status_code)

                with _collecting_application_logs() as collector:
                    with boundary.install():
                        self.assertFalse(send_email(
                            RECIPIENT_EMAIL, EMAIL_SUBJECT, EMAIL_CONTENT
                        ))

                self.assertEqual(len(boundary.calls), 1)
                lines = _rendered_log_lines(collector)
                self.assertTrue(any(
                    EMAIL_FAILURE_MESSAGE in line for line in lines
                ))
                self.assertTrue(any(
                    str(status_code) in line for line in lines
                ))

    def test_send_email_reports_a_rejected_message(self):
        rejection = BadRequestsError(
            EMAIL_REJECTED_STATUS,
            'Bad Request',
            EMAIL_REJECTION_BODY,
            {},
        )
        boundary = _SendGridBoundary(error=rejection)

        with _collecting_application_logs() as collector:
            with boundary.install():
                self.assertFalse(send_email(
                    RECIPIENT_EMAIL, EMAIL_SUBJECT, EMAIL_CONTENT
                ))

        self.assertEqual(len(boundary.calls), 1)
        lines = _rendered_log_lines(collector)
        self.assertTrue(lines)
        self.assertTrue(any(
            EMAIL_FAILURE_MESSAGE in line for line in lines
        ))
        self.assertTrue(any(
            BadRequestsError.__name__ in line for line in lines
        ))
        for line in lines:
            self.assertNotIn(settings.SENDGRID_API_KEY, line)
            self.assertNotIn(RECIPIENT_EMAIL, line)

    def test_send_email_swallows_a_transport_failure(self):
        boundary = _SendGridBoundary(
            error=HTTPError(
                EMAIL_UNAVAILABLE_STATUS,
                'Service Unavailable',
                b'',
                {},
            )
        )

        with _collecting_application_logs() as collector:
            with boundary.install():
                self.assertFalse(send_email(
                    RECIPIENT_EMAIL, EMAIL_SUBJECT, EMAIL_CONTENT
                ))

        lines = _rendered_log_lines(collector)
        self.assertTrue(any(
            EMAIL_FAILURE_MESSAGE in line for line in lines
        ))
        for line in lines:
            self.assertNotIn(settings.SENDGRID_API_KEY, line)

    def test_send_email_swallows_a_client_construction_failure(self):
        with patch(
            EMAIL_MODULE + '.SendGridAPIClient',
            side_effect=RuntimeError('transport down'),
        ):
            self.assertFalse(
                send_email(
                    RECIPIENT_EMAIL, EMAIL_SUBJECT, EMAIL_CONTENT
                )
            )

    def test_a_failed_send_records_the_failure_on_the_logger(self):
        with _collecting_application_logs() as collector:
            self.assertFalse(_send_failing_with(EMAIL_FAILURE_DETAIL))

        failures = [
            record
            for record in collector.records
            if record.getMessage() == EMAIL_FAILURE_MESSAGE
        ]
        self.assertEqual(len(failures), 1)
        record = failures[0]
        self.assertEqual(record.levelno, logging.ERROR)
        self.assertEqual(record.name, EMAIL_MODULE)
        self.assertIsNone(record.exc_info)
        self.assertEqual(record.exception_type, 'RuntimeError')
        self.assertTrue(record.exception_module)
        self.assertEqual(record.reason, REASON_SEND_FAILED)
        self.assertIn(REDACTION_PLACEHOLDER, record.exception_message)
        self.assertNotIn(
            settings.SENDGRID_API_KEY, record.exception_message
        )
        self.assertNotIn(
            settings.SENDGRID_API_KEY, repr(vars(record))
        )

    def test_no_error_level_record_carries_a_traceback(self):
        with _collecting_application_logs() as collector:
            self.assertFalse(_send_failing_with(EMAIL_FAILURE_DETAIL))

        errors = [
            record
            for record in collector.records
            if record.levelno >= logging.ERROR
        ]
        self.assertTrue(errors)
        for record in errors:
            self.assertIsNone(record.exc_info)
            self.assertNotIn('Traceback', repr(vars(record)))

    def test_a_failed_send_reaches_no_rendered_line_with_the_key(self):
        for label, detail in (
            ('quoted in free prose', EMAIL_FAILURE_DETAIL),
            ('named beside a key', EMAIL_KEYED_FAILURE_DETAIL),
        ):
            with self.subTest(label):
                with _collecting_application_logs() as collector:
                    self.assertFalse(_send_failing_with(detail))

                self.assertTrue(collector.records)
                self.assertTrue(any(
                    REDACTION_PLACEHOLDER
                    in getattr(record, 'exception_message', '')
                    for record in collector.records
                ))
                for record in collector.records:
                    self.assertNotIn(
                        settings.SENDGRID_API_KEY, repr(vars(record))
                    )
                rendered = _rendered_log_lines(collector)
                for line in rendered:
                    self.assertNotIn(settings.SENDGRID_API_KEY, line)
                self.assertTrue(any(
                    REDACTION_PLACEHOLDER in line for line in rendered
                ))

    def test_the_send_path_writes_no_bare_output(self):
        for module in BARE_OUTPUT_FREE_MODULES:
            with self.subTest(module.__name__):
                source = inspect.getsource(module)
                self.assertNotIn('print(', source)


def test_a_failed_send_emits_one_redacted_structured_record():
    with _collecting_emitted_lines() as lines:
        assert _send_failing_with(EMAIL_FAILURE_DETAIL) is False

    for line in lines:
        assert settings.SENDGRID_API_KEY not in line
        assert BARE_PRINT_SIGNATURE not in line

    entries = _structured_entries(lines)
    failures = [
        entry
        for entry in entries
        if entry.get('message') == EMAIL_FAILURE_MESSAGE
    ]
    assert len(failures) == 1

    failure = failures[0]
    assert failure['level'] == 'ERROR'
    assert failure['logger'] == EMAIL_MODULE
    assert 'exception' not in failure
    context = failure['context']
    assert context['exception_type'] == 'RuntimeError'
    assert context['reason'] == REASON_SEND_FAILED
    assert REDACTION_PLACEHOLDER in context['exception_message']
    assert settings.SENDGRID_API_KEY not in context['exception_message']
    for entry in entries:
        assert 'Traceback' not in json.dumps(entry)


def test_a_rejected_send_records_the_status_it_was_refused_with():
    client = MagicMock()
    client.send.return_value = MagicMock(status_code=400)

    with _collecting_emitted_lines() as lines:
        with patch(
            EMAIL_MODULE + '.SendGridAPIClient', return_value=client
        ):
            assert send_email(
                EMAIL_RECIPIENT, EMAIL_SUBJECT, EMAIL_BODY
            ) is False

    entries = [json.loads(line) for line in lines]
    failures = [
        entry
        for entry in entries
        if entry.get('message') == EMAIL_FAILURE_MESSAGE
    ]
    assert len(failures) == 1

    failure = failures[0]
    assert failure['level'] == 'ERROR'
    assert failure['logger'] == EMAIL_MODULE
    assert failure['context']['status_code'] == 400
    assert failure['context']['expected_status_code'] == (
        email_service_module.ACCEPTED_STATUS
    )
    assert 'exception' not in failure
    assert settings.SENDGRID_API_KEY not in json.dumps(failure)


def test_a_failed_send_writes_no_failure_detail_to_a_stream(capsys):
    assert _send_failing_with(EMAIL_FAILURE_DETAIL) is False

    flush_log_queue(LOG_DRAIN_TIMEOUT)
    captured = capsys.readouterr()

    for stream in (captured.out, captured.err):
        assert BARE_PRINT_SIGNATURE not in stream
        assert settings.SENDGRID_API_KEY not in stream


def _run(coroutine):
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

    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.routes = []

    @staticmethod
    def _path(sent):
        return sent.url.path

    def handle(self, sent):
        self.routes.append(assert_paypal_request(sent))
        self.calls.append(sent)
        for suffix, status, payload in self.responses:
            if self._path(sent).endswith(suffix):
                return httpx.Response(status, json=payload)
        raise AssertionError(
            'no response is queued for {0} {1}'.format(
                sent.method, sent.url
            )
        )

    def paths(self):
        return [self._path(sent) for sent in self.calls]

    def matching(self, suffix):
        return [
            sent
            for sent in self.calls
            if self._path(sent).endswith(suffix)
        ]


class TestPayPalService(unittest.TestCase):

    def setUp(self):
        paypal_service.reset_access_token_cache()
        self.engine = enforce_sqlite_foreign_keys(
            create_engine(
                'sqlite://',
                connect_args={'check_same_thread': False},
                poolclass=StaticPool,
            )
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
            self.assertEqual(
                refused.exception.issue,
                paypal_service.ISSUE_ORDER_ALREADY_CAPTURED,
            )
            self.assertTrue(
                subscriptions_module._is_already_captured(
                    refused.exception
                )
            )
            self.assertEqual(
                refused.exception.audit_fields()["provider_issue"],
                paypal_service.ISSUE_ORDER_ALREADY_CAPTURED,
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

    def test_another_refusal_carries_its_own_issue_code(self):
        _recorder, transport = self._transport([
            ('/capture', 422, {
                'name': 'UNPROCESSABLE_ENTITY',
                'details': [{'issue': 'INSTRUMENT_DECLINED'}],
            }),
        ])
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
        self.assertEqual(refused.exception.issue, 'INSTRUMENT_DECLINED')
        self.assertFalse(
            subscriptions_module._is_already_captured(refused.exception)
        )

    def test_an_error_body_naming_no_issue_carries_no_code(self):
        _recorder, transport = self._transport([
            ('/capture', 422, {'message': 'the order was not settled'}),
        ])
        with transport:
            with self.assertRaises(
                paypal_service.PayPalAPIError
            ) as refused:
                _run(paypal_service.capture_order(
                    self.db, ORDER_ID, self.owner
                ))
        self.assertIsNone(refused.exception.issue)
        self.assertFalse(
            subscriptions_module._is_already_captured(refused.exception)
        )

    def test_the_error_name_is_read_when_no_detail_names_an_issue(self):
        _recorder, transport = self._transport([
            ('/capture', 422, {
                'name': paypal_service.ISSUE_ORDER_ALREADY_CAPTURED,
                'details': [{'description': 'no issue field here'}],
            }),
        ])
        with transport:
            with self.assertRaises(
                paypal_service.PayPalAPIError
            ) as refused:
                _run(paypal_service.capture_order(
                    self.db, ORDER_ID, self.owner
                ))
        self.assertEqual(
            refused.exception.issue,
            paypal_service.ISSUE_ORDER_ALREADY_CAPTURED,
        )

    def test_only_an_allowlisted_field_of_the_error_body_is_read(self):
        _recorder, transport = self._transport([
            ('/capture', 422, {
                'issue': paypal_service.ISSUE_ORDER_ALREADY_CAPTURED,
                'error_description': (
                    paypal_service.ISSUE_ORDER_ALREADY_CAPTURED
                ),
                'debug_id': paypal_service.ISSUE_ORDER_ALREADY_CAPTURED,
            }),
        ])
        with transport:
            with self.assertRaises(
                paypal_service.PayPalAPIError
            ) as refused:
                _run(paypal_service.capture_order(
                    self.db, ORDER_ID, self.owner
                ))
        self.assertIsNone(refused.exception.issue)

    def test_an_issue_value_outside_the_accepted_shape_is_discarded(self):
        for label, value in (
            ('lower case', 'order_already_captured'),
            ('punctuated', 'ORDER-ALREADY-CAPTURED'),
            ('spaced prose', 'ORDER ALREADY CAPTURED'),
            ('over the ceiling', 'A' * 65),
            ('not a string', 17),
            ('empty', ''),
        ):
            with self.subTest(label):
                _recorder, transport = self._transport([
                    ('/capture', 422, {'details': [{'issue': value}]}),
                ])
                with transport:
                    with self.assertRaises(
                        paypal_service.PayPalAPIError
                    ) as refused:
                        _run(paypal_service.capture_order(
                            self.db, ORDER_ID, self.owner
                        ))
                self.assertIsNone(refused.exception.issue)

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


class TestProviderCorrelation(unittest.TestCase):

    def _contexts(self, collector):
        return [
            json.loads(line).get(CONTEXT_FIELD, {})
            for line in _rendered_log_lines(collector)
        ]

    def test_the_bound_identifier_reaches_a_listing_provider_record(self):
        token = bind_request_id(BOUND_REQUEST_ID)
        try:
            with _collecting_application_logs() as collector:
                with _provider(
                    _raising(
                        lambda request: httpx.ConnectError(
                            PROVIDER_UNREACHABLE_DETAIL,
                            request=request,
                        )
                    )
                ):
                    with self.assertRaises(ListingProviderError):
                        fetch_listings(zip_codes=['12345'], filters={})
        finally:
            reset_request_id(token)

        contexts = self._contexts(collector)
        self.assertTrue(contexts)
        self.assertTrue(any(
            context.get(REQUEST_ID_FIELD) == BOUND_REQUEST_ID
            for context in contexts
        ))

    def test_the_bound_identifier_reaches_an_email_provider_record(self):
        boundary = _SendGridBoundary(
            error=BadRequestsError(
                EMAIL_REJECTED_STATUS,
                'Bad Request',
                EMAIL_REJECTION_BODY,
                {},
            )
        )
        token = bind_request_id(BOUND_REQUEST_ID)
        try:
            with _collecting_application_logs() as collector:
                with boundary.install():
                    send_email(
                        RECIPIENT_EMAIL, EMAIL_SUBJECT, EMAIL_CONTENT
                    )
        finally:
            reset_request_id(token)

        contexts = self._contexts(collector)
        self.assertTrue(any(
            context.get(REQUEST_ID_FIELD) == BOUND_REQUEST_ID
            for context in contexts
        ))


class TestProviderContractGuard(unittest.TestCase):

    def _authenticated(self, **overrides):
        arguments = {
            'method': 'POST',
            'url': settings.PAYPAL_API_BASE + ORDER_PATH + '/capture',
            'headers': {
                'Authorization': 'Bearer ' + STAND_IN_GRANT,
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'Prefer': 'return=representation',
            },
            'json_body': {},
            'timeout': settings.HTTP_TIMEOUT_SECONDS,
        }
        arguments.update(overrides)
        return arguments

    def test_a_well_formed_settle_call_is_accepted(self):
        self.assertEqual(
            assert_paypal_contract(**self._authenticated()),
            PAYPAL_ROUTE_CAPTURE_ORDER,
        )

    def test_another_host_is_refused(self):
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(**self._authenticated(
                url='https://api-m.paypal.com' + ORDER_PATH + '/capture'
            ))

    def test_an_unknown_path_is_refused(self):
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(**self._authenticated(
                url=settings.PAYPAL_API_BASE + '/v2/checkout/refunds'
            ))

    def test_the_wrong_method_is_refused(self):
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(**self._authenticated(method='GET'))

    def test_a_missing_grant_is_refused(self):
        headers = self._authenticated()['headers'].copy()
        del headers['Authorization']
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(
                **self._authenticated(headers=headers)
            )

    def test_an_empty_grant_is_refused(self):
        headers = self._authenticated()['headers'].copy()
        headers['Authorization'] = 'Bearer  '
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(
                **self._authenticated(headers=headers)
            )

    def test_a_missing_body_is_refused(self):
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(
                **self._authenticated(json_body=None)
            )

    def test_a_missing_representation_preference_is_refused(self):
        headers = self._authenticated()['headers'].copy()
        del headers['Prefer']
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(
                **self._authenticated(headers=headers)
            )

    def test_a_missing_timeout_is_refused(self):
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(**self._authenticated(timeout=None))

    def test_another_timeout_is_refused(self):
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(**self._authenticated(
                timeout=settings.HTTP_TIMEOUT_SECONDS + 1
            ))

    def test_a_credential_exchange_without_the_grant_type_is_refused(self):
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(
                method='POST',
                url=settings.PAYPAL_API_BASE + PAYPAL_OAUTH_PATH,
                headers={'Accept': 'application/json'},
                data={},
                auth=(
                    settings.PAYPAL_CLIENT_ID,
                    settings.PAYPAL_CLIENT_SECRET,
                ),
                timeout=settings.HTTP_TIMEOUT_SECONDS,
            )

    def test_a_credential_exchange_without_credentials_is_refused(self):
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(
                method='POST',
                url=settings.PAYPAL_API_BASE + PAYPAL_OAUTH_PATH,
                headers={'Accept': 'application/json'},
                data={'grant_type': 'client_credentials'},
                auth=None,
                timeout=settings.HTTP_TIMEOUT_SECONDS,
            )

    def test_a_verifier_document_missing_a_field_is_refused(self):
        document = dict(
            (field, 'value') for field in PAYPAL_VERIFY_FIELDS
        )
        document['webhook_id'] = settings.PAYPAL_WEBHOOK_ID
        del document['transmission_sig']
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(**self._authenticated(
                url=settings.PAYPAL_API_BASE + PAYPAL_VERIFY_PATH,
                json_body=document,
            ))

    def test_a_verifier_document_naming_another_webhook_is_refused(self):
        document = dict(
            (field, 'value') for field in PAYPAL_VERIFY_FIELDS
        )
        document['webhook_id'] = 'another-webhook-identifier'
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(**self._authenticated(
                url=settings.PAYPAL_API_BASE + PAYPAL_VERIFY_PATH,
                json_body=document,
            ))


def _created_order_body(plan_id=PLAN_ID):
    plan = get_plan(plan_id)
    return {
        'intent': 'CAPTURE',
        'purchase_units': [
            {
                'amount': {
                    'currency_code': plan.currency,
                    'value': format_amount(plan.amount),
                },
                'description': 'Subscription Payment',
            }
        ],
        'payment_source': {
            'paypal': {
                'experience_context': {
                    'return_url': 'https://app.example/r',
                    'cancel_url': 'https://app.example/c',
                    'user_action': 'PAY_NOW',
                    'shipping_preference': 'NO_SHIPPING',
                    'payment_method_preference': (
                        'IMMEDIATE_PAYMENT_REQUIRED'
                    ),
                }
            }
        },
    }


def _without(mapping, *path):
    altered = copy.deepcopy(mapping)
    target = altered
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]
    return altered


def _replacing(mapping, path, value):
    altered = copy.deepcopy(mapping)
    target = altered
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return altered


_CONTEXT = ('payment_source', 'paypal', 'experience_context')

_AMOUNT = ('purchase_units', 0, 'amount')


class TestTheCreateOrderBodyContract(unittest.TestCase):

    def _assert_refused(self, document):
        with self.assertRaises(PayPalContractError):
            assert_create_order_body(document)

    def test_the_complete_document_is_accepted(self):
        assert_create_order_body(_created_order_body())

    def test_every_catalog_plan_prices_an_acceptable_order(self):
        for plan_id in sorted(PLAN_IDS):
            with self.subTest(plan_id):
                assert_create_order_body(_created_order_body(plan_id))

    def test_a_body_that_is_not_an_object_is_refused(self):
        for label, document in (
            ('a list', [_created_order_body()]),
            ('a string', 'intent=CAPTURE'),
            ('nothing', None),
        ):
            with self.subTest(label):
                self._assert_refused(document)

    def test_an_added_top_level_field_is_refused(self):
        self._assert_refused(
            _replacing(_created_order_body(), ('payer',), {'x': 1})
        )

    def test_a_missing_intent_is_refused(self):
        self._assert_refused(_without(_created_order_body(), 'intent'))

    def test_another_intent_is_refused(self):
        self._assert_refused(
            _replacing(_created_order_body(), ('intent',), 'AUTHORIZE')
        )

    def test_missing_purchase_units_are_refused(self):
        self._assert_refused(
            _without(_created_order_body(), 'purchase_units')
        )

    def test_more_than_one_purchase_unit_is_refused(self):
        document = _created_order_body()
        document['purchase_units'].append(
            copy.deepcopy(document['purchase_units'][0])
        )
        self._assert_refused(document)

    def test_an_added_purchase_unit_field_is_refused(self):
        self._assert_refused(
            _replacing(
                _created_order_body(),
                ('purchase_units', 0, 'reference_id'),
                'unit-1',
            )
        )

    def test_a_missing_description_is_refused(self):
        self._assert_refused(
            _without(_created_order_body(), 'purchase_units', 0,
                     'description')
        )

    def test_another_description_is_refused(self):
        self._assert_refused(
            _replacing(
                _created_order_body(),
                ('purchase_units', 0, 'description'),
                'Donation',
            )
        )

    def test_a_missing_amount_is_refused(self):
        self._assert_refused(
            _without(_created_order_body(), 'purchase_units', 0, 'amount')
        )

    def test_an_added_amount_field_is_refused(self):
        self._assert_refused(
            _replacing(
                _created_order_body(),
                _AMOUNT + ('breakdown',),
                {},
            )
        )

    def test_a_price_outside_the_catalog_is_refused(self):
        for label, value in (
            ('a cent below', '9.98'),
            ('a cent above', '10.00'),
            ('nothing at all', '0.00'),
            ('unformatted', '9.9'),
        ):
            with self.subTest(label):
                self._assert_refused(
                    _replacing(
                        _created_order_body(),
                        _AMOUNT + ('value',),
                        value,
                    )
                )

    def test_another_currency_is_refused(self):
        self._assert_refused(
            _replacing(
                _created_order_body(),
                _AMOUNT + ('currency_code',),
                'EUR',
            )
        )

    def test_a_missing_payment_source_is_refused(self):
        self._assert_refused(
            _without(_created_order_body(), 'payment_source')
        )

    def test_another_payment_source_is_refused(self):
        self._assert_refused(
            _replacing(
                _created_order_body(),
                ('payment_source',),
                {'card': {'number': '4111111111111111'}},
            )
        )

    def test_a_missing_experience_context_is_refused(self):
        self._assert_refused(
            _without(
                _created_order_body(),
                'payment_source',
                'paypal',
                'experience_context',
            )
        )

    def test_an_added_experience_context_field_is_refused(self):
        self._assert_refused(
            _replacing(
                _created_order_body(),
                _CONTEXT + ('brand_name',),
                'Apartment Finder',
            )
        )

    def test_each_fixed_experience_value_is_required(self):
        for field, value in (
            ('user_action', 'CONTINUE'),
            ('shipping_preference', 'GET_FROM_FILE'),
            ('payment_method_preference', 'UNRESTRICTED'),
        ):
            with self.subTest(field + ' altered'):
                self._assert_refused(
                    _replacing(
                        _created_order_body(),
                        _CONTEXT + (field,),
                        value,
                    )
                )
            with self.subTest(field + ' absent'):
                self._assert_refused(
                    _without(
                        _created_order_body(),
                        'payment_source',
                        'paypal',
                        'experience_context',
                        field,
                    )
                )

    def test_each_redirect_target_must_be_absolute(self):
        for field in ('return_url', 'cancel_url'):
            for label, value in (
                ('absent', None),
                ('blank', '   '),
                ('relative', '/subscription'),
                ('not text', 17),
            ):
                with self.subTest(field + ' is ' + label):
                    self._assert_refused(
                        _replacing(
                            _created_order_body(),
                            _CONTEXT + (field,),
                            value,
                        )
                    )


class TestTheCaptureBodyContract(unittest.TestCase):

    def test_the_empty_object_is_accepted(self):
        assert_capture_body({})

    def test_any_member_is_refused(self):
        for label, document in (
            ('a payer identifier', {'payer_id': 'PAYER-1'}),
            ('an amount', {'amount': {'value': '9.99'}}),
            ('a note', {'note_to_payer': 'thanks'}),
            ('nothing at all', None),
            ('a list', []),
            ('a string', ''),
        ):
            with self.subTest(label):
                with self.assertRaises(PayPalContractError):
                    assert_capture_body(document)

    def test_the_guard_refuses_a_settle_call_carrying_a_body(self):
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(
                method='POST',
                url=(
                    settings.PAYPAL_API_BASE + ORDER_PATH + '/capture'
                ),
                headers={
                    'Authorization': 'Bearer ' + STAND_IN_GRANT,
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'Prefer': 'return=representation',
                },
                json_body={'payer_id': 'PAYER-1'},
                timeout=settings.HTTP_TIMEOUT_SECONDS,
            )

    def test_the_guard_refuses_a_created_order_priced_elsewhere(self):
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(
                method='POST',
                url=settings.PAYPAL_API_BASE + PAYPAL_ORDERS_PATH,
                headers={
                    'Authorization': 'Bearer ' + STAND_IN_GRANT,
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                },
                json_body=_replacing(
                    _created_order_body(),
                    _AMOUNT + ('value',),
                    '0.01',
                ),
                timeout=settings.HTTP_TIMEOUT_SECONDS,
            )


class TestProviderCredentialRegistration(unittest.TestCase):

    def test_every_configured_provider_credential_is_registered(self):
        for name in PROVIDER_SECRET_SETTINGS:
            configured = getattr(settings, name)
            with self.subTest(name):
                self.assertGreaterEqual(
                    len(configured), MIN_SECRET_VALUE_LENGTH
                )
                rendered = redact(
                    'the provider rejected ' + configured + ' upstream'
                )
                self.assertNotIn(configured, rendered)
                self.assertIn(REDACTION_PLACEHOLDER, rendered)

    def test_a_registrable_credential_is_accepted_and_held(self):
        value = 'v' * MIN_SECRET_VALUE_LENGTH
        held = register_required_secret_values(value)

        self.assertGreaterEqual(held, 1)
        self.assertNotIn(value, redact('provider prose ' + value))

    def test_a_credential_the_registry_refuses_raises(self):
        value = 'w' * (MIN_SECRET_VALUE_LENGTH - 1)

        with self.assertRaises(ValueError) as raised:
            register_required_secret_values(value)

        message = str(raised.exception)
        self.assertNotIn(value, message)
        self.assertIn('could not be registered', message)
        self.assertIn(value, redact('provider prose ' + value))

    def test_a_value_that_is_not_text_raises(self):
        with self.assertRaises(ValueError):
            register_required_secret_values(None)


class TestProviderEventTaxonomy(unittest.TestCase):

    def test_a_discarded_entry_warns_under_a_stable_reason(self):
        payload = {'listings': [{'id': 1}, 'not-an-object']}
        with _collecting_application_logs() as collector:
            with _provider(_answering(payload)):
                self.assertEqual(len(_fetch()), 1)

        discards = [
            record
            for record in collector.records
            if getattr(record, 'reason', None)
            == zillow_service.REASON_LISTING_NOT_OBJECT
        ]
        self.assertEqual(len(discards), 1)
        self.assertEqual(discards[0].levelno, logging.WARNING)
        self.assertEqual(discards[0].received, 2)
        self.assertEqual(discards[0].discarded, 1)

    def test_a_truncated_page_warns_under_a_stable_reason(self):
        over = zillow_service.MAX_PROVIDER_LISTINGS + 3
        payload = {'listings': [{'id': index} for index in range(over)]}
        with _collecting_application_logs() as collector:
            with _provider(_answering(payload)):
                returned = _fetch()

        self.assertEqual(
            len(returned), zillow_service.MAX_PROVIDER_LISTINGS
        )
        truncations = [
            record
            for record in collector.records
            if getattr(record, 'reason', None)
            == zillow_service.REASON_TOO_MANY_LISTINGS
        ]
        self.assertEqual(len(truncations), 1)
        self.assertEqual(truncations[0].levelno, logging.WARNING)

    def test_no_partial_success_is_recorded_at_error_level(self):
        payload = {
            'listings': ['not-an-object']
            + [{'id': index} for index in range(3)]
        }
        with _collecting_application_logs() as collector:
            with _provider(_answering(payload)):
                self.assertEqual(len(_fetch()), 3)

        for record in collector.records:
            self.assertLess(record.levelno, logging.ERROR)

    def test_a_whole_refused_call_is_still_an_error(self):
        with _collecting_application_logs() as collector:
            with _provider(_answering({'listings': []}, status_code=500)):
                _refused(self, zillow_service.REASON_REQUEST_FAILED)

        self.assertTrue([
            record
            for record in collector.records
            if record.levelno >= logging.ERROR
        ])

    def test_a_completed_rest_call_is_not_collected_at_information(self):
        source = inspect.getsource(paypal_service)
        for message in (
            'PayPal REST call completed',
            'PayPal REST read completed',
        ):
            with self.subTest(message):
                index = source.index(message)
                emitter = source.rindex('logger.', 0, index)
                self.assertTrue(
                    source.startswith('logger.debug(', emitter),
                    source[emitter:index],
                )


class TestOutboundCorrelation(unittest.TestCase):

    def test_the_provider_call_carries_the_bound_trace(self):
        token = bind_trace_context()
        try:
            expected = current_traceparent()
            with _provider(_answering({'listings': []})) as recorder:
                _fetch()
        finally:
            reset_trace_context(token)

        self.assertTrue(expected)
        self.assertEqual(
            recorder.sent.headers[TRACEPARENT_HEADER], expected
        )

    def test_no_header_is_sent_when_no_trace_is_bound(self):
        with _provider(_answering({'listings': []})) as recorder:
            _fetch()

        self.assertNotIn(TRACEPARENT_HEADER, recorder.sent.headers)

    def test_the_credential_header_survives_the_addition(self):
        token = bind_trace_context()
        try:
            with _provider(_answering({'listings': []})) as recorder:
                _fetch()
        finally:
            reset_trace_context(token)

        self.assertEqual(
            recorder.sent.headers[API_KEY_HEADER],
            settings.ZILLOW_API_KEY,
        )


class TestOutboundClientRecordsAreGoverned(unittest.TestCase):

    def test_a_client_record_naming_the_target_loses_its_query(self):
        postal_code = '90210'
        neighbourhood = 'PRIVATEFILTERVALUE'
        target = '%s?zip_codes=%s&neighborhood=%s&api_key=%s' % (
            settings.ZILLOW_API_URL,
            postal_code,
            neighbourhood,
            settings.ZILLOW_API_KEY,
        )
        with _collecting_emitted_lines() as lines:
            with _provider(_answering({'listings': []})):
                _fetch(
                    zip_codes=(postal_code,),
                    filters={'neighborhood': neighbourhood},
                )
            logging.getLogger('httpx').warning(
                'HTTP Request: GET %s', target
            )
            logging.getLogger('httpcore.connection').warning(
                'connect_tcp.started for %s', target
            )

        self.assertTrue(lines)
        for line in lines:
            self.assertNotIn(postal_code, line)
            self.assertNotIn(neighbourhood, line)
            self.assertNotIn(settings.ZILLOW_API_KEY, line)
        entries = _structured_entries(lines)
        self.assertTrue([
            entry
            for entry in entries
            if str(entry.get('logger', '')).startswith('httpx')
        ])


if __name__ == '__main__':
    unittest.main()
