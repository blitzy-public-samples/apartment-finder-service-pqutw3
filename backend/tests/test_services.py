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

#: Path of the order the contract cases address.
ORDER_PATH = PAYPAL_ORDERS_PATH + '/' + ORDER_ID

#: Grant the contract cases present.
STAND_IN_GRANT = 'contract-case-access-token'
APPROVAL_URL = 'https://www.sandbox.paypal.com/checkoutnow?token=1'

#: Header the listing provider credential is carried in.
API_KEY_HEADER = 'X-API-Key'

#: Query parameter name the cases below assert the credential is absent
#: from, by name and by value.
LEGACY_KEY_PARAM = 'api_key'

#: Target the SendGrid package transmits a message to.
SENDGRID_SEND_URL = 'https://api.sendgrid.com/v3/mail/send'

#: Segments the package appends to reach that target. The service
#: configures the timeout on the root client and the package copies it
#: onto each chained sub-client it builds to walk them.
SENDGRID_URL_PATH = ['mail', 'send']

#: Address the delivery cases send to.
RECIPIENT_EMAIL = 'test@example.com'

#: Subject the delivery cases send.
EMAIL_SUBJECT = 'Test Notification'

#: Body the delivery cases send.
EMAIL_CONTENT = '<p>This is a test notification.</p>'

#: Status the provider reports for an accepted message.
EMAIL_ACCEPTED_STATUS = 202

#: The only status the service reports as a delivery.
EMAIL_DELIVERED_STATUSES = (EMAIL_ACCEPTED_STATUS,)

#: Statuses in the success range that the Mail Send endpoint does not
#: report for a queued message. Reaching one means the request reached
#: something other than that endpoint, so the service reports a failure.
EMAIL_UNEXPECTED_SUCCESS_STATUSES = (200, 201, 203, 204)

#: Status the rejection case reports.
EMAIL_REJECTED_STATUS = 400

#: Status the unreachable case reports.
EMAIL_UNAVAILABLE_STATUS = 503

#: Body the rejection case carries.
EMAIL_REJECTION_BODY = b'{"errors":[{"message":"bad request"}]}'

#: Message the service records when a delivery fails. Read from the
#: module, so a message the module changes cannot leave these cases
#: silently matching nothing.
EMAIL_FAILURE_MESSAGE = email_service_module.EMAIL_FAILURE_MESSAGE

#: Reason the service records beside that message.
REASON_SEND_FAILED = email_service_module.REASON_SEND_FAILED

#: Detail carried by the bound transport failure below. It is plain
#: prose naming no credential and no key.
PROVIDER_UNREACHABLE_DETAIL = 'the listing provider was unreachable'

#: Correlation identifier the provider cases bind before calling.
BOUND_REQUEST_ID = 'caller0trace0provider1'

#: Address every notification case sends to.
EMAIL_RECIPIENT = 'notified@example.com'

#: Body every notification case sends.
EMAIL_BODY = 'Three listings match your saved search.'

#: Failure detail quoting the notification credential in free prose,
#: with no key name beside it.
EMAIL_FAILURE_DETAIL = (
    'the provider rejected the credential '
    + settings.SENDGRID_API_KEY
)

#: Failure detail naming the notification credential beside a
#: credential-shaped key.
EMAIL_KEYED_FAILURE_DETAIL = (
    'unauthorized: api_key=' + settings.SENDGRID_API_KEY
)

#: Exactly what a failed send wrote to standard output before its
#: failure path was routed through the structured logger.
BARE_PRINT_SIGNATURE = EMAIL_FAILURE_DETAIL

#: Longest the assertions below wait for the queue-backed log listener
#: to write every record one send produced.
LOG_DRAIN_TIMEOUT = 5.0

#: Modules whose bare output calls were replaced by the structured
#: logger. None of them may write to a stream directly.
BARE_OUTPUT_FREE_MODULES = (
    email_service_module,
    zillow_service_module,
    listing_updater_module,
)


def _send_failing_with(detail):
    """Runs one send whose provider construction raises ``detail``."""
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


class _ProviderRecorder:
    """Answers provider calls with ``responder`` and records each one."""

    def __init__(self, responder):
        self._responder = responder
        self.requests = []

    def handle(self, request):
        self.requests.append(request)
        return self._responder(request)

    @property
    def sent(self):
        """Returns the one request the provider received."""
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
    """Returns a responder answering with ``payload`` as a JSON body."""

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
    """Returns a responder that fails the way the provider would."""

    def responder(request):
        raise error_factory(request)

    return responder


def _fetch(zip_codes=('12345',), filters=None):
    """Runs one provider fetch with the module's own entry point."""
    return fetch_listings(
        zip_codes=list(zip_codes), filters=dict(filters or {})
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
        """The credential is carried in the provider request's headers."""
        with _provider(_answering({'listings': []})) as recorder:
            _fetch()

        self.assertEqual(
            recorder.sent.headers[API_KEY_HEADER],
            settings.ZILLOW_API_KEY,
        )

    def test_api_key_is_absent_from_the_request_target(self):
        """The credential appears nowhere in the sent target."""
        with _provider(_answering({'listings': []})) as recorder:
            _fetch()

        self.assertNotIn(
            settings.ZILLOW_API_KEY, str(recorder.sent.url)
        )

    def test_the_bound_request_identifier_is_sent_to_the_provider(self):
        """The provider receives the identifier the local record carries.

        Without it a provider-side record can only be matched to a local
        one by timestamp, which is a guess. Sending it makes the join
        exact from either side.
        """
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
        """An unbound call sends no empty identifier.

        A blank header would be indistinguishable from a real one on the
        provider's side, so the header is omitted instead.
        """
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
        """The identifier is not a place a secret can leak into."""
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
        """A deployed configuration cannot address the shipped default.

        The endpoint this repository ships is a reserved documentation
        domain, which stands in for a provider contract this repository
        never verified against a real service. The settings refuse it
        outside a local environment, so a deployment must name a real
        endpoint before any call is made. This asserts that refusal from
        the service's own side.
        """
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
        """The credential appears in no query parameter, name or value.

        The parameter name the credential previously travelled under is
        asserted absent alongside the value itself.
        """
        with _provider(_answering({'listings': []})) as recorder:
            _fetch()

        query = recorder.sent.url.query.decode('utf-8')

        self.assertNotIn(settings.ZILLOW_API_KEY, query)
        self.assertNotIn(LEGACY_KEY_PARAM, query)

    def test_the_search_values_reach_the_provider(self):
        """The caller's search terms are sent, and only sent."""
        with _provider(_answering({'listings': []})) as recorder:
            _fetch(zip_codes=('90210', '10001'), filters={'max_rent': 3000})

        query = recorder.sent.url.query.decode('utf-8')

        self.assertIn('90210', query)
        self.assertIn('10001', query)
        self.assertIn('3000', query)

    def test_every_request_carries_a_timeout(self):
        """The provider call is bounded by the configured timeout."""
        with _provider(_answering({'listings': []})) as recorder:
            _fetch()

        timeout = recorder.sent.extensions['timeout']

        self.assertEqual(timeout['connect'], settings.HTTP_TIMEOUT_SECONDS)
        self.assertEqual(timeout['read'], settings.HTTP_TIMEOUT_SECONDS)
        self.assertGreater(settings.HTTP_TIMEOUT_SECONDS, 0)

    def test_the_client_factory_carries_the_configured_timeout(self):
        """The client the service builds is bounded before any call."""
        with zillow_service._client() as client:
            self.assertEqual(
                client.timeout.read, settings.HTTP_TIMEOUT_SECONDS
            )
            self.assertEqual(
                client.timeout.connect, settings.HTTP_TIMEOUT_SECONDS
            )

    def test_a_chunk_past_the_configured_size_is_refused_unsent(self):
        """More postal codes than one request accepts issues no call.

        The caller chunks to the same setting, so an oversized list is a
        caller defect rather than provider input, and it is refused
        before a request is assembled.
        """
        ceiling = int(settings.INGESTION_ZIP_CODE_CHUNK)
        oversized = [
            '9{0:04d}'.format(index) for index in range(ceiling + 1)
        ]

        with _collecting_application_logs() as collector:
            with _provider(_answering({'listings': []})) as recorder:
                self.assertEqual(_fetch(zip_codes=oversized), [])

        self.assertEqual(recorder.requests, [])
        self.assertIn(
            zillow_service.REASON_CHUNK_TOO_LARGE, _reasons(collector)
        )

    def test_a_chunk_at_the_configured_size_is_sent(self):
        """The configured size is the largest chunk accepted."""
        ceiling = int(settings.INGESTION_ZIP_CODE_CHUNK)
        allowed = ['9{0:04d}'.format(index) for index in range(ceiling)]

        with _provider(_answering({'listings': []})) as recorder:
            self.assertEqual(_fetch(zip_codes=allowed), [])

        self.assertEqual(len(recorder.requests), 1)

    def test_a_refused_chunk_carries_no_credential_into_the_record(self):
        """The refusal names counts only, never the key or the codes."""
        ceiling = int(settings.INGESTION_ZIP_CODE_CHUNK)
        oversized = [
            '9{0:04d}'.format(index) for index in range(ceiling + 1)
        ]

        with _collecting_application_logs() as collector:
            with _provider(_answering({'listings': []})):
                _fetch(zip_codes=oversized)

        for line in _rendered_log_lines(collector):
            self.assertNotIn(settings.ZILLOW_API_KEY, line)

    def test_provider_failure_yields_an_empty_list(self):
        with _provider(
            _raising(
                lambda request: httpx.ConnectError(
                    'unreachable', request=request
                )
            )
        ):
            self.assertEqual(_fetch(), [])

    def test_a_rejected_status_yields_an_empty_list(self):
        """A status the provider refuses with contributes nothing."""
        with _provider(_answering({'listings': []}, status_code=503)):
            self.assertEqual(_fetch(), [])

    def test_an_undecodable_body_yields_an_empty_list(self):
        with _provider(_answering_bytes(b'not json at all')):
            self.assertEqual(_fetch(), [])

    def test_a_declared_length_past_the_cap_is_refused_unread(self):
        """A body announcing itself as oversized is never read."""
        cap = zillow_service.MAX_PROVIDER_RESPONSE_BYTES
        with _collecting_application_logs() as collector:
            with _provider(
                _answering_bytes(
                    b'{"listings": [{"id": 1}]}', declared=cap + 1
                )
            ):
                self.assertEqual(_fetch(), [])

        self.assertIn(
            zillow_service.REASON_RESPONSE_TOO_LARGE,
            _reasons(collector),
        )
        self.assertIn(cap + 1, _measured_sizes(collector))

    def test_a_body_past_the_cap_stops_being_read(self):
        """An undeclared oversized body is abandoned mid-stream."""
        cap = zillow_service.MAX_PROVIDER_RESPONSE_BYTES
        chunk = b'x' * 65536
        produced = []
        with _collecting_application_logs() as collector:
            with _provider(
                _answering_in_chunks(chunk, 64, produced)
            ):
                self.assertEqual(_fetch(), [])

        self.assertIn(
            zillow_service.REASON_RESPONSE_TOO_LARGE,
            _reasons(collector),
        )
        # The read stopped as soon as the accumulated bytes passed the
        # cap, rather than draining the whole body.
        self.assertLess(len(produced) * len(chunk), 2 * cap)
        self.assertGreater(len(produced) * len(chunk), cap)

    def test_a_body_at_the_cap_is_accepted(self):
        """The cap is the largest body accepted, not the first refused."""
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
        """A response is capped at the accepted number of listings."""
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
        """The listing cap is a maximum, not a threshold."""
        limit = zillow_service.MAX_PROVIDER_LISTINGS
        payload = {'listings': [{'id': index} for index in range(limit)]}
        with _provider(_answering(payload)):
            self.assertEqual(len(_fetch()), limit)

    def test_no_search_value_reaches_a_log_record(self):
        """No postal code or filter value reaches a rendered line.

        The failure the HTTP library raises names the full request
        target, which carries every search value the caller supplied. The
        record emitted for it carries the exception's class and nothing
        else, and no traceback is attached.
        """
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
                self.assertEqual(
                    _fetch(
                        zip_codes=(postal_code,),
                        filters={'neighborhood': neighbourhood},
                    ),
                    [],
                )

        self.assertTrue(collector.records)
        for record in collector.records:
            self.assertIsNone(record.exc_info)
        for line in _rendered_log_lines(collector):
            self.assertNotIn(postal_code, line)
            self.assertNotIn(neighbourhood, line)
            self.assertNotIn(settings.ZILLOW_API_KEY, line)
            self.assertNotIn(settings.ZILLOW_API_URL, line)

    def test_a_failure_is_recorded_as_its_class(self):
        """A refused call stays observable without its message."""
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
                self.assertEqual(_fetch(), [])

        contexts = _contexts(collector)
        self.assertTrue(contexts)
        self.assertEqual(contexts[0]['exception_type'], 'ReadTimeout')
        self.assertEqual(contexts[0]['exception_module'], 'httpx')

    def test_api_key_is_absent_from_every_log_record(self):
        """The credential reaches no rendered log line.

        The provider failure quotes the credential in free prose, with no
        key name beside it, which is the shape no key-based rule would
        catch.
        """
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
                self.assertEqual(_fetch(), [])

        self.assertTrue(collector.records)
        for line in _rendered_log_lines(collector):
            self.assertNotIn(key, line)

    def test_the_credential_is_registered_for_replacement(self):
        """The credential is removed from any text carrying it.

        Nothing in this module renders it. The registry covers every
        other component that might, provider prose included.
        """
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
    """Returns the reason each collected record names."""
    return [
        context['reason']
        for context in _contexts(collector)
        if context.get('reason')
    ]


def _measured_sizes(collector):
    """Returns the body size each collected record measured."""
    return [
        context['response_bytes']
        for context in _contexts(collector)
        if context.get('response_bytes') is not None
    ]


class _SendGridResponse(object):
    """Stands in for the response ``python_http_client`` reads.

    The three members the package's ``Response`` reads are provided, so
    the value returned here travels the same path a real delivery does.
    """

    def __init__(self, status_code=EMAIL_ACCEPTED_STATUS, body=b''):
        self.status_code = status_code
        self.body = body

    def getcode(self):
        """Returns the status the provider reported."""
        return self.status_code

    def read(self):
        """Returns the body the provider returned."""
        return self.body

    def info(self):
        """Returns the headers the provider returned."""
        return {}


class _SendGridBoundary(object):
    """Records the request the SendGrid package would transmit.

    The recorder replaces ``python_http_client.client.Client._make_request``,
    the seam that package documents as the one to stand in for, so the
    request asserted on is the one the package built: its method, target,
    headers and serialised body. ``client_timeout`` is the timeout the
    leaf client carries, which the package copies from the client the
    service configured onto each chained sub-client it builds.
    """

    def __init__(self, error=None, status_code=EMAIL_ACCEPTED_STATUS):
        self.error = error
        self.status_code = status_code
        self.calls = []

    def install(self):
        """Returns the patch that installs this recorder."""
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
        """Returns the single recorded request."""
        assert len(self.calls) == 1, self.calls
        return self.calls[0]


class TestEmailService(unittest.TestCase):
    """Delivery through the pinned SendGrid package's own boundary."""

    def test_send_email_transmits_the_documented_request(self):
        """The transmitted request is the one the provider documents.

        The method, target, authorization, content type and serialised
        message are asserted, together with the timeout the leaf client
        carries -- which the package copies onto every chained sub-client,
        so it is the timeout the delivery would have been bounded by.
        """
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
        """Each accepted status is reported as a delivery."""
        for status_code in EMAIL_DELIVERED_STATUSES:
            with self.subTest(status_code):
                boundary = _SendGridBoundary(status_code=status_code)
                with boundary.install():
                    self.assertTrue(send_email(
                        RECIPIENT_EMAIL, EMAIL_SUBJECT, EMAIL_CONTENT
                    ))

    def test_the_accepted_status_is_the_one_the_endpoint_reports(self):
        """The service names one status, and it is the documented one."""
        self.assertEqual(email_service_module.ACCEPTED_STATUS, 202)
        self.assertEqual(
            EMAIL_DELIVERED_STATUSES, (email_service_module.ACCEPTED_STATUS,)
        )

    def test_send_email_refuses_another_success_status(self):
        """Another 2xx is a failure, not a delivery.

        The Mail Send endpoint reports one status for a queued message.
        Another success status means the request was answered by something
        else -- a redirect target, a proxy or an error page returning 200 --
        so treating it as a delivery would report a message as sent that
        the provider never queued.
        """
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
        """A non-2xx delivery raises in the package and is reported.

        The pinned package raises :class:`BadRequestsError` for a ``400``
        rather than returning a response, which is the shape asserted
        here.
        """
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
        """A failure reaching the provider is reported, not raised."""
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
        """A failure before the request is built is reported."""
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
        """A failed send emits one structured record naming the module.

        The record carries the failure as discrete fields -- the class,
        the defining module and the redacted message -- and carries **no**
        exception information at error level, because attaching the
        exception makes the handler render the whole traceback, and a
        traceback of a provider client call embeds the request it was
        making and the local frames it was making it from.

        The provider's own message travels as a field, redacted as the
        field is built rather than as the line is written, so the
        credential is absent from the record object itself and not only
        from the rendered output.
        """
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
        """No record at error level renders a traceback.

        A traceback of the provider client names the request it was
        issuing and every local frame, so it belongs at DEBUG -- where the
        configured level suppresses it outside a local run -- and never at
        the level a deployment collects.
        """
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
        """Neither the record nor any rendered line carries the key.

        Two failures are driven. The first quotes the credential in free
        prose, and the second names it beside a credential-shaped key.
        Each case asserts the provider message was carried, that the
        placeholder stands where the credential stood, and that the
        credential appears in no field of the record and in no rendered
        line.
        """
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
        """No module on the notification path calls ``print``.

        The three modules whose bare calls were replaced by the
        structured logger are read and asserted to contain none.
        """
        for module in BARE_OUTPUT_FREE_MODULES:
            with self.subTest(module.__name__):
                source = inspect.getsource(module)
                self.assertNotIn('print(', source)


def test_a_failed_send_emits_one_redacted_structured_record():
    """Every line a failed send emits is a redacted structured record.

    The real logging path runs rather than a stand-in for it: the lines
    read are the ones the handler the governed loggers dispatch to
    actually wrote.
    """
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
    # The failure travels as discrete fields under the record's context,
    # and no rendered traceback is emitted at this level.
    assert 'exception' not in failure
    context = failure['context']
    assert context['exception_type'] == 'RuntimeError'
    assert context['reason'] == REASON_SEND_FAILED
    assert REDACTION_PLACEHOLDER in context['exception_message']
    assert settings.SENDGRID_API_KEY not in context['exception_message']
    for entry in entries:
        assert 'Traceback' not in json.dumps(entry)


def test_a_rejected_send_records_the_status_it_was_refused_with():
    """A send the provider refuses is recorded with its status.

    The refusal arrives as a reported status rather than as a raised
    failure, so it carries no exception to record. One line is emitted
    naming the status received and the status expected, which is what
    makes a silent non-delivery visible.
    """
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
    """A failed send writes the failure detail to no stream.

    The real logging path runs rather than a stand-in for it, and the
    streams are read once the queue-backed listener has drained.
    """
    assert _send_failing_with(EMAIL_FAILURE_DETAIL) is False

    flush_log_queue(LOG_DRAIN_TIMEOUT)
    captured = capsys.readouterr()

    for stream in (captured.out, captured.err):
        assert BARE_PRINT_SIGNATURE not in stream
        assert settings.SENDGRID_API_KEY not in stream


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
    """Answers PayPal REST calls and records every outbound call made.

    Every call is asserted against the provider wire contract before a
    response is served, so a call carrying the wrong method, host, path,
    authentication, headers, body or timeout raises rather than receiving
    a plausible answer. ``routes`` holds the contract route each recorded
    call addressed.
    """

    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.routes = []

    @staticmethod
    def _path(sent):
        """Returns the path of one outbound httpx call."""
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
    """The payment chain settles in the order PayPal documents."""

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
            # The decisive field: the provider's own issue code, which is
            # what the endpoint discriminates the recovery on.
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
        """A refusal under the same status carries a different code.

        The status and the failure category are identical to the
        already-captured case above, so the issue code is the only field
        that separates the two, and the endpoint's discriminator refuses
        this one.
        """
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
        """A body with no allowlisted field yields no issue code."""
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
        """The body's own name supplies the code when details do not."""
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
        """No field outside the allowlist reaches the issue code."""
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
        """A code of another shape is dropped rather than carried."""
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
    """An inbound identifier survives into the provider's own records."""

    def _contexts(self, collector):
        """Returns the context of every rendered record."""
        return [
            json.loads(line).get(CONTEXT_FIELD, {})
            for line in _rendered_log_lines(collector)
        ]

    def test_the_bound_identifier_reaches_a_listing_provider_record(self):
        """A provider failure records the identifier bound to the caller."""
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
        """A delivery failure records the identifier bound to the caller."""
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
    """The guard every provider stand-in in the suite validates through.

    Each case hands :func:`assert_paypal_contract` a request that departs
    from the provider contract in one respect and asserts it is refused,
    so a stand-in cannot answer a malformed call with a plausible
    response.
    """

    def _authenticated(self, **overrides):
        """Returns the arguments of a well-formed settle call."""
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
        """The positive control resolves to the settle route."""
        self.assertEqual(
            assert_paypal_contract(**self._authenticated()),
            PAYPAL_ROUTE_CAPTURE_ORDER,
        )

    def test_another_host_is_refused(self):
        """A target outside the configured host is refused."""
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(**self._authenticated(
                url='https://api-m.paypal.com' + ORDER_PATH + '/capture'
            ))

    def test_an_unknown_path_is_refused(self):
        """A path the service never addresses is refused."""
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(**self._authenticated(
                url=settings.PAYPAL_API_BASE + '/v2/checkout/refunds'
            ))

    def test_the_wrong_method_is_refused(self):
        """A settle call sent as a read is refused."""
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(**self._authenticated(method='GET'))

    def test_a_missing_grant_is_refused(self):
        """An authenticated call carrying no Bearer grant is refused."""
        headers = self._authenticated()['headers'].copy()
        del headers['Authorization']
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(
                **self._authenticated(headers=headers)
            )

    def test_an_empty_grant_is_refused(self):
        """An authenticated call carrying a blank grant is refused."""
        headers = self._authenticated()['headers'].copy()
        headers['Authorization'] = 'Bearer  '
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(
                **self._authenticated(headers=headers)
            )

    def test_a_missing_body_is_refused(self):
        """A write call carrying no body is refused."""
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(
                **self._authenticated(json_body=None)
            )

    def test_a_missing_representation_preference_is_refused(self):
        """A settle call carrying no preference header is refused."""
        headers = self._authenticated()['headers'].copy()
        del headers['Prefer']
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(
                **self._authenticated(headers=headers)
            )

    def test_a_missing_timeout_is_refused(self):
        """A call carrying no timeout is refused."""
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(**self._authenticated(timeout=None))

    def test_another_timeout_is_refused(self):
        """A call carrying a timeout other than the configured one."""
        with self.assertRaises(PayPalContractError):
            assert_paypal_contract(**self._authenticated(
                timeout=settings.HTTP_TIMEOUT_SECONDS + 1
            ))

    def test_a_credential_exchange_without_the_grant_type_is_refused(self):
        """A token call sending no client-credentials grant is refused."""
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
        """A token call sending no Basic credentials is refused."""
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
        """A verifier document short of one field is refused."""
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
        """A verifier document naming another webhook is refused."""
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
    """Returns the complete create-order document for ``plan_id``."""
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
    """Returns ``mapping`` with the member at ``path`` removed."""
    altered = copy.deepcopy(mapping)
    target = altered
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]
    return altered


def _replacing(mapping, path, value):
    """Returns ``mapping`` with the member at ``path`` set to ``value``."""
    altered = copy.deepcopy(mapping)
    target = altered
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return altered


#: Path of the payer experience context inside the created order.
_CONTEXT = ('payment_source', 'paypal', 'experience_context')

#: Path of the single purchase unit's amount.
_AMOUNT = ('purchase_units', 0, 'amount')


class TestTheCreateOrderBodyContract(unittest.TestCase):
    """One departure per required create-order field is refused.

    The positive control asserts the complete document is accepted, and
    every case below alters exactly one required field or value and
    asserts the guard refuses it, so no field of the outbound document is
    asserted only by its presence.
    """

    def _assert_refused(self, document):
        """Assert the guard refuses ``document`` as a created order."""
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
    """The settle call's body is the empty object and nothing else."""

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
        """The refusal reaches the shared guard, not only the helper."""
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
        """The create-order refusal reaches the shared guard too."""
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
    """Registration of the credentials each provider module handles."""

    def test_every_configured_provider_credential_is_registered(self):
        """Each configured credential is replaced in free prose.

        The value is quoted with no key name beside it, which shape
        matching does not reach, so a rendered placeholder shows the
        registry holds the value.
        """
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
        """A value at the floor is registered and reported held."""
        value = 'v' * MIN_SECRET_VALUE_LENGTH
        held = register_required_secret_values(value)

        self.assertGreaterEqual(held, 1)
        self.assertNotIn(value, redact('provider prose ' + value))

    def test_a_credential_the_registry_refuses_raises(self):
        """A value below the floor raises rather than being ignored.

        The raised message is asserted to name neither the value nor any
        part of it, so the refusal itself discloses nothing.
        """
        value = 'w' * (MIN_SECRET_VALUE_LENGTH - 1)

        with self.assertRaises(ValueError) as raised:
            register_required_secret_values(value)

        message = str(raised.exception)
        self.assertNotIn(value, message)
        self.assertIn('could not be registered', message)
        self.assertIn(value, redact('provider prose ' + value))

    def test_a_value_that_is_not_text_raises(self):
        """A non-string value raises rather than being ignored."""
        with self.assertRaises(ValueError):
            register_required_secret_values(None)


class TestProviderEventTaxonomy(unittest.TestCase):
    """A partial success is a warning, and a routine success is not news.

    Level is what a deployment alerts and pages on, so a record's level is
    a claim about whether a human is needed. A discarded entry and a
    truncated page are both partial successes -- the pass completed and
    the corpus was written -- so they warn. A completed REST call is
    routine, so it is not collected at all unless a run is being
    debugged. Each partial success also carries a stable ``reason``, so a
    query selects it by field rather than by matching its prose.
    """

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
        """A pass that returned nothing keeps its error level."""
        with _collecting_application_logs() as collector:
            with _provider(_answering({'listings': []}, status_code=500)):
                self.assertEqual(_fetch(), [])

        self.assertTrue([
            record
            for record in collector.records
            if record.levelno >= logging.ERROR
        ])

    def test_a_completed_rest_call_is_not_collected_at_information(self):
        """The two PayPal success records sit below the collected level.

        A record per completed call at information level makes the
        provider's routine traffic the bulk of the log, which is what
        pushes the refusals and the failures out of a retention window.
        """
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
    """An outbound provider call carries the trace it was made under.

    Without it the provider's own record of the call cannot be joined to
    this service's record of the request that caused it, which is what
    makes a provider-side investigation possible at all.
    """

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
        """An unbound call sends no correlation header at all."""
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
    """A record the HTTP client writes discloses no search value.

    The client logs its request target at information level, and that
    target carries every postal code and filter value the caller
    supplied. The record has to travel through the redacting handler, or
    the search terms this service takes care never to log itself arrive in
    the log by another route.
    """

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
