import asyncio
import json
import logging
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from conftest import (
    PayPalContractError,
    assert_paypal_request,
    assert_verifier_embeds_event,
    embedded_event_bytes,
)

from backend.app.api.endpoints import subscriptions as subscriptions_module
from backend.app.core.authorization import Role
from backend.app.core.config import settings
from backend.app.core.logging import (
    BASE_LOGGER_NAME,
    CONTEXT_FIELD,
    REQUEST_ID_FIELD,
    RedactingFilter,
    RedactingJsonFormatter,
)
from backend.app.core.plans import PREMIUM_MONTHLY, format_amount, get_plan
from backend.app.db.models import Subscription, User, WebhookEvent
from backend.app.main import REQUEST_ID_HEADER, app, limiter
from backend.app.services import paypal_service
from backend.tests.support import CLIENT_BASE_URL

SERVICE = "backend.app.services.paypal_service"

WEBHOOK_PATH = "/subscriptions/webhook"

TOKEN_PATH = "/v1/oauth2/token"

VERIFY_PATH = "/v1/notifications/verify-webhook-signature"

ACCESS_TOKEN = "verifier-access-token-value"

PLAN = get_plan(PREMIUM_MONTHLY)

ORDER_ID = "ORDER-WEBHOOK-H4-1"

CAPTURE_ID = "CAPTURE-WEBHOOK-H4-1"

TRANSMISSION_ID = "3f6c1e00-1111-2222-3333-444455556666"

SUPPLIED_REQUEST_ID = "caller0trace0webhook1"

TRANSMISSION_SIG = "dmFsaWQtc2lnbmF0dXJlLXZhbHVl"

TAMPERED_SIG = "dGFtcGVyZWQtc2lnbmF0dXJlLXZhbHVl"

TRANSMISSION_TIME = "2026-08-07T10:00:00Z"

AUTH_ALGO = "SHA256withRSA"

ALLOWED_CERT_URL = (
    "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-H4"
)

SUBSCRIBER_EMAIL = "webhook.payer@example.com"

POSTBACK_FIELDS = (
    "auth_algo",
    "cert_url",
    "transmission_id",
    "transmission_sig",
    "transmission_time",
    "webhook_id",
    paypal_service.WEBHOOK_EVENT_FIELD,
)

DOCUMENTED_HEADERS = (
    ("PAYPAL-AUTH-ALGO", paypal_service.AUTH_ALGO_HEADER, "auth_algo"),
    ("PAYPAL-CERT-URL", paypal_service.CERT_URL_HEADER, "cert_url"),
    (
        "PAYPAL-TRANSMISSION-ID",
        paypal_service.TRANSMISSION_ID_HEADER,
        "transmission_id",
    ),
    (
        "PAYPAL-TRANSMISSION-SIG",
        paypal_service.TRANSMISSION_SIG_HEADER,
        "transmission_sig",
    ),
    (
        "PAYPAL-TRANSMISSION-TIME",
        paypal_service.TRANSMISSION_TIME_HEADER,
        "transmission_time",
    ),
)

FOREIGN_HOST_CERT_URL = "https://certs.attacker.invalid/cert.pem"

PREFIXED_HOST_CERT_URL = (
    "https://api.paypal.com.attacker.invalid/cert.pem"
)

UNBOUNDED_HOST_CERT_URL = "https://notapi.paypal.com/cert.pem"

USERINFO_CERT_URL = (
    "https://api.paypal.com@certs.attacker.invalid/cert.pem"
)

PATH_CERT_URL = (
    "https://certs.attacker.invalid/api.paypal.com/cert.pem"
)

PLAIN_SCHEME_CERT_URL = (
    "http://api.sandbox.paypal.com/v1/notifications/certs/C1"
)

HOSTILE_CERT_URLS = (
    pytest.param(
        FOREIGN_HOST_CERT_URL, id="wholly_different_domain"
    ),
    pytest.param(
        PREFIXED_HOST_CERT_URL,
        id="allowlisted_name_as_prefix_of_attacker_domain",
    ),
    pytest.param(
        UNBOUNDED_HOST_CERT_URL,
        id="allowlisted_name_without_a_dot_boundary",
    ),
    pytest.param(
        USERINFO_CERT_URL, id="allowlisted_name_in_the_userinfo"
    ),
    pytest.param(PATH_CERT_URL, id="allowlisted_name_in_the_path"),
    pytest.param(PLAIN_SCHEME_CERT_URL, id="scheme_is_not_tls"),
)


NON_CANONICAL_EVENT_BODIES = (
    pytest.param(
        b'{\n  "event_type" : "PAYMENT.CAPTURE.COMPLETED" ,\n'
        b'  "id": "WH-H4-CAPTURE"\n}',
        id="indented_with_spaced_separators",
    ),
    pytest.param(
        b'{"id":"WH-H4-CAPTURE","event_type":'
        b'"PAYMENT.CAPTURE.COMPLETED","note":"caf\\u00e9"}',
        id="escaped_non_ascii_that_would_re_encode",
    ),
    pytest.param(
        b'{"event_type":"PAYMENT.CAPTURE.COMPLETED","amount":1.50,'
        b'"note":"caf\xc3\xa9"}',
        id="literal_non_ascii_and_a_trailing_zero_number",
    ),
)


class RecordedCall(object):

    def __init__(self, outbound):
        self.method = outbound.method
        self.path = outbound.url.path
        self.target = str(outbound.url)
        self.headers = dict(outbound.headers)
        self.timeout = dict(outbound.extensions.get("timeout") or {})
        try:
            self.content = bytes(outbound.content)
        except httpx.StreamError:
            self.content = b""

    def arguments(self):
        parts = [self.method, self.target]
        for name, value in self.headers.items():
            parts.append("{0}: {1}".format(name, value))
        parts.append(self.content.decode("utf-8", "replace"))
        return "\n".join(parts)

    def mentions(self, value):
        return value in self.arguments()

    def document(self):
        return json.loads(self.content.decode("utf-8"))

    def event_bytes(self):
        return embedded_event_bytes(self.content)


class VerifierTransport(object):

    UNSET_STATUS = object()

    def __init__(
        self,
        status=paypal_service.VERIFICATION_SUCCESS,
        unreachable=False,
        verify_status_code=200,
        verify_text=None,
        token_status_code=200,
    ):
        self.status = status
        self.unreachable = unreachable
        self.verify_status_code = verify_status_code
        self.verify_text = verify_text
        self.token_status_code = token_status_code
        self.calls = []

        @asynccontextmanager
        async def open_client():
            transport = httpx.MockTransport(self.respond)
            async with httpx.AsyncClient(
                transport=transport
            ) as stand_in:
                yield stand_in

        self.open_client = open_client

    def respond(self, outbound):
        """Asserts ``outbound``, records it, and answers its path.

        The request is asserted against the provider wire contract before
        a response is served, so a call carrying the wrong method, host,
        path, authentication, headers, verifier document or timeout raises
        rather than receiving a plausible answer.
        """
        call = RecordedCall(outbound)
        call.route = assert_paypal_request(outbound)
        self.calls.append(call)
        if call.path == TOKEN_PATH:
            if self.token_status_code != 200:
                return httpx.Response(
                    self.token_status_code,
                    json={"error": "invalid_client"},
                )
            return httpx.Response(
                200,
                json={
                    "access_token": ACCESS_TOKEN,
                    "expires_in": 3600,
                },
            )
        if self.unreachable:
            raise httpx.ConnectError("verifier unreachable")
        if self.verify_text is not None:
            return httpx.Response(
                self.verify_status_code,
                content=self.verify_text,
                headers={"Content-Type": "application/json"},
            )
        if self.status is self.UNSET_STATUS:
            return httpx.Response(self.verify_status_code, json={})
        return httpx.Response(
            self.verify_status_code,
            json={"verification_status": self.status},
        )

    @property
    def paths(self):
        return [call.path for call in self.calls]

    def verify_calls(self):
        return [
            call for call in self.calls if call.path == VERIFY_PATH
        ]

    def mentions(self, value):
        return any(call.mentions(value) for call in self.calls)


def webhook_headers(
    cert_url=ALLOWED_CERT_URL,
    transmission_id=TRANSMISSION_ID,
    signature=TRANSMISSION_SIG,
    dropped=None,
):
    """Returns the five headers a PayPal notification must carry.

    ``dropped`` names one header to omit, which is what the
    missing-header cases vary.
    """
    headers = {
        paypal_service.AUTH_ALGO_HEADER: AUTH_ALGO,
        paypal_service.CERT_URL_HEADER: cert_url,
        paypal_service.TRANSMISSION_ID_HEADER: transmission_id,
        paypal_service.TRANSMISSION_SIG_HEADER: signature,
        paypal_service.TRANSMISSION_TIME_HEADER: TRANSMISSION_TIME,
    }
    if dropped is not None:
        headers.pop(dropped, None)
    return headers


def capture_completed_event(order_id=ORDER_ID, value=None):
    """Returns a settled-capture notification naming ``order_id``.

    The reported amount defaults to the plan's own amount, so the
    notification is one the endpoint will act on.
    """
    return {
        "id": "WH-H4-CAPTURE",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {
            "id": CAPTURE_ID,
            "status": "COMPLETED",
            "amount": {
                "currency_code": PLAN.currency,
                "value": (
                    value
                    if value is not None
                    else format_amount(PLAN.amount)
                ),
            },
            "supplementary_data": {
                "related_ids": {"order_id": order_id}
            },
        },
    }


def notification_bytes(event):
    return json.dumps(event).encode("utf-8")


def deliver(client, body, headers):
    """Posts one notification to the unauthenticated webhook route.

    No ``Authorization`` header is sent: the signature is what admits
    the request.
    """
    sent = dict(headers)
    sent["Content-Type"] = "application/json"
    return client.post(WEBHOOK_PATH, content=body, headers=sent)


def stored_state(db):
    """Returns the event, subscription and role state these cases
    compare."""
    db.expire_all()
    events = [
        (event.transmission_id, event.event_type)
        for event in db.query(WebhookEvent)
        .order_by(WebhookEvent.transmission_id)
        .all()
    ]
    subscriptions = [
        (
            row.id,
            row.status,
            row.start_date,
            row.end_date,
            row.plan_id,
            row.amount,
            row.currency,
            row.paypal_order_id,
        )
        for row in db.query(Subscription).order_by(Subscription.id).all()
    ]
    roles = [
        (account.id, account.role)
        for account in db.query(User).order_by(User.id).all()
    ]
    return {
        "event_count": len(events),
        "events": events,
        "subscriptions": subscriptions,
        "roles": roles,
    }


def logged_reasons(records):
    return [
        record.reason
        for record in records
        if getattr(record, "reason", None) is not None
    ]


def values_found_in(records, values):
    rendered = [repr(vars(record)) for record in records]
    return [
        value
        for value in values
        if any(value in text for text in rendered)
    ]


def formatted_lines(records):
    """Returns each record as the line the process would write.

    The application's redacting filter and formatter are applied, so the
    text asserted on is the serialised record rather than its attributes.
    """
    log_filter = RedactingFilter()
    formatter = RedactingJsonFormatter()
    return [
        formatter.format(record)
        for record in records
        if log_filter.filter(record)
    ]


def record_with_reason(records, reason):
    matching = [
        record
        for record in records
        if getattr(record, "reason", None) == reason
    ]
    assert len(matching) == 1, reason
    return matching[0]


def activations(records):
    return [
        record
        for record in records
        if getattr(record, "granted_role", None) is not None
    ]


CONFIDENTIAL_VALUES = (
    TRANSMISSION_SIG,
    TAMPERED_SIG,
    ACCESS_TOKEN,
    settings.PAYPAL_CLIENT_SECRET,
    settings.PAYPAL_WEBHOOK_ID,
    ALLOWED_CERT_URL,
)

STEP_BOUND_SECONDS = 15.0

PAIR_BOUND_SECONDS = 60.0

CONTROLLED_OPERATIONS = ("flush", "commit", "rollback")

LEFT_BY_COMMIT = "commit"

LEFT_BY_ROLLBACK = "rollback"


UNCHECKABLE_ANSWERS = (
    pytest.param("unreachable", True, id="verifier_unreachable"),
    pytest.param(
        "token_status_code", 401, id="grant_refused_401"
    ),
    pytest.param(
        "token_status_code", 403, id="grant_refused_403"
    ),
    pytest.param(
        "verify_status_code", 400, id="verifier_client_error_400"
    ),
    pytest.param(
        "verify_status_code", 422, id="verifier_client_error_422"
    ),
    pytest.param(
        "verify_status_code", 500, id="verifier_server_error_500"
    ),
    pytest.param(
        "verify_status_code", 503, id="verifier_server_error_503"
    ),
    pytest.param(
        "verify_text", b"not-json-at-all", id="body_is_not_json"
    ),
    pytest.param(
        "verify_text", b'"SUCCESS"', id="body_is_not_an_object"
    ),
    pytest.param(
        "status", VerifierTransport.UNSET_STATUS, id="status_absent"
    ),
    pytest.param("status", None, id="status_is_null"),
    pytest.param("status", 1, id="status_is_a_number"),
    pytest.param("status", "", id="status_is_empty"),
    pytest.param("status", "PENDING", id="status_is_unrecognised"),
    pytest.param("status", "success", id="status_is_lower_case"),
)


class ConcurrentDeliveryBarrier(object):

    def __init__(self, holder_commit_fails=False):
        self.holder_commit_fails = holder_commit_fails
        self.holder_session = None
        self.waiter_session = None
        self.holder_inserted = threading.Event()
        self.waiter_waiting = threading.Event()
        self.holder_released = threading.Event()
        self.holder_left = threading.Event()
        self.holder_outcome = None
        self.held_flush_threads = []
        self.overlapped = False

    def _role(self, session):
        if self.holder_session is None or self.holder_session is session:
            self.holder_session = session
            return "holder"
        if self.waiter_session is None or self.waiter_session is session:
            self.waiter_session = session
            return "waiter"
        return "other"

    def interpose(self, operation, perform):
        """Returns the result of one session operation, held if needed.

        ``operation`` is the bound session method the route handed to
        ``_in_session`` and ``perform`` runs it unchanged. An operation
        outside :data:`CONTROLLED_OPERATIONS`, or one belonging to
        neither delivery, is performed as it stands.
        """
        session = getattr(operation, "__self__", None)
        name = getattr(operation, "__name__", "")
        if session is None or name not in CONTROLLED_OPERATIONS:
            return perform()
        role = self._role(session)
        if role == "other":
            return perform()
        if name == "flush":
            return self._flush(role, perform)
        if name == "commit":
            return self._commit(role, perform)
        return self._rollback(role, perform)

    def _flush(self, role, perform):
        self.held_flush_threads.append(threading.current_thread().ident)
        if role == "holder":
            result = perform()
            self.holder_inserted.set()
            assert self.holder_released.wait(STEP_BOUND_SECONDS), (
                "the first delivery was never released from its flush"
            )
            return result
        self.waiter_waiting.set()
        assert self.holder_left.wait(STEP_BOUND_SECONDS), (
            "the waiting delivery's flush never resolved"
        )
        if self.holder_outcome == LEFT_BY_COMMIT:
            raise IntegrityError(
                "INSERT INTO webhook_events (transmission_id) VALUES (?)",
                {},
                Exception(
                    "UNIQUE constraint failed: "
                    "webhook_events.transmission_id"
                ),
            )
        return perform()

    def _commit(self, role, perform):
        if role == "holder" and self.holder_commit_fails:
            raise SQLAlchemyError("the transition could not be recorded")
        result = perform()
        if role == "holder":
            self._record_departure(LEFT_BY_COMMIT)
        return result

    def _rollback(self, role, perform):
        result = perform()
        if role == "holder":
            self._record_departure(LEFT_BY_ROLLBACK)
        return result

    def _record_departure(self, outcome):
        if self.holder_outcome is None:
            self.holder_outcome = outcome
            self.holder_left.set()


def controlled_deliveries(monkeypatch, barrier):
    """Routes every session operation of the route through ``barrier``.

    The replacement delegates to the real
    :func:`backend.app.api.endpoints.subscriptions._in_session`, so each
    operation still runs in a worker thread and a wait the barrier takes
    is a wait taken off the event loop.
    """
    perform_in_session = subscriptions_module._in_session

    async def in_session(operation, *args, **kwargs):

        def held(*call_args, **call_kwargs):
            return barrier.interpose(
                operation,
                lambda: operation(*call_args, **call_kwargs),
            )

        return await perform_in_session(held, *args, **kwargs)

    monkeypatch.setattr(
        subscriptions_module, "_in_session", in_session
    )


async def reached(signal, description):
    loop = asyncio.get_event_loop()
    arrived = await loop.run_in_executor(
        None, signal.wait, STEP_BOUND_SECONDS
    )
    assert arrived, description


async def deliver_together(barrier, body, headers):
    """Answers two overlapping deliveries of one notification.

    The first delivery is started and held once its delivery row is
    inserted; the second is started and held where the uniqueness
    constraint would make it wait; the first is then released. Both are
    driven as tasks on this event loop and the pair is bounded by
    :data:`PAIR_BOUND_SECONDS`. The two responses are returned in the
    order the deliveries were started.
    """
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=CLIENT_BASE_URL,
    ) as caller:

        async def post():
            sent = dict(headers)
            sent["Content-Type"] = "application/json"
            return await caller.post(
                WEBHOOK_PATH, content=body, headers=sent
            )

        first = asyncio.ensure_future(post())
        await reached(
            barrier.holder_inserted,
            "the first delivery never recorded its delivery row",
        )
        second = asyncio.ensure_future(post())
        await reached(
            barrier.waiter_waiting,
            "the second delivery never reached the contended insert",
        )
        barrier.overlapped = not first.done()
        barrier.holder_released.set()
        return await asyncio.wait_for(
            asyncio.gather(first, second), PAIR_BOUND_SECONDS
        )


@pytest.fixture(autouse=True)
def fresh_provider_state():
    """Clears the shared token cache and throttle counters per case."""
    paypal_service.reset_access_token_cache()
    limiter.reset()
    try:
        yield
    finally:
        paypal_service.reset_access_token_cache()
        limiter.reset()


@pytest.fixture
def recorder():
    """Yields the transport that answers a passing signature check."""
    stand_in = VerifierTransport()
    with patch(SERVICE + "._client", new=stand_in.open_client):
        yield stand_in


@pytest.fixture
def failing_recorder():
    """Yields the transport that answers a failing signature check."""
    stand_in = VerifierTransport(status="FAILURE")
    with patch(SERVICE + "._client", new=stand_in.open_client):
        yield stand_in


@pytest.fixture
def subscriber(user_factory):
    """Returns the account the seeded subscription belongs to."""
    return user_factory(SUBSCRIBER_EMAIL)


@pytest.fixture
def pending_subscription(db, subscriber):
    """Stores the pending row the notifications name by its order."""
    row = Subscription(
        user_id=subscriber.id,
        start_date=datetime.now(timezone.utc),
        status=subscriptions_module.PENDING_STATUS,
        plan_id=PREMIUM_MONTHLY,
        amount=PLAN.amount,
        currency=PLAN.currency,
        paypal_order_id=ORDER_ID,
    )
    db.add(row)
    db.commit()
    return row


@pytest.fixture
def captured_records(caplog):
    """Yields ``caplog`` wired to the application logger.

    The application logger does not propagate. Its handler list carries
    ``caplog``'s handler for the duration of the case and is restored
    once the case ends.
    """
    base_logger = logging.getLogger(BASE_LOGGER_NAME)
    caplog.set_level(logging.DEBUG, logger=BASE_LOGGER_NAME)
    base_logger.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        base_logger.removeHandler(caplog.handler)


def test_the_documented_paypal_headers_are_the_ones_required():
    for documented, configured, field in DOCUMENTED_HEADERS:
        assert configured == documented
        assert configured in paypal_service.REQUIRED_WEBHOOK_HEADERS
        assert field in POSTBACK_FIELDS
    assert len(paypal_service.REQUIRED_WEBHOOK_HEADERS) == len(
        DOCUMENTED_HEADERS
    )
    assert sorted(webhook_headers()) == sorted(
        paypal_service.REQUIRED_WEBHOOK_HEADERS
    )


@pytest.mark.asyncio
async def test_a_verified_notification_reports_its_transmission_id(
    recorder,
):
    outcome = await paypal_service.verify_webhook_signature(
        webhook_headers(),
        notification_bytes(capture_completed_event()),
    )

    assert outcome.verified is True
    assert outcome.transmission_id == TRANSMISSION_ID
    assert outcome.event_type == "PAYMENT.CAPTURE.COMPLETED"
    assert outcome.reason is None
    assert outcome.retryable is False
    assert len(recorder.verify_calls()) == 1


@pytest.mark.asyncio
async def test_a_verified_notification_posts_the_documented_fields(
    recorder,
):
    event = capture_completed_event()

    outcome = await paypal_service.verify_webhook_signature(
        webhook_headers(), notification_bytes(event)
    )

    assert outcome.verified is True
    posted = recorder.verify_calls()
    assert len(posted) == 1
    document = posted[0].document()
    assert sorted(document) == sorted(POSTBACK_FIELDS)
    assert document["auth_algo"] == AUTH_ALGO
    assert document["cert_url"] == ALLOWED_CERT_URL
    assert document["transmission_id"] == TRANSMISSION_ID
    assert document["transmission_sig"] == TRANSMISSION_SIG
    assert document["transmission_time"] == TRANSMISSION_TIME
    assert document["webhook_id"] == settings.PAYPAL_WEBHOOK_ID
    assert document[paypal_service.WEBHOOK_EVENT_FIELD] == event


@pytest.mark.asyncio
@pytest.mark.parametrize("body", NON_CANONICAL_EVENT_BODIES)
async def test_the_posted_document_carries_the_arrived_bytes_verbatim(
    recorder, body
):
    outcome = await paypal_service.verify_webhook_signature(
        webhook_headers(), body
    )

    assert outcome.verified is True
    posted = recorder.verify_calls()
    assert len(posted) == 1
    assert_verifier_embeds_event(posted[0].content, body)
    assert posted[0].event_bytes() == body
    assert body in posted[0].content


@pytest.mark.asyncio
async def test_a_re_serialised_document_fails_the_byte_assertion(
    recorder,
):
    body = b'{\n  "event_type" : "PAYMENT.CAPTURE.COMPLETED"\n}'
    rebuilt = json.dumps(json.loads(body.decode("utf-8"))).encode(
        "utf-8"
    )
    document = (
        b'{"webhook_id":"W","'
        + paypal_service.WEBHOOK_EVENT_FIELD.encode("utf-8")
        + b'":'
        + rebuilt
        + b"}"
    )

    assert rebuilt != body
    assert json.loads(rebuilt.decode("utf-8")) == json.loads(
        body.decode("utf-8")
    )
    with pytest.raises(PayPalContractError):
        assert_verifier_embeds_event(document, body)


@pytest.mark.asyncio
async def test_a_tampered_signature_is_rejected(failing_recorder):
    outcome = await paypal_service.verify_webhook_signature(
        webhook_headers(signature=TAMPERED_SIG),
        notification_bytes(capture_completed_event()),
    )

    assert outcome.verified is False
    assert outcome.reason == paypal_service.REASON_SIGNATURE
    assert outcome.retryable is False
    assert outcome.transmission_id is None
    assert outcome.event_type is None
    posted = failing_recorder.verify_calls()
    assert len(posted) == 1
    assert posted[0].document()["transmission_sig"] == TAMPERED_SIG


@pytest.mark.asyncio
async def test_an_unreachable_verifier_is_reported_as_retryable():
    stand_in = VerifierTransport(unreachable=True)

    with patch(SERVICE + "._client", new=stand_in.open_client):
        outcome = await paypal_service.verify_webhook_signature(
            webhook_headers(),
            notification_bytes(capture_completed_event()),
        )

    assert outcome.verified is False
    assert outcome.reason == (
        paypal_service.REASON_VERIFIER_UNAVAILABLE
    )
    assert outcome.retryable is True
    assert outcome.transmission_id is None


@pytest.mark.asyncio
@pytest.mark.parametrize("keyword, value", UNCHECKABLE_ANSWERS)
async def test_an_answer_that_settles_nothing_is_reported_unavailable(
    keyword, value
):
    stand_in = VerifierTransport(**{keyword: value})

    with patch(SERVICE + "._client", new=stand_in.open_client):
        outcome = await paypal_service.verify_webhook_signature(
            webhook_headers(),
            notification_bytes(capture_completed_event()),
        )

    assert outcome.verified is False
    assert outcome.reason == (
        paypal_service.REASON_VERIFIER_UNAVAILABLE
    )
    assert outcome.retryable is True
    assert outcome.transmission_id is None
    assert outcome.event_type is None


@pytest.mark.asyncio
async def test_only_an_explicit_failure_is_a_signature_rejection():
    stand_in = VerifierTransport(
        status=paypal_service.VERIFICATION_FAILURE
    )

    with patch(SERVICE + "._client", new=stand_in.open_client):
        outcome = await paypal_service.verify_webhook_signature(
            webhook_headers(),
            notification_bytes(capture_completed_event()),
        )

    assert outcome.verified is False
    assert outcome.reason == paypal_service.REASON_SIGNATURE
    assert outcome.retryable is False


@pytest.mark.asyncio
async def test_a_client_error_from_the_verifier_is_not_a_rejection(
):
    stand_in = VerifierTransport(verify_status_code=400)

    with patch(SERVICE + "._client", new=stand_in.open_client):
        outcome = await paypal_service.verify_webhook_signature(
            webhook_headers(),
            notification_bytes(capture_completed_event()),
        )

    assert outcome.reason != paypal_service.REASON_SIGNATURE
    assert outcome.reason == (
        paypal_service.REASON_VERIFIER_UNAVAILABLE
    )
    assert outcome.retryable is True


@pytest.mark.asyncio
async def test_a_malformed_notification_body_is_rejected_without_a_call(
    recorder,
):
    outcome = await paypal_service.verify_webhook_signature(
        webhook_headers(), b"not-a-json-object"
    )

    assert outcome.verified is False
    assert outcome.reason == paypal_service.REASON_MALFORMED_BODY
    assert recorder.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("hostile_url", HOSTILE_CERT_URLS)
async def test_the_certificate_host_allowlist_is_applied_before_any_call(
    recorder, hostile_url
):
    outcome = await paypal_service.verify_webhook_signature(
        webhook_headers(cert_url=hostile_url),
        notification_bytes(capture_completed_event()),
    )

    assert outcome.verified is False
    assert outcome.reason == paypal_service.REASON_CERTIFICATE_HOST
    assert outcome.retryable is False
    assert recorder.calls == []
    assert recorder.paths == []
    assert recorder.mentions(hostile_url) is False


@pytest.mark.asyncio
async def test_a_certificate_host_on_the_allowlist_reaches_the_verifier(
    recorder,
):
    outcome = await paypal_service.verify_webhook_signature(
        webhook_headers(),
        notification_bytes(capture_completed_event()),
    )

    assert outcome.verified is True
    assert recorder.paths == [TOKEN_PATH, VERIFY_PATH]
    assert recorder.mentions(ALLOWED_CERT_URL) is True


@pytest.mark.asyncio
async def test_every_outbound_call_carries_an_explicit_timeout(recorder):
    outcome = await paypal_service.verify_webhook_signature(
        webhook_headers(),
        notification_bytes(capture_completed_event()),
    )

    assert outcome.verified is True
    assert recorder.paths == [TOKEN_PATH, VERIFY_PATH]
    for call in recorder.calls:
        assert call.timeout
        assert set(call.timeout.values()) == {
            settings.HTTP_TIMEOUT_SECONDS
        }


@pytest.mark.parametrize(
    "dropped", paypal_service.REQUIRED_WEBHOOK_HEADERS
)
def test_a_missing_required_header_is_rejected(
    client, db, recorder, captured_records, pending_subscription, dropped
):
    expected = (
        paypal_service.REASON_CERTIFICATE_HOST
        if dropped == paypal_service.CERT_URL_HEADER
        else paypal_service.REASON_MISSING_HEADER
    )
    before = stored_state(db)

    response = deliver(
        client,
        notification_bytes(capture_completed_event()),
        webhook_headers(dropped=dropped),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        subscriptions_module.WEBHOOK_REJECTED_DETAIL
    )
    assert expected in logged_reasons(captured_records.records)
    assert recorder.calls == []
    assert stored_state(db) == before
    assert db.query(WebhookEvent).count() == 0


def test_a_failed_verification_changes_no_database_state(
    client, db, failing_recorder, pending_subscription
):
    before = stored_state(db)
    assert before["event_count"] == 0
    assert len(before["subscriptions"]) == 1

    response = deliver(
        client,
        notification_bytes(capture_completed_event()),
        webhook_headers(signature=TAMPERED_SIG),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        subscriptions_module.WEBHOOK_REJECTED_DETAIL
    )
    after = stored_state(db)
    assert after == before
    assert after["event_count"] == 0
    assert db.query(WebhookEvent).count() == 0
    assert (
        db.query(Subscription).one().status
        == subscriptions_module.PENDING_STATUS
    )
    assert db.query(Subscription).one().end_date is None


def test_an_unverifiable_notification_changes_no_database_state(
    client, db, pending_subscription
):
    stand_in = VerifierTransport(unreachable=True)
    before = stored_state(db)

    with patch(SERVICE + "._client", new=stand_in.open_client):
        response = deliver(
            client,
            notification_bytes(capture_completed_event()),
            webhook_headers(),
        )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        subscriptions_module.WEBHOOK_UNVERIFIABLE_DETAIL
    )
    assert stored_state(db) == before
    assert db.query(WebhookEvent).count() == 0
    assert (
        db.query(Subscription).one().status
        == subscriptions_module.PENDING_STATUS
    )


@pytest.mark.parametrize("keyword, value", UNCHECKABLE_ANSWERS)
def test_an_answer_that_settles_nothing_is_answered_503(
    client, db, pending_subscription, keyword, value
):
    stand_in = VerifierTransport(**{keyword: value})
    before = stored_state(db)

    with patch(SERVICE + "._client", new=stand_in.open_client):
        response = deliver(
            client,
            notification_bytes(capture_completed_event()),
            webhook_headers(),
        )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        subscriptions_module.WEBHOOK_UNVERIFIABLE_DETAIL
    )
    assert stored_state(db) == before
    assert db.query(WebhookEvent).count() == 0
    assert (
        db.query(Subscription).one().status
        == subscriptions_module.PENDING_STATUS
    )
    assert db.query(Subscription).one().end_date is None


def test_only_a_reported_failure_is_answered_400(
    client, db, pending_subscription
):
    stand_in = VerifierTransport(
        status=paypal_service.VERIFICATION_FAILURE
    )
    before = stored_state(db)

    with patch(SERVICE + "._client", new=stand_in.open_client):
        response = deliver(
            client,
            notification_bytes(capture_completed_event()),
            webhook_headers(signature=TAMPERED_SIG),
        )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        subscriptions_module.WEBHOOK_REJECTED_DETAIL
    )
    assert stored_state(db) == before
    assert db.query(WebhookEvent).count() == 0


def test_a_failed_verification_is_logged_without_the_signature(
    client, db, failing_recorder, captured_records, pending_subscription
):
    response = deliver(
        client,
        notification_bytes(capture_completed_event()),
        webhook_headers(signature=TAMPERED_SIG),
    )

    assert response.status_code == 400
    records = captured_records.records
    assert paypal_service.REASON_SIGNATURE in logged_reasons(records)
    assert [
        record
        for record in records
        if record.levelno >= logging.WARNING
    ]
    assert values_found_in(records, (WEBHOOK_PATH,)) == [WEBHOOK_PATH]
    assert values_found_in(records, CONFIDENTIAL_VALUES) == []


def test_a_hostile_certificate_host_records_no_delivery(
    client, db, recorder, captured_records, pending_subscription
):
    before = stored_state(db)

    response = deliver(
        client,
        notification_bytes(capture_completed_event()),
        webhook_headers(cert_url=PREFIXED_HOST_CERT_URL),
    )

    assert response.status_code == 400
    assert recorder.calls == []
    assert recorder.mentions(PREFIXED_HOST_CERT_URL) is False
    assert paypal_service.REASON_CERTIFICATE_HOST in logged_reasons(
        captured_records.records
    )
    assert values_found_in(
        captured_records.records, (PREFIXED_HOST_CERT_URL,)
    ) == []
    assert stored_state(db) == before
    assert db.query(WebhookEvent).count() == 0


def test_a_verified_notification_is_answered_with_a_success_status(
    client, db, recorder, pending_subscription
):
    response = deliver(
        client,
        notification_bytes(capture_completed_event()),
        webhook_headers(),
    )

    assert 200 <= response.status_code < 300
    assert response.json()["status"] == (
        subscriptions_module.OUTCOME_PROCESSED
    )
    assert len(recorder.verify_calls()) == 1
    db.expire_all()
    assert (
        db.query(Subscription).one().status
        == subscriptions_module.ACTIVE_STATUS
    )
    assert db.query(WebhookEvent).count() == 1


def test_a_rejected_notification_is_not_answered_with_a_success(
    client, db, failing_recorder, pending_subscription
):
    response = deliver(
        client,
        notification_bytes(capture_completed_event()),
        webhook_headers(signature=TAMPERED_SIG),
    )

    assert response.status_code == 400
    assert not 200 <= response.status_code < 300
    db.expire_all()
    assert (
        db.query(Subscription).one().status
        == subscriptions_module.PENDING_STATUS
    )


def test_a_replayed_transmission_id_is_rejected_and_processed_once(
    client, db, recorder, pending_subscription
):
    body = notification_bytes(capture_completed_event())
    headers = webhook_headers()

    first = deliver(client, body, headers)

    assert 200 <= first.status_code < 300
    assert first.json()["status"] == (
        subscriptions_module.OUTCOME_PROCESSED
    )
    settled = stored_state(db)
    assert settled["event_count"] == 1
    assert (
        db.query(Subscription).one().status
        == subscriptions_module.ACTIVE_STATUS
    )
    assert db.query(User).one().role == PLAN.required_role

    replay = deliver(client, body, headers)

    assert replay.json()["status"] == (
        subscriptions_module.OUTCOME_DUPLICATE
    )
    assert replay.json()["status"] != (
        subscriptions_module.OUTCOME_PROCESSED
    )
    assert len(recorder.verify_calls()) == 2
    assert (
        db.query(WebhookEvent)
        .filter(WebhookEvent.transmission_id == TRANSMISSION_ID)
        .count()
        == 1
    )
    assert db.query(WebhookEvent).count() == 1
    assert stored_state(db) == settled
    assert db.query(Subscription).count() == 1
    assert db.query(User).one().role == PLAN.required_role


def test_an_unrecorded_delivery_is_answered_for_redelivery(
    client, db, recorder, captured_records, pending_subscription
):
    """A delivery whose record cannot be resolved is answered 503.

    The arbitration reports that it could neither write the delivery row
    nor find the identifier recorded. PayPal redelivers a notification it
    is not answered ``2xx`` for, so the response carries a status that
    asks for exactly that, one record names the reason, and no state
    changes.
    """
    with patch.object(
        subscriptions_module,
        "_record_delivery",
        new=AsyncMock(
            return_value=subscriptions_module.RECORD_UNRESOLVED
        ),
    ):
        response = deliver(
            client,
            notification_bytes(capture_completed_event()),
            webhook_headers(),
        )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        subscriptions_module.WEBHOOK_NOT_RECORDED_DETAIL
    )
    record = record_with_reason(
        captured_records.records,
        subscriptions_module.REASON_DELIVERY_NOT_RECORDED,
    )
    context = json.loads(formatted_lines([record])[0])[CONTEXT_FIELD]
    assert context["transmission_id"] == TRANSMISSION_ID
    db.expire_all()
    assert db.query(WebhookEvent).count() == 0
    assert (
        db.query(Subscription).one().status
        == subscriptions_module.PENDING_STATUS
    )
    assert db.query(User).one().role == Role.REGISTERED.value


def test_a_supplied_correlation_id_reaches_the_rejection_record(
    client, db, failing_recorder, captured_records, pending_subscription
):
    response = deliver(
        client,
        notification_bytes(capture_completed_event()),
        dict(
            webhook_headers(signature=TAMPERED_SIG),
            **{REQUEST_ID_HEADER: SUPPLIED_REQUEST_ID}
        ),
    )

    assert response.status_code == 400
    assert response.headers[REQUEST_ID_HEADER] == SUPPLIED_REQUEST_ID

    record = record_with_reason(
        captured_records.records, paypal_service.REASON_SIGNATURE
    )
    context = json.loads(formatted_lines([record])[0])[CONTEXT_FIELD]
    assert context[REQUEST_ID_FIELD] == SUPPLIED_REQUEST_ID


def test_a_supplied_correlation_id_reaches_the_replay_record(
    client, db, recorder, captured_records, pending_subscription
):
    body = notification_bytes(capture_completed_event())
    headers = dict(
        webhook_headers(), **{REQUEST_ID_HEADER: SUPPLIED_REQUEST_ID}
    )

    assert 200 <= deliver(client, body, headers).status_code < 300
    captured_records.clear()

    replay = deliver(client, body, headers)

    assert replay.json()["status"] == (
        subscriptions_module.OUTCOME_DUPLICATE
    )
    record = record_with_reason(
        captured_records.records, subscriptions_module.REASON_REPLAY
    )
    context = json.loads(formatted_lines([record])[0])[CONTEXT_FIELD]
    assert context[REQUEST_ID_FIELD] == SUPPLIED_REQUEST_ID
    assert context["transmission_id"] == TRANSMISSION_ID


def test_a_replayed_delivery_is_recorded_with_its_delivery_identity(
    client, db, recorder, captured_records, pending_subscription
):
    body = notification_bytes(capture_completed_event())
    headers = webhook_headers()

    assert 200 <= deliver(client, body, headers).status_code < 300
    captured_records.clear()

    replay = deliver(client, body, headers)

    assert replay.json()["status"] == (
        subscriptions_module.OUTCOME_DUPLICATE
    )

    records = captured_records.records
    record = record_with_reason(records, subscriptions_module.REASON_REPLAY)
    assert record.levelno >= logging.WARNING
    assert record.transmission_id == TRANSMISSION_ID
    assert record.paypal_order_id == ORDER_ID

    lines = formatted_lines([record])
    assert len(lines) == 1
    context = json.loads(lines[0])[CONTEXT_FIELD]
    assert context["transmission_id"] == TRANSMISSION_ID
    assert context["paypal_order_id"] == ORDER_ID
    assert context["path"] == WEBHOOK_PATH
    assert values_found_in(records, CONFIDENTIAL_VALUES) == []


@pytest.mark.asyncio
async def test_two_simultaneous_deliveries_are_processed_exactly_once(
    monkeypatch, client, db, recorder, captured_records,
    pending_subscription,
):
    barrier = ConcurrentDeliveryBarrier()
    controlled_deliveries(monkeypatch, barrier)

    first, second = await deliver_together(
        barrier,
        notification_bytes(capture_completed_event()),
        webhook_headers(),
    )

    assert barrier.overlapped is True
    assert barrier.holder_outcome == LEFT_BY_COMMIT
    assert 200 <= first.status_code < 300
    assert 200 <= second.status_code < 300
    assert first.json()["status"] == (
        subscriptions_module.OUTCOME_PROCESSED
    )
    assert second.json()["status"] == (
        subscriptions_module.OUTCOME_DUPLICATE
    )
    assert len(recorder.verify_calls()) == 2
    db.expire_all()
    assert (
        db.query(WebhookEvent)
        .filter(WebhookEvent.transmission_id == TRANSMISSION_ID)
        .count()
        == 1
    )
    assert db.query(WebhookEvent).count() == 1
    assert db.query(Subscription).count() == 1
    assert (
        db.query(Subscription).one().status
        == subscriptions_module.ACTIVE_STATUS
    )
    assert db.query(User).one().role == PLAN.required_role
    assert len(activations(captured_records.records)) == 1
    assert subscriptions_module.REASON_REPLAY in logged_reasons(
        captured_records.records
    )
    assert values_found_in(
        captured_records.records, CONFIDENTIAL_VALUES
    ) == []


@pytest.mark.asyncio
async def test_a_waiting_delivery_settles_once_the_first_rolls_back(
    monkeypatch, client, db, recorder, pending_subscription
):
    barrier = ConcurrentDeliveryBarrier(holder_commit_fails=True)
    controlled_deliveries(monkeypatch, barrier)

    first, second = await deliver_together(
        barrier,
        notification_bytes(capture_completed_event()),
        webhook_headers(),
    )

    assert barrier.overlapped is True
    assert barrier.holder_outcome == LEFT_BY_ROLLBACK
    assert first.status_code == 503
    assert first.json()["detail"] == (
        subscriptions_module.RECONCILIATION_DETAIL
    )
    assert second.json()["status"] == (
        subscriptions_module.OUTCOME_PROCESSED
    )
    assert second.json()["status"] != (
        subscriptions_module.OUTCOME_DUPLICATE
    )
    db.expire_all()
    assert (
        db.query(WebhookEvent)
        .filter(WebhookEvent.transmission_id == TRANSMISSION_ID)
        .count()
        == 1
    )
    assert db.query(WebhookEvent).count() == 1
    assert db.query(Subscription).count() == 1
    assert (
        db.query(Subscription).one().status
        == subscriptions_module.ACTIVE_STATUS
    )
    assert db.query(User).one().role == PLAN.required_role


@pytest.mark.asyncio
async def test_a_contended_insert_waits_off_the_event_loop(
    monkeypatch, client, db, recorder, pending_subscription
):
    barrier = ConcurrentDeliveryBarrier()
    controlled_deliveries(monkeypatch, barrier)
    loop_thread = threading.current_thread().ident

    first, second = await deliver_together(
        barrier,
        notification_bytes(capture_completed_event()),
        webhook_headers(),
    )

    assert barrier.overlapped is True
    assert len(barrier.held_flush_threads) == 2
    assert loop_thread not in barrier.held_flush_threads
    assert 200 <= first.status_code < 300
    assert 200 <= second.status_code < 300
    assert first.json()["status"] == (
        subscriptions_module.OUTCOME_PROCESSED
    )
    assert second.json()["status"] == (
        subscriptions_module.OUTCOME_DUPLICATE
    )


class RealIndexContention(object):

    def __init__(self, holder_commit_fails=False):
        self.holder_commit_fails = holder_commit_fails
        self.holder_session = None
        self.holder_inserted = threading.Event()
        self.release_holder = threading.Event()
        self.held_flush_threads = []
        self.overlapped = False

    def interpose(self, operation, perform):
        session = getattr(operation, "__self__", None)
        name = getattr(operation, "__name__", "")
        if session is None or name not in CONTROLLED_OPERATIONS:
            return perform()
        if (
            name == "commit"
            and session is self.holder_session
            and self.holder_commit_fails
        ):
            raise SQLAlchemyError("the transition could not be recorded")
        if name != "flush" or self.holder_session is not None:
            return perform()
        self.holder_session = session
        self.held_flush_threads.append(threading.current_thread().ident)
        result = perform()
        self.holder_inserted.set()
        assert self.release_holder.wait(STEP_BOUND_SECONDS), (
            "the first delivery was never released from its flush"
        )
        return result


async def deliver_against_the_index(barrier, blocked, body, headers):
    """Answers two overlapping deliveries, the second held by the server.

    The first delivery is started and held once its delivery row is
    inserted; the second is started and is waited for until the server
    reports a backend of this case's database waiting on a lock; the first
    is then released. The two responses are returned in the order the
    deliveries were started.
    """
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=CLIENT_BASE_URL,
    ) as caller:

        async def post():
            sent = dict(headers)
            sent["Content-Type"] = "application/json"
            return await caller.post(
                WEBHOOK_PATH, content=body, headers=sent
            )

        first = asyncio.ensure_future(post())
        await reached(
            barrier.holder_inserted,
            "the first delivery never recorded its delivery row",
        )
        second = asyncio.ensure_future(post())
        loop = asyncio.get_event_loop()
        waited = await loop.run_in_executor(None, blocked, 1)
        assert waited, (
            "the second delivery was never seen waiting on the unique "
            "index the first holds"
        )
        barrier.overlapped = not first.done()
        barrier.release_holder.set()
        return await asyncio.wait_for(
            asyncio.gather(first, second), PAIR_BOUND_SECONDS
        )


@pytest.fixture
def postgres_subscriber(postgres_db, password_hash):
    """Returns the account the seeded subscription belongs to."""
    account = User(
        email=SUBSCRIBER_EMAIL,
        hashed_password=password_hash,
        created_at=datetime.now(timezone.utc),
        role=Role.REGISTERED.value,
    )
    postgres_db.add(account)
    postgres_db.commit()
    postgres_db.refresh(account)
    return account


@pytest.fixture
def postgres_pending_subscription(postgres_db, postgres_subscriber):
    """Stores the pending row the notifications name by its order."""
    row = Subscription(
        user_id=postgres_subscriber.id,
        start_date=datetime.now(timezone.utc),
        status=subscriptions_module.PENDING_STATUS,
        plan_id=PREMIUM_MONTHLY,
        amount=PLAN.amount,
        currency=PLAN.currency,
        paypal_order_id=ORDER_ID,
    )
    postgres_db.add(row)
    postgres_db.commit()
    return row


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_the_unique_index_makes_the_repeat_wait_on_postgres(
    monkeypatch,
    postgres_client,
    postgres_db,
    postgres_observer,
    recorder,
    postgres_pending_subscription,
):
    barrier = RealIndexContention()
    controlled_deliveries(monkeypatch, barrier)

    first, second = await deliver_against_the_index(
        barrier,
        postgres_observer,
        notification_bytes(capture_completed_event()),
        webhook_headers(),
    )

    assert barrier.overlapped is True
    assert 200 <= first.status_code < 300
    assert 200 <= second.status_code < 300
    assert first.json()["status"] == (
        subscriptions_module.OUTCOME_PROCESSED
    )
    assert second.json()["status"] == (
        subscriptions_module.OUTCOME_DUPLICATE
    )
    postgres_db.expire_all()
    assert (
        postgres_db.query(WebhookEvent)
        .filter(WebhookEvent.transmission_id == TRANSMISSION_ID)
        .count()
        == 1
    )
    assert postgres_db.query(WebhookEvent).count() == 1
    assert postgres_db.query(Subscription).count() == 1
    assert (
        postgres_db.query(Subscription).one().status
        == subscriptions_module.ACTIVE_STATUS
    )
    assert postgres_db.query(User).one().role == PLAN.required_role


#: Seconds the case below waits before releasing the delivery row it
#: holds uncommitted. It is above
#: ``conftest.POSTGRES_SHORT_STATEMENT_TIMEOUT_SECONDS``, so the waiting
#: write is ended by the server at least once before the row it waits on
#: is committed, and below the budget
#: ``subscriptions_module.MAX_RECORD_ATTEMPTS`` statement bounds give the
#: arbitration, so the arbitration still resolves.
HOLD_BEFORE_COMMIT_SECONDS = 1.5


def _hold_delivery(session, transmission_id, event_type):
    """Insert a delivery row on ``session`` and leave it uncommitted."""
    session.add(
        WebhookEvent(
            transmission_id=transmission_id, event_type=event_type
        )
    )
    session.flush()


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_a_cancelled_wait_resolves_to_a_duplicate_on_postgres(
    postgres_db, postgres_short_timeout_session_factory
):
    """A write the server ends still reports the committed duplicate.

    Every PostgreSQL connection this service opens carries a statement
    bound, so the write that waits on the delivery identifier is ended by
    the server rather than waiting indefinitely. The ending is not the
    uniqueness constraint deciding, so the arbitration reads the
    identifier back and attempts the write again. Here the row it waits
    on is committed while it is retrying, so the arbitration reports the
    delivery as already recorded, exactly one row is stored, and the
    request that was waiting wrote nothing of its own.
    """
    identifier = "cancelled-then-committed-0001"
    _hold_delivery(postgres_db, identifier, "PAYMENT.CAPTURE.COMPLETED")

    releasing = threading.Thread(
        target=lambda: (
            time.sleep(HOLD_BEFORE_COMMIT_SECONDS),
            postgres_db.commit(),
        )
    )
    waiting = postgres_short_timeout_session_factory()
    releasing.start()
    try:
        outcome = await subscriptions_module._record_delivery(
            waiting, identifier, "PAYMENT.CAPTURE.COMPLETED"
        )
    finally:
        releasing.join(STEP_BOUND_SECONDS)
        waiting.close()

    assert outcome == subscriptions_module.RECORD_DUPLICATE
    postgres_db.expire_all()
    assert (
        postgres_db.query(WebhookEvent)
        .filter(WebhookEvent.transmission_id == identifier)
        .count()
        == 1
    )


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_an_unresolved_delivery_writes_nothing_on_postgres(
    postgres_db, postgres_short_timeout_session_factory
):
    """A write no attempt can decide is reported, not answered as done.

    The delivery row it waits on is never committed, so every attempt is
    ended by the server and the identifier is never found recorded. The
    arbitration reports that it could not resolve, which the route
    answers with a status PayPal redelivers under, and nothing is
    written.
    """
    identifier = "cancelled-and-never-committed-0001"
    _hold_delivery(postgres_db, identifier, "PAYMENT.CAPTURE.COMPLETED")

    waiting = postgres_short_timeout_session_factory()
    try:
        outcome = await subscriptions_module._record_delivery(
            waiting, identifier, "PAYMENT.CAPTURE.COMPLETED"
        )
    finally:
        waiting.close()
        postgres_db.rollback()

    assert outcome == subscriptions_module.RECORD_UNRESOLVED
    postgres_db.expire_all()
    assert postgres_db.query(WebhookEvent).count() == 0


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_the_waiting_delivery_settles_when_the_index_frees_on_postgres(
    monkeypatch,
    postgres_client,
    postgres_db,
    postgres_observer,
    recorder,
    postgres_pending_subscription,
):
    barrier = RealIndexContention(holder_commit_fails=True)
    controlled_deliveries(monkeypatch, barrier)

    first, second = await deliver_against_the_index(
        barrier,
        postgres_observer,
        notification_bytes(capture_completed_event()),
        webhook_headers(),
    )

    assert barrier.overlapped is True
    assert first.status_code == 503
    assert first.json()["detail"] == (
        subscriptions_module.RECONCILIATION_DETAIL
    )
    assert second.json()["status"] == (
        subscriptions_module.OUTCOME_PROCESSED
    )
    postgres_db.expire_all()
    assert (
        postgres_db.query(WebhookEvent)
        .filter(WebhookEvent.transmission_id == TRANSMISSION_ID)
        .count()
        == 1
    )
    assert postgres_db.query(WebhookEvent).count() == 1
    assert postgres_db.query(Subscription).count() == 1
    assert (
        postgres_db.query(Subscription).one().status
        == subscriptions_module.ACTIVE_STATUS
    )
    assert postgres_db.query(User).one().role == PLAN.required_role
