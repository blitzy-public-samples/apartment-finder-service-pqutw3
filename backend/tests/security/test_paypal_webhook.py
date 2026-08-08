"""Webhook authenticity, certificate-host and replay regressions.

Finding H-4 is the complete absence of PayPal webhook signature
verification anywhere in the codebase: every inbound notification was
trusted, so anyone able to reach the service could assert an arbitrary
subscription state. The cases here are the evidence that the control
which closed it works.

Two surfaces are exercised.

* :func:`backend.app.services.paypal_service.verify_webhook_signature`
  is driven directly with crafted headers and bodies. It assembles
  PayPal's documented postback document, checks the host named by the
  ``PAYPAL-CERT-URL`` header against
  ``settings.PAYPAL_CERT_HOST_ALLOWLIST``, requires all five
  ``PAYPAL-*`` headers, posts to PayPal's verify-webhook-signature
  endpoint and returns a
  :class:`backend.app.services.paypal_service.WebhookVerification`. It
  reaches no database on any path.
* ``POST /subscriptions/webhook`` is exercised through the test client
  with the real verification function in place. The route performs the
  ``webhook_events`` insert whose UNIQUE ``transmission_id`` column
  detects a repeated delivery.

Every outbound call is answered by :class:`VerifierTransport`, a
stand-in transport that records each request it is handed and opens no
socket. The cases assert on what the service transmitted and on how
many calls it made.

The three checks the security reviewer of
``docs/review/CRITICAL_DECISIONS.md`` entry 4 must be able to point at
are each a separately named case:

* the allowlist applied before the certificate URL is fetched or
  forwarded --
  ``test_the_certificate_host_allowlist_is_applied_before_any_call``
* a repeated delivery identifier rejected --
  ``test_a_replayed_transmission_id_is_rejected_and_processed_once``
* a failed verification producing no state change --
  ``test_a_failed_verification_changes_no_database_state``
"""

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import patch

import httpx
import pytest

from backend.app.api.endpoints import subscriptions as subscriptions_module
from backend.app.core.config import settings
from backend.app.core.logging import BASE_LOGGER_NAME
from backend.app.core.plans import PREMIUM_MONTHLY, format_amount, get_plan
from backend.app.db.models import Subscription, User, WebhookEvent
from backend.app.main import limiter
from backend.app.services import paypal_service

#: Import path the transport funnel is patched on.
SERVICE = "backend.app.services.paypal_service"

#: Route the notifications are delivered to. It carries no ``/api``
#: segment and is mounted under the existing ``/subscriptions`` prefix.
WEBHOOK_PATH = "/subscriptions/webhook"

#: Path of PayPal's credential-exchange endpoint.
TOKEN_PATH = "/v1/oauth2/token"

#: Path of PayPal's verify-webhook-signature endpoint.
VERIFY_PATH = "/v1/notifications/verify-webhook-signature"

#: Access token the stand-in credential exchange grants.
ACCESS_TOKEN = "verifier-access-token-value"

#: Catalog entry the seeded subscription was priced by.
PLAN = get_plan(PREMIUM_MONTHLY)

#: Order identifier the seeded subscription row carries.
ORDER_ID = "ORDER-WEBHOOK-H4-1"

#: Capture identifier the notifications report.
CAPTURE_ID = "CAPTURE-WEBHOOK-H4-1"

#: Delivery identifier a notification carries unless a case varies it.
TRANSMISSION_ID = "3f6c1e00-1111-2222-3333-444455556666"

#: Signature a notification carries unless a case varies it.
TRANSMISSION_SIG = "dmFsaWQtc2lnbmF0dXJlLXZhbHVl"

#: Signature presented by the tampering cases.
TAMPERED_SIG = "dGFtcGVyZWQtc2lnbmF0dXJlLXZhbHVl"

#: Send time a notification carries.
TRANSMISSION_TIME = "2026-08-07T10:00:00Z"

#: Signature algorithm a notification names.
AUTH_ALGO = "SHA256withRSA"

#: Certificate URL whose host is on the configured allowlist.
ALLOWED_CERT_URL = (
    "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-H4"
)

#: Address of the account the seeded subscription belongs to.
SUBSCRIBER_EMAIL = "webhook.payer@example.com"

#: Every field of the postback document PayPal's verifier is sent.
POSTBACK_FIELDS = (
    "auth_algo",
    "cert_url",
    "transmission_id",
    "transmission_sig",
    "transmission_time",
    "webhook_id",
    paypal_service.WEBHOOK_EVENT_FIELD,
)

#: PayPal's documented inbound header name, the constant the service
#: matches it under, and the postback field it supplies.
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

#: Certificate URL naming a host with no relation to the allowlist.
FOREIGN_HOST_CERT_URL = "https://certs.attacker.invalid/cert.pem"

#: Certificate URL whose host merely begins with an allowlisted name.
PREFIXED_HOST_CERT_URL = (
    "https://api.paypal.com.attacker.invalid/cert.pem"
)

#: Certificate URL whose host ends with an allowlisted name on no dot
#: boundary.
UNBOUNDED_HOST_CERT_URL = "https://notapi.paypal.com/cert.pem"

#: Certificate URL carrying an allowlisted name as user information.
USERINFO_CERT_URL = (
    "https://api.paypal.com@certs.attacker.invalid/cert.pem"
)

#: Certificate URL carrying an allowlisted name in its path.
PATH_CERT_URL = (
    "https://certs.attacker.invalid/api.paypal.com/cert.pem"
)

#: Certificate URL naming an allowlisted host over a plain scheme.
PLAIN_SCHEME_CERT_URL = (
    "http://api.sandbox.paypal.com/v1/notifications/certs/C1"
)

#: Certificate URLs whose host is outside the allowlist. Each shape
#: defeats a different insufficient check.
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


class RecordedCall(object):
    """One outbound request as the stand-in transport received it."""

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
        """Returns every value handed to the transport, as one text."""
        parts = [self.method, self.target]
        for name, value in self.headers.items():
            parts.append("{0}: {1}".format(name, value))
        parts.append(self.content.decode("utf-8", "replace"))
        return "\n".join(parts)

    def mentions(self, value):
        """Returns True when ``value`` appears among the arguments."""
        return value in self.arguments()

    def document(self):
        """Returns the decoded body this call transmitted."""
        return json.loads(self.content.decode("utf-8"))


class VerifierTransport(object):
    """Answers PayPal's endpoints and records every call it is handed.

    ``status`` is the ``verification_status`` the verify endpoint
    reports. ``unreachable`` makes the verify call fail as a transport
    error instead. No request leaves the process.
    """

    def __init__(
        self,
        status=paypal_service.VERIFICATION_SUCCESS,
        unreachable=False,
    ):
        self.status = status
        self.unreachable = unreachable
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
        """Records ``outbound`` and answers the path it addressed."""
        call = RecordedCall(outbound)
        self.calls.append(call)
        if call.path == TOKEN_PATH:
            return httpx.Response(
                200,
                json={
                    "access_token": ACCESS_TOKEN,
                    "expires_in": 3600,
                },
            )
        if self.unreachable:
            raise httpx.ConnectError("verifier unreachable")
        return httpx.Response(
            200, json={"verification_status": self.status}
        )

    @property
    def paths(self):
        """Returns the path of every recorded call, in order."""
        return [call.path for call in self.calls]

    def verify_calls(self):
        """Returns the recorded calls addressed to the verifier."""
        return [
            call for call in self.calls if call.path == VERIFY_PATH
        ]

    def mentions(self, value):
        """Returns True when any recorded call carries ``value``."""
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
    """Returns ``event`` as the raw bytes a delivery carries."""
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
    """Returns every stored value a notification could change."""
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
    """Returns the rejection reason recorded by each record naming one."""
    return [
        record.reason
        for record in records
        if getattr(record, "reason", None) is not None
    ]


def values_found_in(records, values):
    """Returns the members of ``values`` present in any record."""
    rendered = [repr(vars(record)) for record in records]
    return [
        value
        for value in values
        if any(value in text for text in rendered)
    ]


#: Values no log record may carry.
CONFIDENTIAL_VALUES = (
    TRANSMISSION_SIG,
    TAMPERED_SIG,
    ACCESS_TOKEN,
    settings.PAYPAL_CLIENT_SECRET,
    settings.PAYPAL_WEBHOOK_ID,
    ALLOWED_CERT_URL,
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
    """The required headers are PayPal's own documented names."""
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
    """A passing check reports the delivery identifier and event type."""
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
    """The postback carries PayPal's documented field set verbatim."""
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
async def test_a_tampered_signature_is_rejected(failing_recorder):
    """A signature PayPal does not confirm fails the check."""
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
    """A check that could not be completed is not a passing check."""
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
async def test_a_malformed_notification_body_is_rejected_without_a_call(
    recorder,
):
    """A body that is not a JSON object is refused with nothing sent."""
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
    """A certificate host off the allowlist stops the check outright.

    The rejection is asserted together with the transport recording zero
    calls, so the host is refused before the URL is fetched, and the
    hostile value is absent from every argument the transport received,
    so it was not forwarded in a postback either.
    """
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
    """An allowlisted certificate host proceeds to the verify call."""
    outcome = await paypal_service.verify_webhook_signature(
        webhook_headers(),
        notification_bytes(capture_completed_event()),
    )

    assert outcome.verified is True
    assert recorder.paths == [TOKEN_PATH, VERIFY_PATH]
    assert recorder.mentions(ALLOWED_CERT_URL) is True


@pytest.mark.asyncio
async def test_every_outbound_call_carries_an_explicit_timeout(recorder):
    """Each call the check issues carries the configured timeout."""
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
    """Omitting any one required header is refused and changes nothing.

    The certificate URL is the first value checked, so omitting it is
    recorded as a certificate-host rejection and omitting any of the
    other four as a missing-header rejection.
    """
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
    """A refused notification leaves every stored value as it was."""
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
    """A check that could not be completed mutates nothing either."""
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


def test_a_failed_verification_is_logged_without_the_signature(
    client, db, failing_recorder, captured_records, pending_subscription
):
    """The refusal is recorded and carries no confidential value."""
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
    """A hostile certificate host is refused at the route with no call."""
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
    """Receipt is signalled only once the check and the work are done."""
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
    """A notification that fails its check is answered 400, never 2xx."""
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
    """A repeated delivery identifier is not processed a second time.

    The first delivery is accepted and settles the subscription. The
    second carries the same ``PAYPAL-TRANSMISSION-ID`` and is rejected as
    a repeat: ``webhook_events`` holds exactly one row for that
    identifier and the subscription mutation was applied once.
    """
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
