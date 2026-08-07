"""Regression tests for the subscription payment lifecycle.

The cases here cover what the payment path previously allowed: a
subscription activated without the payer ever approving, a settlement
accepted without checking what it settled, a webhook verified against a
re-encoded copy of the notification rather than the bytes that arrived, a
replayed delivery answered with an error that invites PayPal to retry it
forever, and an entitlement that no notification could ever grant or
withdraw.
"""

import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.endpoints import subscriptions as subscriptions_module
from backend.app.api.endpoints.auth import limiter
from backend.app.core.config import settings
from backend.app.core.plans import PREMIUM_MONTHLY, format_amount, get_plan
from backend.app.core.security import (
    create_access_token,
    get_password_hash,
)
from backend.app.db import database as database_module
from backend.app.db.models import (
    Base,
    Subscription,
    User,
    WebhookEvent,
)
from backend.app.main import app
from backend.app.services import paypal_service

PASSWORD = "Str0ng-Passphrase-9"

MODULE = "backend.app.api.endpoints.subscriptions"

SERVICE = "backend.app.services.paypal_service"

ORDER_ID = "ORDER-LIFECYCLE-1"

CAPTURE_ID = "CAPTURE-LIFECYCLE-1"

APPROVAL_URL = "https://www.sandbox.paypal.com/checkoutnow?token=1"

TRANSMISSION_ID = "b1b2b3b4-0000-1111-2222-333344445555"

CERT_URL = "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-1"

PLAN = get_plan(PREMIUM_MONTHLY)


def order_response(order_id=ORDER_ID, with_approval=True):
    """Returns a created-order response shaped like PayPal's."""
    links = [
        {"rel": "self", "href": "https://api-m.sandbox.paypal.com/o/1"}
    ]
    if with_approval:
        links.append({"rel": "payer-action", "href": APPROVAL_URL})
    return {
        "id": order_id,
        "status": "PAYER_ACTION_REQUIRED",
        "links": links,
    }


def capture_response(
    value=None,
    currency=None,
    status="COMPLETED",
    capture_id=CAPTURE_ID,
    order_id=ORDER_ID,
):
    """Returns a capture response shaped like PayPal's."""
    return {
        "id": order_id,
        "status": status,
        "purchase_units": [
            {
                "payments": {
                    "captures": [
                        {
                            "id": capture_id,
                            "status": status,
                            "amount": {
                                "currency_code": (
                                    currency or PLAN.currency
                                ),
                                "value": (
                                    value
                                    if value is not None
                                    else format_amount(PLAN.amount)
                                ),
                            },
                        }
                    ]
                }
            }
        ],
    }


def webhook_headers(cert_url=CERT_URL, transmission_id=TRANSMISSION_ID):
    """Returns the five headers a PayPal notification must carry."""
    return {
        paypal_service.AUTH_ALGO_HEADER: "SHA256withRSA",
        paypal_service.CERT_URL_HEADER: cert_url,
        paypal_service.TRANSMISSION_ID_HEADER: transmission_id,
        paypal_service.TRANSMISSION_SIG_HEADER: "c2lnbmF0dXJl",
        paypal_service.TRANSMISSION_TIME_HEADER: (
            "2026-08-07T10:00:00Z"
        ),
    }


class StubResponse:
    """A successful httpx-like response carrying ``payload``."""

    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.headers = {}

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def stub_client(client):
    """Returns a ``_client`` stand-in that yields ``client``.

    The transport accessor is an asynchronous context manager, so a
    stand-in has to be one too for the call under test to reach it.
    """

    @asynccontextmanager
    async def factory():
        yield client

    return factory


def approved_event(order_id=ORDER_ID):
    """Returns a CHECKOUT.ORDER.APPROVED notification."""
    return {
        "id": "WH-1",
        "event_type": "CHECKOUT.ORDER.APPROVED",
        "resource": {"id": order_id, "status": "APPROVED"},
    }


def capture_completed_event(order_id=ORDER_ID, value=None):
    """Returns a PAYMENT.CAPTURE.COMPLETED notification."""
    return {
        "id": "WH-2",
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


def refunded_event(order_id=ORDER_ID):
    """Returns a PAYMENT.CAPTURE.REFUNDED notification."""
    return {
        "id": "WH-3",
        "event_type": "PAYMENT.CAPTURE.REFUNDED",
        "resource": {
            "id": CAPTURE_ID,
            "supplementary_data": {
                "related_ids": {"order_id": order_id}
            },
        },
    }


def denied_event(order_id=ORDER_ID):
    """Returns a PAYMENT.CAPTURE.DENIED notification."""
    return {
        "id": "WH-4",
        "event_type": "PAYMENT.CAPTURE.DENIED",
        "resource": {
            "id": CAPTURE_ID,
            "supplementary_data": {
                "related_ids": {"order_id": order_id}
            },
        },
    }


@pytest.fixture(autouse=True)
def fresh_rate_limit_counters():
    """Clears the shared limiter counters around each case."""
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
def session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db(session_factory):
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def client(session_factory):
    def override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[database_module.get_db] = override_get_db
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def subscriber(db):
    user = User(
        email="payer@example.com",
        hashed_password=get_password_hash(PASSWORD),
        created_at=datetime.now(timezone.utc),
        role="registered",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def other_user(db):
    user = User(
        email="stranger@example.com",
        hashed_password=get_password_hash(PASSWORD),
        created_at=datetime.now(timezone.utc),
        role="registered",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def bearer(user):
    token = create_access_token(
        {"sub": str(user.id), "role": user.role}
    )
    return {"Authorization": "Bearer " + token}


def open_subscription(client, user, plan_id=PREMIUM_MONTHLY):
    """Opens a subscription with the order call stood in for."""
    with patch(
        MODULE + ".create_order",
        new=AsyncMock(return_value=order_response()),
    ):
        return client.post(
            "/subscriptions/",
            json={"plan_id": plan_id},
            headers=bearer(user),
        )


def deliver(client, event, headers=None, verified=True, reason=None):
    """Delivers one notification with verification stood in for.

    The verification outcome carries the event type, because the real
    check reads it from the body it verified rather than leaving the
    caller to re-read it from an unverified one.
    """
    outcome = paypal_service.WebhookVerification(
        verified=verified,
        transmission_id=(
            (headers or webhook_headers())[
                paypal_service.TRANSMISSION_ID_HEADER
            ]
            if verified
            else None
        ),
        event_type=(
            event.get("event_type")
            if verified and isinstance(event, dict)
            else None
        ),
        reason=reason,
    )
    with patch(
        MODULE + ".verify_webhook_signature",
        new=AsyncMock(return_value=outcome),
    ):
        return client.post(
            "/subscriptions/webhook",
            content=json.dumps(event).encode("utf-8"),
            headers=dict(
                headers or webhook_headers(),
                **{"Content-Type": "application/json"}
            ),
        )


class TestHostedApprovalIsNotSkipped:
    """Creation opens the order and stops; it captures nothing."""

    def test_the_approval_address_is_returned(self, client, subscriber):
        response = open_subscription(client, subscriber)
        assert response.status_code == 200
        assert response.json()["approval_url"] == APPROVAL_URL

    def test_nothing_is_captured_during_creation(
        self, client, subscriber
    ):
        capture = AsyncMock(return_value=capture_response())
        with patch(
            MODULE + ".create_order",
            new=AsyncMock(return_value=order_response()),
        ), patch(MODULE + ".capture_order", new=capture):
            response = client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            )
        assert response.status_code == 200
        capture.assert_not_awaited()

    def test_the_row_is_pending_and_grants_nothing(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == subscriptions_module.PENDING_STATUS
        assert stored.end_date is None
        assert stored.paypal_capture_id is None

        fetched = client.get(
            "/subscriptions/", headers=bearer(subscriber)
        )
        assert fetched.status_code == 200
        assert fetched.json() is None

    def test_the_role_is_not_raised_by_creation(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        db.expire_all()
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

    def test_an_order_without_an_approval_link_is_refused(
        self, client, db, subscriber
    ):
        with patch(
            MODULE + ".create_order",
            new=AsyncMock(
                return_value=order_response(with_approval=False)
            ),
        ):
            response = client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            )
        assert response.status_code == 400
        db.expire_all()
        assert (
            db.query(Subscription).one().status
            == subscriptions_module.FAILED_STATUS
        )

    def test_the_approve_relation_is_also_accepted(self):
        order = {
            "id": ORDER_ID,
            "links": [{"rel": "approve", "href": APPROVAL_URL}],
        }
        assert paypal_service.approval_url(order) == APPROVAL_URL

    @pytest.mark.parametrize(
        "order",
        [
            None,
            {},
            {"links": "not-a-list"},
            {"links": [{"rel": "self", "href": "https://x/y"}]},
            {"links": [{"rel": "approve"}]},
            {"links": [{"rel": "approve", "href": "  "}]},
        ],
    )
    def test_no_approval_address_is_reported_as_none(self, order):
        assert paypal_service.approval_url(order) is None


class TestPaymentIntegrity:
    """A settlement is durable, keyed and checked before it counts."""

    def test_the_row_is_committed_before_the_order_is_opened(
        self, client, db, subscriber
    ):
        """The pending row must exist even when the order call fails.

        A provider outage is answered as a dependency failure rather than
        as a client error, so the status asserted here is ``502``.
        """
        with patch(
            MODULE + ".create_order",
            new=AsyncMock(
                side_effect=paypal_service.PayPalAPIError("down")
            ),
        ):
            response = client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            )
        assert response.status_code == 502
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == subscriptions_module.FAILED_STATUS
        assert stored.paypal_request_id
        assert stored.paypal_order_id is None

    def test_an_idempotency_key_is_persisted_and_sent(
        self, client, db, subscriber
    ):
        creator = AsyncMock(return_value=order_response())
        with patch(MODULE + ".create_order", new=creator):
            client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            )
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.paypal_request_id
        assert creator.await_args.kwargs["idempotency_key"] == (
            stored.paypal_request_id
        )

    def test_the_capture_call_carries_an_idempotency_header(self):
        sent = {}

        class Client:
            async def post(self, path, **kwargs):
                sent["path"] = path
                sent["headers"] = kwargs.get("headers", {})
                return StubResponse(capture_response())

        async def run():
            with patch(
                SERVICE + "._client", new=stub_client(Client())
            ), patch(
                SERVICE + "._bearer_credential",
                new=AsyncMock(return_value="token"),
            ):
                return await paypal_service._post_json(
                    "/x", body={}, idempotency_key="KEY-1"
                )

        import asyncio

        asyncio.get_event_loop().run_until_complete(run())
        assert (
            sent["headers"][paypal_service.IDEMPOTENCY_HEADER]
            == "KEY-1"
        )

    def test_the_amount_sent_is_the_catalog_amount(self):
        sent = {}

        class Client:
            async def post(self, path, **kwargs):
                sent["json"] = kwargs.get("json")
                return StubResponse(order_response())

        async def run():
            with patch(
                SERVICE + "._client", new=stub_client(Client())
            ), patch(
                SERVICE + "._bearer_credential",
                new=AsyncMock(return_value="token"),
            ):
                return await paypal_service.create_order(
                    PREMIUM_MONTHLY, "https://a/r", "https://a/c", "K"
                )

        import asyncio

        asyncio.get_event_loop().run_until_complete(run())
        amount = sent["json"]["purchase_units"][0]["amount"]
        assert amount["value"] == format_amount(PLAN.amount)
        assert amount["currency_code"] == PLAN.currency

    def _settlement(self, payload):
        """Returns what the service reports ``payload`` settled.

        A settlement that does not match the catalog is *returned* as an
        incomplete outcome naming the failed check rather than raised, so
        the caller decides what to do with the row.
        """
        return paypal_service.read_capture(
            payload, ORDER_ID, PLAN.amount, PLAN.currency
        )

    def test_a_matching_capture_is_accepted(self):
        settled = self._settlement(capture_response())
        assert settled.completed is True
        assert settled.reason is None
        assert settled.order_id == ORDER_ID
        assert settled.amount == format_amount(PLAN.amount)
        assert settled.currency == PLAN.currency

    @pytest.mark.parametrize(
        "value", ["0.01", "1.00", "9.98", "999.99", "0.00"]
    )
    def test_a_capture_for_another_amount_is_refused(self, value):
        outcome = self._settlement(capture_response(value=value))
        assert outcome.completed is False
        assert outcome.reason

    @pytest.mark.parametrize("currency", ["EUR", "GBP", "JPY"])
    def test_a_capture_in_another_currency_is_refused(self, currency):
        outcome = self._settlement(capture_response(currency=currency))
        assert outcome.completed is False
        assert outcome.reason

    @pytest.mark.parametrize(
        "status", ["PENDING", "DECLINED", "FAILED", "REFUNDED"]
    )
    def test_a_capture_that_did_not_complete_is_refused(self, status):
        outcome = self._settlement(capture_response(status=status))
        assert outcome.completed is False
        assert outcome.reason

    @pytest.mark.parametrize(
        "capture",
        [
            None,
            {},
            {"purchase_units": []},
            {"purchase_units": [{"payments": {"captures": []}}]},
            {
                "status": "COMPLETED",
                "purchase_units": [
                    {"payments": {"captures": [{"id": "C"}]}}
                ],
            },
        ],
    )
    def test_an_unreadable_capture_is_refused(self, capture):
        outcome = self._settlement(capture)
        assert outcome.completed is False
        assert outcome.reason

    def test_a_capture_naming_another_order_is_refused(self):
        """An order identifier is part of what a settlement must match."""
        outcome = self._settlement(capture_response(order_id="OTHER"))
        assert outcome.completed is False
        assert outcome.reason


class TestWebhookAuthenticity:
    """Verification posts the notification back, host checked first."""

    def _run(self, coroutine):
        import asyncio

        return asyncio.get_event_loop().run_until_complete(coroutine)

    def test_the_postback_carries_the_notification_and_stored_id(self):
        """The postback names the stored webhook, not a supplied one.

        The notification is embedded as the object the route decoded, and
        the webhook identifier is read from configuration, so a caller
        cannot nominate the webhook its own notification is checked
        against.
        """
        notification = approved_event()
        sent = {}

        class Client:
            async def post(self, path, **kwargs):
                sent["path"] = path
                sent["json"] = kwargs.get("json")
                return StubResponse({"verification_status": "SUCCESS"})

        with patch(
            SERVICE + "._client", new=stub_client(Client())
        ), patch(
            SERVICE + "._bearer_credential",
            new=AsyncMock(return_value="token"),
        ):
            outcome = self._run(
                paypal_service.verify_webhook_signature(
                    webhook_headers(), notification
                )
            )

        assert outcome.verified is True
        assert outcome.transmission_id == TRANSMISSION_ID
        assert outcome.event_type == notification["event_type"]
        posted = sent["json"]
        assert posted["webhook_event"] == notification
        assert posted["webhook_id"] == settings.PAYPAL_WEBHOOK_ID
        assert posted["transmission_id"] == TRANSMISSION_ID
        assert posted["cert_url"] == CERT_URL
        assert posted["auth_algo"] == "SHA256withRSA"
        assert posted["transmission_sig"] == "c2lnbmF0dXJl"

    def test_no_supplied_webhook_id_can_displace_the_stored_one(self):
        """A notification naming another webhook is checked against ours."""
        notification = dict(approved_event(), webhook_id="WH-SUPPLIED")
        sent = {}

        class Client:
            async def post(self, path, **kwargs):
                sent["json"] = kwargs.get("json")
                return StubResponse({"verification_status": "SUCCESS"})

        with patch(
            SERVICE + "._client", new=stub_client(Client())
        ), patch(
            SERVICE + "._bearer_credential",
            new=AsyncMock(return_value="token"),
        ):
            self._run(
                paypal_service.verify_webhook_signature(
                    webhook_headers(), notification
                )
            )

        assert sent["json"]["webhook_id"] == settings.PAYPAL_WEBHOOK_ID
        assert sent["json"]["webhook_id"] != "WH-SUPPLIED"

    @pytest.mark.parametrize(
        "cert_url",
        [
            "https://api.attacker.invalid/certs/CERT",
            "https://api.paypal.com.attacker.invalid/certs/CERT",
            "http://api.paypal.com/certs/CERT",
            "https://user:pw@api.paypal.com/certs/CERT",
            "https://paypal.com.evil.test/certs/CERT",
            "not-a-url",
            "",
            "   ",
        ],
    )
    def test_a_certificate_host_outside_the_allowlist_is_refused(
        self, cert_url
    ):
        client_used = {"called": False}

        class Client:
            async def post(self, path, **kwargs):
                client_used["called"] = True
                raise AssertionError("no request may be made")

        with patch(SERVICE + "._client", return_value=Client()):
            outcome = self._run(
                paypal_service.verify_webhook_signature(
                    webhook_headers(cert_url=cert_url), b"{}"
                )
            )
        assert outcome.verified is False
        assert outcome.reason == paypal_service.REASON_CERTIFICATE_HOST
        assert client_used["called"] is False

    @pytest.mark.parametrize(
        "missing", list(paypal_service.REQUIRED_WEBHOOK_HEADERS)
    )
    def test_a_missing_required_header_is_refused(self, missing):
        headers = webhook_headers()
        headers.pop(missing)
        outcome = self._run(
            paypal_service.verify_webhook_signature(headers, b"{}")
        )
        assert outcome.verified is False
        assert outcome.reason in (
            paypal_service.REASON_MISSING_HEADER,
            paypal_service.REASON_CERTIFICATE_HOST,
        )

    @pytest.mark.parametrize(
        "raw", [b"", b"not json", b"[]", b'"text"', b"123"]
    )
    def test_a_body_that_is_not_an_object_is_refused(
        self, client, db, raw
    ):
        """The route decodes the body, so the route is what refuses one.

        A body that does not decode to an object is refused before the
        verifier is reached, so nothing is transmitted to PayPal and no
        delivery is recorded.
        """
        verifier = AsyncMock()
        with patch(MODULE + ".verify_webhook_signature", new=verifier):
            response = client.post(
                "/subscriptions/webhook",
                content=raw,
                headers=dict(
                    webhook_headers(),
                    **{"Content-Type": "application/json"}
                ),
            )
        assert response.status_code == 400
        verifier.assert_not_awaited()
        assert db.query(WebhookEvent).count() == 0

    def test_a_failing_verification_status_is_refused(self):
        class Client:
            async def post(self, path, **kwargs):
                return StubResponse({"verification_status": "FAILURE"})

        with patch(
            SERVICE + "._client", new=stub_client(Client())
        ), patch(
            SERVICE + "._bearer_credential",
            new=AsyncMock(return_value="token"),
        ):
            outcome = self._run(
                paypal_service.verify_webhook_signature(
                    webhook_headers(), {"event_type": "X"}
                )
            )
        assert outcome.verified is False
        assert outcome.reason == paypal_service.REASON_SIGNATURE

    def test_verification_records_nothing_itself(self, caplog):
        """The caller logs each rejection, so the service must not.

        Logging in both places produced two records for one rejection.
        """
        with caplog.at_level("WARNING"):
            outcome = self._run(
                paypal_service.verify_webhook_signature(
                    webhook_headers(cert_url="https://evil.invalid/c"),
                    b"{}",
                )
            )
        assert outcome.verified is False
        assert caplog.records == []


class TestWebhookRejectionChangesNothing:
    """A refused notification leaves the database untouched."""

    def test_a_tampered_signature_is_refused_with_no_change(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        db.expire_all()
        before = db.query(Subscription).one().status

        response = deliver(
            client,
            approved_event(),
            verified=False,
            reason=paypal_service.REASON_SIGNATURE,
        )
        assert response.status_code == 400
        db.expire_all()
        assert db.query(Subscription).one().status == before
        assert db.query(WebhookEvent).count() == 0

    def test_a_refused_notification_records_no_delivery(
        self, client, db
    ):
        response = deliver(
            client,
            approved_event(),
            verified=False,
            reason=paypal_service.REASON_CERTIFICATE_HOST,
        )
        assert response.status_code == 400
        assert db.query(WebhookEvent).count() == 0


class TestWebhookReplay:
    """A repeated delivery is acknowledged and applied once."""

    def test_a_replay_is_answered_with_success_and_no_change(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        with patch(
            MODULE + ".capture_order",
            new=AsyncMock(return_value=capture_response()),
        ):
            first = deliver(client, approved_event())
            assert first.status_code == 200
            assert first.json()["status"] == (
                subscriptions_module.OUTCOME_PROCESSED
            )
            db.expire_all()
            activated_at = db.query(Subscription).one().end_date

            second = deliver(client, approved_event())

        assert second.status_code == 200
        assert second.json()["status"] == (
            subscriptions_module.OUTCOME_DUPLICATE
        )
        db.expire_all()
        assert db.query(WebhookEvent).count() == 1
        assert db.query(Subscription).one().end_date == activated_at

    def test_a_replay_is_not_answered_with_an_error(
        self, client, db, subscriber
    ):
        """PayPal retries anything it cannot see acknowledged."""
        open_subscription(client, subscriber)
        with patch(
            MODULE + ".capture_order",
            new=AsyncMock(return_value=capture_response()),
        ):
            deliver(client, approved_event())
            replay = deliver(client, approved_event())
        assert replay.status_code == 200
        assert replay.status_code != 409

    def test_a_second_distinct_delivery_is_applied(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        with patch(
            MODULE + ".capture_order",
            new=AsyncMock(return_value=capture_response()),
        ):
            deliver(client, approved_event())
            deliver(
                client,
                refunded_event(),
                headers=webhook_headers(
                    transmission_id="another-transmission"
                ),
            )
        db.expire_all()
        assert db.query(WebhookEvent).count() == 2
        # A refund carries its own status, distinct from a denial, so the
        # reason an entitlement ended stays readable from the row.
        assert (
            db.query(Subscription).one().status
            == subscriptions_module.REFUNDED_STATUS
        )


class TestEntitlementLifecycle:
    """Verified events move the status and the role together."""

    def test_approval_captures_activates_and_raises_the_role(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        capture = AsyncMock(return_value=capture_response())
        with patch(MODULE + ".capture_order", new=capture):
            response = deliver(client, approved_event())
        assert response.status_code == 200
        capture.assert_awaited_once()

        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == subscriptions_module.ACTIVE_STATUS
        assert stored.paypal_capture_id == CAPTURE_ID
        assert stored.end_date is not None
        expected = stored.start_date + timedelta(
            days=PLAN.period_days
        )
        assert abs((stored.end_date - expected).total_seconds()) < 5
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == PLAN.required_role
        )

    def test_an_active_subscription_is_returned_by_retrieval(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        with patch(
            MODULE + ".capture_order",
            new=AsyncMock(return_value=capture_response()),
        ):
            deliver(client, approved_event())
        fetched = client.get(
            "/subscriptions/", headers=bearer(subscriber)
        )
        assert fetched.status_code == 200
        assert fetched.json()["status"] == (
            subscriptions_module.ACTIVE_STATUS
        )

    def test_a_completed_capture_event_activates_directly(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        response = deliver(client, capture_completed_event())
        assert response.status_code == 200
        db.expire_all()
        assert (
            db.query(Subscription).one().status
            == subscriptions_module.ACTIVE_STATUS
        )

    def test_a_completed_capture_for_another_amount_entitles_nothing(
        self, client, db, subscriber
    ):
        """A settlement that does not match the catalog writes nothing.

        The row is left as it was, which is pending and without an end
        date, so a redelivery reporting the right amount can still settle
        it and no entitlement is granted meanwhile.
        """
        open_subscription(client, subscriber)
        response = deliver(
            client, capture_completed_event(value="0.01")
        )
        assert response.status_code == 200
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == subscriptions_module.PENDING_STATUS
        assert stored.end_date is None
        assert stored.paypal_capture_id is None
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

    def test_a_mismatched_capture_on_approval_entitles_nothing(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        with patch(
            MODULE + ".capture_order",
            new=AsyncMock(return_value=capture_response(value="0.01")),
        ):
            response = deliver(client, approved_event())
        assert response.status_code == 200
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == subscriptions_module.PENDING_STATUS
        assert stored.end_date is None
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

    def test_a_denial_closes_the_row_without_an_entitlement(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        response = deliver(client, denied_event())
        assert response.status_code == 200
        db.expire_all()
        assert (
            db.query(Subscription).one().status
            == subscriptions_module.CANCELLED_STATUS
        )
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

    def test_a_refund_withdraws_the_entitlement_and_the_role(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        with patch(
            MODULE + ".capture_order",
            new=AsyncMock(return_value=capture_response()),
        ):
            deliver(client, approved_event())
        db.expire_all()
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == PLAN.required_role
        )

        deliver(
            client,
            refunded_event(),
            headers=webhook_headers(transmission_id="refund-1"),
        )
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == subscriptions_module.REFUNDED_STATUS
        assert stored.end_date <= datetime.now(timezone.utc).replace(
            tzinfo=None
        ) + timedelta(seconds=5)
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

        fetched = client.get(
            "/subscriptions/", headers=bearer(subscriber)
        )
        assert fetched.json() is None

    def test_an_administrator_is_never_altered(
        self, client, db, subscriber
    ):
        subscriber.role = "admin"
        db.commit()
        open_subscription(client, subscriber)
        with patch(
            MODULE + ".capture_order",
            new=AsyncMock(return_value=capture_response()),
        ):
            deliver(client, approved_event())
        db.expire_all()
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "admin"
        )

        deliver(
            client,
            refunded_event(),
            headers=webhook_headers(transmission_id="refund-2"),
        )
        db.expire_all()
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "admin"
        )

    def test_an_event_naming_an_unknown_order_changes_nothing(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        response = deliver(
            client, approved_event(order_id="ORDER-NOT-OURS")
        )
        assert response.status_code == 200
        assert response.json()["status"] == (
            subscriptions_module.OUTCOME_IGNORED
        )
        db.expire_all()
        assert (
            db.query(Subscription).one().status
            == subscriptions_module.PENDING_STATUS
        )

    def test_an_unrecognised_event_type_changes_nothing(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        response = deliver(
            client,
            {
                "event_type": "SOMETHING.ELSE",
                "resource": {
                    "id": CAPTURE_ID,
                    "supplementary_data": {
                        "related_ids": {"order_id": ORDER_ID}
                    },
                },
            },
        )
        assert response.status_code == 200
        assert response.json()["status"] == (
            subscriptions_module.OUTCOME_IGNORED
        )
        db.expire_all()
        assert (
            db.query(Subscription).one().status
            == subscriptions_module.PENDING_STATUS
        )

    def test_retrieval_ignores_a_pending_row_with_a_future_end_date(
        self, client, db, subscriber
    ):
        """Status governs access, not the end date alone."""
        row = Subscription(
            user_id=subscriber.id,
            plan_id=PREMIUM_MONTHLY,
            amount=Decimal("9.99"),
            currency="USD",
            status=subscriptions_module.PENDING_STATUS,
            start_date=datetime.now(timezone.utc),
            end_date=datetime.now(timezone.utc)
            + timedelta(days=365),
        )
        db.add(row)
        db.commit()
        fetched = client.get(
            "/subscriptions/", headers=bearer(subscriber)
        )
        assert fetched.status_code == 200
        assert fetched.json() is None


class TestOrderOwnershipBinding:
    """An order is only ever acted on through the row that owns it."""

    def test_another_users_order_is_refused(
        self, db, subscriber, other_user
    ):
        row = Subscription(
            user_id=other_user.id,
            plan_id=PREMIUM_MONTHLY,
            amount=Decimal("9.99"),
            currency="USD",
            status=subscriptions_module.PENDING_STATUS,
            start_date=datetime.now(timezone.utc),
            paypal_order_id=ORDER_ID,
        )
        db.add(row)
        db.commit()
        with pytest.raises(paypal_service.OrderOwnershipError):
            paypal_service._resolve_owned_order(
                db, ORDER_ID, subscriber, None
            )

    def test_an_unknown_order_is_refused_the_same_way(
        self, db, subscriber
    ):
        with pytest.raises(paypal_service.OrderOwnershipError) as first:
            paypal_service._resolve_owned_order(
                db, "ORDER-ABSENT", subscriber, None
            )
        row = Subscription(
            user_id=999999,
            plan_id=PREMIUM_MONTHLY,
            amount=Decimal("9.99"),
            currency="USD",
            status=subscriptions_module.PENDING_STATUS,
            start_date=datetime.now(timezone.utc),
            paypal_order_id=ORDER_ID,
        )
        db.add(row)
        db.commit()
        with pytest.raises(paypal_service.OrderOwnershipError) as second:
            paypal_service._resolve_owned_order(
                db, ORDER_ID, subscriber, None
            )
        assert str(first.value) == str(second.value)

    def test_an_owned_order_resolves(self, db, subscriber):
        row = Subscription(
            user_id=subscriber.id,
            plan_id=PREMIUM_MONTHLY,
            amount=Decimal("9.99"),
            currency="USD",
            status=subscriptions_module.PENDING_STATUS,
            start_date=datetime.now(timezone.utc),
            paypal_order_id=ORDER_ID,
        )
        db.add(row)
        db.commit()
        assert (
            paypal_service._resolve_owned_order(
                db, ORDER_ID, subscriber, None
            ).id
            == row.id
        )

    def test_the_lookup_writes_nothing_when_it_refuses(
        self, db, subscriber
    ):
        with pytest.raises(paypal_service.OrderOwnershipError):
            paypal_service._resolve_owned_order(
                db, "ORDER-ABSENT", subscriber, None
            )
        assert db.query(Subscription).count() == 0


class TestOutboundCallsDoNotBlockTheEventLoop:
    """Every PayPal call is awaited on a pooled, bounded client."""

    @pytest.mark.parametrize(
        "name",
        [
            "create_order",
            "capture_order",
            "fetch_order",
            "verify_webhook_signature",
            "open_http_client",
            "close_http_client",
            "_post_json",
            "_get_json",
            "_exchange_credentials",
            "_bearer_credential",
        ],
    )
    def test_every_call_is_a_coroutine(self, name):
        import inspect

        assert inspect.iscoroutinefunction(
            getattr(paypal_service, name)
        )

    def test_the_pooled_client_is_async_and_bounded(self):
        """One bounded client is shared for the process's lifetime.

        A call made outside that lifetime gets a client of its own, which
        is closed with the block, so no call is issued on a client that
        has already been closed.
        """
        import asyncio

        import httpx

        async def run():
            await paypal_service.close_http_client()
            async with paypal_service._client() as temporary:
                assert isinstance(temporary, httpx.AsyncClient)

            await paypal_service.open_http_client()
            try:
                async with paypal_service._client() as shared:
                    assert isinstance(shared, httpx.AsyncClient)
                    pool = shared._transport._pool
                    assert pool._max_connections == min(
                        paypal_service.MAX_CONNECTIONS,
                        settings.PAYPAL_MAX_CONNECTIONS,
                    )
                    assert shared.timeout.read == (
                        settings.HTTP_TIMEOUT_SECONDS
                    )
                    async with paypal_service._client() as again:
                        assert again is shared
            finally:
                await paypal_service.close_http_client()
            return True

        assert asyncio.get_event_loop().run_until_complete(run())

    def test_the_token_cache_is_not_held_across_the_exchange(self):
        """A second caller must not wait on the first one's network.

        Holding the cache lock across the exchange would serialise every
        request handler behind one outbound call.
        """
        import asyncio

        started = asyncio.Event()

        async def slow_exchange():
            started.set()
            await asyncio.sleep(0.05)
            return "token", 0.0

        async def run():
            paypal_service.reset_access_token_cache()
            with patch(
                SERVICE + "._exchange_credentials",
                new=AsyncMock(side_effect=slow_exchange),
            ):
                first = asyncio.ensure_future(
                    paypal_service._bearer_credential()
                )
                await started.wait()
                # The lock is free while the exchange is in flight.
                assert paypal_service._read_cached_token() is None
                return await first

        assert (
            asyncio.get_event_loop().run_until_complete(run())
            == "token"
        )

    def test_the_webhook_route_is_rate_limited(self, client, db):
        """The unauthenticated route bounds what a caller can ask for."""
        allowed = int(settings.RATE_LIMIT_WEBHOOK.split("/", 1)[0])
        outcome = paypal_service.WebhookVerification(
            verified=False,
            reason=paypal_service.REASON_SIGNATURE,
        )
        statuses = []
        with patch(
            MODULE + ".verify_webhook_signature",
            new=AsyncMock(return_value=outcome),
        ):
            for _ in range(allowed + 1):
                statuses.append(
                    client.post(
                        "/subscriptions/webhook",
                        content=b"{}",
                        headers={"Content-Type": "application/json"},
                    ).status_code
                )
        assert statuses[-1] == 429
        assert statuses[0] == 400


class TestRequestContractStaysPlanOnly:
    """No client value may reach the price or the entitlement."""

    @pytest.mark.parametrize(
        "extra",
        [
            {"amount": "0.01"},
            {"currency": "JPY"},
            {"start_date": "2020-01-01T00:00:00Z"},
            {"end_date": "2099-01-01T00:00:00Z"},
            {"status": "active"},
            {"paypal_order_id": "ORDER-MINE"},
            {"paypal_capture_id": "CAPTURE-MINE"},
            {"user_id": 999},
            {"role": "admin"},
        ],
    )
    def test_an_extra_field_is_rejected(
        self, client, subscriber, extra
    ):
        body = {"plan_id": PREMIUM_MONTHLY}
        body.update(extra)
        with patch(
            MODULE + ".create_order",
            new=AsyncMock(return_value=order_response()),
        ):
            response = client.post(
                "/subscriptions/", json=body, headers=bearer(subscriber)
            )
        assert response.status_code == 422

    def test_the_stored_amount_is_the_catalog_amount(
        self, client, db, subscriber
    ):
        open_subscription(client, subscriber)
        db.expire_all()
        stored = db.query(Subscription).one()
        assert Decimal(str(stored.amount)) == PLAN.amount
        assert stored.currency == PLAN.currency

    def test_an_unknown_plan_is_rejected(self, client, subscriber):
        response = client.post(
            "/subscriptions/",
            json={"plan_id": "free_forever"},
            headers=bearer(subscriber),
        )
        assert response.status_code == 422

    def test_the_callbacks_are_the_configured_ones(
        self, client, subscriber
    ):
        """Both targets are built from the configured return base.

        The approving and the abandoning payer are returned to different
        addresses, so the frontend can tell the two outcomes apart.
        """
        creator = AsyncMock(return_value=order_response())
        with patch(MODULE + ".create_order", new=creator):
            client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            )
        arguments = creator.await_args.args
        base = settings.PAYPAL_RETURN_BASE_URL
        assert arguments[1] == (
            base
            + subscriptions_module.HOSTED_REDIRECT_PATH
            + subscriptions_module.HOSTED_RETURN_PATH
        )
        assert arguments[2] == (
            base
            + subscriptions_module.HOSTED_REDIRECT_PATH
            + subscriptions_module.HOSTED_CANCEL_PATH
        )
        assert arguments[1] != arguments[2]

    def test_the_callbacks_are_not_the_first_cors_origin(self):
        """The setting is independent of the origin list.

        Deriving the callback from ALLOWED_ORIGINS is what let a
        permissive development origin become a payment callback.
        """
        for continuation in (
            subscriptions_module.HOSTED_RETURN_PATH,
            subscriptions_module.HOSTED_CANCEL_PATH,
        ):
            target = subscriptions_module._hosted_redirect_url(
                continuation
            )
            assert target not in settings.ALLOWED_ORIGINS
