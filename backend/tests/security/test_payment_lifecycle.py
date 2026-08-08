"""Regression tests for the subscription payment lifecycle.

The cases here cover what the payment path previously allowed: a
subscription activated without the payer ever approving, a settlement
accepted without checking what it settled, a webhook verified against a
re-encoded copy of the notification rather than the bytes that arrived, a
replayed delivery answered with an error that invites PayPal to retry it
forever, and an entitlement that no notification could ever grant or
withdraw.
"""

import inspect
import json
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.endpoints import subscriptions as subscriptions_module
from backend.app.api.endpoints.auth import limiter
from backend.app.core.config import settings
from backend.app.core.logging import (
    bind_request_id,
    current_request_id,
    reset_request_id,
)
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
    """A successful httpx-like response carrying ``payload``.

    ``content`` and the declared length are derived from the payload, so a
    stand-in is measured against the service's response-size cap exactly
    as a real response is. ``content`` may be given directly to serve a
    body larger than its payload declares.
    """

    def __init__(self, payload, status_code=200, content=None):
        self._payload = payload
        self.status_code = status_code
        if content is None:
            content = json.dumps(payload).encode("utf-8")
        self.content = content
        self.headers = {"Content-Length": str(len(content))}

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class CountedResponse(StubResponse):
    """A response that declares ``declared`` bytes and counts decodes."""

    def __init__(self, payload, declared):
        super().__init__(payload)
        self.headers = {"Content-Length": str(declared)}
        self.decoded = 0

    def json(self):
        self.decoded += 1
        return super().json()


class UnmeasuredResponse(StubResponse):
    """A response declaring no length and exposing no bytes."""

    def __init__(self, payload):
        super().__init__(payload)
        self.headers = {}
        self.content = None


class BoundedClient:
    """A client whose every call answers with one stored response."""

    def __init__(self, response):
        self._response = response
        self.calls = 0

    async def post(self, *args, **kwargs):
        self.calls += 1
        return self._response

    async def request(self, *args, **kwargs):
        self.calls += 1
        return self._response


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
def tracked_client(session_factory):
    """A client that records every request-scoped session handed out."""
    sessions = []

    def override_get_db():
        session = session_factory()
        sessions.append(session)
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[database_module.get_db] = override_get_db
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client, sessions
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

    The verification outcome carries the event type, matching the real
    check, which reads it from the body it verified rather than leaving
    the caller to re-read it from an unverified one.
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
        assert stored.paypal_order_id is None

    def test_an_idempotency_key_is_derived_and_sent(
        self, client, db, subscriber
    ):
        """The key is a function of the committed row's own identifier.

        Nothing is stored for it, so a repeat of an uncertain call
        re-derives the same value from the same row rather than reading a
        column back.
        """
        creator = AsyncMock(return_value=order_response())
        with patch(MODULE + ".create_order", new=creator):
            client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            )
        db.expire_all()
        stored = db.query(Subscription).one()
        sent = creator.await_args.kwargs["idempotency_key"]
        assert sent
        assert sent == paypal_service.order_request_id(stored.id)

    def test_a_repeated_request_reuses_the_open_attempt_and_its_key(
        self, client, db, subscriber
    ):
        """A retry cannot leave a second order orphaned at the provider.

        The open attempt already recorded is reused, so the repeat
        presents the same idempotency key and PayPal resolves it to the
        order the first attempt opened.
        """
        creator = AsyncMock(return_value=order_response())
        with patch(MODULE + ".create_order", new=creator):
            first = client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            )
            second = client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            )
        assert first.status_code == 200
        assert second.status_code == 200
        assert second.json()["id"] == first.json()["id"]

        db.expire_all()
        stored = db.query(Subscription).one()
        keys = [
            call.kwargs["idempotency_key"]
            for call in creator.await_args_list
        ]
        expected = paypal_service.order_request_id(stored.id)
        assert keys == [expected] * 2

    def test_a_failed_attempt_is_reused_rather_than_duplicated(
        self, client, db, subscriber
    ):
        """A failed attempt stays open to the retry that reuses its key."""
        with patch(
            MODULE + ".create_order",
            new=AsyncMock(
                side_effect=paypal_service.PayPalAPIError("down")
            ),
        ):
            assert client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            ).status_code == 502
        db.expire_all()
        failed = db.query(Subscription).one()
        assert failed.status == subscriptions_module.FAILED_STATUS
        first_key = paypal_service.order_request_id(failed.id)

        creator = AsyncMock(return_value=order_response())
        with patch(MODULE + ".create_order", new=creator):
            retried = client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            )
        assert retried.status_code == 200
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.id == failed.id
        assert paypal_service.order_request_id(stored.id) == first_key
        assert stored.status == subscriptions_module.PENDING_STATUS
        assert stored.paypal_order_id == ORDER_ID
        assert creator.await_args.kwargs["idempotency_key"] == first_key

    def test_a_known_order_identifier_survives_a_failed_attempt(
        self, client, db, subscriber
    ):
        """A failed mark never erases the order the provider holds."""
        assert open_subscription(client, subscriber).status_code == 200
        db.expire_all()
        assert db.query(Subscription).one().paypal_order_id == ORDER_ID

        with patch(
            MODULE + ".create_order",
            new=AsyncMock(
                side_effect=paypal_service.PayPalAPIError("down")
            ),
        ):
            assert client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            ).status_code == 502

        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == subscriptions_module.FAILED_STATUS
        assert stored.paypal_order_id == ORDER_ID

    def test_an_unrecordable_order_is_answered_as_reconciliation(
        self, client, db, subscriber
    ):
        """An order the provider holds is never answered as a client fault.

        The provider was already asked to open the order, so a local write
        that fails afterwards leaves provider and local state to be
        reconciled rather than reporting a rejected request.
        """
        from sqlalchemy.exc import SQLAlchemyError
        from sqlalchemy.orm import Session as SqlAlchemySession

        real_commit = SqlAlchemySession.commit
        state = {"calls": 0}

        def fail_the_second_commit(self):
            state["calls"] += 1
            if state["calls"] == 1:
                return real_commit(self)
            raise SQLAlchemyError("order identifier could not be stored")

        with patch(
            MODULE + ".create_order",
            new=AsyncMock(return_value=order_response()),
        ), patch.object(
            SqlAlchemySession, "commit", fail_the_second_commit
        ):
            response = client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            )

        assert response.status_code == 503
        assert response.json()["detail"] == (
            subscriptions_module.RECONCILIATION_DETAIL
        )

    def test_no_transaction_is_open_while_the_provider_is_called(
        self, tracked_client, subscriber
    ):
        """The database connection is not held across the provider call.

        The row is committed first and only plain values are carried past
        the commit, so the request-scoped session holds no transaction --
        and therefore no pooled connection -- while the order is opened.
        """
        client, sessions = tracked_client
        observed = {}

        async def order_observing_the_session(*args, **kwargs):
            observed["open"] = [
                session.in_transaction() for session in sessions
            ]
            return order_response()

        with patch(
            MODULE + ".create_order",
            new=AsyncMock(side_effect=order_observing_the_session),
        ):
            response = client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            )

        assert response.status_code == 200
        assert observed["open"]
        assert not any(observed["open"])

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

        The notification is embedded as the exact bytes that arrived, and
        the webhook identifier is read from configuration, so a caller
        cannot nominate the webhook its own notification is checked
        against.
        """
        notification = approved_event()
        # Indented bytes carrying whitespace a compact re-encoding would
        # not reproduce, so a re-encoded copy is distinguishable from the
        # bytes that arrived.
        raw = json.dumps(notification, indent=2).encode("utf-8")
        sent = {}

        class Client:
            async def post(self, path, **kwargs):
                sent["path"] = path
                sent["content"] = kwargs.get("content")
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
                    webhook_headers(), raw
                )
            )

        assert outcome.verified is True
        assert outcome.transmission_id == TRANSMISSION_ID
        assert outcome.event_type == notification["event_type"]
        # The bytes that arrived are what PayPal is asked to check.
        assert sent["json"] is None
        document = sent["content"]
        assert isinstance(document, bytes)
        assert raw in document
        posted = json.loads(document.decode("utf-8"))
        assert posted["webhook_event"] == notification
        assert posted["webhook_id"] == settings.PAYPAL_WEBHOOK_ID
        assert posted["transmission_id"] == TRANSMISSION_ID
        assert posted["cert_url"] == CERT_URL
        assert posted["auth_algo"] == "SHA256withRSA"
        assert posted["transmission_sig"] == "c2lnbmF0dXJl"

    def test_no_supplied_webhook_id_can_displace_the_stored_one(self):
        """A notification naming another webhook is checked against ours."""
        raw = json.dumps(
            dict(approved_event(), webhook_id="WH-SUPPLIED")
        ).encode("utf-8")
        sent = {}

        class Client:
            async def post(self, path, **kwargs):
                sent["content"] = kwargs.get("content")
                return StubResponse({"verification_status": "SUCCESS"})

        with patch(
            SERVICE + "._client", new=stub_client(Client())
        ), patch(
            SERVICE + "._bearer_credential",
            new=AsyncMock(return_value="token"),
        ):
            self._run(
                paypal_service.verify_webhook_signature(
                    webhook_headers(), raw
                )
            )

        posted = json.loads(sent["content"].decode("utf-8"))
        assert posted["webhook_id"] == settings.PAYPAL_WEBHOOK_ID
        assert posted["webhook_id"] != "WH-SUPPLIED"
        # The supplied value survives only where it arrived, nested
        # inside the notification being checked.
        assert posted["webhook_event"]["webhook_id"] == "WH-SUPPLIED"

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
        "raw", [b"", b"not json", b"[]", b'"text"', b"123", b"\xff\xfe"]
    )
    def test_a_body_that_is_not_an_object_is_refused(
        self, client, db, raw
    ):
        """A body that cannot be a notification is never transmitted.

        The verifier owns the transition from raw bytes to an object, so
        it refuses such a body itself, before any request is made to
        PayPal and before any delivery is recorded.
        """
        reached = {"called": False}

        class Client:
            async def post(self, path, **kwargs):
                reached["called"] = True
                raise AssertionError("no request may be made")

        with patch(
            SERVICE + "._client", new=stub_client(Client())
        ), patch(
            SERVICE + "._bearer_credential",
            new=AsyncMock(return_value="token"),
        ):
            response = client.post(
                "/subscriptions/webhook",
                content=raw,
                headers=dict(
                    webhook_headers(),
                    **{"Content-Type": "application/json"}
                ),
            )
        assert response.status_code == 400
        assert reached["called"] is False
        assert db.query(WebhookEvent).count() == 0

    def test_a_malformed_body_is_reported_as_such(self):
        """The rejection names the check that failed."""
        outcome = self._run(
            paypal_service.verify_webhook_signature(
                webhook_headers(), b"not json"
            )
        )
        assert outcome.verified is False
        assert outcome.reason == paypal_service.REASON_MALFORMED_BODY
        assert outcome.retryable is False

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
                    webhook_headers(), b'{"event_type": "X"}'
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

    def test_the_capture_leaves_the_replay_claim_in_place(
        self, client, db, subscriber
    ):
        """The delivery record survives the call that captures the order.

        The claim on the transmission identifier is taken before the
        capture and must still be held when the transition commits, or the
        first delivery is not recorded and PayPal's redelivery is
        processed as a fresh event.
        """
        open_subscription(client, subscriber)
        seen = {}

        async def capture_observing_the_claim(
            session, order_id, current_user, **kwargs
        ):
            seen["claimed"] = (
                session.query(WebhookEvent)
                .filter(WebhookEvent.transmission_id == TRANSMISSION_ID)
                .count()
            )
            return capture_response()

        with patch(
            MODULE + ".capture_order",
            new=AsyncMock(side_effect=capture_observing_the_claim),
        ):
            first = deliver(client, approved_event())
        assert first.status_code == 200
        # The claim was already held when the provider was called, and it
        # is still recorded afterwards.
        assert seen["claimed"] == 1
        db.expire_all()
        recorded = db.query(WebhookEvent).all()
        assert [row.transmission_id for row in recorded] == [
            TRANSMISSION_ID
        ]

        # The redelivery PayPal would send is therefore a replay.
        capture = AsyncMock(return_value=capture_response())
        with patch(MODULE + ".capture_order", new=capture):
            replay = deliver(client, approved_event())
        assert replay.json()["status"] == (
            subscriptions_module.OUTCOME_DUPLICATE
        )
        capture.assert_not_awaited()

    def test_a_settled_order_is_recovered_from_its_full_outcome(
        self, client, db, subscriber
    ):
        """A charge the provider already took still entitles its buyer.

        The provider refuses the capture because the order is settled, so
        the order is read back and the complete outcome that read produced
        is what activation is measured from.
        """
        open_subscription(client, subscriber)
        already = paypal_service.PayPalAPIError(
            "already captured",
            category=paypal_service.CATEGORY_PROVIDER_CLIENT,
            status_code=422,
        )
        settled = paypal_service.CaptureOutcome(
            completed=True,
            order_id=ORDER_ID,
            status="COMPLETED",
            amount=format_amount(PLAN.amount),
            currency=PLAN.currency,
            capture_id=CAPTURE_ID,
        )
        reader = AsyncMock(return_value=settled)
        with patch(
            MODULE + ".capture_order", new=AsyncMock(side_effect=already)
        ), patch(MODULE + ".verify_settled_order", new=reader):
            recovered = deliver(client, approved_event())

        assert recovered.status_code == 200
        assert recovered.json()["status"] == (
            subscriptions_module.OUTCOME_PROCESSED
        )
        reader.assert_awaited_once()
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == subscriptions_module.ACTIVE_STATUS
        assert not hasattr(stored, "paypal_capture_id")
        assert stored.end_date is not None
        assert db.query(WebhookEvent).count() == 1

    def test_a_settled_order_below_the_plan_price_entitles_nothing(
        self, client, db, subscriber
    ):
        """The read-back outcome is measured, not merely trusted."""
        open_subscription(client, subscriber)
        already = paypal_service.PayPalAPIError(
            "already captured",
            category=paypal_service.CATEGORY_PROVIDER_CLIENT,
            status_code=422,
        )
        short = paypal_service.CaptureOutcome(
            completed=False,
            order_id=ORDER_ID,
            status="COMPLETED",
            amount="0.01",
            currency=PLAN.currency,
            reason=paypal_service.REASON_AMOUNT_MISMATCH,
        )
        with patch(
            MODULE + ".capture_order", new=AsyncMock(side_effect=already)
        ), patch(
            MODULE + ".verify_settled_order",
            new=AsyncMock(return_value=short),
        ):
            refused = deliver(client, approved_event())

        assert refused.status_code == 200
        assert refused.json()["status"] == (
            subscriptions_module.OUTCOME_IGNORED
        )
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == subscriptions_module.PENDING_STATUS
        assert stored.end_date is None


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


class TestTerminalStatusTakesPrecedence:
    """A status the provider settled on is not written over afterwards.

    Two notifications for one order can be outstanding at once: an
    approval whose capture is being awaited, and a refund, reversal or
    denial recorded while that capture is in flight. Every transition is
    decided from the row read back under a write lock, so the terminal
    status stands and no entitlement follows it.
    """

    @staticmethod
    def _record(session_factory, status, order_id=ORDER_ID):
        """Records ``status`` against ``order_id`` from another session."""
        session = session_factory()
        try:
            row = (
                session.query(Subscription)
                .filter(Subscription.paypal_order_id == order_id)
                .one()
            )
            row.status = status
            row.end_date = datetime.now(timezone.utc)
            session.commit()
        finally:
            session.close()

    @staticmethod
    def _revoke_from_another_session(session_factory, event_type):
        """Applies the revoking transition from a session of its own."""
        session = session_factory()
        try:
            row = (
                session.query(Subscription)
                .filter(Subscription.paypal_order_id == ORDER_ID)
                .one()
            )
            outcome = subscriptions_module._revoke(
                session, row, event_type
            )
            session.commit()
            return outcome
        finally:
            session.close()

    @staticmethod
    def _remove(session_factory, order_id=ORDER_ID):
        """Deletes the stored order row from another session."""
        session = session_factory()
        try:
            session.query(Subscription).filter(
                Subscription.paypal_order_id == order_id
            ).delete()
            session.commit()
        finally:
            session.close()

    @staticmethod
    def _settled():
        """Returns the outcome a complete capture of the plan reports."""
        return paypal_service.CaptureOutcome(
            completed=True,
            order_id=ORDER_ID,
            status="COMPLETED",
            amount=format_amount(PLAN.amount),
            currency=PLAN.currency,
            capture_id=CAPTURE_ID,
        )

    def test_the_terminal_statuses_are_the_revoked_ones(self):
        """Only a revoked status is terminal."""
        assert subscriptions_module.TERMINAL_STATUSES == frozenset(
            {
                subscriptions_module.CANCELLED_STATUS,
                subscriptions_module.REFUNDED_STATUS,
            }
        )
        for status in subscriptions_module._REVOKED_STATUSES.values():
            assert status in subscriptions_module.TERMINAL_STATUSES
        for status in (
            subscriptions_module.PENDING_STATUS,
            subscriptions_module.FAILED_STATUS,
            subscriptions_module.ACTIVE_STATUS,
        ):
            assert status not in subscriptions_module.TERMINAL_STATUSES

    @pytest.mark.parametrize(
        "event_type",
        list(subscriptions_module.REVOKING_EVENTS),
    )
    def test_a_revocation_applied_during_the_capture_stands(
        self, client, db, subscriber, session_factory, event_type
    ):
        """An approval settled after a revocation entitles nothing."""
        open_subscription(client, subscriber)
        applied = []

        async def capture(*args, **kwargs):
            applied.append(
                self._revoke_from_another_session(
                    session_factory, event_type
                )
            )
            return capture_response()

        with patch(
            MODULE + ".capture_order", new=AsyncMock(side_effect=capture)
        ):
            response = deliver(client, approved_event())

        assert applied == [subscriptions_module.OUTCOME_PROCESSED]
        assert response.status_code == 200
        assert response.json()["status"] == (
            subscriptions_module.OUTCOME_IGNORED
        )
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == (
            subscriptions_module._REVOKED_STATUSES[event_type]
        )
        assert stored.end_date <= datetime.now(timezone.utc).replace(
            tzinfo=None
        ) + timedelta(seconds=5)
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

    @pytest.mark.parametrize(
        "status",
        [
            subscriptions_module.REFUNDED_STATUS,
            subscriptions_module.CANCELLED_STATUS,
        ],
    )
    def test_a_terminal_status_written_during_the_capture_stands(
        self, client, db, subscriber, session_factory, status
    ):
        """The row read before the capture is not the row written."""
        open_subscription(client, subscriber)

        async def capture(*args, **kwargs):
            self._record(session_factory, status)
            return capture_response()

        with patch(
            MODULE + ".capture_order", new=AsyncMock(side_effect=capture)
        ):
            response = deliver(client, approved_event())

        assert response.status_code == 200
        assert response.json()["status"] == (
            subscriptions_module.OUTCOME_IGNORED
        )
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == status
        assert stored.end_date <= datetime.now(timezone.utc).replace(
            tzinfo=None
        ) + timedelta(seconds=5)
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

    @pytest.mark.parametrize(
        "status",
        [
            subscriptions_module.REFUNDED_STATUS,
            subscriptions_module.CANCELLED_STATUS,
        ],
    )
    def test_the_activation_reads_the_row_back_before_writing(
        self, db, subscriber, session_factory, status
    ):
        """A stale copy is not the copy the write is judged by."""
        db.add(self._pending(subscriber))
        db.commit()
        stale = db.query(Subscription).one()
        assert stale.status == subscriptions_module.PENDING_STATUS
        self._record(session_factory, status)

        outcome = subscriptions_module._activate(
            db,
            stale,
            PLAN,
            self._settled(),
            "CHECKOUT.ORDER.APPROVED",
        )

        assert outcome == subscriptions_module.OUTCOME_IGNORED
        db.rollback()
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == status
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

    def test_a_second_revocation_leaves_the_first_status_alone(
        self, db, subscriber, session_factory
    ):
        """The status the first revocation recorded is the one kept."""
        db.add(self._pending(subscriber))
        db.commit()
        stale = db.query(Subscription).one()
        self._record(
            session_factory, subscriptions_module.REFUNDED_STATUS
        )

        outcome = subscriptions_module._revoke(
            db, stale, "PAYMENT.CAPTURE.DENIED"
        )

        assert outcome == subscriptions_module.OUTCOME_IGNORED
        db.rollback()
        db.expire_all()
        assert (
            db.query(Subscription).one().status
            == subscriptions_module.REFUNDED_STATUS
        )

    @pytest.mark.parametrize("transition", ["_activate", "_revoke"])
    def test_a_removed_row_is_neither_written_nor_recreated(
        self, db, subscriber, session_factory, transition
    ):
        """A row deleted mid-flight is not written back into existence."""
        db.add(self._pending(subscriber))
        db.commit()
        stale = db.query(Subscription).one()
        self._remove(session_factory)

        if transition == "_activate":
            outcome = subscriptions_module._activate(
                db,
                stale,
                PLAN,
                self._settled(),
                "CHECKOUT.ORDER.APPROVED",
            )
        else:
            outcome = subscriptions_module._revoke(
                db, stale, "PAYMENT.CAPTURE.REFUNDED"
            )

        assert outcome == subscriptions_module.OUTCOME_IGNORED
        db.rollback()
        db.expire_all()
        assert db.query(Subscription).count() == 0
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

    def test_the_abandoned_transition_is_recorded_with_its_reason(
        self, db, subscriber, session_factory
    ):
        """An abandoned transition names why it was abandoned."""
        db.add(self._pending(subscriber))
        db.commit()
        stale = db.query(Subscription).one()
        self._record(
            session_factory, subscriptions_module.REFUNDED_STATUS
        )

        with patch.object(
            subscriptions_module.logger, "warning"
        ) as noted:
            outcome = subscriptions_module._activate(
                db,
                stale,
                PLAN,
                self._settled(),
                "CHECKOUT.ORDER.APPROVED",
            )

        assert outcome == subscriptions_module.OUTCOME_IGNORED
        reasons = [
            call.kwargs["extra"].get("reason")
            for call in noted.call_args_list
            if "extra" in call.kwargs
        ]
        assert subscriptions_module.REASON_TERMINAL_STATUS in reasons

    @pytest.mark.parametrize("transition", ["_activate", "_revoke"])
    def test_every_transition_locks_the_row_it_writes(self, transition):
        """Neither transition writes the copy handed to it."""
        source = inspect.getsource(
            getattr(subscriptions_module, transition)
        )
        assert "_lock_subscription(db, subscription)" in source
        assert "TERMINAL_STATUSES" in source
        assert "subscription.status =" not in source
        assert "subscription.end_date =" not in source

    def test_the_lock_discards_the_copy_loaded_earlier(self):
        """The re-read is forced rather than served from the session."""
        source = inspect.getsource(
            subscriptions_module._lock_subscription
        )
        assert "populate_existing()" in source
        assert "with_for_update()" in source

    @staticmethod
    def _pending(subscriber):
        """Returns a pending row naming the order under test."""
        return Subscription(
            user_id=subscriber.id,
            plan_id=PREMIUM_MONTHLY,
            amount=PLAN.amount,
            currency=PLAN.currency,
            status=subscriptions_module.PENDING_STATUS,
            start_date=datetime.now(timezone.utc),
            paypal_order_id=ORDER_ID,
        )


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

    def test_the_shared_client_is_not_handed_to_another_loop(self):
        """A pool belongs to the loop that created it.

        The client opened on one loop is never yielded to a call running
        on another; that call gets a client of its own and closes it with
        the block.
        """
        import asyncio

        async def open_it():
            await paypal_service.close_http_client()
            await paypal_service.open_http_client()
            async with paypal_service._client() as own:
                assert own is paypal_service._shared_client
            return paypal_service._shared_client

        async def use_it_from_another_loop(opened):
            async with paypal_service._client() as other:
                assert other is not opened
                assert not other.is_closed
            return True

        first = asyncio.new_event_loop()
        second = asyncio.new_event_loop()
        try:
            opened = first.run_until_complete(open_it())
            assert second.run_until_complete(
                use_it_from_another_loop(opened)
            )
        finally:
            first.run_until_complete(
                paypal_service.close_http_client()
            )
            first.close()
            second.close()

    def test_a_failed_exchange_is_not_repeated_within_the_backoff(self):
        """A refused credential exchange is not retried on every call.

        The failure is held back for the configured window, and a caller
        arriving inside it is refused with that same failure without a
        request being sent.
        """
        import asyncio

        refusal = paypal_service.PayPalAPIError(
            "grant refused",
            category=paypal_service.CATEGORY_AUTHENTICATION,
            status_code=401,
        )
        exchange = AsyncMock(side_effect=refusal)

        async def run():
            paypal_service.reset_access_token_cache()
            with patch(
                SERVICE + "._exchange_credentials", new=exchange
            ):
                outcomes = []
                for _ in range(3):
                    try:
                        await paypal_service._bearer_credential()
                    except paypal_service.PayPalAPIError as error:
                        outcomes.append(error.category)
                return outcomes

        try:
            categories = asyncio.get_event_loop().run_until_complete(
                run()
            )
        finally:
            paypal_service.reset_access_token_cache()

        assert categories == [
            paypal_service.CATEGORY_AUTHENTICATION
        ] * 3
        # Only the first caller reached the provider.
        assert exchange.await_count == 1

    def test_a_successful_exchange_ends_the_backoff(self):
        """A window opened by a failure does not outlive a success."""
        import asyncio

        results = [
            paypal_service.PayPalAPIError(
                "grant refused",
                category=paypal_service.CATEGORY_AUTHENTICATION,
                status_code=401,
            ),
        ]

        async def exchange():
            if results:
                raise results.pop()
            return "token", 3600.0

        async def run():
            paypal_service.reset_access_token_cache()
            with patch(
                SERVICE + "._exchange_credentials",
                new=AsyncMock(side_effect=exchange),
            ):
                with pytest.raises(paypal_service.PayPalAPIError):
                    await paypal_service._bearer_credential()
                paypal_service.reset_access_token_cache()
                return await paypal_service._bearer_credential()

        try:
            assert asyncio.get_event_loop().run_until_complete(
                run()
            ) == "token"
        finally:
            paypal_service.reset_access_token_cache()

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

    @pytest.mark.parametrize(
        "call", ["capture_order", "verify_settled_order"]
    )
    def test_the_ownership_lookup_runs_on_another_thread(self, call):
        """Neither entry point resolves the owner on the event loop.

        The lookup reaches the database through the caller's synchronous
        session, so it is issued on a worker thread. The thread it ran on
        is recorded and compared with the thread the loop runs on.
        """
        import asyncio

        observed = {}

        def resolve(db, order_id, current_user, request):
            observed["lookup"] = threading.get_ident()
            return SimpleNamespace(id=7)

        async def run():
            observed["loop"] = threading.get_ident()
            with patch(
                SERVICE + "._resolve_owned_order", new=resolve
            ), patch(
                SERVICE + "._post_json",
                new=AsyncMock(return_value=capture_response()),
            ), patch(
                SERVICE + "._get_json",
                new=AsyncMock(return_value=capture_response()),
            ):
                if call == "capture_order":
                    return await paypal_service.capture_order(
                        None, ORDER_ID, SimpleNamespace(id=1)
                    )
                return await paypal_service.verify_settled_order(
                    None,
                    ORDER_ID,
                    SimpleNamespace(id=1),
                    PLAN.amount,
                    PLAN.currency,
                )

        outcome = asyncio.get_event_loop().run_until_complete(run())

        assert outcome is not None
        assert observed["lookup"] != observed["loop"]

    @pytest.mark.parametrize(
        "call", ["capture_order", "verify_settled_order"]
    )
    def test_the_ownership_lookup_is_awaited_off_the_loop(self, call):
        """The lookup is never called directly from the coroutine."""
        source = inspect.getsource(getattr(paypal_service, call))
        assert "run_in_threadpool(" in source
        assert "_resolve_owned_order(db" not in source

    def test_a_reset_during_the_exchange_discards_the_grant(self):
        """A rotation is not undone by an exchange already in flight.

        The caller that asked for the grant still receives it, and
        nothing is held for the callers that follow the rotation.
        """
        import asyncio

        started = asyncio.Event()

        async def slow_exchange():
            started.set()
            await asyncio.sleep(0.05)
            return "grant-from-rotated-credentials", 3600.0

        async def run():
            paypal_service.reset_access_token_cache()
            with patch(
                SERVICE + "._exchange_credentials",
                new=AsyncMock(side_effect=slow_exchange),
            ):
                pending = asyncio.ensure_future(
                    paypal_service._bearer_credential()
                )
                await started.wait()
                paypal_service.reset_access_token_cache()
                granted = await pending
            return granted, paypal_service._read_cached_token()

        try:
            granted, held = asyncio.get_event_loop().run_until_complete(
                run()
            )
        finally:
            paypal_service.reset_access_token_cache()

        assert granted == "grant-from-rotated-credentials"
        assert held is None

    def test_a_reset_during_a_failing_exchange_discards_the_backoff(
        self,
    ):
        """A rotation clears the window a racing failure would open."""
        import asyncio

        started = asyncio.Event()

        async def slow_failure():
            started.set()
            await asyncio.sleep(0.05)
            raise paypal_service.PayPalAPIError(
                "grant refused",
                category=paypal_service.CATEGORY_AUTHENTICATION,
                status_code=401,
            )

        async def run():
            paypal_service.reset_access_token_cache()
            with patch(
                SERVICE + "._exchange_credentials",
                new=AsyncMock(side_effect=slow_failure),
            ):
                pending = asyncio.ensure_future(
                    paypal_service._bearer_credential()
                )
                await started.wait()
                paypal_service.reset_access_token_cache()
                with pytest.raises(paypal_service.PayPalAPIError):
                    await pending
            return paypal_service._held_back_failure()

        try:
            held_back = asyncio.get_event_loop().run_until_complete(
                run()
            )
        finally:
            paypal_service.reset_access_token_cache()

        assert held_back is None

    def test_every_reset_advances_the_cache_generation(self):
        """The generation is what a racing exchange is measured against."""
        try:
            first = paypal_service._current_generation()
            paypal_service.reset_access_token_cache()
            second = paypal_service._current_generation()
            paypal_service.reset_access_token_cache()
            third = paypal_service._current_generation()
        finally:
            paypal_service.reset_access_token_cache()

        assert second == first + 1
        assert third == second + 1

    def test_a_grant_from_the_current_generation_is_held(self):
        """A grant exchanged without a rotation is reused."""
        try:
            paypal_service.reset_access_token_cache()
            generation = paypal_service._current_generation()
            stored = paypal_service._store_cached_token(
                "current-grant", 3600.0, generation
            )
            held = paypal_service._read_cached_token()
        finally:
            paypal_service.reset_access_token_cache()

        assert stored is True
        assert held == "current-grant"

    def test_a_grant_from_an_earlier_generation_is_discarded(self):
        """A grant that lost the race to a rotation is not held."""
        try:
            paypal_service.reset_access_token_cache()
            superseded = paypal_service._current_generation()
            paypal_service.reset_access_token_cache()
            stored = paypal_service._store_cached_token(
                "superseded-grant", 3600.0, superseded
            )
            held = paypal_service._read_cached_token()
        finally:
            paypal_service.reset_access_token_cache()

        assert stored is False
        assert held is None

    def test_a_failure_from_an_earlier_generation_is_discarded(self):
        """A failure that lost the race to a rotation holds nothing back."""
        refusal = paypal_service.PayPalAPIError(
            "grant refused",
            category=paypal_service.CATEGORY_AUTHENTICATION,
            status_code=401,
        )
        try:
            paypal_service.reset_access_token_cache()
            superseded = paypal_service._current_generation()
            paypal_service.reset_access_token_cache()
            recorded = paypal_service._record_exchange_failure(
                refusal, superseded
            )
            held_back = paypal_service._held_back_failure()
        finally:
            paypal_service.reset_access_token_cache()

        assert recorded is False
        assert held_back is None

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


class TestProviderResponsesAreBounded:
    """No provider body past the accepted size is read into memory.

    Every REST helper measures the body before decoding it, so a
    provider or an intermediary answering with an unbounded body cannot
    exhaust the process. The declared length is read first, so a body
    announcing itself as oversized is refused without being parsed at
    all.
    """

    @staticmethod
    def _run(coroutine_factory, response):
        """Awaits ``coroutine_factory`` with ``response`` stood in for."""
        import asyncio

        client = BoundedClient(response)

        async def run():
            paypal_service.reset_access_token_cache()
            with patch(SERVICE + "._client", new=stub_client(client)), patch(
                SERVICE + "._bearer_credential",
                new=AsyncMock(return_value="bearer-token"),
            ):
                return await coroutine_factory()

        try:
            return asyncio.get_event_loop().run_until_complete(run()), client
        finally:
            paypal_service.reset_access_token_cache()

    @staticmethod
    def _post():
        return paypal_service._post_json(
            "/v2/checkout/orders", {}, operation="create_order"
        )

    @staticmethod
    def _read():
        return paypal_service._get_json(
            "/v2/checkout/orders/" + ORDER_ID, operation="fetch_order"
        )

    @staticmethod
    def _exchange():
        return paypal_service._exchange_credentials()

    def test_the_accepted_size_is_a_megabyte(self):
        """The cap is stated once and reported on every refusal."""
        assert paypal_service.MAX_RESPONSE_BYTES == 1048576
        assert paypal_service.REASON_RESPONSE_TOO_LARGE == (
            "response_body_too_large"
        )
        assert paypal_service.CONTENT_LENGTH_HEADER == "Content-Length"

    @pytest.mark.parametrize(
        "call", ["_post", "_read", "_exchange"]
    )
    def test_a_body_past_the_cap_is_refused(self, call):
        """An oversized body raises rather than being decoded."""
        response = StubResponse(
            order_response(),
            content=b"x" * (paypal_service.MAX_RESPONSE_BYTES + 1),
        )
        with pytest.raises(paypal_service.PayPalAPIError) as raised:
            self._run(getattr(self, call), response)
        assert raised.value.category == (
            paypal_service.CATEGORY_MALFORMED_RESPONSE
        )

    @pytest.mark.parametrize(
        "call", ["_post", "_read", "_exchange"]
    )
    def test_a_declared_length_past_the_cap_is_refused_unparsed(
        self, call
    ):
        """A body announcing itself as oversized is never parsed."""
        response = CountedResponse(
            order_response(),
            declared=paypal_service.MAX_RESPONSE_BYTES + 1,
        )
        with pytest.raises(paypal_service.PayPalAPIError) as raised:
            self._run(getattr(self, call), response)
        assert raised.value.category == (
            paypal_service.CATEGORY_MALFORMED_RESPONSE
        )
        assert response.decoded == 0

    def test_a_body_at_the_cap_is_accepted(self):
        """The cap is the largest body accepted, not the first refused."""
        response = StubResponse(
            order_response(),
            content=b"x" * paypal_service.MAX_RESPONSE_BYTES,
        )
        payload, client = self._run(self._post, response)
        assert payload == order_response()
        assert client.calls == 1

    def test_an_unmeasurable_body_is_still_decoded(self):
        """A body declaring no length and carrying no bytes still reads."""
        response = UnmeasuredResponse(order_response())
        payload, client = self._run(self._post, response)
        assert payload == order_response()
        assert client.calls == 1

    def test_a_refusal_names_the_reason_and_the_cap(self):
        """The refusal is recorded with the size it measured."""
        response = StubResponse(
            order_response(),
            content=b"x" * (paypal_service.MAX_RESPONSE_BYTES + 2),
        )
        with patch.object(paypal_service.logger, "error") as noted:
            with pytest.raises(paypal_service.PayPalAPIError):
                self._run(self._post, response)
        extras = [
            call.kwargs["extra"]
            for call in noted.call_args_list
            if "extra" in call.kwargs
        ]
        refusals = [
            extra
            for extra in extras
            if extra.get("reason")
            == paypal_service.REASON_RESPONSE_TOO_LARGE
        ]
        assert refusals
        assert refusals[0]["max_response_bytes"] == (
            paypal_service.MAX_RESPONSE_BYTES
        )
        assert refusals[0]["response_bytes"] == (
            paypal_service.MAX_RESPONSE_BYTES + 2
        )

    def test_no_provider_body_is_decoded_before_it_is_measured(self):
        """Every helper reaches the decoder through the measured path."""
        for name in ("_post_json", "_get_json", "_exchange_credentials"):
            source = inspect.getsource(getattr(paypal_service, name))
            assert "_decoded_object(response" in source
            assert "response.json()" not in source


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
            {"approval_url": "https://checkout.invalid/pay"},
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
        """Each target is the setting that configures it.

        The approving and the abandoning payer are returned to different
        addresses, so the two outcomes stay distinguishable, and both
        address the one ``/subscription`` path the frontend router
        declares, so the payer always lands on a page that exists.
        """
        creator = AsyncMock(return_value=order_response())
        with patch(MODULE + ".create_order", new=creator):
            client.post(
                "/subscriptions/",
                json={"plan_id": PREMIUM_MONTHLY},
                headers=bearer(subscriber),
            )
        arguments = creator.await_args.args
        assert arguments[1] == settings.PAYPAL_RETURN_URL
        assert arguments[2] == settings.PAYPAL_CANCEL_URL
        assert arguments[1] != arguments[2]
        for target in arguments[1:3]:
            assert urlsplit(target).path == "/subscription"

    def test_the_callbacks_are_not_taken_from_the_origin_list(self):
        """Neither address appears in the cross-origin allowlist."""
        for target in (
            settings.PAYPAL_RETURN_URL,
            settings.PAYPAL_CANCEL_URL,
        ):
            assert target not in settings.ALLOWED_ORIGINS


class TestSessionWorkRunsOffTheEventLoop:
    """Neither async route issues a statement on the event loop.

    Two simultaneous deliveries of one notification previously stopped
    the whole service: the second delivery's insert waited on the first
    delivery's uncommitted row while occupying the event loop, so the
    completion of the first delivery's provider call could never be
    delivered, neither request ever finished and nothing recovered
    without restarting the process.
    """

    @pytest.mark.asyncio
    async def test_the_operation_runs_on_another_thread(self):
        caller = threading.get_ident()
        observed = {}

        def operation(marker):
            observed["thread"] = threading.get_ident()
            return marker

        assert await subscriptions_module._in_session(
            operation, "settled"
        ) == "settled"
        assert observed["thread"] != caller

    @pytest.mark.asyncio
    async def test_a_constraint_violation_is_raised_unchanged(self):
        def operation():
            raise IntegrityError("INSERT", {}, Exception("duplicate key"))

        with pytest.raises(IntegrityError):
            await subscriptions_module._in_session(operation)

    @pytest.mark.asyncio
    async def test_any_other_database_error_is_raised_unchanged(self):
        def operation():
            raise SQLAlchemyError("connection lost")

        with pytest.raises(SQLAlchemyError):
            await subscriptions_module._in_session(operation)

    @pytest.mark.asyncio
    async def test_keyword_arguments_reach_the_operation(self):
        def operation(first, second=None):
            return (first, second)

        assert await subscriptions_module._in_session(
            operation, "a", second="b"
        ) == ("a", "b")

    @pytest.mark.asyncio
    async def test_the_bound_request_identifier_reaches_the_thread(self):
        token = bind_request_id("d34db33f")
        try:
            observed = await subscriptions_module._in_session(
                current_request_id
            )
        finally:
            reset_request_id(token)
        assert observed == "d34db33f"

    @pytest.mark.parametrize(
        "route",
        [
            "create_subscription",
            "receive_paypal_webhook",
            "_apply_notification",
            "_settle",
        ],
    )
    @pytest.mark.parametrize(
        "statement",
        ["db.commit()", "db.flush()", "db.rollback()", "db.refresh("],
    )
    def test_no_async_route_issues_a_bare_statement(
        self, route, statement
    ):
        source = inspect.getsource(
            getattr(subscriptions_module, route)
        )
        assert statement not in source

    @pytest.mark.parametrize(
        "route",
        [
            "create_subscription",
            "receive_paypal_webhook",
            "_apply_notification",
            "_settle",
        ],
    )
    def test_every_such_route_is_a_coroutine_function(self, route):
        assert inspect.iscoroutinefunction(
            getattr(subscriptions_module, route)
        )

    def test_a_repeated_delivery_is_still_acknowledged(
        self, client, subscriber, db
    ):
        """The duplicate answer is unchanged by where the flush runs."""
        subscription = Subscription(
            user_id=subscriber.id,
            plan_id=PREMIUM_MONTHLY,
            amount=get_plan(PREMIUM_MONTHLY).amount,
            currency=get_plan(PREMIUM_MONTHLY).currency,
            status="pending",
            start_date=datetime.now(timezone.utc),
            paypal_order_id=ORDER_ID,
        )
        db.add(subscription)
        db.add(
            WebhookEvent(
                transmission_id=TRANSMISSION_ID,
                event_type="CHECKOUT.ORDER.APPROVED",
            )
        )
        db.commit()

        capture = AsyncMock()
        with patch(MODULE + ".capture_order", new=capture):
            response = deliver(
                client,
                {
                    "event_type": "CHECKOUT.ORDER.APPROVED",
                    "resource": {"id": ORDER_ID},
                },
            )
        assert response.status_code == 200
        assert response.json() == {"status": "duplicate"}
        capture.assert_not_awaited()
        assert db.query(WebhookEvent).count() == 1
        db.refresh(subscription)
        assert subscription.status == "pending"

    def test_a_first_delivery_still_settles_and_activates(
        self, client, subscriber, db
    ):
        """The processed answer is unchanged by where the flush runs."""
        subscription = Subscription(
            user_id=subscriber.id,
            plan_id=PREMIUM_MONTHLY,
            amount=get_plan(PREMIUM_MONTHLY).amount,
            currency=get_plan(PREMIUM_MONTHLY).currency,
            status="pending",
            start_date=datetime.now(timezone.utc),
            paypal_order_id=ORDER_ID,
        )
        db.add(subscription)
        db.commit()

        capture = AsyncMock(return_value=capture_response())
        with patch(MODULE + ".capture_order", new=capture):
            response = deliver(
                client,
                {
                    "event_type": "CHECKOUT.ORDER.APPROVED",
                    "resource": {"id": ORDER_ID},
                },
            )
        assert response.status_code == 200
        assert response.json() == {"status": "processed"}
        capture.assert_awaited_once()
        assert db.query(WebhookEvent).count() == 1
        db.refresh(subscription)
        assert subscription.status == "active"

    def test_a_failed_capture_still_rolls_the_delivery_record_back(
        self, client, subscriber, db
    ):
        """A redelivery can still settle a row whose capture failed."""
        subscription = Subscription(
            user_id=subscriber.id,
            plan_id=PREMIUM_MONTHLY,
            amount=get_plan(PREMIUM_MONTHLY).amount,
            currency=get_plan(PREMIUM_MONTHLY).currency,
            status="pending",
            start_date=datetime.now(timezone.utc),
            paypal_order_id=ORDER_ID,
        )
        db.add(subscription)
        db.commit()

        failing = AsyncMock(
            side_effect=paypal_service.PayPalAPIError(
                "capture failed",
                category=paypal_service.CATEGORY_TIMEOUT,
            )
        )
        with patch(MODULE + ".capture_order", new=failing):
            response = deliver(
                client,
                {
                    "event_type": "CHECKOUT.ORDER.APPROVED",
                    "resource": {"id": ORDER_ID},
                },
            )
        assert response.status_code == 504
        assert db.query(WebhookEvent).count() == 0
        db.refresh(subscription)
        assert subscription.status == "pending"

        capture = AsyncMock(return_value=capture_response())
        with patch(MODULE + ".capture_order", new=capture):
            redelivery = deliver(
                client,
                {
                    "event_type": "CHECKOUT.ORDER.APPROVED",
                    "resource": {"id": ORDER_ID},
                },
            )
        assert redelivery.status_code == 200
        assert redelivery.json() == {"status": "processed"}
        assert db.query(WebhookEvent).count() == 1
        db.refresh(subscription)
        assert subscription.status == "active"
