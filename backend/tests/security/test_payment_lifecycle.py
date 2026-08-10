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
from backend.app.core.plans import (
    PLAN_IDS,
    PREMIUM_MONTHLY,
    STATUS_VALUES,
    UnknownPlanError,
    format_amount,
    get_plan,
)
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
from backend.tests.support import enforce_sqlite_foreign_keys

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


def padded_body(payload, size, filler_key="_filler"):
    """Returns ``size`` bytes of JSON, and the object they decode to.

    The object is ``payload`` with one filler field whose value is grown
    until the encoding is exactly ``size`` bytes long, so a body of an
    exact measured size is still valid JSON and still decodes to a known
    object. Used to serve a body at, or one byte either side of, the
    service's response-size cap.
    """
    body = dict(payload)
    body[filler_key] = ""
    overhead = len(json.dumps(body).encode("utf-8"))
    if overhead > size:
        raise ValueError("payload is already longer than the target size")
    body[filler_key] = "x" * (size - overhead)
    encoded = json.dumps(body).encode("utf-8")
    assert len(encoded) == size
    return encoded, body


class StubResponse:
    """A successful httpx-like response streaming ``payload``.

    ``content`` is what ``aiter_bytes`` yields and defaults to the
    payload's JSON encoding, so a stand-in is streamed and measured
    against the service's response-size cap exactly as a real response is.
    ``content`` may be given directly to stream bytes the payload does not
    describe, ``declared`` to announce a length the bytes do not match,
    and ``chunk_size`` to stream the body in more than one piece.
    ``streamed`` counts the bytes handed over and ``decoded`` the number
    of times the buffered decoder was called.
    """

    #: ``declared`` value that leaves the response with no length header.
    NO_LENGTH = "no-length"

    def __init__(
        self,
        payload,
        status_code=200,
        content=None,
        declared=None,
        chunk_size=None,
    ):
        self._payload = payload
        self.status_code = status_code
        if content is None:
            content = json.dumps(payload).encode("utf-8")
        self.content = content
        self.chunk_size = chunk_size
        self.streamed = 0
        self.decoded = 0
        if declared == self.NO_LENGTH:
            self.headers = {}
        else:
            if declared is None:
                declared = len(content)
            self.headers = {"Content-Length": str(declared)}

    def raise_for_status(self):
        return None

    async def aiter_bytes(self):
        """Yields the body in one chunk, or in ``chunk_size`` pieces."""
        body = self.content or b""
        step = self.chunk_size or len(body)
        if step <= 0:
            return
        for start in range(0, len(body), step):
            chunk = body[start:start + step]
            self.streamed += len(chunk)
            yield chunk

    def json(self):
        self.decoded += 1
        return self._payload


class CountedResponse(StubResponse):
    """A response declaring ``declared`` bytes over a valid body."""

    def __init__(self, payload, declared):
        super().__init__(payload, declared=declared)


class UnmeasuredResponse(StubResponse):
    """A response declaring no length at all."""

    def __init__(self, payload):
        super().__init__(payload, declared=StubResponse.NO_LENGTH)


class BoundedClient:
    """A client whose every call answers with one stored response."""

    def __init__(self, response):
        self._response = response
        self.calls = 0

    def stream(self, *args, **kwargs):
        """Returns the response as the streaming context manager."""
        self.calls += 1
        return _streaming(self._response)


def _streaming(response):
    """Returns ``response`` as an asynchronous context manager.

    The service issues every call through ``client.stream``, which is an
    asynchronous context manager over the response, so a stand-in serves
    its response the same way.
    """

    @asynccontextmanager
    async def opened():
        yield response

    return opened()


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


def revoking_event(event_type, order_id=ORDER_ID, identifier="WH-5"):
    """Returns a notification of ``event_type`` naming ``order_id``.

    The resource carries the order identifier under both the capture
    shape and the order shape, so one helper serves the ``PAYMENT.*``
    notifications and the ``CHECKOUT.*`` ones alike.
    """
    return {
        "id": identifier,
        "event_type": event_type,
        "resource": {
            "id": order_id,
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
    engine = enforce_sqlite_foreign_keys(
        create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
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
            def stream(self, method, path, **kwargs):
                sent["method"] = method
                sent["path"] = path
                sent["headers"] = kwargs.get("headers", {})
                return _streaming(StubResponse(capture_response()))

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
            def stream(self, method, path, **kwargs):
                sent["json"] = kwargs.get("json")
                return _streaming(StubResponse(order_response()))

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
            def stream(self, method, path, **kwargs):
                sent["path"] = path
                sent["content"] = kwargs.get("content")
                sent["json"] = kwargs.get("json")
                return _streaming(
                    StubResponse({"verification_status": "SUCCESS"})
                )

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
            def stream(self, method, path, **kwargs):
                sent["content"] = kwargs.get("content")
                return _streaming(
                    StubResponse({"verification_status": "SUCCESS"})
                )

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
            def stream(self, method, path, **kwargs):
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
            def stream(self, method, path, **kwargs):
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
            def stream(self, method, path, **kwargs):
                return _streaming(
                    StubResponse({"verification_status": "FAILURE"})
                )

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
            issue=paypal_service.ISSUE_ORDER_ALREADY_CAPTURED,
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
            issue=paypal_service.ISSUE_ORDER_ALREADY_CAPTURED,
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

    def test_the_recognised_events_are_derived_from_the_status_map(self):
        """One declaration governs both recognition and outcome.

        ``REVOKING_EVENTS`` is the keys of the status map rather than a
        second list beside it, so a notification cannot be recognised
        without an outcome or given an outcome without being recognised.
        """
        assert subscriptions_module.REVOKING_EVENTS == tuple(
            subscriptions_module._REVOKED_STATUSES
        )
        for event_type in subscriptions_module.REVOKING_EVENTS:
            assert event_type in subscriptions_module._REVOKED_STATUSES

    @pytest.mark.parametrize(
        "event_type",
        [
            "CHECKOUT.PAYMENT-APPROVAL.REVERSED",
            "PAYMENT.CAPTURE.DECLINED",
        ],
    )
    def test_a_reversal_or_decline_is_recognised_as_revoking(
        self, event_type
    ):
        """Each names a settlement the provider withdrew.

        Both were previously answered as notifications no transition
        applies to, so a payer whose approval was reversed and a capture
        the provider declined each kept the entitlement the notification
        withdrew.
        """
        assert event_type in subscriptions_module.REVOKING_EVENTS
        assert subscriptions_module._REVOKED_STATUSES[event_type] in (
            subscriptions_module.TERMINAL_STATUSES
        )

    @pytest.mark.parametrize(
        "event_type",
        [
            "CHECKOUT.PAYMENT-APPROVAL.REVERSED",
            "PAYMENT.CAPTURE.DECLINED",
        ],
    )
    def test_a_reversal_withdraws_the_entitlement_and_the_role(
        self, client, db, subscriber, event_type
    ):
        """The notification closes the window and demotes the account."""
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

        response = deliver(
            client,
            revoking_event(event_type),
            headers=webhook_headers(transmission_id="revoke-1"),
        )

        assert response.status_code == 200
        assert response.json()["status"] == (
            subscriptions_module.OUTCOME_PROCESSED
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
        "event_type",
        [
            "CHECKOUT.PAYMENT-APPROVAL.REVERSED",
            "PAYMENT.CAPTURE.DECLINED",
        ],
    )
    def test_a_replayed_reversal_changes_nothing_further(
        self, client, db, subscriber, event_type
    ):
        """The same delivery twice is recorded once and applied once."""
        open_subscription(client, subscriber)
        with patch(
            MODULE + ".capture_order",
            new=AsyncMock(return_value=capture_response()),
        ):
            deliver(client, approved_event())

        headers = webhook_headers(transmission_id="revoke-replay")
        first = deliver(
            client, revoking_event(event_type), headers=headers
        )
        db.expire_all()
        settled = db.query(Subscription).one()
        status_after_first = settled.status
        end_after_first = settled.end_date

        second = deliver(
            client, revoking_event(event_type), headers=headers
        )

        assert first.json()["status"] == (
            subscriptions_module.OUTCOME_PROCESSED
        )
        assert second.status_code == 200
        assert second.json()["status"] == (
            subscriptions_module.OUTCOME_DUPLICATE
        )
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == status_after_first
        assert stored.end_date == end_after_first
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

    @pytest.mark.parametrize(
        "event_type",
        [
            "CHECKOUT.PAYMENT-APPROVAL.REVERSED",
            "PAYMENT.CAPTURE.DECLINED",
        ],
    )
    def test_a_reversal_naming_an_unknown_order_changes_nothing(
        self, client, db, subscriber, event_type
    ):
        """A notification for another order leaves this one alone."""
        open_subscription(client, subscriber)
        with patch(
            MODULE + ".capture_order",
            new=AsyncMock(return_value=capture_response()),
        ):
            deliver(client, approved_event())
        db.expire_all()
        before = db.query(Subscription).one().status

        response = deliver(
            client,
            revoking_event(event_type, order_id="ORDER-NOT-OURS"),
            headers=webhook_headers(transmission_id="revoke-unknown"),
        )

        assert response.status_code == 200
        assert response.json()["status"] == (
            subscriptions_module.OUTCOME_IGNORED
        )
        db.expire_all()
        assert db.query(Subscription).one().status == before
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == PLAN.required_role
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
        self, db, subscriber, other_user
    ):
        with pytest.raises(paypal_service.OrderOwnershipError) as first:
            paypal_service._resolve_owned_order(
                db, "ORDER-ABSENT", subscriber, None
            )
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

    Every REST helper streams its response and accumulates the bytes under
    the cap rather than buffering the whole body first, so a provider or an
    intermediary answering with an unbounded body cannot exhaust the
    process -- and cannot do so once per connection in the pool. The
    declared length is read first, so a body announcing itself as
    oversized is refused without any of it being read; a body that
    declares nothing, or under-declares, is stopped as soon as the bytes
    received pass the cap.
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
    def test_a_declared_length_past_the_cap_is_refused_unread(
        self, call
    ):
        """A body announcing itself as oversized is never read."""
        response = CountedResponse(
            order_response(),
            declared=paypal_service.MAX_RESPONSE_BYTES + 1,
        )
        with pytest.raises(paypal_service.PayPalAPIError) as raised:
            self._run(getattr(self, call), response)
        assert raised.value.category == (
            paypal_service.CATEGORY_MALFORMED_RESPONSE
        )
        assert response.streamed == 0
        assert response.decoded == 0

    @pytest.mark.parametrize(
        "call", ["_post", "_read", "_exchange"]
    )
    def test_an_under_declared_body_is_stopped_while_it_streams(
        self, call
    ):
        """A body longer than it declares is stopped at the cap.

        The declaration cannot be trusted, so the accumulated bytes are
        the control. The read stops one chunk past the cap rather than
        continuing to the end of an unbounded body.
        """
        cap = paypal_service.MAX_RESPONSE_BYTES
        chunk = 64 * 1024
        response = StubResponse(
            order_response(),
            content=b"x" * (cap + 4 * chunk),
            declared=8,
            chunk_size=chunk,
        )
        with pytest.raises(paypal_service.PayPalAPIError) as raised:
            self._run(getattr(self, call), response)
        assert raised.value.category == (
            paypal_service.CATEGORY_MALFORMED_RESPONSE
        )
        assert response.streamed <= cap + chunk
        assert response.streamed < len(response.content)
        assert response.decoded == 0

    def test_a_body_at_the_cap_is_accepted(self):
        """The cap is the largest body accepted, not the first refused."""
        cap = paypal_service.MAX_RESPONSE_BYTES
        encoded, expected = padded_body(order_response(), cap)
        response = StubResponse(
            expected, content=encoded, chunk_size=32 * 1024
        )
        payload, client = self._run(self._post, response)
        assert payload == expected
        assert response.streamed == cap
        assert client.calls == 1

    def test_a_body_one_byte_past_the_cap_is_refused(self):
        """The first refused body is one byte past the cap."""
        cap = paypal_service.MAX_RESPONSE_BYTES
        encoded, expected = padded_body(order_response(), cap + 1)
        response = StubResponse(
            expected,
            content=encoded,
            declared=StubResponse.NO_LENGTH,
            chunk_size=32 * 1024,
        )
        with pytest.raises(paypal_service.PayPalAPIError) as raised:
            self._run(self._post, response)
        assert raised.value.category == (
            paypal_service.CATEGORY_MALFORMED_RESPONSE
        )
        assert response.decoded == 0

    def test_an_unmeasurable_body_is_still_decoded(self):
        """A body declaring no length is accumulated and read."""
        response = UnmeasuredResponse(order_response())
        payload, client = self._run(self._post, response)
        assert payload == order_response()
        assert response.streamed == len(response.content)
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

    def test_no_refusal_record_carries_any_of_the_body(self):
        """A refusal names sizes, never bytes."""
        marker = "s3cret-body-marker"
        cap = paypal_service.MAX_RESPONSE_BYTES
        response = StubResponse(
            order_response(),
            content=marker.encode("utf-8") + b"x" * (cap + 1),
            declared=StubResponse.NO_LENGTH,
            chunk_size=32 * 1024,
        )
        with patch.object(paypal_service.logger, "error") as noted:
            with pytest.raises(paypal_service.PayPalAPIError):
                self._run(self._post, response)
        rendered = repr(noted.call_args_list)
        assert marker not in rendered

    def test_every_helper_streams_rather_than_buffering(self):
        """No helper awaits a fully buffered response."""
        for name in ("_post_json", "_get_json", "_exchange_credentials"):
            source = inspect.getsource(getattr(paypal_service, name))
            assert "client.stream(" in source
            assert "_bounded_body(response" in source
            assert "await client.post(" not in source
            assert "await client.request(" not in source

    def test_no_provider_body_is_decoded_before_it_is_measured(self):
        """Every helper reaches the decoder through the measured path."""
        for name in ("_post_json", "_get_json", "_exchange_credentials"):
            source = inspect.getsource(getattr(paypal_service, name))
            assert "_decoded_object(response" in source
            assert "response.json()" not in source

    def test_every_helper_reads_through_the_bounded_reader(self):
        """No helper calls the transport directly.

        Calling the client's own method would buffer the whole body before
        anything measured it, which is what the bounded reader exists to
        prevent, so the source is asserted rather than only the outcome.
        """
        for name in ("_post_json", "_get_json", "_exchange_credentials"):
            source = inspect.getsource(getattr(paypal_service, name))
            # Either bounded reader satisfies the claim: _bounded_body()
            # accumulates an already-opened stream under the cap, and
            # _read_bounded() opens the stream itself under the same cap.
            assert (
                "_bounded_body(" in source or "_read_bounded(" in source
            ), name
            assert "client.post(" not in source
            assert "client.request(" not in source


class TestProviderRecordsCarryBothSidesOfTheJoin:
    """One record names the local request and the provider case.

    A provider support case is opened with the provider's own debug
    identifier, and a local investigation starts from the request
    identifier. A record carrying only one of the two leaves the join to be
    guessed from timestamps, so the completion record, the read record and
    the failure record each carry the provider order alongside the
    identifier the logger binds.
    """

    @staticmethod
    def _run(coroutine_factory, response, request_id="req-join-1"):
        """Awaits the factory with ``response`` stood in and an id bound."""
        import asyncio

        client = BoundedClient(response)
        token = bind_request_id(request_id)

        async def run():
            paypal_service.reset_access_token_cache()
            with patch(SERVICE + "._client", new=stub_client(client)), patch(
                SERVICE + "._bearer_credential",
                new=AsyncMock(return_value="bearer-token"),
            ):
                return await coroutine_factory()

        try:
            return asyncio.get_event_loop().run_until_complete(run())
        finally:
            reset_request_id(token)
            paypal_service.reset_access_token_cache()

    @staticmethod
    def _extras(recorded):
        """Returns the extras of every record the patch captured."""
        return [
            call.kwargs["extra"]
            for call in recorded.call_args_list
            if "extra" in call.kwargs
        ]

    def test_the_field_is_named_once(self):
        assert paypal_service.PROVIDER_ORDER_FIELD == "provider_order_id"

    def test_a_read_records_the_order_it_was_about(self):
        response = StubResponse(order_response())

        with patch.object(paypal_service.logger, "debug") as noted:
            self._run(
                lambda: paypal_service.fetch_order(ORDER_ID), response
            )

        carried = [
            extra
            for extra in self._extras(noted)
            if extra.get(paypal_service.PROVIDER_ORDER_FIELD) == ORDER_ID
        ]
        assert carried

    def test_a_failed_read_records_the_order_it_was_about(self):
        import httpx

        class Refusing(StubResponse):
            """A response whose status check raises, as httpx's does."""

            def raise_for_status(self):
                raise httpx.HTTPStatusError(
                    "server error",
                    request=httpx.Request("GET", "https://x/y"),
                    response=httpx.Response(500),
                )

        with patch.object(paypal_service.logger, "error") as noted:
            with pytest.raises(paypal_service.PayPalAPIError):
                self._run(
                    lambda: paypal_service.fetch_order(ORDER_ID),
                    Refusing(order_response()),
                )

        carried = [
            extra
            for extra in self._extras(noted)
            if extra.get(paypal_service.PROVIDER_ORDER_FIELD) == ORDER_ID
        ]
        assert carried

    def test_the_local_identifier_reaches_the_same_record(self):
        """The logger adds the bound identifier, so one record has both.

        The record is rendered through the real formatter rather than
        inspected as keyword arguments, because the rendered line is what
        an operator joins on.
        """
        import io
        import json
        import logging

        from backend.app.core.logging import (
            RedactingFilter,
            RedactingJsonFormatter,
        )

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(RedactingJsonFormatter())
        handler.addFilter(RedactingFilter())
        service_logger = paypal_service.logger
        previous = list(service_logger.handlers)
        propagated = service_logger.propagate
        service_logger.handlers = [handler]
        service_logger.propagate = False
        service_logger.setLevel(logging.DEBUG)
        try:
            self._run(
                lambda: paypal_service.fetch_order(ORDER_ID),
                StubResponse(order_response()),
                request_id="req-join-2",
            )
        finally:
            service_logger.handlers = previous
            service_logger.propagate = propagated

        joined = []
        for line in stream.getvalue().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            context = entry.get("context") or {}
            if (
                context.get("request_id") == "req-join-2"
                and context.get(paypal_service.PROVIDER_ORDER_FIELD)
                == ORDER_ID
            ):
                joined.append(entry)

        assert joined


class TestTheReadStopsAtTheCap:
    """A body past the cap is abandoned mid-transfer, not buffered.

    The cases above measure a response that has already been received. The
    cases here drive the reader against a real transport, so the question
    they answer is different: how much of an oversized body reaches this
    process before the read gives up. A reader that buffered first and
    measured afterwards would pass every case above while still holding
    the whole body, which is the defect these cases close.

    The transport is a real client over
    :class:`httpx.MockTransport`, so the streaming path runs rather than
    the direct-call path a test double takes.
    """

    CHUNK_BYTES = 65536

    def _chunks_beyond_the_cap(self):
        """Returns how many chunks carry the cap, plus a margin."""
        return (
            paypal_service.MAX_RESPONSE_BYTES // self.CHUNK_BYTES
        ) + 4

    def _read(self, handler):
        """Returns the response the bounded reader produces for ``handler``."""
        import asyncio

        import httpx

        async def run():
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler)
            ) as client:
                assert hasattr(client, "stream")
                return await paypal_service._read_bounded(
                    client,
                    "GET",
                    "https://api-m.sandbox.paypal.com/v2/checkout/orders",
                    operation="fetch_order",
                )

        return asyncio.get_event_loop().run_until_complete(run())

    def _streaming_handler(self, served, total_chunks):
        """Returns a handler streaming ``total_chunks`` chunks."""
        import httpx

        def handler(request):
            async def body():
                for _ in range(total_chunks):
                    served.append(1)
                    yield b"y" * self.CHUNK_BYTES

            return httpx.Response(
                200,
                content=body(),
                headers={paypal_service.DEBUG_ID_HEADER: "DBG-STREAM"},
            )

        return handler

    def test_a_body_within_the_cap_is_read_and_decoded(self):
        """The bounded read is transparent for a normal response."""
        import httpx

        def handler(request):
            return httpx.Response(
                200,
                json=order_response(),
                headers={paypal_service.DEBUG_ID_HEADER: "DBG-SMALL"},
            )

        response = self._read(handler)

        assert response.status_code == 200
        assert response.json() == order_response()
        assert paypal_service._debug_id(response) == "DBG-SMALL"

    def test_an_oversized_body_stops_the_transfer_early(self):
        """The read gives up before the provider finishes sending."""
        served = []
        total = self._chunks_beyond_the_cap()

        response = self._read(self._streaming_handler(served, total))

        assert len(response.content) == (
            paypal_service.MAX_RESPONSE_BYTES + 1
        )
        assert len(served) < total
        assert len(served) * self.CHUNK_BYTES < (
            total * self.CHUNK_BYTES
        )

    def test_the_bytes_held_are_one_past_the_cap_not_the_whole_body(self):
        """What is kept is the smallest amount that proves the refusal."""
        served = []
        total = self._chunks_beyond_the_cap()

        response = self._read(self._streaming_handler(served, total))

        assert len(response.content) < total * self.CHUNK_BYTES
        assert len(response.content) > (
            paypal_service.MAX_RESPONSE_BYTES
        )

    def test_the_held_body_is_then_refused_by_the_decoder(self):
        """The truncated body is refused rather than parsed."""
        served = []
        response = self._read(
            self._streaming_handler(served, self._chunks_beyond_the_cap())
        )

        with pytest.raises(paypal_service.PayPalAPIError) as raised:
            paypal_service._decoded_object(
                response, "fetch_order", response.content
            )

        assert raised.value.category == (
            paypal_service.CATEGORY_MALFORMED_RESPONSE
        )

    def test_a_declared_oversized_length_reads_no_chunk_at_all(self):
        """A transfer announcing itself oversized is refused unread."""
        import httpx

        served = []

        def handler(request):
            async def body():
                served.append(1)
                yield b"y" * self.CHUNK_BYTES

            return httpx.Response(
                200,
                content=body(),
                headers={
                    paypal_service.CONTENT_LENGTH_HEADER: str(
                        paypal_service.MAX_RESPONSE_BYTES + 1
                    ),
                    paypal_service.DEBUG_ID_HEADER: "DBG-DECLARED",
                },
            )

        with pytest.raises(paypal_service.PayPalAPIError) as raised:
            self._read(handler)

        assert raised.value.category == (
            paypal_service.CATEGORY_MALFORMED_RESPONSE
        )
        assert raised.value.debug_id == "DBG-DECLARED"
        assert served == []

    def test_the_reconstructed_response_carries_the_provider_metadata(self):
        """Status, debug identifier and request survive the read."""
        import httpx

        def handler(request):
            return httpx.Response(
                404,
                json={"name": "RESOURCE_NOT_FOUND"},
                headers={paypal_service.DEBUG_ID_HEADER: "DBG-META"},
            )

        response = self._read(handler)

        assert response.status_code == 404
        assert paypal_service._debug_id(response) == "DBG-META"
        assert response.request is not None

    def test_a_double_exposing_no_stream_is_called_directly(self):
        """A client without a stream method still answers.

        The suite's own doubles expose only the verb methods, so the
        reader falls back to calling them. Without that fallback every
        payment case would have to grow a streaming double.
        """
        import asyncio

        class Double:
            def __init__(self):
                self.calls = []

            async def get(self, url, **kwargs):
                self.calls.append(("get", url))
                return StubResponse(order_response())

        double = Double()

        async def run():
            return await paypal_service._read_bounded(
                double, "GET", "https://x/y", operation="fetch_order"
            )

        response = asyncio.get_event_loop().run_until_complete(run())

        assert response.json() == order_response()
        assert double.calls == [("get", "https://x/y")]


class TestTheBoundHoldsAgainstTheRealClient:
    """The cap holds against ``httpx`` itself, not only a stand-in.

    The cases above install a stand-in in place of the client. These drive
    a real ``httpx.AsyncClient`` over a mock transport, so the streaming
    call, the chunked read, the status check and the error classification
    are the library's own.
    """

    @staticmethod
    def _run(coroutine_factory, handler):
        """Awaits ``coroutine_factory`` against a real client."""
        import asyncio

        import httpx

        served = {"requests": 0}

        def respond(request):
            served["requests"] += 1
            return handler(request)

        async def run():
            paypal_service.reset_access_token_cache()
            client = httpx.AsyncClient(
                transport=httpx.MockTransport(respond)
            )

            @asynccontextmanager
            async def lend():
                yield client

            try:
                with patch(SERVICE + "._client", new=lend), patch(
                    SERVICE + "._bearer_credential",
                    new=AsyncMock(return_value="bearer-token"),
                ):
                    return await coroutine_factory()
            finally:
                await client.aclose()

        try:
            return (
                asyncio.get_event_loop().run_until_complete(run()),
                served,
            )
        finally:
            paypal_service.reset_access_token_cache()

    @staticmethod
    def _post():
        return paypal_service._post_json(
            "/v2/checkout/orders", {}, operation="create_order"
        )

    def test_a_real_oversized_stream_is_refused(self):
        """An unbounded chunked body is stopped by the accumulator."""
        import httpx

        cap = paypal_service.MAX_RESPONSE_BYTES
        chunk = b"x" * (64 * 1024)
        pieces = (cap // len(chunk)) + 8
        sent = {"pieces": 0}

        async def unbounded():
            for _ in range(pieces):
                sent["pieces"] += 1
                yield chunk

        def handler(request):
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=unbounded(),
            )

        with pytest.raises(paypal_service.PayPalAPIError) as raised:
            self._run(self._post, handler)
        assert raised.value.category == (
            paypal_service.CATEGORY_MALFORMED_RESPONSE
        )
        assert sent["pieces"] < pieces

    def test_a_real_declared_length_past_the_cap_is_refused(self):
        """A declaration past the cap is refused before the read."""
        import httpx

        cap = paypal_service.MAX_RESPONSE_BYTES
        read = {"bytes": 0}

        async def stream():
            read["bytes"] += 8
            yield b"x" * 8

        def handler(request):
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(cap + 1),
                },
                content=stream(),
            )

        with pytest.raises(paypal_service.PayPalAPIError) as raised:
            self._run(self._post, handler)
        assert raised.value.category == (
            paypal_service.CATEGORY_MALFORMED_RESPONSE
        )
        assert read["bytes"] == 0

    def test_a_real_body_within_the_cap_is_decoded(self):
        """A body under the cap streams through and decodes."""
        import httpx

        expected = order_response()

        def handler(request):
            return httpx.Response(
                200,
                json=expected,
                headers={"PayPal-Debug-Id": "DBG-1"},
            )

        payload, served = self._run(self._post, handler)
        assert payload == expected
        assert served["requests"] == 1

    def test_a_real_failure_still_carries_its_issue_code(self):
        """The bounded error body is what the issue code is read from."""
        import httpx

        def handler(request):
            return httpx.Response(
                422,
                json={
                    "name": "UNPROCESSABLE_ENTITY",
                    "details": [{"issue": "INSTRUMENT_DECLINED"}],
                },
                headers={"PayPal-Debug-Id": "DBG-2"},
            )

        with pytest.raises(paypal_service.PayPalAPIError) as raised:
            self._run(self._post, handler)
        assert raised.value.status_code == 422
        assert raised.value.issue == "INSTRUMENT_DECLINED"
        assert raised.value.debug_id == "DBG-2"

    def test_a_streamed_failure_body_still_carries_its_issue_code(self):
        """A streamed error body is read once, and that read is the one.

        A streamed response holds no buffered content, so the issue code
        can only come from the bytes the bounded read already accumulated.
        Reading the response a second time would yield nothing.
        """
        import httpx

        async def stream():
            yield b'{"name": "UNPROCESSABLE_ENTITY", "details": '
            yield b'[{"issue": "INSTRUMENT_DECLINED"}]}'

        def handler(request):
            return httpx.Response(
                422,
                headers={
                    "Content-Type": "application/json",
                    "PayPal-Debug-Id": "DBG-4",
                },
                content=stream(),
            )

        with pytest.raises(paypal_service.PayPalAPIError) as raised:
            self._run(self._post, handler)
        assert raised.value.status_code == 422
        assert raised.value.issue == "INSTRUMENT_DECLINED"
        assert raised.value.debug_id == "DBG-4"

    def test_a_real_failure_body_past_the_cap_yields_no_issue_code(self):
        """A refused error body contributes no issue code.

        The status still classifies the failure, so the caller keeps the
        provider status and the debug identifier; only the issue code,
        which would have required reading the refused body, is absent.
        """
        import httpx

        cap = paypal_service.MAX_RESPONSE_BYTES

        async def stream():
            yield b"{}"

        def handler(request):
            return httpx.Response(
                500,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(cap + 1),
                    "PayPal-Debug-Id": "DBG-3",
                },
                content=stream(),
            )

        with patch.object(paypal_service.logger, "error") as noted:
            with pytest.raises(paypal_service.PayPalAPIError) as raised:
                self._run(self._post, handler)
        assert raised.value.issue is None
        assert raised.value.status_code == 500
        assert raised.value.debug_id == "DBG-3"
        assert raised.value.category == (
            paypal_service.CATEGORY_PROVIDER_SERVER
        )
        reasons = [
            call.kwargs["extra"].get("reason")
            for call in noted.call_args_list
            if "extra" in call.kwargs
        ]
        assert paypal_service.REASON_RESPONSE_TOO_LARGE in reasons

    def test_a_real_undecodable_body_is_classified_malformed(self):
        """A body that is not JSON raises rather than propagating."""
        import httpx

        def handler(request):
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=b"not json at all",
            )

        with pytest.raises(paypal_service.PayPalAPIError) as raised:
            self._run(self._post, handler)
        assert raised.value.category == (
            paypal_service.CATEGORY_MALFORMED_RESPONSE
        )


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


class TestTheAmountContractRefusesWhatItCannotPrice:
    """The catalog prices in exact decimals or refuses the value.

    Every amount this service charges comes from the catalog and is
    rendered by :func:`backend.app.core.plans.format_amount`, so that
    renderer is the last point at which a value that cannot be expressed
    as an exact two-place decimal can be stopped. A value it accepted
    loosely -- a float, a value rounded to fit, a non-finite decimal --
    would be sent to the provider as the amount to charge.
    """

    @pytest.mark.parametrize(
        "value, rendered",
        [
            pytest.param(Decimal("9.99"), "9.99", id="decimal"),
            pytest.param(Decimal("9.9"), "9.90", id="one_place"),
            pytest.param(Decimal("10"), "10.00", id="whole_decimal"),
            pytest.param(10, "10.00", id="whole_number"),
            pytest.param(0, "0.00", id="zero"),
            pytest.param("99.99", "99.99", id="text"),
            pytest.param(" 99.99 ", "99.99", id="padded_text"),
        ],
    )
    def test_an_exact_amount_is_rendered_to_two_places(
        self, value, rendered
    ):
        assert format_amount(value) == rendered

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("nine ninety nine", id="words"),
            pytest.param("", id="empty"),
            pytest.param("9,99", id="comma_separator"),
            pytest.param("$9.99", id="currency_symbol"),
        ],
    )
    def test_text_that_is_not_a_decimal_is_refused(self, value):
        with pytest.raises(ValueError):
            format_amount(value)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(9.99, id="float"),
            pytest.param(True, id="boolean"),
            pytest.param(None, id="none"),
            pytest.param(Decimal, id="type_object"),
        ],
    )
    def test_a_type_the_catalog_does_not_price_in_is_refused(
        self, value
    ):
        with pytest.raises(TypeError):
            format_amount(value)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(Decimal("NaN"), id="not_a_number"),
            pytest.param(Decimal("Infinity"), id="infinity"),
            pytest.param(Decimal("-Infinity"), id="negative_infinity"),
            pytest.param("NaN", id="text_not_a_number"),
        ],
    )
    def test_an_amount_that_is_not_finite_is_refused(self, value):
        with pytest.raises(ValueError):
            format_amount(value)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("9.999", id="three_places"),
            pytest.param(Decimal("0.001"), id="below_a_cent"),
            pytest.param("1.005", id="halfway_below_a_cent"),
        ],
    )
    def test_an_amount_finer_than_a_cent_is_refused(self, value):
        """Refused rather than rounded: a rounded charge is a wrong one."""
        with pytest.raises(ValueError):
            format_amount(value)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(Decimal("1E+30"), id="beyond_the_precision"),
            pytest.param("1E+40", id="text_beyond_the_precision"),
        ],
    )
    def test_an_amount_beyond_the_representable_range_is_refused(
        self, value
    ):
        with pytest.raises(ValueError):
            format_amount(value)

    @pytest.mark.parametrize(
        "plan_id",
        [
            pytest.param("premium_weekly", id="never_published"),
            pytest.param("", id="empty"),
            pytest.param("PREMIUM_MONTHLY", id="wrong_case"),
            pytest.param(None, id="none"),
            pytest.param(17, id="not_text"),
            pytest.param(["premium_monthly"], id="unhashable"),
        ],
    )
    def test_an_identifier_the_catalog_does_not_publish_is_refused(
        self, plan_id
    ):
        with pytest.raises(UnknownPlanError) as refused:
            get_plan(plan_id)
        assert refused.value.plan_id == plan_id

    def test_every_published_plan_prices_exactly(self):
        """No catalog entry carries an amount the renderer refuses."""
        for plan_id in PLAN_IDS:
            plan = get_plan(plan_id)
            assert format_amount(plan.amount) == str(plan.amount)
            assert plan.period_days >= 1
            assert plan.currency == plan.currency.upper()


class TestANotificationThatCannotBeAppliedChangesNothing:
    """A verified notification the service cannot act on is acknowledged.

    Each case here is a delivery PayPal signed and this service could not
    apply: it named no order, it named an order whose row is closed, or it
    named a row priced by a plan the catalog no longer publishes. Every
    one of them is acknowledged so PayPal stops retrying, records why, and
    leaves the stored row and the subscriber's role exactly as they were.
    """

    @staticmethod
    def _row(subscriber, status="pending", plan_id=PREMIUM_MONTHLY):
        """Returns a stored subscription naming the order under test."""
        return Subscription(
            user_id=subscriber.id,
            plan_id=plan_id,
            amount=PLAN.amount,
            currency=PLAN.currency,
            status=status,
            start_date=datetime.now(timezone.utc),
            paypal_order_id=ORDER_ID,
        )

    @staticmethod
    def _settled(capture_id=CAPTURE_ID):
        """Returns the outcome a complete capture of the plan reports."""
        return paypal_service.CaptureOutcome(
            completed=True,
            order_id=ORDER_ID,
            status="COMPLETED",
            amount=format_amount(PLAN.amount),
            currency=PLAN.currency,
            capture_id=capture_id,
        )

    @staticmethod
    def _record(session_factory, status):
        """Records ``status`` against the order from another session."""
        session = session_factory()
        try:
            row = (
                session.query(Subscription)
                .filter(Subscription.paypal_order_id == ORDER_ID)
                .one()
            )
            row.status = status
            session.commit()
        finally:
            session.close()

    def test_a_notification_naming_no_order_is_acknowledged(
        self, client, db, subscriber
    ):
        db.add(self._row(subscriber))
        db.commit()

        response = deliver(
            client,
            {
                "id": "WH-NO-ORDER",
                "event_type": "PAYMENT.CAPTURE.COMPLETED",
                "resource": {"status": "COMPLETED"},
            },
        )

        assert response.status_code == 200
        assert response.json() == {
            "status": subscriptions_module.OUTCOME_IGNORED
        }
        db.expire_all()
        assert db.query(Subscription).one().status == "pending"
        assert db.query(WebhookEvent).count() == 1

    @pytest.mark.parametrize(
        "status",
        [
            subscriptions_module.CANCELLED_STATUS,
            subscriptions_module.REFUNDED_STATUS,
        ],
    )
    def test_an_order_already_closed_is_left_closed(
        self, client, db, subscriber, status
    ):
        db.add(self._row(subscriber, status=status))
        db.commit()

        response = deliver(client, capture_completed_event())

        assert response.status_code == 200
        assert response.json() == {
            "status": subscriptions_module.OUTCOME_IGNORED
        }
        db.expire_all()
        assert db.query(Subscription).one().status == status
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

    def test_an_order_priced_by_an_unpublished_plan_is_acknowledged(
        self, client, db, subscriber
    ):
        """A row the catalog can no longer price grants nothing."""
        db.add(self._row(subscriber, plan_id="premium_retired"))
        db.commit()

        response = deliver(client, capture_completed_event())

        assert response.status_code == 200
        assert response.json() == {
            "status": subscriptions_module.OUTCOME_IGNORED
        }
        db.expire_all()
        assert db.query(Subscription).one().status == "pending"
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

    def test_the_refusal_names_why_the_plan_could_not_be_read(
        self, client, db, subscriber
    ):
        db.add(self._row(subscriber, plan_id="premium_retired"))
        db.commit()

        with patch.object(
            subscriptions_module.logger, "error"
        ) as recorded:
            deliver(client, capture_completed_event())

        reasons = [
            call.kwargs["extra"].get("reason")
            for call in recorded.call_args_list
            if "extra" in call.kwargs
        ]
        assert (
            subscriptions_module.REASON_PLAN_UNAVAILABLE in reasons
        )

    def test_a_settled_capture_carrying_no_identifier_activates_nothing(
        self, db, subscriber
    ):
        """A settlement that cannot be reconciled grants no entitlement.

        Every outcome the provider reader builds carries the provider's
        capture identifier, so this is the guard behind that contract: an
        outcome reporting a complete capture with no identifier is refused
        rather than activated, because the row it produced could never be
        reconciled against the provider afterwards.
        """
        db.add(self._row(subscriber))
        db.commit()
        stored = db.query(Subscription).one()

        outcome = subscriptions_module._activate(
            db,
            stored,
            PLAN,
            self._settled(capture_id=None),
            "PAYMENT.CAPTURE.COMPLETED",
        )

        assert outcome == subscriptions_module.OUTCOME_IGNORED
        db.rollback()
        db.expire_all()
        assert db.query(Subscription).one().status == "pending"
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )

    def test_the_unreconcilable_capture_is_recorded_with_its_reason(
        self, db, subscriber
    ):
        db.add(self._row(subscriber))
        db.commit()
        stored = db.query(Subscription).one()

        with patch.object(
            subscriptions_module.logger, "error"
        ) as recorded:
            subscriptions_module._activate(
                db,
                stored,
                PLAN,
                self._settled(capture_id=""),
                "PAYMENT.CAPTURE.COMPLETED",
            )

        reasons = [
            call.kwargs["extra"].get("reason")
            for call in recorded.call_args_list
            if "extra" in call.kwargs
        ]
        assert (
            subscriptions_module.REASON_UNRECONCILABLE_CAPTURE in reasons
        )

    def test_a_row_activated_while_the_capture_was_in_flight_is_left(
        self, db, subscriber, session_factory
    ):
        """A second settlement of one order writes the row once."""
        db.add(self._row(subscriber))
        db.commit()
        stale = db.query(Subscription).one()
        self._record(session_factory, subscriptions_module.ACTIVE_STATUS)

        outcome = subscriptions_module._activate(
            db,
            stale,
            PLAN,
            self._settled(),
            "PAYMENT.CAPTURE.COMPLETED",
        )

        assert outcome == subscriptions_module.OUTCOME_PROCESSED
        db.rollback()
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == subscriptions_module.ACTIVE_STATUS
        assert stored.end_date is None

    def test_a_row_in_a_status_no_transition_covers_is_left_alone(
        self, db, subscriber, session_factory
    ):
        """A status outside the published set is not written over.

        Every status the application writes is one of five, and each is
        covered by a transition. This is the guard for a row carrying
        something else -- a value only a later revision or a manual edit
        could store -- which is refused rather than treated as open.
        """
        unpublished = "suspended"
        assert unpublished not in STATUS_VALUES
        db.add(self._row(subscriber))
        db.commit()
        stale = db.query(Subscription).one()
        self._record(session_factory, unpublished)

        outcome = subscriptions_module._activate(
            db,
            stale,
            PLAN,
            self._settled(),
            "PAYMENT.CAPTURE.COMPLETED",
        )

        assert outcome == subscriptions_module.OUTCOME_IGNORED
        db.rollback()
        db.expire_all()
        stored = db.query(Subscription).one()
        assert stored.status == unpublished
        assert (
            db.query(User).filter(User.id == subscriber.id).one().role
            == "registered"
        )
