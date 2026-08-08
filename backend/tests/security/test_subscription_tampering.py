"""Price and entitlement tampering regression tests.

This module is the named verifier for two findings.

* **H-2** -- the client dictated the charge amount and the entitlement
  dates. Every ``test_h2_*`` case here submits a tampered subscription
  request and asserts the server's own values won: the tampered field is
  refused, no row carries it, the stored price is the plan catalog's
  price, and the stored entitlement window is the catalog period measured
  from the server clock.
* **H-3** -- payment capture accepted both identifiers from the caller
  with no ownership check. Every ``test_h3_*`` case drives
  :func:`backend.app.services.paypal_service.capture_order`, whose
  server-side lookup resolves the stored ``paypal_order_id`` to its row
  and compares that row's owner with the authenticated principal.

Units under test: :mod:`backend.app.api.endpoints.subscriptions`,
:mod:`backend.app.core.plans` and :mod:`backend.app.schema.subscription`.

Every outbound PayPal call is served by a stand-in installed at the
transport boundary of :mod:`backend.app.services.paypal_service`, so no
case reaches the network. The stand-in records each call, which is what
the "no payment call was made" assertions read.

Rationale for the choices made here -- including the three places where
the implemented behaviour differs from the shape this module was
originally described with -- is recorded in
``docs/security/DECISION_LOG.md`` section 18, not in this file.
"""

from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import status
from sqlalchemy import inspect as sqlalchemy_inspect

from backend.app.api.endpoints import subscriptions as subscriptions_module
from backend.app.core.plans import (
    PLAN_IDS,
    PREMIUM_ANNUAL,
    PREMIUM_MONTHLY,
    UnknownPlanError,
    format_amount,
    get_plan,
)
from backend.app.db.models import Subscription as SubscriptionModel
from backend.app.db.models import User, WebhookEvent
from backend.app.main import app
from backend.app.services import paypal_service
from backend.app.services.paypal_service import (
    CaptureOutcome,
    OrderOwnershipError,
    WebhookVerification,
    capture_order,
    read_capture,
)

#: Route that opens a subscription. The trailing slash is part of it.
CREATE_PATH = '/subscriptions/'

#: Route that receives one PayPal notification.
WEBHOOK_PATH = '/subscriptions/webhook'

#: Both catalog identifiers. Every price and period case runs once
#: per published plan.
CATALOG_PLAN_IDS = (PREMIUM_MONTHLY, PREMIUM_ANNUAL)

#: Provider order identifier the stand-in reports for a created order.
ORDER_ID = 'ORDER-TAMPERING-1'

#: Provider capture identifier the stand-in reports for a settlement.
CAPTURE_ID = 'CAPTURE-TAMPERING-1'

#: Order identifier stored on the row a second principal reaches for.
OWNED_ORDER_ID = 'ORDER-TAMPERING-OWNED'

#: Payer-approval target the stand-in reports. Its host sits under a
#: registrable domain of ``settings.PAYPAL_CERT_HOST_ALLOWLIST``, which
#: is the condition :func:`paypal_service.approval_url` applies.
APPROVAL_URL = 'https://www.sandbox.paypal.com/checkoutnow?token=1'

#: Delivery identifier carried by the notification each case delivers.
TRANSMISSION_ID = 'c7d8e9f0-1111-2222-3333-444455556666'

#: Bearer value the credential accessor is stood in with. It is never
#: asserted on and cannot match a provider credential pattern.
STAND_IN_GRANT = 'not-a-real-grant'

#: Notification reporting that the payer approved an order.
APPROVED_EVENT = subscriptions_module.EVENT_ORDER_APPROVED

#: Status the provider reports for a settled capture.
SETTLED_STATUS = paypal_service.CAPTURE_COMPLETED_STATUS

#: Seconds a stored timestamp may differ from the clock reading the
#: assertion takes.
CLOCK_TOLERANCE_SECONDS = 120.0

#: Amounts a client may submit in place of the catalog price.
TAMPERED_AMOUNTS = ('0.01', '0', '-100.00', '1000000.00')

#: Identifiers the catalog does not publish. The last two are a
#: differently-cased and a hyphenated variant of a real identifier.
UNKNOWN_PLAN_IDS = (
    'free_forever',
    '',
    'PREMIUM_MONTHLY',
    'premium-monthly',
)


class StandInResponse(object):
    """One provider response served at the transport boundary."""

    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = {} if payload is None else payload
        self.headers = {}

    def json(self):
        """Returns the decoded body this response carries."""
        return self._payload

    def raise_for_status(self):
        """Reports no transport failure."""
        return None


class RecordingTransport(object):
    """Serves queued responses and records every call it is handed.

    ``calls`` holds one ``(url, kwargs)`` pair per call, in order. The
    last queued response is served repeatedly once the queue is down to
    it.
    """

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    async def post(self, url, **kwargs):
        """Records one call and returns the response due for it."""
        self.calls.append((url, kwargs))
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]

    async def get(self, url, **kwargs):
        """Records one read and returns the response due for it."""
        return await self.post(url, **kwargs)


@contextmanager
def provider_transport(responses):
    """Yields a recording stand-in installed on the provider module.

    The stand-in is installed as an asynchronous context manager,
    which is how the provider acquires its client. The credential
    accessor is stood in alongside it: no case performs a credential
    exchange and none holds a cached grant.
    """
    transport = RecordingTransport(responses)

    @asynccontextmanager
    async def lend_the_stand_in():
        yield transport

    with patch.object(paypal_service, '_client', lend_the_stand_in):
        with patch.object(
            paypal_service,
            '_bearer_credential',
            AsyncMock(return_value=STAND_IN_GRANT),
        ):
            yield transport


def order_reply(order_id=ORDER_ID):
    """Returns a created-order body shaped like the provider's."""
    return StandInResponse(
        200,
        {
            'id': order_id,
            'status': 'PAYER_ACTION_REQUIRED',
            'links': [
                {
                    'rel': 'self',
                    'href': 'https://api-m.sandbox.paypal.com/o/1',
                },
                {'rel': 'payer-action', 'href': APPROVAL_URL},
            ],
        },
    )


def capture_reply(plan, order_id=ORDER_ID):
    """Returns a settled-capture body for ``plan``.

    The settled amount and currency are rendered from the catalog
    entry.
    """
    return StandInResponse(
        200,
        {
            'id': order_id,
            'status': SETTLED_STATUS,
            'purchase_units': [
                {
                    'payments': {
                        'captures': [
                            {
                                'id': CAPTURE_ID,
                                'status': SETTLED_STATUS,
                                'amount': {
                                    'currency_code': plan.currency,
                                    'value': format_amount(plan.amount),
                                },
                            }
                        ]
                    }
                }
            ],
        },
    )


def approval_notification(order_id=ORDER_ID):
    """Returns a payer-approval notification naming ``order_id``."""
    return {
        'id': 'WH-TAMPERING-1',
        'event_type': APPROVED_EVENT,
        'resource': {'id': order_id, 'status': 'APPROVED'},
    }


def rejection_status():
    """Returns the refusal status the generated schema declares.

    The status is read from the application's own OpenAPI document for
    :data:`CREATE_PATH`, and the single non-success status that document
    declares is returned.
    """
    responses = app.openapi()['paths'][CREATE_PATH]['post']['responses']
    declared = sorted(
        int(code) for code in responses if not str(code).startswith('2')
    )
    assert declared == [status.HTTP_422_UNPROCESSABLE_CONTENT], declared
    return declared[0]


def open_subscription(test_client, headers, body):
    """Posts one subscription request and returns the response."""
    return test_client.post(CREATE_PATH, json=body, headers=headers)


def deliver_approval(test_client, order_id=ORDER_ID):
    """Delivers one payer-approval notification for ``order_id``.

    The signature check is stood in with a passing outcome carrying the
    delivery identifier and the event type, which is the shape the real
    check returns for a notification it verified. No assertion in this
    module concerns the signature, the certificate host or a repeated
    delivery.
    """
    notification = approval_notification(order_id)
    outcome = WebhookVerification(
        verified=True,
        transmission_id=TRANSMISSION_ID,
        event_type=notification['event_type'],
    )
    with patch.object(
        subscriptions_module,
        'verify_webhook_signature',
        new=AsyncMock(return_value=outcome),
    ):
        return test_client.post(
            WEBHOOK_PATH,
            json=notification,
            headers={'Content-Type': 'application/json'},
        )


def stored_rows(session):
    """Returns every stored subscription row, oldest first."""
    session.expire_all()
    return (
        session.query(SubscriptionModel)
        .order_by(SubscriptionModel.id)
        .all()
    )


def only_row(session):
    """Returns the single stored subscription row."""
    rows = stored_rows(session)
    assert len(rows) == 1, rows
    return rows[0]


def column_snapshot(row):
    """Returns every mapped column of ``row`` keyed by its name.

    Every column the model declares is included, read from the model's
    own mapper.
    """
    mapper = sqlalchemy_inspect(type(row))
    return dict(
        (attribute.key, getattr(row, attribute.key))
        for attribute in mapper.column_attrs
    )


def naive_utc_now():
    """Returns the current UTC instant without its offset.

    Stored timestamps carry no offset, so this reading carries none
    either.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def assert_close_to_now(moment):
    """Asserts ``moment`` is within the tolerated clock window."""
    assert moment is not None
    difference = abs((naive_utc_now() - moment).total_seconds())
    assert difference <= CLOCK_TOLERANCE_SECONDS, difference


def seed_owned_order(session, owner, plan_id=PREMIUM_MONTHLY,
                     order_id=OWNED_ORDER_ID):
    """Stores one pending subscription owned by ``owner``.

    The row is priced from the catalog and carries ``order_id`` on the
    uniquely-constrained provider column, which is the column the
    ownership lookup resolves.
    """
    plan = get_plan(plan_id)
    subscription = SubscriptionModel(
        user_id=owner.id,
        plan_id=plan.plan_id,
        amount=plan.amount,
        currency=plan.currency,
        status=subscriptions_module.PENDING_STATUS,
        start_date=datetime.now(timezone.utc),
        end_date=None,
        paypal_order_id=order_id,
    )
    session.add(subscription)
    session.commit()
    session.refresh(subscription)
    return subscription


def account_snapshot(session, *principals):
    """Returns the stored role of each principal, keyed by identifier."""
    session.expire_all()
    return dict(
        (
            principal.id,
            session.query(User)
            .filter(User.id == principal.id)
            .one()
            .role,
        )
        for principal in principals
    )


@pytest.mark.parametrize('plan_id', CATALOG_PLAN_IDS)
@pytest.mark.parametrize('tampered_amount', TAMPERED_AMOUNTS)
def test_h2_a_client_supplied_amount_is_refused_and_never_reaches_the_row(
    client, db, registered_user, auth_header_factory, plan_id,
    tampered_amount,
):
    """A body carrying an amount is refused and never reaches a row.

    Asserts the response status is the one the generated schema declares
    for a refused body, that no subscription row exists after the
    refusal, and that no provider call was issued. The clean request is
    then submitted and the row it stores is asserted to carry the
    catalog amount and currency and not the submitted amount.
    """
    plan = get_plan(plan_id)
    submitted = Decimal(tampered_amount)
    headers = auth_header_factory(registered_user)
    body = {'plan_id': plan_id, 'amount': tampered_amount}

    with provider_transport([order_reply()]) as transport:
        refused = open_subscription(client, headers, body)

        assert refused.status_code == rejection_status()
        assert transport.calls == []
        assert stored_rows(db) == []

        accepted = open_subscription(
            client, headers, {'plan_id': plan_id}
        )

    assert accepted.status_code == status.HTTP_200_OK
    assert len(transport.calls) == 1
    row = only_row(db)
    assert Decimal(str(row.amount)) == plan.amount
    assert Decimal(str(row.amount)) != submitted
    assert row.currency == plan.currency


@pytest.mark.parametrize('plan_id', CATALOG_PLAN_IDS)
@pytest.mark.parametrize(
    'tampered_field',
    ['currency', 'payment_method', 'status', 'user_id'],
)
def test_h2_a_client_supplied_price_field_is_refused(
    client, db, registered_user, auth_header_factory, plan_id,
    tampered_field,
):
    """A body carrying any out-of-contract field is refused.

    Asserts the refusal status, that nothing was stored, and that no
    provider call was issued. The fields include ``payment_method``,
    which the request contract does not declare.
    """
    body = {'plan_id': plan_id, tampered_field: 'paypal'}
    with provider_transport([order_reply()]) as transport:
        response = open_subscription(
            client, auth_header_factory(registered_user), body
        )

    assert response.status_code == rejection_status()
    assert transport.calls == []
    assert stored_rows(db) == []


@pytest.mark.parametrize('plan_id', CATALOG_PLAN_IDS)
def test_h2_the_stored_price_is_the_catalog_price(
    client, db, registered_user, auth_header_factory, plan_id,
):
    """The clean request stores the catalog amount and currency.

    Both values are read from :func:`get_plan`, so each assertion is an
    equality with the catalog itself.
    """
    plan = get_plan(plan_id)
    with provider_transport([order_reply()]) as transport:
        response = open_subscription(
            client,
            auth_header_factory(registered_user),
            {'plan_id': plan_id},
        )

    assert response.status_code == status.HTTP_200_OK
    assert len(transport.calls) == 1
    row = only_row(db)
    assert row.plan_id == plan.plan_id
    assert Decimal(str(row.amount)) == plan.amount
    assert row.currency == plan.currency
    assert row.user_id == registered_user.id


@pytest.mark.parametrize('plan_id', CATALOG_PLAN_IDS)
@pytest.mark.parametrize(
    'tampered_window',
    [
        {'start_date': '2020-01-01T00:00:00+00:00'},
        {'end_date': '2099-01-01T00:00:00+00:00'},
        {
            'start_date': '2020-01-01T00:00:00+00:00',
            'end_date': '2099-01-01T00:00:00+00:00',
        },
    ],
)
def test_h2_a_client_supplied_entitlement_window_is_refused(
    client, db, registered_user, auth_header_factory, plan_id,
    tampered_window,
):
    """A body carrying entitlement dates is refused and stores nothing.

    Asserts the refusal status, that no subscription row exists after the
    refusal, and that no provider call was issued. The clean request is
    then submitted and the row it stores is asserted to carry neither
    submitted date.
    """
    headers = auth_header_factory(registered_user)
    body = {'plan_id': plan_id}
    body.update(tampered_window)
    submitted = set(
        datetime.fromisoformat(value).replace(tzinfo=None)
        for value in tampered_window.values()
    )

    with provider_transport([order_reply()]) as transport:
        refused = open_subscription(client, headers, body)

        assert refused.status_code == rejection_status()
        assert transport.calls == []
        assert stored_rows(db) == []

        accepted = open_subscription(
            client, headers, {'plan_id': plan_id}
        )

    assert accepted.status_code == status.HTTP_200_OK
    row = only_row(db)
    assert row.start_date not in submitted
    assert row.end_date is None


@pytest.mark.parametrize('plan_id', CATALOG_PLAN_IDS)
def test_h2_the_opened_row_carries_no_entitlement_window(
    client, db, registered_user, auth_header_factory, plan_id,
):
    """The clean request stores a server-clock start and no end.

    Asserts the stored ``start_date`` is within the tolerated window of
    the clock this case reads, and that ``end_date`` is absent, so no
    date a client could have sent is present on the row at all.
    """
    with provider_transport([order_reply()]) as transport:
        response = open_subscription(
            client,
            auth_header_factory(registered_user),
            {'plan_id': plan_id},
        )

    assert response.status_code == status.HTTP_200_OK
    assert len(transport.calls) == 1
    row = only_row(db)
    assert_close_to_now(row.start_date)
    assert row.end_date is None
    assert row.status == subscriptions_module.PENDING_STATUS


@pytest.mark.parametrize('plan_id', CATALOG_PLAN_IDS)
def test_h2_the_entitlement_window_is_the_catalog_period(
    client, db, registered_user, auth_header_factory, plan_id,
):
    """The settled row's window is the catalog period from the clock.

    The window is measured after the settlement that grants it: the
    stored ``start_date`` is within the tolerated window of the clock,
    and ``end_date`` minus ``start_date`` equals the plan's own
    ``period_days`` read from :func:`get_plan`. The role the plan
    carries is stored on the account by the same settlement.
    """
    plan = get_plan(plan_id)
    with provider_transport(
        [order_reply(), capture_reply(plan)]
    ) as transport:
        opened = open_subscription(
            client,
            auth_header_factory(registered_user),
            {'plan_id': plan_id},
        )
        assert opened.status_code == status.HTTP_200_OK
        delivered = deliver_approval(client)

    assert delivered.status_code == status.HTTP_200_OK
    assert delivered.json() == {
        'status': subscriptions_module.OUTCOME_PROCESSED
    }
    assert len(transport.calls) == 2

    row = only_row(db)
    assert row.status == subscriptions_module.ACTIVE_STATUS
    assert_close_to_now(row.start_date)
    assert row.end_date is not None
    assert row.end_date - row.start_date == timedelta(
        days=plan.period_days
    )
    assert Decimal(str(row.amount)) == plan.amount
    assert row.currency == plan.currency
    assert account_snapshot(db, registered_user) == {
        registered_user.id: plan.required_role
    }


@pytest.mark.parametrize('unknown_plan_id', UNKNOWN_PLAN_IDS)
def test_h2_an_unknown_plan_is_refused_before_any_row_or_payment_call(
    client, db, registered_user, auth_header_factory, unknown_plan_id,
):
    """An identifier the catalog does not publish is refused.

    Asserts the refusal status, that the subscriptions table holds the
    same number of rows as before the request and is empty, and that the
    payment transport was never invoked, so the refusal precedes both the
    write and the outbound call.
    """
    count_before = db.query(SubscriptionModel).count()
    with provider_transport([order_reply()]) as transport:
        response = open_subscription(
            client,
            auth_header_factory(registered_user),
            {'plan_id': unknown_plan_id},
        )

    assert response.status_code == rejection_status()
    assert transport.calls == []
    db.expire_all()
    assert db.query(SubscriptionModel).count() == count_before
    assert stored_rows(db) == []


def test_h2_the_catalog_is_the_only_source_of_plan_identifiers():
    """The catalog publishes exactly the two known identifiers.

    Asserts :data:`PLAN_IDS` holds those two and nothing else, that
    :func:`get_plan` raises :class:`UnknownPlanError` for every
    unrecognised identifier and retains the rejected value, and that
    each published entry carries a positive amount, a currency and a
    positive period.

    Also asserts that no amount in :data:`TAMPERED_AMOUNTS` equals a
    published amount and that no published period is shared by both
    plans, so the inequality and per-plan period assertions the other
    cases make cannot hold by coincidence.
    """
    assert PLAN_IDS == frozenset({PREMIUM_MONTHLY, PREMIUM_ANNUAL})
    assert set(CATALOG_PLAN_IDS) == set(PLAN_IDS)

    for unknown_plan_id in UNKNOWN_PLAN_IDS:
        assert unknown_plan_id not in PLAN_IDS
        with pytest.raises(UnknownPlanError) as refusal:
            get_plan(unknown_plan_id)
        assert refusal.value.plan_id == unknown_plan_id

    published = [get_plan(plan_id) for plan_id in sorted(PLAN_IDS)]
    for plan in published:
        assert plan.plan_id in PLAN_IDS
        assert plan.amount > Decimal('0')
        assert plan.currency
        assert plan.period_days > 0
        for tampered_amount in TAMPERED_AMOUNTS:
            assert Decimal(tampered_amount) != plan.amount

    periods = [plan.period_days for plan in published]
    assert len(set(periods)) == len(periods)


@pytest.mark.asyncio
async def test_h3_capturing_another_principals_order_is_refused(
    db, registered_user, second_registered_user,
):
    """A capture presented by a non-owner is refused before any call.

    Asserts :class:`OrderOwnershipError` is raised for the order stored
    against the first principal when the second presents it, and that
    the payment transport recorded no call, so nothing left the process.
    """
    plan = get_plan(PREMIUM_MONTHLY)
    seed_owned_order(db, registered_user)

    with provider_transport([capture_reply(plan, OWNED_ORDER_ID)]) as (
        transport
    ):
        with pytest.raises(OrderOwnershipError):
            await capture_order(
                db, OWNED_ORDER_ID, second_registered_user
            )

    assert transport.calls == []


@pytest.mark.asyncio
async def test_h3_a_refused_capture_changes_no_stored_state(
    db, registered_user, second_registered_user,
):
    """A refused capture leaves every stored value as it was.

    Asserts the owning row's every mapped column, the subscription row
    count, the delivery-record count and both principals' stored roles
    are identical before and after the refusal. The comparison covers
    every value the capture path writes.
    """
    plan = get_plan(PREMIUM_MONTHLY)
    owned = seed_owned_order(db, registered_user)

    columns_before = column_snapshot(owned)
    count_before = db.query(SubscriptionModel).count()
    roles_before = account_snapshot(
        db, registered_user, second_registered_user
    )
    events_before = db.query(WebhookEvent).count()

    with provider_transport([capture_reply(plan, OWNED_ORDER_ID)]):
        with pytest.raises(OrderOwnershipError):
            await capture_order(
                db, OWNED_ORDER_ID, second_registered_user
            )

    db.expire_all()
    reloaded = (
        db.query(SubscriptionModel)
        .filter(SubscriptionModel.id == owned.id)
        .one()
    )
    assert column_snapshot(reloaded) == columns_before
    assert db.query(SubscriptionModel).count() == count_before
    assert db.query(WebhookEvent).count() == events_before
    assert account_snapshot(
        db, registered_user, second_registered_user
    ) == roles_before


@pytest.mark.asyncio
async def test_h3_an_unstored_order_is_refused_on_the_same_terms(
    db, registered_user,
):
    """An identifier resolving to no row is refused identically.

    Asserts the owner of a stored order cannot capture an identifier the
    service never stored, so the lookup refuses an unmatched identifier
    as well as one belonging to somebody else.
    """
    plan = get_plan(PREMIUM_MONTHLY)
    seed_owned_order(db, registered_user)

    with provider_transport([capture_reply(plan, ORDER_ID)]) as transport:
        with pytest.raises(OrderOwnershipError):
            await capture_order(db, ORDER_ID, registered_user)

    assert transport.calls == []


@pytest.mark.asyncio
async def test_h3_capture_proceeds_and_settles_for_the_owning_principal(
    db, registered_user,
):
    """The owner's own order is captured and settles for the plan price.

    Asserts exactly one provider call was issued, that the returned
    envelope measures as a completed capture against the catalog amount
    and currency, and that it carries the provider's own capture
    identifier.
    """
    plan = get_plan(PREMIUM_MONTHLY)
    seed_owned_order(db, registered_user)

    with provider_transport([capture_reply(plan, OWNED_ORDER_ID)]) as (
        transport
    ):
        envelope = await capture_order(
            db, OWNED_ORDER_ID, registered_user
        )

    assert len(transport.calls) == 1
    outcome = read_capture(
        envelope, OWNED_ORDER_ID, plan.amount, plan.currency
    )
    assert isinstance(outcome, CaptureOutcome)
    assert outcome.completed is True
    assert outcome.reason is None
    assert outcome.order_id == OWNED_ORDER_ID
    assert outcome.currency == plan.currency
    assert Decimal(outcome.amount) == plan.amount
    assert outcome.capture_id == CAPTURE_ID
