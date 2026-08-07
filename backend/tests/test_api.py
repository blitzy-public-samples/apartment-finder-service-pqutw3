import asyncio
import logging as stdlib_logging
from contextlib import asynccontextmanager, contextmanager
from itertools import count
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import urlsplit

import bcrypt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session as SqlAlchemySession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.pool import StaticPool
from starlette.exceptions import (
    HTTPException as StarletteHTTPException,
)

from backend.app.api.endpoints import auth as auth_module
from backend.app.api.endpoints import (
    subscriptions as subscriptions_module,
)
from backend.app.api.endpoints.auth import DUPLICATE_EMAIL_DETAIL
from backend.app.api.endpoints.auth import limiter as auth_limiter
from backend.app.api.endpoints.filters import FILTER_NOT_STORED_DETAIL
from backend.app.api.endpoints.listings import LISTING_NOT_STORED_DETAIL
from backend.app.api.endpoints.subscriptions import RECONCILIATION_DETAIL
from backend.app.core import authorization
from backend.app.core.authorization import (
    REFUSAL_MESSAGE,
    Role,
    audit_failure_count,
    reset_audit_failure_count,
)
from backend.app.core.config import settings
from backend.app.core.logging import (
    HANDLER_NAME,
    configure_logging,
    log_exception,
    redact,
    unredacted_handler_names,
)
from backend.app.core.plans import (
    PREMIUM_MONTHLY,
    STATUS_ACTIVE,
    STATUS_FAILED,
    STATUS_PENDING,
    get_plan,
)
from backend.app.core.security import (
    create_access_token,
    get_password_hash,
)
from backend.app.db import database as database_module
from backend.app.db.models import (
    Base,
    Filter,
    Filter as FilterModel,
    Listing as ListingModel,
    Subscription as SubscriptionModel,
    User,
    WebhookEvent,
    ZipCode,
)
from backend.app.main import (
    REQUEST_ID_HEADER,
    THROTTLED_MESSAGE,
    BodySizeLimitMiddleware,
    app,
)
from backend.app.schema import subscription as subscription_schema
from backend.app.schema.subscription import SubscriptionCreate
from backend.app.services import paypal_service as paypal_module
from backend.app.services.paypal_service import (
    CATEGORY_PROVIDER_CLIENT,
    CATEGORY_PROVIDER_SERVER,
    IDEMPOTENCY_HEADER,
    CaptureOutcome,
    PayPalAPIError,
    PayPalError,
    WebhookVerification,
)

PASSWORD = 'testpassword123'

#: A password satisfying the registration complexity policy.
REGISTRATION_PASSWORD = 'Str0ng-Passphrase-9'

AUTH_MODULE = 'backend.app.api.endpoints.auth'

SUBSCRIPTIONS_MODULE = 'backend.app.api.endpoints.subscriptions'

ORDER_ID = 'ORDER-TEST-1'

APPROVAL_URL = 'https://www.paypal.com/checkoutnow?token=' + ORDER_ID

#: The five headers a PayPal notification must carry. The signature check
#: is stood in for, so the values need only be present.
PAYPAL_HEADERS = {
    'PAYPAL-AUTH-ALGO': 'SHA256withRSA',
    'PAYPAL-CERT-URL': 'https://api.sandbox.paypal.com/certs/CERT-1',
    'PAYPAL-TRANSMISSION-ID': 'transmission-test-1',
    'PAYPAL-TRANSMISSION-SIG': 'signature',
    'PAYPAL-TRANSMISSION-TIME': '2026-01-01T00:00:00Z',
}


def order_response(order_id=ORDER_ID):
    """Returns an opened order carrying its payer-approval target."""
    return {
        'id': order_id,
        'status': 'PAYER_ACTION_REQUIRED',
        'links': [
            {
                'rel': 'payer-action',
                'href': (
                    'https://www.paypal.com/checkoutnow?token=' + order_id
                ),
                'method': 'GET',
            }
        ],
    }


def capture_response(order_id=ORDER_ID, status='COMPLETED', value='9.99'):
    """Returns a capture response reporting ``status`` and ``value``."""
    return {
        'id': order_id,
        'status': status,
        'purchase_units': [
            {
                'payments': {
                    'captures': [
                        {
                            'id': 'CAPTURE-1',
                            'status': status,
                            'amount': {
                                'currency_code': 'USD',
                                'value': value,
                            },
                        }
                    ]
                }
            }
        ],
    }


def approved_event(order_id=ORDER_ID):
    """Returns the notification body reporting an approved order."""
    return {
        'event_type': 'CHECKOUT.ORDER.APPROVED',
        'resource': {'id': order_id},
    }


def verified_approval(transmission_id=None):
    """Returns the outcome of a passing check on an approval event."""
    return WebhookVerification(
        verified=True,
        transmission_id=(
            transmission_id or PAYPAL_HEADERS['PAYPAL-TRANSMISSION-ID']
        ),
        event_type='CHECKOUT.ORDER.APPROVED',
    )


#: Source of a distinct delivery identifier per notification, so a second
#: delivery is a fresh event rather than a replay of the first.
_deliveries = count(1)


def verified_delivery(transmission_id=None, event_type=None):
    """Returns a passing check carrying a distinct delivery identifier."""
    return WebhookVerification(
        verified=True,
        transmission_id=(
            transmission_id or 'transmission-%d' % next(_deliveries)
        ),
        event_type=event_type or 'CHECKOUT.ORDER.APPROVED',
    )


def deliver_approval(
    client,
    order_id=ORDER_ID,
    capture=None,
    transmission_id=None,
    verification=None,
):
    """Delivers one signature-verified approval and settles the order.

    The signature check and the capture call are both stood in for. The
    delivery identifier is distinct per call unless one is supplied.
    Returns the response together with the capture stand-in, so a caller
    can assert how many times the provider was asked to settle.
    """
    checked = verification or verified_delivery(transmission_id)
    settlement = (
        capture
        if capture is not None
        else AsyncMock(return_value=capture_response())
    )
    with patch(
        SUBSCRIPTIONS_MODULE + '.verify_webhook_signature',
        new=AsyncMock(return_value=checked),
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order', new=settlement
    ):
        response = client.post(
            '/subscriptions/webhook',
            json=approved_event(order_id),
            headers=PAYPAL_HEADERS,
        )
    return response, settlement


@pytest.fixture
def session_factory():
    engine = create_engine(
        'sqlite://',
        connect_args={'check_same_thread': False},
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
    with TestClient(app, base_url='http://localhost') as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def registered_user(db):
    user = User(
        email='testuser@example.com',
        hashed_password=get_password_hash(PASSWORD),
        created_at=datetime.now(timezone.utc),
        role='registered',
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def other_user(db):
    """A second valid account, used for the cross-tenant negatives."""
    user = User(
        email='otheruser@example.com',
        hashed_password=get_password_hash(PASSWORD),
        created_at=datetime.now(timezone.utc),
        role='registered',
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def admin_user(db):
    """An account holding the administrative role."""
    user = User(
        email='adminuser@example.com',
        hashed_password=get_password_hash(PASSWORD),
        created_at=datetime.now(timezone.utc),
        role='admin',
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def bearer(user):
    token = create_access_token(
        data={'sub': str(user.id), 'role': user.role}
    )
    return {'Authorization': 'Bearer ' + token}


def test_user_registration(client, db):
    response = client.post('/auth/register', json={
        'email': 'newuser@example.com',
        'password': 'Str0ng-Passphrase-9'
    })
    assert response.status_code == 200
    body = response.json()
    assert body['user']['email'] == 'newuser@example.com'
    assert 'id' in body['user']
    assert 'access_token' in body
    assert body['token_type'] == 'bearer'
    assert 'hashed_password' not in response.text


def test_user_login_accepts_a_json_body(client, registered_user):
    response = client.post('/auth/login', json={
        'email': registered_user.email,
        'password': PASSWORD
    })
    assert response.status_code == 200
    body = response.json()
    assert 'access_token' in body
    assert 'token_type' in body


def test_login_response_shape_is_unchanged(client, registered_user):
    """The frozen contract: fields may be added, none removed."""
    response = client.post('/auth/login', json={
        'email': registered_user.email,
        'password': PASSWORD
    })
    assert response.status_code == 200
    assert {'access_token', 'token_type'} <= set(response.json())
    assert response.json()['token_type'] == 'bearer'


def test_login_rejects_a_wrong_password(client, registered_user):
    response = client.post('/auth/login', json={
        'email': registered_user.email,
        'password': 'not-the-password'
    })
    assert response.status_code == 401


def test_a_relationship_attribute_is_not_an_accepted_lookup_column(db):
    """A relationship is an InstrumentedAttribute but not a column."""
    for model, relationship_name in (
        (User, 'filters'),
        (User, 'subscriptions'),
        (Filter, 'criteria'),
        (Filter, 'zip_codes'),
    ):
        assert isinstance(
            getattr(model, relationship_name), InstrumentedAttribute
        )
        with pytest.raises(ValueError):
            authorization._lookup_conditions(
                model, {relationship_name: 'x'}
            )


def test_a_mapped_column_is_an_accepted_lookup_column(db):
    conditions = authorization._lookup_conditions(
        SubscriptionModel, {'paypal_order_id': ORDER_ID}
    )
    assert len(conditions) == 1


def test_an_unmapped_class_is_refused_as_a_lookup_model(db):
    with pytest.raises(ValueError):
        authorization._lookup_conditions(dict, {'id': 1})


def test_a_non_unique_lookup_prefers_the_row_the_caller_owns(
    db, registered_user, other_user
):
    """A foreign row ordered first must not deny an owned row."""
    moment = datetime.now(timezone.utc)
    foreign = SubscriptionModel(
        user_id=other_user.id,
        status=STATUS_ACTIVE,
        start_date=moment,
        end_date=moment + timedelta(days=30),
    )
    owned = SubscriptionModel(
        user_id=registered_user.id,
        status=STATUS_ACTIVE,
        start_date=moment,
        end_date=moment + timedelta(days=30),
    )
    db.add_all([foreign, owned])
    db.commit()

    resolved = authorization.load_owned(
        db, SubscriptionModel, registered_user, status=STATUS_ACTIVE
    )
    assert resolved.id == owned.id
    assert resolved.user_id == registered_user.id


def test_a_lookup_matching_only_a_foreign_row_is_not_found(
    db, registered_user, other_user
):
    moment = datetime.now(timezone.utc)
    db.add(
        SubscriptionModel(
            user_id=other_user.id,
            status=STATUS_ACTIVE,
            start_date=moment,
            end_date=moment + timedelta(days=30),
        )
    )
    db.commit()

    with pytest.raises(HTTPException) as refused:
        authorization.load_owned(
            db, SubscriptionModel, registered_user, status=STATUS_ACTIVE
        )
    # Indistinguishable from a lookup that matched no row at all.
    assert refused.value.status_code == 404


def test_a_lookup_matching_no_row_is_not_found(db, registered_user):
    with pytest.raises(HTTPException) as refused:
        authorization.load_owned(
            db, SubscriptionModel, registered_user, status=STATUS_ACTIVE
        )
    assert refused.value.status_code == 404


def test_an_active_subscription_derives_the_premium_role(
    db, registered_user
):
    """A paid entitlement raises the effective role above the stored one."""
    assert registered_user.role == 'registered'
    assert authorization.effective_role(db, registered_user) is Role.REGISTERED

    moment = datetime.now(timezone.utc)
    db.add(
        SubscriptionModel(
            user_id=registered_user.id,
            plan_id=PREMIUM_MONTHLY,
            status=STATUS_ACTIVE,
            start_date=moment,
            end_date=moment + timedelta(days=30),
        )
    )
    db.commit()

    assert authorization.entitled_role(db, registered_user) is Role.PREMIUM
    assert authorization.effective_role(db, registered_user) is Role.PREMIUM
    # The stored row is unchanged: the grant is derived, never written.
    db.expire_all()
    assert db.query(User).filter(
        User.id == registered_user.id
    ).one().role == 'registered'


def test_an_expired_subscription_derives_nothing(db, registered_user):
    """The entitlement lapses on expiry with nothing having to demote it."""
    moment = datetime.now(timezone.utc)
    db.add(
        SubscriptionModel(
            user_id=registered_user.id,
            plan_id=PREMIUM_MONTHLY,
            status=STATUS_ACTIVE,
            start_date=moment - timedelta(days=60),
            end_date=moment - timedelta(days=1),
        )
    )
    db.commit()

    assert authorization.entitled_role(db, registered_user) is None
    assert authorization.effective_role(db, registered_user) is Role.REGISTERED


def test_a_pending_subscription_derives_nothing(db, registered_user):
    """Only a captured payment grants an entitlement."""
    moment = datetime.now(timezone.utc)
    db.add(
        SubscriptionModel(
            user_id=registered_user.id,
            plan_id=PREMIUM_MONTHLY,
            status=STATUS_PENDING,
            start_date=moment,
            end_date=moment + timedelta(days=30),
        )
    )
    db.commit()

    assert authorization.entitled_role(db, registered_user) is None


def test_another_users_subscription_derives_nothing(
    db, registered_user, other_user
):
    moment = datetime.now(timezone.utc)
    db.add(
        SubscriptionModel(
            user_id=other_user.id,
            plan_id=PREMIUM_MONTHLY,
            status=STATUS_ACTIVE,
            start_date=moment,
            end_date=moment + timedelta(days=30),
        )
    )
    db.commit()

    assert authorization.entitled_role(db, registered_user) is None


def test_an_unknown_plan_derives_nothing(db, registered_user):
    """A row naming a plan the catalog does not publish grants nothing."""
    moment = datetime.now(timezone.utc)
    db.add(
        SubscriptionModel(
            user_id=registered_user.id,
            plan_id='not_a_published_plan',
            status=STATUS_ACTIVE,
            start_date=moment,
            end_date=moment + timedelta(days=30),
        )
    )
    db.commit()

    assert authorization.entitled_role(db, registered_user) is None


def test_a_stored_admin_role_is_never_lowered_by_derivation(
    db, registered_user
):
    registered_user.role = 'admin'
    db.commit()
    assert authorization.effective_role(db, registered_user) is Role.ADMIN


def test_the_failed_attempt_write_takes_a_row_lock(registered_user, db):
    """The counter's read-modify-write is serialized by a row lock.

    The statement is compiled against PostgreSQL because SQLite omits
    the locking clause, so the assertion has to name the dialect that
    honours it.
    """
    statement = (
        db.query(User)
        .filter(User.id == registered_user.id)
        .populate_existing()
        .with_for_update()
        .statement
    )
    compiled = str(statement.compile(dialect=postgresql.dialect()))
    assert 'FOR UPDATE' in compiled


def test_repeated_failures_lock_the_account(registered_user, db):
    """The attempt reaching the configured limit locks the account."""
    moment = datetime.now(timezone.utc)
    for _ in range(settings.LOGIN_MAX_ATTEMPTS):
        auth_module._record_failed_attempt(db, registered_user, moment)

    db.expire_all()
    locked = db.query(User).filter(User.id == registered_user.id).one()
    assert locked.failed_login_attempts == settings.LOGIN_MAX_ATTEMPTS
    assert locked.locked_until is not None
    assert auth_module._is_locked(locked, moment)


def test_no_counted_failure_is_lost_across_repeated_writes(
    registered_user, db
):
    """Every counted failure is applied, none overwriting another."""
    moment = datetime.now(timezone.utc)
    for expected in range(1, settings.LOGIN_MAX_ATTEMPTS):
        auth_module._record_failed_attempt(db, registered_user, moment)
        db.expire_all()
        assert db.query(User).filter(
            User.id == registered_user.id
        ).one().failed_login_attempts == expected


def test_an_expired_lock_restarts_the_count(registered_user, db):
    moment = datetime.now(timezone.utc)
    registered_user.failed_login_attempts = 4
    registered_user.locked_until = moment - timedelta(minutes=1)
    db.commit()

    auth_module._record_failed_attempt(db, registered_user, moment)

    db.expire_all()
    row = db.query(User).filter(User.id == registered_user.id).one()
    assert row.failed_login_attempts == 1
    assert row.locked_until is None


def test_a_successful_attempt_clears_the_count_and_the_lock(
    registered_user, db
):
    moment = datetime.now(timezone.utc)
    auth_module._record_failed_attempt(db, registered_user, moment)

    auth_module._record_successful_attempt(db, registered_user)

    db.expire_all()
    row = db.query(User).filter(User.id == registered_user.id).one()
    assert row.failed_login_attempts == 0
    assert row.locked_until is None


def test_a_failed_persistence_is_recorded_rather_than_raised(
    registered_user, db
):
    """A database fault must not change the answer the caller gives."""
    moment = datetime.now(timezone.utc)
    with patch(
        AUTH_MODULE + '._lock_row',
        side_effect=SQLAlchemyError('lock unavailable'),
    ):
        auth_module._record_failed_attempt(db, registered_user, moment)
        auth_module._record_successful_attempt(db, registered_user)

    # The session is left clean, so the request can still be answered.
    assert not db.dirty
    assert not db.new


def test_a_registration_race_answers_as_an_ordinary_duplicate(client):
    """The email unique constraint is authoritative when it fires.

    The commit is made to raise the constraint violation that a second
    concurrent registration for one address would produce.
    """
    violation = IntegrityError(
        'INSERT INTO users', {}, Exception('duplicate key value')
    )
    with patch.object(
        SqlAlchemySession, 'commit', side_effect=violation
    ):
        response = client.post(
            '/auth/register',
            json={
                'email': 'racer@example.com',
                'password': REGISTRATION_PASSWORD,
            },
        )

    assert response.status_code == 400
    assert response.json()['detail'] == DUPLICATE_EMAIL_DETAIL


def test_listing_retrieval_is_public(client):
    response = client.get('/listings/')
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_listing_retrieval_needs_no_authorization_header(client):
    response = client.get('/listings/')
    assert response.status_code == 200


def test_filter_creation_requires_authentication(client):
    response = client.post('/filters/', json={
        'name': 'Test Filter',
        'criteria': []
    })
    assert response.status_code == 401


def test_filter_listing_is_scoped_to_the_caller(
    client, registered_user
):
    response = client.get('/filters/', headers=bearer(registered_user))
    assert response.status_code == 200
    assert response.json() == []


def _filter_body(**overrides):
    body = {
        'name': 'Cambridge two-bed',
        'zip_codes': [{'code': '02139'}, {'code': '02140'}],
        'criteria': [{'field': 'rent', 'operator': 'lte', 'value': '3000'}],
    }
    body.update(overrides)
    return body


def test_an_accepted_zip_code_is_persisted_as_a_child_row(
    client, registered_user, db
):
    """Every postal code the contract admits reaches the database."""
    created = client.post(
        '/filters/',
        json=_filter_body(),
        headers=bearer(registered_user),
    )
    assert created.status_code == 200

    # Returned by the response model rather than silently dropped.
    assert sorted(z['code'] for z in created.json()['zip_codes']) == [
        '02139', '02140'
    ]

    # Present as real zip_codes rows bound to the filter.
    db.expire_all()
    stored = db.query(FilterModel).one()
    assert sorted(z.code for z in stored.zip_codes) == ['02139', '02140']
    assert all(z.filter_id == stored.id for z in stored.zip_codes)
    assert db.query(ZipCode).count() == 2

    # The criteria children are unaffected.
    assert [c.field for c in stored.criteria] == ['rent']


def test_a_filter_without_zip_codes_still_stores(
    client, registered_user, db
):
    created = client.post(
        '/filters/',
        json=_filter_body(zip_codes=[]),
        headers=bearer(registered_user),
    )
    assert created.status_code == 200
    assert created.json()['zip_codes'] == []
    assert db.query(ZipCode).count() == 0


def test_a_filter_that_cannot_be_stored_is_rolled_back(
    client, registered_user, db
):
    with patch.object(
        SqlAlchemySession,
        'commit',
        side_effect=SQLAlchemyError('disk full'),
    ):
        response = client.post(
            '/filters/',
            json=_filter_body(),
            headers=bearer(registered_user),
        )

    assert response.status_code == 500
    assert response.json()['detail'] == FILTER_NOT_STORED_DETAIL
    db.expire_all()
    assert db.query(FilterModel).count() == 0
    assert db.query(ZipCode).count() == 0


def test_a_listing_that_cannot_be_stored_is_rolled_back(
    client, admin_user, db
):
    with patch.object(
        SqlAlchemySession,
        'commit',
        side_effect=SQLAlchemyError('disk full'),
    ):
        response = client.post(
            '/listings/',
            json={'rent': 2400.0},
            headers=bearer(admin_user),
        )

    assert response.status_code == 500
    assert response.json()['detail'] == LISTING_NOT_STORED_DETAIL
    db.expire_all()
    assert db.query(ListingModel).count() == 0


def test_a_listing_is_stored_by_an_administrator(
    client, admin_user, db
):
    response = client.post(
        '/listings/',
        json={'rent': 2400.0, 'bedrooms': 2},
        headers=bearer(admin_user),
    )
    assert response.status_code == 200
    db.expire_all()
    stored = db.query(ListingModel).one()
    assert stored.rent == 2400.0
    assert stored.bedrooms == 2


def test_a_registered_user_cannot_store_a_listing(
    client, registered_user, db
):
    """The one intentional breaking change: the write is admin-only."""
    response = client.post(
        '/listings/',
        json={'rent': 2400.0},
        headers=bearer(registered_user),
    )
    assert response.status_code == 403
    assert db.query(ListingModel).count() == 0


def test_subscription_creation_and_retrieval(
    client, registered_user
):
    """Creation opens an order for approval and captures nothing.

    The row it records entitles nothing until a settlement is proven, so
    the retrieval route reports nothing while it is pending and reports
    the row once the verified approval has activated it.
    """
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        return_value=order_response(),
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order',
    ) as capture:
        created = client.post(
            '/subscriptions/',
            json={'plan_id': 'premium_monthly'},
            headers=bearer(registered_user),
        )
    assert created.status_code == 200
    body = created.json()
    assert body['user_id'] == registered_user.id
    assert body['status'] == 'pending'
    assert body['approval_url'] == APPROVAL_URL
    assert capture.call_count == 0

    pending = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    )
    assert pending.status_code == 200
    assert pending.json() is None

    settled, _ = deliver_approval(client)
    assert settled.status_code == 200
    assert settled.json() == {'status': 'processed'}

    fetched = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    )
    assert fetched.status_code == 200
    assert fetched.json()['id'] == body['id']
    assert fetched.json()['status'] == 'active'


def test_subscription_creation_prices_from_the_catalog(
    client, db, registered_user
):
    """Neither the amount nor the entitlement window is client supplied."""
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        return_value=order_response(),
    ):
        created = client.post(
            '/subscriptions/',
            json={'plan_id': 'premium_monthly'},
            headers=bearer(registered_user),
        )
    assert created.status_code == 200
    plan = get_plan('premium_monthly')
    row = db.query(SubscriptionModel).filter_by(
        id=created.json()['id']
    ).first()
    assert Decimal(str(row.amount)) == plan.amount
    assert row.currency == plan.currency
    assert row.paypal_order_id == ORDER_ID
    assert row.end_date is None


def test_subscription_creation_rejects_a_client_amount(
    client, registered_user
):
    """The charge amount is absent from the contract, not validated."""
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        return_value=order_response(),
    ):
        response = client.post(
            '/subscriptions/',
            json={'plan_id': 'premium_monthly', 'amount': '0.01'},
            headers=bearer(registered_user),
        )
    assert response.status_code == 422


def test_verified_approval_captures_and_grants_the_plan_role(
    client, db, registered_user
):
    """Entitlement follows a capture PayPal reported as complete."""
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        return_value=order_response(),
    ):
        created = client.post(
            '/subscriptions/',
            json={'plan_id': 'premium_monthly'},
            headers=bearer(registered_user),
        )
    assert created.json()['status'] == 'pending'

    with patch(
        SUBSCRIPTIONS_MODULE + '.verify_webhook_signature',
        return_value=verified_approval(),
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order',
        return_value=capture_response(),
    ):
        delivered = client.post(
            '/subscriptions/webhook',
            json=approved_event(),
            headers=PAYPAL_HEADERS,
        )
    assert delivered.status_code == 200
    assert delivered.json() == {'status': 'processed'}

    db.expire_all()
    row = db.query(SubscriptionModel).filter_by(
        id=created.json()['id']
    ).first()
    assert row.status == 'active'
    assert row.end_date is not None
    assert db.query(User).filter_by(
        id=registered_user.id
    ).first().role == 'premium'


def test_a_capture_that_is_not_complete_grants_nothing(
    client, db, registered_user
):
    """A tampered captured amount leaves the subscription pending."""
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        return_value=order_response(),
    ):
        created = client.post(
            '/subscriptions/',
            json={'plan_id': 'premium_monthly'},
            headers=bearer(registered_user),
        )

    with patch(
        SUBSCRIPTIONS_MODULE + '.verify_webhook_signature',
        return_value=verified_approval(),
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order',
        return_value=capture_response(value='0.01'),
    ):
        delivered = client.post(
            '/subscriptions/webhook',
            json=approved_event(),
            headers=PAYPAL_HEADERS,
        )
    assert delivered.status_code == 200
    assert delivered.json() == {'status': 'ignored'}

    db.expire_all()
    row = db.query(SubscriptionModel).filter_by(
        id=created.json()['id']
    ).first()
    assert row.status == 'pending'
    assert db.query(User).filter_by(
        id=registered_user.id
    ).first().role == 'registered'


def test_a_repeated_delivery_is_acknowledged_without_reprocessing(
    client, registered_user
):
    """PayPal redelivers anything not answered 2xx, so a replay is 200."""
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        return_value=order_response(),
    ):
        client.post(
            '/subscriptions/',
            json={'plan_id': 'premium_monthly'},
            headers=bearer(registered_user),
        )

    with patch(
        SUBSCRIPTIONS_MODULE + '.verify_webhook_signature',
        return_value=verified_approval(),
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order',
        return_value=capture_response(),
    ) as capture:
        first = client.post(
            '/subscriptions/webhook',
            json=approved_event(),
            headers=PAYPAL_HEADERS,
        )
        second = client.post(
            '/subscriptions/webhook',
            json=approved_event(),
            headers=PAYPAL_HEADERS,
        )
    assert first.json() == {'status': 'processed'}
    assert second.status_code == 200
    assert second.json() == {'status': 'duplicate'}
    assert capture.call_count == 1


def test_an_unverified_notification_changes_no_state(client, db):
    """A rejected notification writes nothing at all."""
    rejected = WebhookVerification(
        verified=False, reason='signature_not_verified'
    )
    with patch(
        SUBSCRIPTIONS_MODULE + '.verify_webhook_signature',
        return_value=rejected,
    ):
        response = client.post(
            '/subscriptions/webhook',
            json=approved_event(),
            headers=PAYPAL_HEADERS,
        )
    assert response.status_code == 400
    assert db.query(WebhookEvent).count() == 0
    assert db.query(SubscriptionModel).count() == 0


def test_a_provider_outage_is_not_reported_as_a_client_error(
    client, registered_user, db
):
    """A dependency failure is answered 502, not 400."""
    outage = PayPalAPIError(
        'unavailable', category=CATEGORY_PROVIDER_SERVER, status_code=503
    )
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order', side_effect=outage
    ):
        response = client.post(
            '/subscriptions/',
            json={'plan_id': 'premium_monthly'},
            headers=bearer(registered_user),
        )
    assert response.status_code == 502
    # The attempt stays recorded, entitling nothing.
    stored = db.query(SubscriptionModel).one()
    assert stored.status == STATUS_FAILED
    assert stored.end_date is None


def _open_subscription(client, user, plan_id=PREMIUM_MONTHLY):
    """Opens one subscription with the order call stood in for."""
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        return_value=order_response(),
    ):
        return client.post(
            '/subscriptions/',
            json={'plan_id': plan_id},
            headers=bearer(user),
        )


def test_the_ownership_row_is_durable_before_the_capture(
    client, registered_user, session_factory
):
    """A settled charge can never be the first durable thing to happen.

    Creation commits the pending row and captures nothing; the verified
    approval stands in for the remote capture call and reads the database
    from an independent session, so it only sees the row if that row was
    genuinely committed before the charge.
    """
    seen = {}

    async def observing_capture(db, order_id, current_user, **kwargs):
        independent = session_factory()
        try:
            row = independent.query(SubscriptionModel).filter(
                SubscriptionModel.paypal_order_id == order_id
            ).one_or_none()
            seen['committed'] = row is not None
            seen['status'] = row.status if row else None
            seen['end_date'] = row.end_date if row else None
            seen['user_id'] = row.user_id if row else None
            seen['request_id'] = (
                paypal_module.order_request_id(row.id) if row else None
            )
        finally:
            independent.close()
        return capture_response()

    created = _open_subscription(client, registered_user)
    assert created.status_code == 200
    assert created.json()['status'] == STATUS_PENDING
    assert created.json()['end_date'] is None

    settled, _ = deliver_approval(
        client, capture=AsyncMock(side_effect=observing_capture)
    )

    assert settled.status_code == 200
    # Durable, owned, and granting nothing at the moment of the charge.
    assert seen['committed'] is True
    assert seen['status'] == STATUS_PENDING
    assert seen['end_date'] is None
    assert seen['user_id'] == registered_user.id
    assert seen['request_id']

    # Activated only after the charge settled.
    entitling = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    ).json()
    assert entitling['status'] == STATUS_ACTIVE
    assert entitling['end_date'] is not None


def test_a_failed_capture_leaves_a_failed_row_and_no_entitlement(
    client, registered_user, db
):
    """A provider refusal at capture entitles nothing.

    A provider failure with no category is a dependency failure, so it
    is answered 502 rather than as a client error.
    """
    assert _open_subscription(client, registered_user).status_code == 200

    refused, _ = deliver_approval(
        client,
        capture=AsyncMock(
            side_effect=PayPalAPIError('capture declined')
        ),
    )

    assert refused.status_code == 502

    db.expire_all()
    row = db.query(SubscriptionModel).filter(
        SubscriptionModel.paypal_order_id == ORDER_ID
    ).one()
    # Retained for reconciliation, entitling nothing.
    assert row.status == STATUS_PENDING
    assert row.end_date is None
    assert authorization.entitled_role(db, registered_user) is None
    assert client.get(
        '/subscriptions/', headers=bearer(registered_user)
    ).json() is None
    # The delivery record went back with the transition, so PayPal's
    # redelivery is processed rather than dismissed as a replay.
    assert db.query(WebhookEvent).count() == 0


def test_a_duplicate_order_identifier_is_not_captured_again(
    client, registered_user, db
):
    """The uniqueness constraint stops a second capture of one order."""
    moment = datetime.now(timezone.utc)
    db.add(
        SubscriptionModel(
            user_id=registered_user.id,
            status=STATUS_PENDING,
            start_date=moment,
            paypal_order_id=ORDER_ID,
        )
    )
    db.commit()

    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        return_value=order_response(),
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order'
    ) as mock_capture:
        refused = client.post(
            '/subscriptions/',
            json={'plan_id': PREMIUM_MONTHLY},
            headers=bearer(registered_user),
        )

    assert refused.status_code == 400
    assert mock_capture.call_count == 0


def test_a_settled_charge_that_cannot_activate_reports_reconciliation(
    client, registered_user
):
    """The durable pending row is what reconciliation is left to finish."""
    assert _open_subscription(client, registered_user).status_code == 200

    def fail_the_activation(self):
        raise SQLAlchemyError('activation could not be committed')

    with patch.object(SqlAlchemySession, 'commit', fail_the_activation):
        response, _ = deliver_approval(client)

    assert response.status_code == 503
    assert response.json()['detail'] == RECONCILIATION_DETAIL


def test_a_successful_subscription_derives_the_premium_entitlement(
    client, registered_user, db
):
    """The paid role is derived from the settled row, end to end."""
    assert _open_subscription(client, registered_user).status_code == 200

    settled, _ = deliver_approval(client)
    assert settled.status_code == 200

    db.expire_all()
    assert authorization.entitled_role(db, registered_user) is Role.PREMIUM
    assert authorization.effective_role(db, registered_user) is Role.PREMIUM
    assert db.query(User).filter(
        User.id == registered_user.id
    ).one().role == 'premium'


def test_no_client_field_can_influence_the_charge_or_the_window(
    client, registered_user, db
):
    """Amount, currency, dates, status and order id are server-owned."""
    tampered = client.post(
        '/subscriptions/',
        json={
            'plan_id': PREMIUM_MONTHLY,
            'amount': '0.01',
            'currency': 'XXX',
            'status': STATUS_ACTIVE,
            'start_date': '2000-01-01T00:00:00Z',
            'end_date': '2099-01-01T00:00:00Z',
            'paypal_order_id': 'ATTACKER-ORDER',
        },
        headers=bearer(registered_user),
    )
    # Every one of those fields is outside the contract.
    assert tampered.status_code == 422
    assert db.query(SubscriptionModel).count() == 0

    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        return_value=order_response(),
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order',
        return_value={'status': 'COMPLETED'},
    ):
        created = client.post(
            '/subscriptions/',
            json={'plan_id': PREMIUM_MONTHLY},
            headers=bearer(registered_user),
        )
    assert created.status_code == 200

    db.expire_all()
    row = db.query(SubscriptionModel).one()
    plan = get_plan(PREMIUM_MONTHLY)
    assert Decimal(str(row.amount)) == plan.amount
    assert row.currency == plan.currency
    assert row.paypal_order_id == ORDER_ID
    assert row.start_date.year >= 2020
    # The response projects neither the amount nor the order identifier.
    assert 'amount' not in created.json()
    assert 'paypal_order_id' not in created.json()


def test_subscription_retrieval_requires_authentication(client):
    assert client.get('/subscriptions/').status_code == 401


def test_health_endpoint_reports_ready(client):
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok'}


def test_every_response_carries_a_correlation_id(client):
    """A served response carries the identifier its records share."""
    response = client.get('/health')
    assert response.status_code == 200
    identifier = response.headers.get(REQUEST_ID_HEADER)
    assert identifier
    assert identifier.isalnum()


def test_a_supplied_correlation_id_is_honoured(client):
    """A caller's own identifier is adopted, so traces join up."""
    response = client.get(
        '/health', headers={REQUEST_ID_HEADER: 'caller0trace1'}
    )
    assert response.headers[REQUEST_ID_HEADER] == 'caller0trace1'


@pytest.mark.parametrize('supplied', [
    'has spaces',
    'has/separators',
    'has\nnewline',
    '',
    'x' * 200,
])
def test_an_unusable_correlation_id_is_replaced(client, supplied):
    """An identifier that could corrupt a record is not adopted."""
    response = client.get(
        '/health', headers={REQUEST_ID_HEADER: supplied}
    )
    returned = response.headers[REQUEST_ID_HEADER]
    assert returned != supplied
    assert returned.isalnum()


def test_a_rejected_request_still_carries_a_correlation_id(client):
    """A failure is the case the identifier matters most for."""
    response = client.get('/subscriptions/')
    assert response.status_code == 401
    assert response.headers.get(REQUEST_ID_HEADER)


@pytest.mark.parametrize('text, expected', [
    ('boot /srv/app/backend/app/main.py', 'boot <path>/main.py'),
    ('read C:\\app\\backend\\app\\main.py', 'read <path>/main.py'),
    ('owner alice.smith@example.com', 'owner [REDACTED]'),
])
def test_redaction_covers_internal_paths_and_pii(text, expected):
    """A path or an address never reaches a record intact."""
    assert redact(text) == expected


@pytest.mark.parametrize('value', [
    'api_key=SUPERSECRET',
    'token=abc.def.ghi',
    'password=hunter2',
])
def test_redaction_still_covers_credentials(value):
    """The credential cover the path rules were added beside."""
    assert 'SUPERSECRET' not in redact(value)
    assert redact(value) != value


@pytest.mark.parametrize('path', [
    '/subscriptions/webhook',
    '/health',
    '/listings/',
])
def test_redaction_leaves_route_paths_intact(path):
    """An audited route path stays readable, or audit loses meaning."""
    assert redact(path) == path


def collected(logger_name):
    """Returns a logger and the list its records are appended to."""
    records = []

    class Collector(stdlib_logging.Handler):
        def emit(self, record):
            records.append(record)

    logger = stdlib_logging.getLogger(logger_name)
    logger.handlers = [Collector()]
    logger.setLevel(stdlib_logging.INFO)
    logger.propagate = False
    return logger, records


def test_a_logged_exception_carries_no_traceback():
    """The failure is described by fields, not by a stack dump."""
    logger, records = collected('test.f11.exception')
    try:
        raise RuntimeError('failed reading /srv/app/backend/key.py')
    except RuntimeError as error:
        log_exception(logger, 'Ingestion failed', error)

    assert len(records) == 1
    record = records[0]
    assert record.exc_info is None
    assert 'Traceback' not in record.getMessage()
    assert record.exception_type == 'RuntimeError'
    assert '/srv/app/backend' not in record.exception_message
    assert '<path>/key.py' in record.exception_message


@contextmanager
def watching_audit_trail():
    """Yields the records written to the governed namespace."""
    records = []

    class Collector(stdlib_logging.Handler):
        def emit(self, record):
            records.append(record)

    collector = Collector()
    governed = stdlib_logging.getLogger('backend')
    previous = governed.level
    governed.addHandler(collector)
    governed.setLevel(stdlib_logging.INFO)
    try:
        yield records
    finally:
        governed.removeHandler(collector)
        governed.setLevel(previous)


def messages(records):
    """Returns the plain message of every collected record."""
    return [record.getMessage() for record in records]


def test_a_denial_survives_a_failing_audit_sink(
    client, registered_user, capsys
):
    """A denial reaches a sink even when the primary one fails."""
    reset_audit_failure_count()
    broken = Mock()
    broken.warning.side_effect = RuntimeError('sink down')
    broken.info.side_effect = RuntimeError('sink down')
    try:
        with patch(
            'backend.app.core.authorization.logger', broken
        ):
            response = client.post(
                '/listings/',
                json={'street_address': '1 Main St', 'rent': '1000.00'},
                headers=bearer(registered_user),
            )
        assert response.status_code == 403
        assert audit_failure_count() >= 1
        assert REFUSAL_MESSAGE in capsys.readouterr().err
    finally:
        reset_audit_failure_count()


def test_a_refusal_is_audited_exactly_once(client, registered_user):
    """One refusal produces one canonical record, not two."""
    with watching_audit_trail() as records:
        response = client.post(
            '/listings/',
            json={'street_address': '1 Main St', 'rent': '1000.00'},
            headers=bearer(registered_user),
        )
    assert response.status_code == 403
    written = messages(records)
    assert written.count(REFUSAL_MESSAGE) == 1
    assert 'Request rejected' not in written


def test_a_foreign_log_handler_is_removed_and_reported():
    """A handler that would bypass redaction does not survive."""
    governed = stdlib_logging.getLogger('backend')
    foreign = stdlib_logging.StreamHandler()
    governed.addHandler(foreign)
    try:
        assert foreign in governed.handlers
        configure_logging()
        assert foreign not in governed.handlers
        assert any(
            'StreamHandler' in name
            for name in unredacted_handler_names()
        )
        kept = [
            handler for handler in governed.handlers
            if getattr(handler, 'name', None) == HANDLER_NAME
        ]
        assert len(kept) == 1
    finally:
        if foreign in governed.handlers:
            governed.removeHandler(foreign)
        configure_logging()


def test_a_child_logger_cannot_bypass_redaction():
    """A handler on a descendant is stripped and made to propagate."""
    child = stdlib_logging.getLogger('backend.child.bypass')
    escape = stdlib_logging.StreamHandler()
    child.addHandler(escape)
    child.propagate = False
    try:
        configure_logging()
        assert child.handlers == []
        assert child.propagate is True
    finally:
        if escape in child.handlers:
            child.removeHandler(escape)
        configure_logging()


def test_an_oversized_body_is_rejected(client):
    """A body past the cap is refused before it can be handled."""
    oversized = 'x' * (1024 * 1024 + 512)
    response = client.post(
        '/filters/',
        content=('{"note": "' + oversized + '"}').encode('utf-8'),
        headers={'Content-Type': 'application/json'},
    )
    assert response.status_code == 413


def drive_capped_request(declared, chunks, cap=32):
    """Returns the statuses a capped middleware produces for a body.

    A declared oversize is answered before the request is handled at
    all. A body that overruns while it is being read is refused from
    inside ``receive``, which raises through the handler reading it,
    so ``reached`` reports whether the body was read to its end
    rather than whether the handler was entered.
    """
    reached = []
    statuses = []

    async def inner(scope, receive, send):
        while True:
            message = await receive()
            if not message.get('more_body'):
                break
        reached.append(True)
        await send({
            'type': 'http.response.start',
            'status': 200,
            'headers': [],
        })
        await send({'type': 'http.response.body', 'body': b''})

    guarded = BodySizeLimitMiddleware(inner, max_body_bytes=cap)
    headers = []
    if declared is not None:
        headers.append((b'content-length', str(declared).encode()))
    scope = {
        'type': 'http',
        'method': 'POST',
        'path': '/filters/',
        'headers': headers,
        'query_string': b'',
        'client': ('1.2.3.4', 1),
    }
    pending = list(chunks)

    async def receive():
        if pending:
            chunk = pending.pop(0)
            return {
                'type': 'http.request',
                'body': chunk,
                'more_body': bool(pending),
            }
        return {'type': 'http.request', 'body': b'', 'more_body': False}

    async def send(message):
        if message['type'] == 'http.response.start':
            statuses.append(message['status'])

    try:
        asyncio.run(guarded(scope, receive, send))
    except StarletteHTTPException as refused:
        statuses.append(refused.status_code)
    return statuses, bool(reached)


def test_a_body_within_its_declaration_is_served():
    """The cap does not interfere with an ordinary request."""
    statuses, reached = drive_capped_request(8, [b'x' * 8])
    assert statuses == [200]
    assert reached


def test_a_body_that_understates_its_length_is_rejected():
    """Received bytes are counted, so a false declaration fails."""
    statuses, reached = drive_capped_request(
        10, [b'x' * 26, b'y' * 26]
    )
    assert statuses == [413]
    assert not reached


def test_a_body_declaring_no_length_is_rejected():
    """A chunked body is held to the same cap."""
    statuses, reached = drive_capped_request(
        None, [b'x' * 20, b'y' * 20]
    )
    assert statuses == [413]
    assert not reached


def test_an_oversized_declaration_is_rejected_early():
    """A declaration past the cap is refused before any read."""
    statuses, reached = drive_capped_request(4096, [b'x' * 8])
    assert statuses == [413]
    assert not reached


def test_throttling_is_audited_and_answered_429(client):
    """Exhausting the credential limit is refused and recorded."""
    limiter = app.state.limiter
    limiter.reset()
    try:
        with watching_audit_trail() as records:
            statuses = []
            for _ in range(12):
                statuses.append(client.post('/auth/login', json={
                    'email': 'absent@example.com',
                    'password': 'whatever-value-1'
                }).status_code)
                if statuses[-1] == 429:
                    break
        assert 429 in statuses
        throttled = [
            record for record in records
            if record.getMessage() == THROTTLED_MESSAGE
        ]
        assert len(throttled) == 1
        assert throttled[0].policy
        assert throttled[0].path == '/auth/login'
        assert throttled[0].method == 'POST'
    finally:
        limiter.reset()


class FakeResponse:
    """Stands in for a provider response at the transport boundary."""

    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class FakeClient:
    """Records the calls a provider function issues."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]


@contextmanager
def provider_transport(responses):
    """Yields a fake transport installed on the provider module.

    The client is recorded against a loop, and only a call running on
    that loop is given it, so the stand-in is installed through the same
    context manager the provider functions acquire it from.
    """
    fake = FakeClient(responses)

    @asynccontextmanager
    async def lend_the_stand_in():
        yield fake

    with patch.object(paypal_module, '_client', lend_the_stand_in):
        with patch.object(
            paypal_module,
            '_bearer_credential',
            AsyncMock(return_value='token-value'),
        ):
            yield fake


def test_order_creation_sends_a_stable_idempotency_key():
    """A repeat of an uncertain call resolves to the same order."""
    from backend.app.services.paypal_service import (
        capture_request_id,
        order_request_id,
    )

    assert order_request_id(7) == order_request_id(7)
    assert order_request_id(7) != order_request_id(8)
    assert order_request_id(7) != capture_request_id(7)

    with provider_transport([FakeResponse(200, order_response())]) as fake:
        asyncio.run(paypal_module.create_order(
            'premium_monthly',
            'https://example.test/return',
            'https://example.test/cancel',
            idempotency_key=order_request_id(7),
        ))
    _, kwargs = fake.calls[0]
    assert kwargs['headers'][IDEMPOTENCY_HEADER] == order_request_id(7)


def test_order_creation_uses_the_current_experience_context():
    """The redirect targets travel in the supported field."""
    with provider_transport([FakeResponse(200, order_response())]) as fake:
        asyncio.run(paypal_module.create_order(
            'premium_monthly',
            'https://example.test/return',
            'https://example.test/cancel',
        ))
    _, kwargs = fake.calls[0]
    body = kwargs['json']
    context = body['payment_source']['paypal']['experience_context']
    assert context['return_url'] == 'https://example.test/return'
    assert context['cancel_url'] == 'https://example.test/cancel'
    assert 'application_context' not in body


def test_a_rejected_token_is_refreshed_once():
    """A stale grant is discarded and the call repeated once."""
    responses = [
        FakeResponse(401, {'name': 'INVALID_TOKEN'}),
        FakeResponse(200, order_response()),
    ]
    discard = Mock()
    with provider_transport(responses) as fake:
        with patch.object(
            paypal_module, 'reset_access_token_cache', discard
        ):
            order = asyncio.run(paypal_module.create_order(
                'premium_monthly',
                'https://example.test/return',
                'https://example.test/cancel',
            ))
    assert order['id'] == ORDER_ID
    assert discard.call_count == 1
    assert len(fake.calls) == 2


def owned_order(db, user, order_id=ORDER_ID):
    """Persists a pending subscription owned by ``user``."""
    plan = get_plan('premium_monthly')
    subscription = SubscriptionModel(
        user_id=user.id,
        plan_id='premium_monthly',
        amount=plan.amount,
        currency=plan.currency,
        status='pending',
        paypal_order_id=order_id,
        start_date=datetime.now(timezone.utc),
    )
    db.add(subscription)
    db.commit()
    db.refresh(subscription)
    return subscription


def test_capture_is_refused_for_another_principals_order(db, registered_user):
    """An order is captured only by the principal that owns it."""
    owned_order(db, registered_user)
    intruder = User(
        email='intruder@example.com',
        hashed_password=get_password_hash(PASSWORD),
        created_at=datetime.now(timezone.utc),
        role='registered',
    )
    db.add(intruder)
    db.commit()
    db.refresh(intruder)

    with provider_transport([FakeResponse(200, capture_response())]) as fake:
        with pytest.raises(paypal_module.OrderOwnershipError):
            asyncio.run(paypal_module.capture_order(
                db, ORDER_ID, intruder
            ))
    assert fake.calls == []


def test_capture_is_refused_for_an_unknown_order(db, registered_user):
    """An order resolving to no row is refused on the same terms."""
    with provider_transport([FakeResponse(200, capture_response())]) as fake:
        with pytest.raises(paypal_module.OrderOwnershipError):
            asyncio.run(paypal_module.capture_order(
                db, 'ORDER-DOES-NOT-EXIST', registered_user
            ))
    assert fake.calls == []


def test_capture_proceeds_for_the_owning_principal(db, registered_user):
    """The owner's own order is captured, so the guard is not blanket."""
    owned_order(db, registered_user)
    with provider_transport([FakeResponse(200, capture_response())]) as fake:
        captured = asyncio.run(paypal_module.capture_order(
            db, ORDER_ID, registered_user
        ))
    assert captured['status'] == 'COMPLETED'
    assert len(fake.calls) == 1


def _published_routes():
    """Returns every (method, path) pair the application publishes."""
    pairs = set()
    for route in app.routes:
        for method in getattr(route, 'methods', None) or []:
            pairs.add((method, route.path))
    return pairs


def test_route_paths_and_prefixes_are_unchanged():
    pairs = _published_routes()
    for expected in [
        ('POST', '/auth/register'),
        ('POST', '/auth/login'),
        ('GET', '/listings/'),
        ('POST', '/listings/'),
        ('GET', '/filters/'),
        ('POST', '/filters/'),
        ('GET', '/subscriptions/'),
        ('POST', '/subscriptions/'),
    ]:
        assert expected in pairs, expected


def test_the_webhook_is_the_only_additive_subscription_route():
    """The subscription surface is the two frozen routes plus the webhook.

    A route that took a PayPal identifier from a client would be a fourth
    one, so the set is asserted exactly rather than by membership.
    """
    published = {
        pair
        for pair in _published_routes()
        if pair[1].startswith('/subscriptions')
    }
    assert published == {
        ('GET', '/subscriptions/'),
        ('POST', '/subscriptions/'),
        ('POST', '/subscriptions/webhook'),
    }
    assert ('POST', '/subscriptions/capture') not in published


def test_no_route_accepts_a_paypal_identifier_from_a_client():
    """No request contract declares a provider identifier field."""
    assert not hasattr(subscription_schema, 'SubscriptionCapture')
    assert set(SubscriptionCreate.__fields__) == {'plan_id'}


# ---------------------------------------------------------------
# Coverage carried over from the C_app_tmp_cur_test_api_py review scope.
# ---------------------------------------------------------------

# Four ASCII characters satisfying every complexity rule followed by
# enough filler to carry the value one byte past the bcrypt ceiling.
OVER_LIMIT_PASSWORD = 'Aa1!' + 'x' * 69


# The four router prefixes, which are a frozen interface.
API_PREFIXES = ('/auth', '/listings', '/filters', '/subscriptions')


# The eight pre-existing routes plus the one additive route, the webhook
# listener, mounted under the existing /subscriptions prefix.
EXPECTED_API_ROUTES = {
    ('POST', '/auth/register'),
    ('POST', '/auth/login'),
    ('GET', '/listings/'),
    ('POST', '/listings/'),
    ('GET', '/filters/'),
    ('POST', '/filters/'),
    ('GET', '/subscriptions/'),
    ('POST', '/subscriptions/'),
    ('POST', '/subscriptions/webhook'),
}


@pytest.fixture
def unthrottled():
    """Suspends the shared rate limiter for a burst of requests.

    The lockout counter and the rate limiter are separate controls. These
    cases exercise the counter over more requests than the per-address
    rate allows, so the limiter is suspended and its state cleared here.
    """
    was_enabled = auth_limiter.enabled
    auth_limiter.enabled = False
    try:
        yield
    finally:
        auth_limiter.enabled = was_enabled
        auth_limiter.reset()


def _seed(db, email, role):
    """Stores one user carrying ``role`` and returns the row."""
    user = User(
        email=email,
        hashed_password=get_password_hash(PASSWORD),
        created_at=datetime.now(timezone.utc),
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def second_user(db):
    return _seed(db, 'otheruser@example.com', 'registered')


def test_each_failed_login_is_counted_exactly_once(
    client, db, registered_user, unthrottled
):
    """The counter is raised by the database, not read-modify-written."""
    for expected in (1, 2, 3):
        response = client.post('/auth/login', json={
            'email': registered_user.email,
            'password': 'not-the-password'
        })
        assert response.status_code == 401
        db.expire_all()
        stored = db.query(User).filter(
            User.id == registered_user.id
        ).one()
        assert stored.failed_login_attempts == expected
        assert stored.locked_until is None


def test_reaching_the_attempt_limit_locks_the_account(
    client, db, registered_user, unthrottled
):
    limit = settings.LOGIN_MAX_ATTEMPTS
    for _ in range(limit):
        client.post('/auth/login', json={
            'email': registered_user.email,
            'password': 'not-the-password'
        })
    db.expire_all()
    stored = db.query(User).filter(User.id == registered_user.id).one()
    assert stored.failed_login_attempts == limit
    assert stored.locked_until is not None

    # The correct password is refused identically while the lock holds.
    locked = client.post('/auth/login', json={
        'email': registered_user.email,
        'password': PASSWORD
    })
    assert locked.status_code == 401
    db.expire_all()
    assert db.query(User).filter(
        User.id == registered_user.id
    ).one().failed_login_attempts == limit


def test_a_successful_login_clears_the_counter(
    client, db, registered_user, unthrottled
):
    client.post('/auth/login', json={
        'email': registered_user.email,
        'password': 'not-the-password'
    })
    response = client.post('/auth/login', json={
        'email': registered_user.email,
        'password': PASSWORD
    })
    assert response.status_code == 200
    db.expire_all()
    stored = db.query(User).filter(User.id == registered_user.id).one()
    assert stored.failed_login_attempts == 0
    assert stored.locked_until is None


def test_filter_creation_persists_the_submitted_zip_codes(
    client, db, registered_user
):
    """Postal codes accepted by the contract reach the zip_codes table."""
    response = client.post(
        '/filters/',
        json={
            'name': 'Downtown',
            'zip_codes': [{'code': '94105'}, {'code': '94107-1234'}],
            'criteria': [
                {'field': 'rent', 'operator': 'lte', 'value': '3500'}
            ],
        },
        headers=bearer(registered_user),
    )
    assert response.status_code == 200
    body = response.json()
    assert [entry['code'] for entry in body['zip_codes']] == [
        '94105', '94107-1234'
    ]
    assert body['user_id'] == registered_user.id

    db.expire_all()
    stored = db.query(FilterModel).filter(
        FilterModel.user_id == registered_user.id
    ).one()
    assert sorted(row.code for row in stored.zip_codes) == [
        '94105', '94107-1234'
    ]
    assert [row.field for row in stored.criteria] == ['rent']


def test_filter_creation_accepts_no_zip_codes(
    client, db, registered_user
):
    response = client.post(
        '/filters/',
        json={
            'name': 'Anywhere',
            'criteria': [
                {'field': 'rent', 'operator': 'lte', 'value': '3500'}
            ],
        },
        headers=bearer(registered_user),
    )
    assert response.status_code == 200
    assert response.json()['zip_codes'] == []

    db.expire_all()
    stored = db.query(FilterModel).filter(
        FilterModel.user_id == registered_user.id
    ).one()
    assert stored.zip_codes == []


def test_a_filter_is_not_visible_to_another_account(
    client, db, registered_user, second_user
):
    created = client.post(
        '/filters/',
        json={
            'name': 'Mine',
            'zip_codes': [{'code': '94105'}],
            'criteria': [
                {'field': 'rent', 'operator': 'lte', 'value': '3500'}
            ],
        },
        headers=bearer(registered_user),
    )
    assert created.status_code == 200
    assert client.get(
        '/filters/', headers=bearer(second_user)
    ).json() == []
    assert len(client.get(
        '/filters/', headers=bearer(registered_user)
    ).json()) == 1


def _created_order(order_id=ORDER_ID):
    """Returns a PayPal create-order object carrying an approval link."""
    return {
        'id': order_id,
        'status': 'PAYER_ACTION_REQUIRED',
        'links': [
            {'rel': 'self', 'href': 'https://api.example/o/' + order_id},
            {'rel': 'payer-action', 'href': APPROVAL_URL},
        ],
    }


def _settled(plan_id='premium_monthly'):
    """Returns the settled capture response the service reports.

    The amount and currency are read from the catalog, so the response
    matches what the endpoint validates the settlement against.
    """
    plan = get_plan(plan_id)
    return capture_response(value=str(plan.amount))


def _post_plan(client, user, plan_id='premium_monthly'):
    """Posts one subscription-creation request."""
    return client.post(
        '/subscriptions/',
        json={'plan_id': plan_id},
        headers=bearer(user),
    )


def _open_order(client, user, plan_id='premium_monthly'):
    """Opens a subscription order and returns the response."""
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        new=AsyncMock(return_value=_created_order()),
    ):
        return _post_plan(client, user, plan_id)


def test_subscription_creation_returns_the_approval_redirect(
    client, db, registered_user
):
    """Creation opens the order and hands back the hosted redirect."""
    created = _open_order(client, registered_user)
    assert created.status_code == 200
    body = created.json()
    assert body['user_id'] == registered_user.id
    assert body['status'] == 'pending'
    assert body['approval_url'] == APPROVAL_URL

    db.expire_all()
    stored = db.query(SubscriptionModel).filter(
        SubscriptionModel.paypal_order_id == ORDER_ID
    ).one()
    assert stored.status == 'pending'
    assert stored.end_date is None
    assert str(stored.amount) == str(get_plan('premium_monthly').amount)


def test_creation_grants_no_entitlement_before_settlement(
    client, db, registered_user
):
    assert _open_order(client, registered_user).status_code == 200

    # No active row is reported and no role was granted.
    fetched = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    )
    assert fetched.status_code == 200
    assert fetched.json() is None
    db.expire_all()
    assert db.query(User).filter(
        User.id == registered_user.id
    ).one().role == 'registered'


def test_capture_activates_and_grants_the_plan_role(
    client, db, registered_user
):
    assert _open_order(client, registered_user).status_code == 200

    captured, _ = deliver_approval(
        client, capture=AsyncMock(return_value=_settled())
    )
    assert captured.status_code == 200
    assert captured.json() == {'status': 'processed'}

    db.expire_all()
    stored = db.query(SubscriptionModel).filter(
        SubscriptionModel.paypal_order_id == ORDER_ID
    ).one()
    assert stored.status == 'active'
    assert stored.end_date is not None
    assert db.query(User).filter(
        User.id == registered_user.id
    ).one().role == 'premium'

    fetched = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    )
    assert fetched.status_code == 200
    assert fetched.json()['id'] == stored.id


def test_an_unsettled_capture_changes_nothing(
    client, db, registered_user
):
    assert _open_order(client, registered_user).status_code == 200

    # A settlement that does not match the catalog is measured and
    # refused; the row is left as it was so a later attempt can settle it.
    refused, _ = deliver_approval(
        client,
        capture=AsyncMock(return_value=capture_response(value='0.01')),
    )
    assert refused.status_code == 200
    assert refused.json() == {'status': 'ignored'}

    db.expire_all()
    stored = db.query(SubscriptionModel).filter(
        SubscriptionModel.paypal_order_id == ORDER_ID
    ).one()
    assert stored.status == 'pending'
    assert stored.end_date is None
    assert db.query(User).filter(
        User.id == registered_user.id
    ).one().role == 'registered'


def test_capture_is_repeatable_without_a_second_settlement(
    client, registered_user
):
    """A second approval of a settled order captures nothing again."""
    assert _open_order(client, registered_user).status_code == 200

    first_response, first = deliver_approval(
        client, capture=AsyncMock(return_value=_settled())
    )
    assert first_response.status_code == 200
    assert first.await_count == 1

    # A second distinct delivery for the same order finds it already
    # active and asks the provider for nothing.
    repeated, second = deliver_approval(
        client, capture=AsyncMock(return_value=_settled())
    )
    assert repeated.status_code == 200
    assert repeated.json() == {'status': 'processed'}
    assert second.await_count == 0
    assert client.get(
        '/subscriptions/', headers=bearer(registered_user)
    ).json()['status'] == 'active'


def test_the_order_idempotency_key_is_derived_from_the_stored_row(
    client, db, registered_user
):
    """The key is a function of the committed row, stored nowhere.

    Re-deriving it from the same row is what makes a repeat of an
    uncertain call present the same ``PayPal-Request-Id``, so no column is
    needed to remember it.
    """
    creator = AsyncMock(return_value=_created_order())
    with patch(SUBSCRIPTIONS_MODULE + '.create_order', new=creator):
        assert _post_plan(client, registered_user).status_code == 200

    stored = db.query(SubscriptionModel).one()
    sent = creator.await_args.kwargs['idempotency_key']
    assert sent == paypal_module.order_request_id(stored.id)
    assert sent == paypal_module.order_request_id(stored.id)
    # Nothing on the row remembers it, and nothing needs to.
    assert not hasattr(stored, 'paypal_request_id')


def test_the_capture_identifier_is_carried_in_the_audit_record(
    client, db, registered_user
):
    """A settled charge stays reconcilable through the activation record.

    The provider's capture identifier is not a stored column, so the
    activation record is where a reconciliation reads it from.
    """
    assert _open_order(client, registered_user).status_code == 200

    with watching_audit_trail() as records:
        settled, _ = deliver_approval(
            client, capture=AsyncMock(return_value=_settled())
        )
    assert settled.status_code == 200

    activations = [
        record for record in records
        if getattr(record, 'paypal_capture_id', None) is not None
    ]
    assert activations, messages(records)
    record = activations[0]
    assert record.paypal_capture_id == 'CAPTURE-1'
    assert record.paypal_order_id == ORDER_ID
    assert record.subscription_status == 'active'
    assert db.query(SubscriptionModel).one().status == 'active'
    assert not hasattr(
        db.query(SubscriptionModel).one(), 'paypal_capture_id'
    )


def test_an_order_already_captured_is_read_back_and_activated(
    client, db, registered_user
):
    """A settled order is measured, not charged again.

    PayPal rejects a second capture of an order it has already settled, so
    the approval continuation reads that order back and measures what it
    settled against the catalog rather than refusing the entitlement the
    payer has paid for.
    """
    assert _open_order(client, registered_user).status_code == 200

    plan = get_plan(PREMIUM_MONTHLY)
    already = PayPalAPIError(
        'ORDER_ALREADY_CAPTURED',
        category=CATEGORY_PROVIDER_CLIENT,
        status_code=422,
    )
    read_back = AsyncMock(return_value=CaptureOutcome(
        completed=True,
        order_id=ORDER_ID,
        status='COMPLETED',
        amount=str(plan.amount),
        currency=plan.currency,
        capture_id='CAPTURE-READ-BACK',
    ))
    with patch(
        SUBSCRIPTIONS_MODULE + '.verify_settled_order', new=read_back
    ):
        delivered, _ = deliver_approval(
            client, capture=AsyncMock(side_effect=already)
        )

    assert delivered.status_code == 200
    assert delivered.json() == {'status': 'processed'}
    assert read_back.await_count == 1

    db.expire_all()
    stored = db.query(SubscriptionModel).filter(
        SubscriptionModel.paypal_order_id == ORDER_ID
    ).one()
    assert stored.status == 'active'
    assert stored.end_date is not None
    assert db.query(User).filter(
        User.id == registered_user.id
    ).one().role == 'premium'


def test_a_provider_refusal_at_capture_is_not_read_back(
    client, db, registered_user
):
    """Only an already-settled order is read back, never a refusal."""
    assert _open_order(client, registered_user).status_code == 200

    refused = PayPalAPIError(
        'capture declined',
        category=CATEGORY_PROVIDER_SERVER,
        status_code=503,
    )
    read_back = AsyncMock()
    with patch(
        SUBSCRIPTIONS_MODULE + '.verify_settled_order', new=read_back
    ):
        delivered, _ = deliver_approval(
            client, capture=AsyncMock(side_effect=refused)
        )

    assert delivered.status_code == 502
    read_back.assert_not_awaited()

    db.expire_all()
    assert db.query(SubscriptionModel).filter(
        SubscriptionModel.paypal_order_id == ORDER_ID
    ).one().status == 'pending'
    assert db.query(WebhookEvent).count() == 0


def test_an_approval_naming_a_foreign_order_activates_nothing(
    client, db, registered_user, second_user
):
    """A notification cannot move an order to a different account.

    The account entitled is resolved from the stored order identifier, so
    a second account gains nothing from the delivery and the row it does
    not own stays exactly as it was.
    """
    assert _open_order(client, registered_user).status_code == 200

    delivered, _ = deliver_approval(
        client, capture=AsyncMock(return_value=_settled())
    )
    assert delivered.status_code == 200

    db.expire_all()
    assert db.query(User).filter(
        User.id == second_user.id
    ).one().role == 'registered'
    assert client.get(
        '/subscriptions/', headers=bearer(second_user)
    ).json() is None


def test_an_approval_naming_an_unknown_order_activates_nothing(
    client, db, registered_user
):
    """A notification for an order this service never opened is ignored."""
    assert _open_order(client, registered_user).status_code == 200

    attempted = AsyncMock(return_value=_settled())
    with patch(
        SUBSCRIPTIONS_MODULE + '.verify_webhook_signature',
        return_value=verified_approval(),
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order', new=attempted
    ):
        response = client.post(
            '/subscriptions/webhook',
            json=approved_event(order_id='ORDER-DOES-NOT-EXIST'),
            headers=PAYPAL_HEADERS,
        )
    assert response.status_code == 200
    assert response.json() == {'status': 'ignored'}


def test_a_notification_naming_an_unopened_order_is_ignored(
    client, db, registered_user, second_user
):
    """A notification is bound to the row that opened the order.

    An order this service never opened resolves to no row, so nothing is
    captured and no account is entitled.
    """
    assert _open_order(client, registered_user).status_code == 200

    ignored, attempted = deliver_approval(
        client, order_id='ORDER-DOES-NOT-EXIST'
    )
    assert ignored.status_code == 200
    assert ignored.json() == {'status': 'ignored'}
    assert attempted.await_count == 0

    db.expire_all()
    assert db.query(SubscriptionModel).filter(
        SubscriptionModel.paypal_order_id == ORDER_ID
    ).one().status == 'pending'
    assert db.query(User).filter(
        User.id == second_user.id
    ).one().role == 'registered'


def test_the_payer_return_target_is_not_the_first_cors_origin(
    client, registered_user, monkeypatch
):
    """Each hosted-redirect target is the setting that configures it.

    The origin list is reordered around the call, and both targets stay
    the configured addresses.
    """
    monkeypatch.setattr(
        settings,
        'ALLOWED_ORIGINS',
        ['https://attacker.example.com', 'http://localhost:3000'],
    )
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        new=AsyncMock(return_value=_created_order()),
    ) as opened:
        assert _post_plan(client, registered_user).status_code == 200
    _plan_id, return_url, cancel_url = opened.await_args.args
    assert return_url == settings.PAYPAL_RETURN_URL
    assert cancel_url == settings.PAYPAL_CANCEL_URL
    assert return_url != cancel_url
    assert settings.ALLOWED_ORIGINS[0] not in return_url


def test_both_payer_return_targets_use_the_declared_frontend_path(
    client, registered_user
):
    """A returning payer lands on a route the frontend actually declares.

    The frontend router declares one subscription route, ``/subscription``.
    Both targets address exactly that path and differ only by a query
    string, so neither outcome sends the payer to a path that does not
    exist.
    """
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        new=AsyncMock(return_value=_created_order()),
    ) as opened:
        assert _post_plan(client, registered_user).status_code == 200
    _plan_id, return_url, cancel_url = opened.await_args.args

    declared = '/subscription'
    assert urlsplit(settings.PAYPAL_RETURN_URL).path == declared
    assert urlsplit(settings.PAYPAL_CANCEL_URL).path == declared
    for target in (return_url, cancel_url):
        parts = urlsplit(target)
        assert parts.path == declared
        assert parts.query
    assert urlsplit(return_url).query != urlsplit(cancel_url).query


def test_expired_entitlement_is_withdrawn_on_retrieval(
    client, db, registered_user
):
    """An expired window lowers a plan-granted role back to the baseline."""
    started = datetime.now(timezone.utc) - timedelta(days=60)
    db.add(SubscriptionModel(
        user_id=registered_user.id,
        plan_id='premium_monthly',
        amount=get_plan('premium_monthly').amount,
        currency='USD',
        status='active',
        start_date=started,
        end_date=started + timedelta(days=30),
        paypal_order_id='ORDER-EXPIRED-1',
    ))
    registered_user.role = 'premium'
    db.commit()

    fetched = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    )
    assert fetched.status_code == 200
    assert fetched.json() is None
    db.expire_all()
    assert db.query(User).filter(
        User.id == registered_user.id
    ).one().role == 'registered'


def test_an_administrator_is_never_demoted_on_retrieval(
    client, db, admin_user
):
    fetched = client.get('/subscriptions/', headers=bearer(admin_user))
    assert fetched.status_code == 200
    assert fetched.json() is None
    db.expire_all()
    assert db.query(User).filter(
        User.id == admin_user.id
    ).one().role == 'admin'


def _api_routes():
    """Collects the (method, path) pairs mounted under the API prefixes."""
    pairs = set()
    for route in app.routes:
        path = getattr(route, 'path', '')
        if not path.startswith(API_PREFIXES):
            continue
        for method in getattr(route, 'methods', None) or []:
            if method in ('HEAD', 'OPTIONS'):
                continue
            pairs.add((method, path))
    return pairs


def test_every_router_prefix_is_still_mounted():
    mounted = {path.split('/')[1] for _, path in _api_routes()}
    assert mounted == {
        'auth', 'listings', 'filters', 'subscriptions'
    }


def test_the_api_route_surface_is_exactly_the_expected_nine():
    """The surface is the eight originals plus the webhook, and no more."""
    assert _api_routes() == EXPECTED_API_ROUTES


@pytest.mark.parametrize('prefix', [b'2a', b'2b'])
def test_pre_existing_bcrypt_hashes_still_verify(client, db, prefix):
    """Stored hashes keep working, so no account needs a reset."""
    legacy = bcrypt.hashpw(
        PASSWORD.encode(), bcrypt.gensalt(rounds=4, prefix=prefix)
    ).decode()
    assert legacy.startswith('$' + prefix.decode() + '$')

    email = 'legacy-' + prefix.decode() + '@example.com'
    db.add(User(
        email=email,
        hashed_password=legacy,
        created_at=datetime.now(timezone.utc),
        role='registered',
    ))
    db.commit()

    response = client.post('/auth/login', json={
        'email': email,
        'password': PASSWORD,
    })
    assert response.status_code == 200
    assert 'access_token' in response.json()


def test_a_password_past_the_byte_ceiling_is_refused_cleanly(client):
    """The ceiling yields a validation error, never a server fault."""
    assert len(OVER_LIMIT_PASSWORD.encode()) == 73

    registered = client.post('/auth/register', json={
        'email': 'toolong@example.com',
        'password': OVER_LIMIT_PASSWORD,
    })
    assert registered.status_code == 422

    attempted = client.post('/auth/login', json={
        'email': 'toolong@example.com',
        'password': OVER_LIMIT_PASSWORD,
    })
    assert attempted.status_code == 422


# ---------------------------------------------------------------
# Coverage carried over from the C_app_tmp_w005_test_api_py review scope.
# ---------------------------------------------------------------

PAYPAL_ORDER = {
    'id': ORDER_ID,
    'status': 'CREATED',
    'links': [
        {'rel': 'self', 'href': 'https://api-m.sandbox.paypal.com/o/1'},
        {'rel': 'approve', 'href': APPROVAL_URL},
    ],
}


TRANSMISSION_ID = 'TRANSMISSION-TEST-1'


APPROVAL_NOTIFICATION = {
    'event_type': 'CHECKOUT.ORDER.APPROVED',
    'resource': {'id': ORDER_ID},
}


def open_subscription(client, user):
    """Creates a pending subscription with the order call stood in for."""
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        return_value=PAYPAL_ORDER,
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order',
    ) as capture:
        created = client.post(
            '/subscriptions/',
            json={'plan_id': 'premium_monthly'},
            headers=bearer(user),
        )
    capture.assert_not_called()
    return created


def approve_subscription(client, transmission_id=TRANSMISSION_ID):
    """Delivers a signature-verified approval for the opened order."""
    verification = WebhookVerification(
        verified=True,
        transmission_id=transmission_id,
        event_type='CHECKOUT.ORDER.APPROVED',
    )
    with patch(
        SUBSCRIPTIONS_MODULE + '.verify_webhook_signature',
        return_value=verification,
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order',
        return_value=capture_response(),
    ) as capture:
        delivered = client.post(
            '/subscriptions/webhook', json=APPROVAL_NOTIFICATION
        )
    return delivered, capture


def test_subscription_creation_returns_the_hosted_approval_target(
    client, registered_user
):
    """Creation opens the order and defers capture to the approval."""
    created = open_subscription(client, registered_user)

    assert created.status_code == 200
    body = created.json()
    assert body['user_id'] == registered_user.id
    assert body['status'] == 'pending'
    assert body['end_date'] is None
    assert body['approval_url'] == APPROVAL_URL
    assert 'paypal_order_id' not in body


def test_a_pending_subscription_grants_no_entitlement(
    client, registered_user
):
    open_subscription(client, registered_user)

    fetched = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    )
    assert fetched.status_code == 200
    assert fetched.json() is None


def test_a_verified_approval_captures_and_activates(
    client, registered_user
):
    created = open_subscription(client, registered_user)
    delivered, capture = approve_subscription(client)

    assert delivered.status_code == 200
    assert capture.call_args.args[1] == ORDER_ID

    fetched = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    )
    assert fetched.status_code == 200
    body = fetched.json()
    assert body['id'] == created.json()['id']
    assert body['status'] == 'active'
    assert body['end_date'] is not None


def test_a_replayed_approval_is_acknowledged_and_captures_once(
    client, registered_user
):
    open_subscription(client, registered_user)
    assert approve_subscription(client)[0].status_code == 200

    replayed, capture = approve_subscription(client)
    assert replayed.status_code == 200
    assert replayed.json() == {
        'status': subscriptions_module.OUTCOME_DUPLICATE
    }
    capture.assert_not_called()


def test_an_unsettled_approval_leaves_no_change(
    client, registered_user
):
    """A failed capture rolls back the delivery record with the row."""
    open_subscription(client, registered_user)
    verification = WebhookVerification(
        verified=True,
        transmission_id=TRANSMISSION_ID,
        event_type='CHECKOUT.ORDER.APPROVED',
    )
    with patch(
        SUBSCRIPTIONS_MODULE + '.verify_webhook_signature',
        return_value=verification,
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order',
        side_effect=PayPalError('capture refused'),
    ):
        unsettled = client.post(
            '/subscriptions/webhook', json=APPROVAL_NOTIFICATION
        )

    assert unsettled.status_code == 502
    assert client.get(
        '/subscriptions/', headers=bearer(registered_user)
    ).json() is None

    # The same delivery settles once the capture succeeds
    assert approve_subscription(client)[0].status_code == 200
    assert client.get(
        '/subscriptions/', headers=bearer(registered_user)
    ).json()['status'] == 'active'


def test_an_unverified_notification_changes_nothing(
    client, registered_user
):
    open_subscription(client, registered_user)
    verification = WebhookVerification(
        verified=False, reason='signature_not_verified'
    )
    with patch(
        SUBSCRIPTIONS_MODULE + '.verify_webhook_signature',
        return_value=verification,
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order',
    ) as capture:
        rejected = client.post(
            '/subscriptions/webhook', json=APPROVAL_NOTIFICATION
        )

    assert rejected.status_code == 400
    capture.assert_not_called()
    fetched = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    )
    assert fetched.json() is None


# ---------------------------------------------------------------
# Coverage carried over from the C_app_tmp_w007_test_api_py review scope.
# ---------------------------------------------------------------

OPENED_ORDER = {
    'id': ORDER_ID,
    'status': 'CREATED',
    'links': [
        {'rel': 'self', 'href': 'https://api-m.sandbox.paypal.com/x'},
        {'rel': 'approve', 'href': APPROVAL_URL},
    ],
}


# The provider response a settled capture returns, which the endpoint
# measures against the catalog's own amount and currency.
SETTLED_CAPTURE = capture_response()


def open_order(client, user):
    """Open a subscription order with the PayPal call stood in for."""
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        return_value=OPENED_ORDER,
    ):
        return client.post(
            '/subscriptions/',
            json={'plan_id': 'premium_monthly'},
            headers=bearer(user),
        )


def settle_order(client, order_id=ORDER_ID):
    """Settle an approved order through the signature-verified webhook."""
    return deliver_approval(
        client,
        order_id=order_id,
        capture=AsyncMock(return_value=SETTLED_CAPTURE),
    )


def test_subscription_creation_captures_nothing(
    client, db, registered_user
):
    """The order is durable and unsettled until the payer approves."""
    with patch(SUBSCRIPTIONS_MODULE + '.capture_order') as capture:
        created = open_order(client, registered_user)
    assert created.status_code == 200
    capture.assert_not_called()

    stored = db.query(SubscriptionModel).one()
    assert stored.status == 'pending'
    assert stored.end_date is None
    assert stored.paypal_order_id == ORDER_ID

    db.expire_all()
    assert db.query(User).filter(
        User.id == registered_user.id
    ).one().role == 'registered'


def test_subscription_capture_activates_and_grants_the_plan_role(
    client, db, registered_user
):
    created = open_order(client, registered_user)
    assert created.status_code == 200

    settled, capture = settle_order(client)
    assert settled.status_code == 200
    capture.assert_awaited_once()
    assert settled.json() == {'status': 'processed'}

    fetched = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    )
    assert fetched.json()['status'] == 'active'
    assert fetched.json()['id'] == created.json()['id']

    db.expire_all()
    assert db.query(User).filter(
        User.id == registered_user.id
    ).one().role == 'premium'


def test_subscription_retrieval_returns_the_settled_row(
    client, db, registered_user
):
    created = open_order(client, registered_user)
    settle_order(client)

    fetched = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    )
    assert fetched.status_code == 200
    assert fetched.json()['id'] == created.json()['id']
    assert fetched.json()['status'] == 'active'


def test_a_pending_subscription_is_not_reported_as_active(
    client, db, registered_user
):
    assert open_order(client, registered_user).status_code == 200
    fetched = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    )
    assert fetched.status_code == 200
    assert fetched.json() is None


def test_repeating_the_capture_settles_nothing_twice(
    client, db, registered_user
):
    open_order(client, registered_user)
    settle_order(client)

    repeated, capture = settle_order(client)
    assert repeated.status_code == 200
    assert repeated.json() == {'status': 'processed'}
    capture.assert_not_awaited()
    assert client.get(
        '/subscriptions/', headers=bearer(registered_user)
    ).json()['status'] == 'active'


def test_a_settlement_entitles_only_the_account_that_opened_it(
    client, db, registered_user
):
    """The webhook entitles the row's own owner and nobody else."""
    open_order(client, registered_user)
    intruder = User(
        email='intruder@example.com',
        hashed_password=get_password_hash(PASSWORD),
        created_at=datetime.now(timezone.utc),
        role='registered',
    )
    db.add(intruder)
    db.commit()
    db.refresh(intruder)

    bound = {}

    async def recording_capture(session, order_id, current_user, **kwargs):
        bound['owner_id'] = current_user.id
        return SETTLED_CAPTURE

    settled, capture = deliver_approval(
        client, capture=AsyncMock(side_effect=recording_capture)
    )
    assert settled.status_code == 200
    capture.assert_awaited_once()
    # The capture was bound to the row's owner, not to the caller.
    assert bound['owner_id'] == registered_user.id

    db.expire_all()
    assert db.query(User).filter(
        User.id == intruder.id
    ).one().role == 'registered'
    assert client.get(
        '/subscriptions/', headers=bearer(intruder)
    ).json() is None
