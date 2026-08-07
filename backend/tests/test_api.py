from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.security import (
    create_access_token,
    get_password_hash,
)
from backend.app.db import database as database_module
from backend.app.db.models import Base, User
from backend.app.main import app

PASSWORD = 'testpassword123'

SUBSCRIPTIONS_MODULE = 'backend.app.api.endpoints.subscriptions'

ORDER_ID = 'ORDER-TEST-1'


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


def test_subscription_creation_and_retrieval(
    client, registered_user
):
    """The PayPal order and capture calls are stood in for here."""
    with patch(
        SUBSCRIPTIONS_MODULE + '.create_order',
        return_value={'id': ORDER_ID},
    ), patch(
        SUBSCRIPTIONS_MODULE + '.capture_order',
        return_value={'status': 'COMPLETED'},
    ):
        created = client.post(
            '/subscriptions/',
            json={'plan_id': 'premium_monthly'},
            headers=bearer(registered_user),
        )
    assert created.status_code == 200
    assert created.json()['user_id'] == registered_user.id

    fetched = client.get(
        '/subscriptions/', headers=bearer(registered_user)
    )
    assert fetched.status_code == 200
    assert fetched.json()['id'] == created.json()['id']


def test_subscription_retrieval_requires_authentication(client):
    assert client.get('/subscriptions/').status_code == 401


def test_health_endpoint_reports_ready(client):
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok'}


def test_route_paths_and_prefixes_are_unchanged():
    pairs = set()
    for route in app.routes:
        for method in getattr(route, 'methods', None) or []:
            pairs.add((method, route.path))
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
