"""Request-validation regression tests for every write endpoint.

Each test proves one endpoint refuses a body it does not declare, so a
client cannot set a server-owned column by adding a key to the request.
"""
import pytest
from pydantic import ValidationError

from backend.app.db.models import Listing as ListingModel
from backend.app.schema.filter import FilterCreate
from backend.app.schema.listing import ListingCreate
from backend.app.schema.subscription import SubscriptionCreate
from backend.app.schema.user import UserCreate, UserLogin

# SEC-04: clears every rule in backend/app/schema/user.py
POLICY_PASSWORD = "Validation1!Secret"

# SEC-05: every key below is declared by ListingCreate
DECLARED_LISTING_BODY = {
    "rent": 2400.0,
    "bedrooms": 2,
    "bathrooms": 1,
    "street_address": "1 Test Way",
}

# SEC-05: every key below is declared by Criteria
DECLARED_CRITERION = {
    "field": "rent",
    "operator": "lt",
    "value": "3000",
}

# SEC-05: every key below is declared by FilterCreate
DECLARED_FILTER_BODY = {
    "name": "Two bedrooms",
    "criteria": [DECLARED_CRITERION],
}

# SEC-05: every key below is declared by SubscriptionCreate
EMPTY_PLAN_SUBSCRIPTION_BODY = {
    "plan_id": "",
    "payment_method": "paypal",
    "amount": 9.99,
    "start_date": "2030-01-01T00:00:00",
}


def _bearer(access_token):
    """Return the request header that carries one access token."""
    return {"Authorization": "Bearer " + access_token}


def _without(body, key):
    """Return a copy of one body with a single key removed."""
    return {name: value for name, value in body.items() if name != key}


def _rejected_fields(response):
    """Return the field names one error response reports."""
    return response.json().get("fields", [])


def _assert_rejected(response, status_code, field=None):
    """Assert the status, no server fault, and the named field."""
    # SEC-05: no server fault; the payload stops at the request boundary
    assert response.status_code != 500, response.text
    assert response.status_code == status_code, response.text
    if field is not None:
        assert field in _rejected_fields(response), response.text


# ---------------------------------------------------------------------
# An unknown key is rejected
# ---------------------------------------------------------------------
def test_register_refuses_undeclared_key(client, unique_email):
    """The register route refuses a body carrying an undeclared key."""
    response = client.post(
        "/auth/register",
        json={
            "email": unique_email,
            "password": POLICY_PASSWORD,
            "is_admin": True,
        },
    )
    # SEC-05: unknown key rejected; closes the CWE-915 vector
    _assert_rejected(response, 422, "is_admin")


def test_register_refuses_client_supplied_identifier(
    client, unique_email
):
    """The register route refuses a client-supplied record identifier."""
    response = client.post(
        "/auth/register",
        json={
            "email": unique_email,
            "password": POLICY_PASSWORD,
            "id": 4321,
        },
    )
    # SEC-05: unknown key rejected; closes the CWE-915 vector
    _assert_rejected(response, 422, "id")


def test_login_refuses_undeclared_key(client, registered_user):
    """The login route refuses a body carrying an undeclared key."""
    response = client.post(
        "/auth/login",
        json={
            "email": registered_user["email"],
            "password": registered_user["password"],
            "is_admin": True,
        },
    )
    # SEC-05: unknown key rejected; closes the CWE-915 vector
    _assert_rejected(response, 422, "is_admin")


def test_listing_refuses_client_supplied_owner(
    client, register_user, db_session
):
    """The listing route refuses a client-supplied owner and writes
    no row."""
    account = register_user()
    # SEC-05: authenticated first; sub-dependencies resolve before body
    # validation
    response = client.post(
        "/listings/",
        json=dict(DECLARED_LISTING_BODY, owner_id=account["id"]),
        headers=_bearer(account["access_token"]),
    )
    # SEC-05: unknown key rejected; closes the CWE-915 vector at
    # listings.py:31
    _assert_rejected(response, 422, "owner_id")
    assert db_session.query(ListingModel).count() == 0


def test_listing_refuses_client_supplied_identifier(
    client, register_user
):
    """The listing route refuses a client-supplied record identifier."""
    account = register_user()
    # SEC-05: authenticated first; sub-dependencies resolve before body
    # validation
    response = client.post(
        "/listings/",
        json=dict(DECLARED_LISTING_BODY, id=99),
        headers=_bearer(account["access_token"]),
    )
    # SEC-05: unknown key rejected; closes the CWE-915 vector
    _assert_rejected(response, 422, "id")


def test_filter_refuses_undeclared_key(client, register_user):
    """The filter route refuses a body carrying an undeclared key."""
    account = register_user()
    # SEC-05: authenticated first; sub-dependencies resolve before body
    # validation
    response = client.post(
        "/filters/",
        json=dict(DECLARED_FILTER_BODY, user_id=account["id"]),
        headers=_bearer(account["access_token"]),
    )
    # SEC-05: unknown key rejected; closes the CWE-915 vector
    _assert_rejected(response, 422, "user_id")


def test_filter_refuses_undeclared_nested_key(client, register_user):
    """The filter route refuses an undeclared key nested inside one
    criterion."""
    account = register_user()
    # SEC-05: authenticated first; sub-dependencies resolve before body
    # validation
    response = client.post(
        "/filters/",
        json={
            "name": "Two bedrooms",
            "criteria": [dict(DECLARED_CRITERION, id=7)],
        },
        headers=_bearer(account["access_token"]),
    )
    # SEC-05: unknown key rejected in a nested model
    _assert_rejected(response, 422, "criteria.0.id")


def test_subscription_refuses_undeclared_key(client, register_user):
    """The subscription route refuses a body carrying an undeclared
    key."""
    account = register_user()
    # SEC-05: authenticated first; sub-dependencies resolve before body
    # validation
    response = client.post(
        "/subscriptions/",
        json=dict(EMPTY_PLAN_SUBSCRIPTION_BODY, user_id=account["id"]),
        headers=_bearer(account["access_token"]),
    )
    # SEC-05: unknown key rejected; closes the CWE-915 vector
    _assert_rejected(response, 422, "user_id")


# ---------------------------------------------------------------------
# The guard answers before the body is read
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "path, body",
    (
        ("/listings/", dict(DECLARED_LISTING_BODY, owner_id=1)),
        ("/filters/", dict(DECLARED_FILTER_BODY, user_id=1)),
        (
            "/subscriptions/",
            dict(EMPTY_PLAN_SUBSCRIPTION_BODY, user_id=1),
        ),
    ),
    ids=(
        "listings",
        "filters",
        "subscriptions",
    ),
)
def test_undeclared_key_without_credentials_is_refused(
    client, path, body
):
    """The guard refuses a request carrying no credentials before
    anything reads the body."""
    # SEC-06: the session cookie rides on any client that holds one
    client.cookies.clear()
    assert not client.cookies
    response = client.post(path, json=body)
    # SEC-05: no credentials; the guard answers before body validation
    _assert_rejected(response, 401)
    assert response.status_code != 422


# ---------------------------------------------------------------------
# A required key is missing
# ---------------------------------------------------------------------
def test_register_refuses_missing_password(client, unique_email):
    """The register route refuses a body with no password."""
    response = client.post(
        "/auth/register",
        json={"email": unique_email},
    )
    _assert_rejected(response, 422, "password")


def test_listing_refuses_missing_rent(client, register_user):
    """The listing route refuses a body with no rent."""
    account = register_user()
    response = client.post(
        "/listings/",
        json=_without(DECLARED_LISTING_BODY, "rent"),
        headers=_bearer(account["access_token"]),
    )
    _assert_rejected(response, 422, "rent")


def test_subscription_refuses_missing_plan(client, register_user):
    """The subscription route refuses a body with no plan identifier."""
    account = register_user()
    response = client.post(
        "/subscriptions/",
        json=_without(EMPTY_PLAN_SUBSCRIPTION_BODY, "plan_id"),
        headers=_bearer(account["access_token"]),
    )
    _assert_rejected(response, 422, "plan_id")


# ---------------------------------------------------------------------
# A value arrives malformed or wrongly typed
# ---------------------------------------------------------------------
def test_register_refuses_malformed_email(client):
    """The register route refuses an address that is not an email."""
    response = client.post(
        "/auth/register",
        json={"email": "not-an-email", "password": POLICY_PASSWORD},
    )
    _assert_rejected(response, 422, "email")


def test_register_refuses_wrongly_typed_password(client, unique_email):
    """The register route refuses a password sent as a number."""
    response = client.post(
        "/auth/register",
        json={"email": unique_email, "password": 987654321012},
    )
    _assert_rejected(response, 422, "password")


@pytest.mark.parametrize(
    "field, value",
    (
        ("rent", "two thousand"),
        ("rent", True),
        ("bedrooms", [2]),
        ("street_address", 12),
    ),
    ids=(
        "rent-string",
        "rent-boolean",
        "bedrooms-array",
        "address-number",
    ),
)
def test_listing_refuses_wrongly_typed_field(
    client, register_user, field, value
):
    """The listing route refuses a declared field sent as the wrong
    type."""
    account = register_user()
    response = client.post(
        "/listings/",
        json=dict(DECLARED_LISTING_BODY, **{field: value}),
        headers=_bearer(account["access_token"]),
    )
    _assert_rejected(response, 422, field)


def test_filter_refuses_wrongly_typed_name(client, register_user):
    """The filter route refuses a name sent as a number."""
    account = register_user()
    response = client.post(
        "/filters/",
        json=dict(DECLARED_FILTER_BODY, name=5),
        headers=_bearer(account["access_token"]),
    )
    _assert_rejected(response, 422, "name")


@pytest.mark.parametrize(
    "field, value",
    (
        ("amount", "free"),
        ("start_date", 20300101),
        ("payment_method", 5),
    ),
    ids=(
        "amount-string",
        "start-date-number",
        "payment-method-number",
    ),
)
def test_subscription_refuses_wrongly_typed_field(
    client, register_user, field, value
):
    """The subscription route refuses a declared field sent as the
    wrong type."""
    account = register_user()
    response = client.post(
        "/subscriptions/",
        json=dict(EMPTY_PLAN_SUBSCRIPTION_BODY, **{field: value}),
        headers=_bearer(account["access_token"]),
    )
    _assert_rejected(response, 422, field)


# ---------------------------------------------------------------------
# A declared key arrives empty
# ---------------------------------------------------------------------
def test_filter_empty_name_and_criteria_answer_bad_request(
    client, register_user
):
    """The filter route answers 400 when the name and the criteria
    arrive empty."""
    account = register_user()
    response = client.post(
        "/filters/",
        json={"name": "", "criteria": []},
        headers=_bearer(account["access_token"]),
    )
    # SEC-05: an empty declared value reaches filters.py:14-15
    _assert_rejected(response, 400)
    assert response.status_code != 422


def test_subscription_empty_plan_answers_bad_request(
    client, register_user
):
    """The subscription route answers 400 when the plan identifier
    arrives empty."""
    account = register_user()
    response = client.post(
        "/subscriptions/",
        json=EMPTY_PLAN_SUBSCRIPTION_BODY,
        headers=_bearer(account["access_token"]),
    )
    # SEC-05: an empty declared value reaches subscriptions.py:20-21
    _assert_rejected(response, 400)
    assert response.status_code != 422


# ---------------------------------------------------------------------
# A body of declared keys only
# ---------------------------------------------------------------------
def test_declared_listing_body_writes_no_row(
    client, register_user, db_session
):
    """A body of declared fields alone still writes no listing row."""
    account = register_user()
    response = client.post(
        "/listings/",
        json=DECLARED_LISTING_BODY,
        headers=_bearer(account["access_token"]),
    )
    assert not (200 <= response.status_code < 300), response.text
    assert db_session.query(ListingModel).count() == 0


# ---------------------------------------------------------------------
# The request schemas reject an unknown key on their own
# ---------------------------------------------------------------------
UNKNOWN_KEY_MODEL_CASES = (
    (
        UserCreate,
        {
            "email": "schema-probe@example.com",
            "password": POLICY_PASSWORD,
            "is_admin": True,
        },
        "is_admin",
    ),
    (
        UserLogin,
        {
            "email": "schema-probe@example.com",
            "password": POLICY_PASSWORD,
            "is_admin": True,
        },
        "is_admin",
    ),
    (
        ListingCreate,
        dict(DECLARED_LISTING_BODY, owner_id=1),
        "owner_id",
    ),
    (
        FilterCreate,
        dict(DECLARED_FILTER_BODY, user_id=1),
        "user_id",
    ),
    (
        SubscriptionCreate,
        dict(EMPTY_PLAN_SUBSCRIPTION_BODY, user_id=1),
        "user_id",
    ),
)


@pytest.mark.parametrize(
    "model, payload, unknown_key",
    UNKNOWN_KEY_MODEL_CASES,
    ids=[case[0].__name__ for case in UNKNOWN_KEY_MODEL_CASES],
)
def test_create_model_refuses_unknown_key(model, payload, unknown_key):
    """Each create model refuses an unknown key with no route
    involved."""
    with pytest.raises(ValidationError) as raised:
        model(**payload)
    errors = raised.value.errors()
    # SEC-05: unknown key rejected; closes the CWE-915 vector
    assert (unknown_key,) in [error["loc"] for error in errors]
    assert "value_error.extra" in [error["type"] for error in errors]
