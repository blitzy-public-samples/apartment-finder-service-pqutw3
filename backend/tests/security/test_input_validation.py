"""Request-validation regression tests for the write endpoints.

The endpoints and the request models are driven against unknown, missing,
malformed, wrongly typed and empty declared fields. A body carrying an
undeclared key is refused, so a client cannot set a server-owned column
by adding a key to the request.

The same file pins the contracts a validation change could quietly move:
the set of paths and verbs the application declares, the pagination the
public read path applies, the response model the filter route declares,
and the answer a duplicate address receives.

A nested body carries the same duty. A criterion inside a filter
declares strict scalars, so a number, a boolean or any other JSON type
is refused where a string is declared, and a NUL byte the driver cannot
store is refused with it.

The subscription amount also carries a domain. A value outside it - NaN,
either infinity, a magnitude no float holds, or a figure at or beneath
the floor - stops at the request boundary, ahead of the payment call.

A rejection is also written down, and an undeclared key's name is text
the caller chose. The last cases here read the record as well as the
reply: the caller is told which key was refused, and the record names
the position instead, bounded in count and in length.
"""
import logging
import re
from contextlib import contextmanager
from datetime import datetime
from typing import List

import pytest
from conftest import test_engine
from fastapi.routing import APIRoute
from pydantic import ValidationError
from sqlalchemy import event, text
from sqlalchemy.dialects import postgresql, sqlite

from backend.app.db.models import Criteria as CriteriaModel
from backend.app.db.models import Filter as FilterModel
from backend.app.api.endpoints import subscriptions as subscription_endpoint
from backend.app.db.models import Listing as ListingModel
from backend.app.main import (
    _MAX_LOGGED_FIELDS,
    _MAX_LOGGED_NAME_LENGTH,
    _UNDECLARED_FIELD,
    _error_envelope,
    _loggable_field_names,
    app,
)
from backend.app.schema.filter import (
    MAX_CRITERIA,
    MAX_CRITERION_VALUE,
    MAX_FILTER_NAME,
    Criteria,
    Filter,
    FilterCreate,
)
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

# SEC-05: nested criterion values the request boundary refuses
REFUSED_CRITERION_VALUES = (
    pytest.param("value", 1500, id="value-number"),
    pytest.param("value", True, id="value-boolean"),
    pytest.param("value", 12.5, id="value-float"),
    pytest.param("value", ["3000"], id="value-array"),
    pytest.param("value", {"amount": "3000"}, id="value-object"),
    pytest.param("field", 7, id="field-number"),
    pytest.param("operator", False, id="operator-boolean"),
)

# SEC-05: every key below is declared by SubscriptionCreate
EMPTY_PLAN_SUBSCRIPTION_BODY = {
    "plan_id": "",
    "payment_method": "paypal",
    "amount": 9.99,
    "start_date": "2030-01-01T00:00:00",
}

# SEC-08: the frozen sanitized-envelope contract, written out rather than
# read back from the function that builds it. Deriving the expectation
# from the code under test makes it agree with any shape that code
# returns, including a renamed or dropped key.
# test_the_frozen_envelope_contract_matches_the_application below is what
# fails if the application's envelope moves.
ENVELOPE_KEYS = frozenset({"detail", "error_id", "fields"})

# SEC-08: the correlation key the caller quotes to support, likewise fixed
_CORRELATION_KEY = "error_id"

# SEC-08: the detail an unhandled fault returns and the shape of the
# correlation identifier beside it. Both are written out here for the
# same reason as the key set above.
SANITIZED_FAULT_DETAIL = "Internal server error"
CORRELATION_ID = re.compile(r"[0-9a-f]{32}")

# AAP 0.8.3: the status the listing write path answers with. The route
# clears the request boundary and then fails on a model defect the AAP
# places out of scope: ListingModel declares no owner_id column while
# listings.py:23 passes one, and the model's non-null created_at and
# updated_at columns are never supplied. Adding columns needs migration
# tooling the repository does not carry (AAP 0.9.2), so what this module
# pins is the answer the defect produces rather than a working write.
KNOWN_LISTING_DEFECT_STATUS = 500

# SEC-08: text the sanitized reply must not carry. The defect above
# raises TypeError from a named module against a named column, and none
# of that may reach the caller.
WITHHELD_FAULT_TEXT = (
    "traceback",
    "typeerror",
    "exceptiongroup",
    "owner_id",
    "listingmodel",
    "backend/app",
    "backend.app",
    "insert into",
)

# AAP 0.8.3: the frozen public read path - unauthenticated, trailing
# slash, no /api prefix
PUBLIC_READ_PATH = "/listings/"
FILTER_PATH = "/filters/"
REGISTER_PATH = "/auth/register"

# AAP 0.8.3: every path and verb the application declares. A verb absent
# from this table is also absent from the method list CORSMiddleware
# advertises.
DECLARED_ROUTES = frozenset({
    ("/auth/register", "POST"),
    ("/auth/login", "POST"),
    ("/auth/logout", "POST"),
    ("/listings/", "GET"),
    ("/listings/", "POST"),
    ("/filters/", "GET"),
    ("/filters/", "POST"),
    ("/subscriptions/", "GET"),
    ("/subscriptions/", "POST"),
})

# AAP 0.8.3: verbs no route declares and CORS does not advertise
UNDECLARED_METHODS = frozenset({"PUT", "PATCH", "DELETE"})

# AAP 0.8.3: the key set the filter route's declared response model
# publishes. Written out rather than read from Filter.__fields__: derived
# from the model, the assertion would accept whatever the model declares,
# including a field added to it or the password hash the outbound user
# model used to carry. A field added here is a deliberate contract change.
DECLARED_FILTER_RESPONSE_KEYS = frozenset({
    "id",
    "user_id",
    "name",
    "created_at",
    "last_used",
    "zip_codes",
    "criteria",
})

# AAP 0.8.3: enough rows for three pages of two
SEEDED_LISTING_COUNT = 5
PAGE_SIZE = 2

# AAP 0.8.3: the frozen bounds are plain integers with no declared
# range, so a value the integer conversion refuses is the only bound the
# request boundary stops
REFUSED_PAGINATION = (
    pytest.param({"skip": "abc"}, "skip", id="non-numeric-skip"),
    pytest.param({"limit": "abc"}, "limit", id="non-numeric-limit"),
)

# AAP 0.8.3: bounds inside the frozen domain, each answered as a page
ADMITTED_PAGINATION = (
    pytest.param({"skip": -1}, id="negative-skip"),
    pytest.param({"limit": -1}, id="negative-limit"),
    pytest.param({"limit": 0}, id="zero-limit"),
    pytest.param({"skip": 2 ** 63 - 1}, id="widest-bindable-skip"),
)

# the widest bound the driver binds is a signed 64-bit integer, so one
# past it reaches the statement and the database handler answers it
UNBINDABLE_BOUND = 2 ** 63

# SEC-05: a payload that executes in a document and is inert in JSON
SCRIPT_PAYLOAD = "<script>alert('filter-name')</script>"

# SEC-05: an undeclared key whose name is the payload. A rejection that
# copies the name into the record writes caller-chosen text to the log
# (CWE-117), and the name here is shaped like an address and a bearer
# value so a record quoting it is unmistakable.
UNDECLARED_KEY_NAME = "zzz-undeclared-7301-victim@example.com"
UNDECLARED_NESTED_NAME = "zzz-undeclared-7302-Bearer-token"

# SEC-05: more nested rejections than one record may name
FLOODING_CRITERION_COUNT = _MAX_LOGGED_FIELDS + 1


class _RecordedPaymentCall:
    """Stand in for the payment call and record every await of it."""

    def __init__(self):
        self.awaits = []

    async def __call__(self, *args, **kwargs):
        self.awaits.append((args, kwargs))
        return False


@pytest.fixture(autouse=True)
def payment_call(monkeypatch):
    """Replace the payment call the subscription route awaits."""
    # SEC-05/SEC-09: subscriptions.py binds process_payment into the
    # endpoint module namespace at import, so the name the route awaits is
    # the one replaced here. The real callable reaches PayPal from a worker
    # thread, so a body that slipped past the request boundary would make
    # this suite perform provider I/O and depend on a network answer.
    recorder = _RecordedPaymentCall()
    monkeypatch.setattr(
        subscription_endpoint, "process_payment", recorder
    )
    yield recorder
    # SEC-05: no case in this module may reach the payment call. Every
    # subscription body here is refused by the request schema or by the
    # route's own guard, and both answer before the call.
    assert recorder.awaits == [], (
        "the payment call was awaited {0} time(s): {1!r}".format(
            len(recorder.awaits), recorder.awaits
        )
    )


def _bearer(access_token):
    """Return the request header that carries one access token."""
    return {"Authorization": "Bearer " + access_token}


def _without(body, key):
    """Return a copy of one body with a single key removed."""
    return {name: value for name, value in body.items() if name != key}


def _post_raw(client, path, raw_body, access_token):
    """Post one raw JSON document with no client-side encoding."""
    headers = _bearer(access_token)
    headers["content-type"] = "application/json"
    return client.post(path, content=raw_body, headers=headers)


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


def _user_row_count(session, email):
    """Return how many account rows carry one address."""
    # the bound parameter keeps the address out of the statement text
    return session.execute(
        text("SELECT COUNT(*) FROM users WHERE email = :email"),
        {"email": email},
    ).scalar()


@contextmanager
def _recorded_inserts(table):
    """Collect the insert statements one block sends to ``table``."""
    prefix = "INSERT INTO {0}".format(table.upper())
    recorded = []

    def record(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith(prefix):
            recorded.append(statement)

    event.listen(test_engine, "before_cursor_execute", record)
    try:
        yield recorded
    finally:
        event.remove(test_engine, "before_cursor_execute", record)


def _application_route_table():
    """Return every (path, verb) pair the application declares."""
    # the framework's own documentation routes are not APIRoute
    # instances; they never enter the comparison
    return {
        (route.path, method)
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in route.methods
    }


def _route_for(path, method):
    """Return the single declared route serving one path and verb."""
    matches = [
        route
        for route in app.routes
        if isinstance(route, APIRoute)
        and route.path == path
        and method in route.methods
    ]
    assert len(matches) == 1, matches
    return matches[0]


def _seed_listings(session, count):
    """Write listing rows directly and return their identifiers.

    The create route cannot write a row - the model declares no owner
    column and two non-null timestamps the body never carries - so the
    read path is seeded through the session instead.
    """
    stamped = datetime.utcnow()
    rows = [
        ListingModel(
            rent=1000.0 + index,
            bedrooms=1,
            bathrooms=1,
            street_address="{0} Page Street".format(index),
            created_at=stamped,
            updated_at=stamped,
        )
        for index in range(count)
    ]
    session.add_all(rows)
    session.commit()
    # Listing.id is declared int, matching the INTEGER primary key
    return [row.id for row in rows]


def seed_filter(session, user_id, name=DECLARED_FILTER_BODY["name"]):
    """Write one filter row with its criteria child and return its id.

    ``POST /filters/`` cannot write a row for the reason AAP 0.8.3
    records: the endpoint hands a mapped relationship a request model and
    supplies no value for the non-null ``created_at`` column. The read
    path is seeded through the session instead, matching how the listing
    read path is seeded above.
    """
    row = FilterModel(
        name=name,
        user_id=user_id,
        created_at=datetime.utcnow(),
        criteria=[
            CriteriaModel(**DECLARED_CRITERION),
        ],
    )
    session.add(row)
    session.commit()
    return row.id


def _read_listings(client, **bounds):
    """Read the public listing page, sending no credentials."""
    return client.get(PUBLIC_READ_PATH, params=bounds or None)


def _listing_ids(response):
    return [entry["id"] for entry in response.json()]


# ---------------------------------------------------------------------
# The frozen envelope contract
# ---------------------------------------------------------------------
def test_the_frozen_envelope_contract_matches_the_application():
    """The hardcoded envelope contract is the one the application builds.

    ENVELOPE_KEYS and _CORRELATION_KEY are written out at the top of this
    module rather than read back from the function that builds the
    envelope, so a change to that function fails here instead of quietly
    redefining what every rejection case below asserts.
    """
    built = _error_envelope("a detail", "a correlation id")

    assert set(built) == ENVELOPE_KEYS
    assert built["detail"] == "a detail"
    assert built[_CORRELATION_KEY] == "a correlation id"
    assert built["fields"] == []

    # SEC-08: a rejected field name reaches the caller, nothing more
    assert _error_envelope("d", "i", ["email"])["fields"] == ["email"]


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
    _assert_rejected(response, 422, "is_admin")


def test_listing_refuses_client_supplied_owner(
    client, register_user, db_session
):
    """The listing route refuses a client-supplied owner and writes
    no row."""
    account = register_user()
    # SEC-05: authenticated caller
    response = client.post(
        "/listings/",
        json=dict(DECLARED_LISTING_BODY, owner_id=account["id"]),
        headers=_bearer(account["access_token"]),
    )
    _assert_rejected(response, 422, "owner_id")
    assert db_session.query(ListingModel).count() == 0


def test_listing_refuses_client_supplied_identifier(
    client, register_user
):
    """The listing route refuses a client-supplied record identifier."""
    account = register_user()
    response = client.post(
        "/listings/",
        json=dict(DECLARED_LISTING_BODY, id=99),
        headers=_bearer(account["access_token"]),
    )
    _assert_rejected(response, 422, "id")


def test_filter_refuses_undeclared_key(client, register_user):
    """The filter route refuses a body carrying an undeclared key."""
    account = register_user()
    response = client.post(
        "/filters/",
        json=dict(DECLARED_FILTER_BODY, user_id=account["id"]),
        headers=_bearer(account["access_token"]),
    )
    _assert_rejected(response, 422, "user_id")


def test_filter_refuses_undeclared_nested_key(client, register_user):
    """The filter route refuses an undeclared key nested inside one
    criterion."""
    account = register_user()
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


def test_subscription_refuses_undeclared_key(
    client, register_user, payment_call
):
    """The subscription route refuses a body carrying an undeclared
    key."""
    account = register_user()
    response = client.post(
        "/subscriptions/",
        json=dict(EMPTY_PLAN_SUBSCRIPTION_BODY, user_id=account["id"]),
        headers=_bearer(account["access_token"]),
    )
    _assert_rejected(response, 422, "user_id")
    # SEC-05: the refusal lands ahead of the payment call
    assert payment_call.awaits == []


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
    # SEC-06: no session cookie on this client
    client.cookies.clear()
    assert not client.cookies
    response = client.post(path, json=body)
    # SEC-05: unauthenticated branch
    _assert_rejected(response, 401)
    assert response.status_code != 422


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


def test_subscription_refuses_missing_plan(
    client, register_user, payment_call
):
    """The subscription route refuses a body with no plan identifier."""
    account = register_user()
    response = client.post(
        "/subscriptions/",
        json=_without(EMPTY_PLAN_SUBSCRIPTION_BODY, "plan_id"),
        headers=_bearer(account["access_token"]),
    )
    _assert_rejected(response, 422, "plan_id")
    # SEC-05: the refusal lands ahead of the payment call
    assert payment_call.awaits == []


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
        ("rent", {"amount": 2400}),
        ("bedrooms", [2]),
        ("street_address", {"line1": "1 Test Way"}),
    ),
    ids=(
        "rent-unparsable-string",
        "rent-object",
        "bedrooms-array",
        "address-object",
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
    """The filter route refuses a name sent as an array."""
    account = register_user()
    response = client.post(
        "/filters/",
        json=dict(DECLARED_FILTER_BODY, name=["Two bedrooms"]),
        headers=_bearer(account["access_token"]),
    )
    _assert_rejected(response, 422, "name")


# SEC-05: the nested scalars a criterion declares
CRITERION_FIELDS = ("field", "operator", "value")

# SEC-05: every JSON type a nested scalar is not. A permissive string
# type coerces the first three of these into text and stores whatever
# the caller sent under a name the operator never wrote.
WRONG_NESTED_TYPES = (
    pytest.param(3000, id="number"),
    pytest.param(True, id="boolean"),
    pytest.param(2.5, id="float"),
    pytest.param(["3000"], id="array"),
    pytest.param({"value": "3000"}, id="object"),
    pytest.param(None, id="null"),
)


def _criterion_with(name, value):
    """Return one filter body whose criterion carries a single value."""
    return {
        "name": DECLARED_FILTER_BODY["name"],
        "criteria": [dict(DECLARED_CRITERION, **{name: value})],
    }


@pytest.mark.parametrize("name", CRITERION_FIELDS)
@pytest.mark.parametrize("value", WRONG_NESTED_TYPES)
def test_filter_refuses_a_wrongly_typed_criterion(
    client, register_user, db_session, name, value
):
    """The filter route refuses a nested scalar sent as another type."""
    account = register_user()
    response = client.post(
        "/filters/",
        json=_criterion_with(name, value),
        headers=_bearer(account["access_token"]),
    )
    # SEC-05: the nested type holds at the request boundary and the
    # error names the position inside the list, not just the list
    _assert_rejected(response, 422, "criteria.0.{0}".format(name))
    assert db_session.query(FilterModel).count() == 0


@pytest.mark.parametrize("name", CRITERION_FIELDS)
@pytest.mark.parametrize("value", WRONG_NESTED_TYPES)
def test_criterion_model_refuses_a_wrongly_typed_scalar(name, value):
    """The criterion model refuses the same value with no route
    involved."""
    with pytest.raises(ValidationError) as raised:
        Criteria(**dict(DECLARED_CRITERION, **{name: value}))
    assert (name,) in [error["loc"] for error in raised.value.errors()]


@pytest.mark.parametrize("name", CRITERION_FIELDS)
def test_filter_refuses_a_nul_byte_in_a_criterion(
    client, register_user, db_session, name
):
    """The filter route refuses a NUL byte inside a criterion."""
    account = register_user()
    response = client.post(
        "/filters/",
        json=_criterion_with(name, "re\x00nt"),
        headers=_bearer(account["access_token"]),
    )
    # SEC-05: the byte the driver cannot store never reaches the commit,
    # so an authenticated caller cannot force a server fault with it
    _assert_rejected(response, 422, "criteria.0.{0}".format(name))
    assert db_session.query(FilterModel).count() == 0


@pytest.mark.parametrize("name", CRITERION_FIELDS)
def test_criterion_model_refuses_a_nul_byte(name):
    """The criterion model refuses a NUL byte in each scalar."""
    with pytest.raises(ValidationError) as raised:
        Criteria(**dict(DECLARED_CRITERION, **{name: "re\x00nt"}))
    assert (name,) in [error["loc"] for error in raised.value.errors()]


def test_filter_refuses_a_nul_byte_in_the_name(
    client, register_user, db_session
):
    """The filter route refuses a NUL byte in the filter name."""
    account = register_user()
    response = client.post(
        "/filters/",
        json=dict(DECLARED_FILTER_BODY, name="Two\x00bedrooms"),
        headers=_bearer(account["access_token"]),
    )
    _assert_rejected(response, 422, "name")
    assert db_session.query(FilterModel).count() == 0


def test_filter_admits_a_declared_criterion():
    """The filter model admits a criterion of declared strings."""
    model = FilterCreate(**DECLARED_FILTER_BODY)
    assert model.name == DECLARED_FILTER_BODY["name"]
    assert [criterion.dict() for criterion in model.criteria] == [
        DECLARED_CRITERION
    ]


@pytest.mark.parametrize(
    "field, value",
    (
        ("amount", "free"),
        ("start_date", "not-a-date"),
        ("payment_method", ["paypal"]),
    ),
    ids=(
        "amount-unparsable-string",
        "start-date-unparsable-string",
        "payment-method-array",
    ),
)
def test_subscription_refuses_wrongly_typed_field(
    client, register_user, payment_call, field, value
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
    # SEC-05: the refusal lands ahead of the payment call
    assert payment_call.awaits == []


# ---------------------------------------------------------------------
# The subscription amount arrives outside its domain
# ---------------------------------------------------------------------
# SEC-05: the wire spellings a JSON body carries for a value no float holds
NON_FINITE_LITERALS = ("NaN", "Infinity", "-Infinity", "1e309", "-1e309")

# SEC-05: a magnitude float() refuses outright, raising OverflowError
UNREPRESENTABLE_MAGNITUDE = 10 ** 400

SUBSCRIPTION_DOMAIN_CASES = (
    ("amount", 0),
    ("amount", -19.99),
    ("amount", UNREPRESENTABLE_MAGNITUDE),
)

SUBSCRIPTION_DOMAIN_IDS = (
    "amount-zero",
    "amount-negative",
    "amount-unrepresentable",
)

# SEC-05: a named plan, keeping the empty-plan path out of these cases
NAMED_PLAN = "monthly"


@pytest.mark.parametrize(
    "field, value", SUBSCRIPTION_DOMAIN_CASES, ids=SUBSCRIPTION_DOMAIN_IDS
)
def test_subscription_refuses_out_of_domain_amount(
    client, register_user, payment_call, field, value
):
    """The subscription route refuses an amount outside its domain."""
    account = register_user()
    response = client.post(
        "/subscriptions/",
        json=dict(
            EMPTY_PLAN_SUBSCRIPTION_BODY,
            plan_id=NAMED_PLAN,
            **{field: value}
        ),
        headers=_bearer(account["access_token"]),
    )
    # SEC-05: the amount domain holds ahead of the payment call
    _assert_rejected(response, 422, field)
    # SEC-05: the refusal lands ahead of the payment call
    assert payment_call.awaits == []


@pytest.mark.parametrize(
    "field, value", SUBSCRIPTION_DOMAIN_CASES, ids=SUBSCRIPTION_DOMAIN_IDS
)
def test_subscription_model_refuses_out_of_domain_amount(field, value):
    """The subscription model refuses the same amount with no route
    involved."""
    with pytest.raises(ValidationError) as raised:
        SubscriptionCreate(
            **dict(
                EMPTY_PLAN_SUBSCRIPTION_BODY,
                plan_id=NAMED_PLAN,
                **{field: value}
            )
        )
    assert (field,) in [error["loc"] for error in raised.value.errors()]


@pytest.mark.parametrize("literal", NON_FINITE_LITERALS)
def test_subscription_refuses_every_non_finite_amount(
    client, register_user, payment_call, literal
):
    """The subscription route refuses each wire spelling of a non-finite
    amount."""
    account = register_user()
    body = (
        '{"plan_id": "monthly", "payment_method": "paypal",'
        ' "amount": %s, "start_date": "2030-01-01T00:00:00"}' % literal
    )
    response = _post_raw(
        client, "/subscriptions/", body, account["access_token"]
    )
    # SEC-05: NaN and both infinities stop ahead of the payment call
    _assert_rejected(response, 422, "amount")
    # SEC-05: the refusal lands ahead of the payment call
    assert payment_call.awaits == []


@pytest.mark.parametrize(
    "end_date",
    ("2029-12-31T23:59:59", "2030-01-01T00:00:00"),
    ids=("end-before-start", "end-equals-start"),
)
def test_subscription_refuses_an_unordered_term(
    client, register_user, payment_call, end_date
):
    """The subscription route refuses a term that ends before it
    begins."""
    account = register_user()
    response = client.post(
        "/subscriptions/",
        json=dict(
            EMPTY_PLAN_SUBSCRIPTION_BODY,
            plan_id=NAMED_PLAN,
            end_date=end_date,
        ),
        headers=_bearer(account["access_token"]),
    )
    # SEC-05: the term order holds at the request boundary
    _assert_rejected(response, 422, "end_date")
    # SEC-05: the refusal lands ahead of the payment call
    assert payment_call.awaits == []


def test_subscription_admits_an_ordered_term_and_an_open_one():
    """The subscription model admits an ordered term and an open one."""
    ordered = SubscriptionCreate(
        **dict(
            EMPTY_PLAN_SUBSCRIPTION_BODY,
            plan_id=NAMED_PLAN,
            end_date="2031-01-01T00:00:00",
        )
    )
    assert ordered.end_date > ordered.start_date
    open_ended = SubscriptionCreate(
        **dict(EMPTY_PLAN_SUBSCRIPTION_BODY, plan_id=NAMED_PLAN)
    )
    assert open_ended.end_date is None


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
    client, register_user, payment_call
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
    # SEC-05: the refusal lands ahead of the payment call
    assert payment_call.awaits == []


def test_declared_listing_body_writes_no_row(
    client, register_user, db_session
):
    """A body of declared fields alone still writes no listing row.

    The status is asserted exactly. A test that only ruled out a 2xx
    would also pass on a 401, a 422, a 429 or a 502, and each of those
    means something different: the guard refused the caller, the request
    boundary refused the body, the throttle answered, or a dependency
    did. Ruling out success alone therefore keeps passing after the
    contract moves, which is what makes the exact status the assertion.
    """
    account = register_user()
    response = client.post(
        "/listings/",
        json=DECLARED_LISTING_BODY,
        headers=_bearer(account["access_token"]),
    )

    # AAP 0.8.3: every key in the body is declared, so the request
    # boundary admits it and the failure that follows is the known model
    # defect KNOWN_LISTING_DEFECT_STATUS documents - not a rejection
    assert response.status_code == KNOWN_LISTING_DEFECT_STATUS, response.text

    # SEC-08: the defect answers through the uniform sanitized envelope,
    # so a caller cannot tell a model defect from any other server fault
    reported = response.json()
    assert set(reported) == ENVELOPE_KEYS
    assert reported["detail"] == SANITIZED_FAULT_DETAIL
    assert reported["fields"] == []
    assert CORRELATION_ID.fullmatch(reported[_CORRELATION_KEY]), response.text

    # SEC-08: no exception type, module path, column name or statement
    # text reaches the caller
    lowered = response.text.lower()
    for withheld in WITHHELD_FAULT_TEXT:
        assert withheld not in lowered, response.text

    # SEC-05: the failed write leaves no row behind
    assert db_session.query(ListingModel).count() == 0


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
    assert (unknown_key,) in [error["loc"] for error in errors]
    assert "value_error.extra" in [error["type"] for error in errors]


# ---------------------------------------------------------------------
# One address registers once
# ---------------------------------------------------------------------
def test_registering_one_address_twice_answers_bad_request(
    client, db_session, unique_email
):
    """A second registration of one address answers 400, never 500.

    Two defences answer this: a pre-check before the insert and an
    IntegrityError branch for the request that loses the race. Both
    return the same 400, so the caller cannot tell which one answered
    and cannot learn anything from the difference.
    """
    body = {"email": unique_email, "password": POLICY_PASSWORD}

    first = client.post(REGISTER_PATH, json=body)
    assert first.status_code == 200, first.text

    second = client.post(REGISTER_PATH, json=body)

    # SEC-08: a rejected duplicate is a 400 carrying the uniform
    # envelope, and never a server fault
    _assert_rejected(second, 400)
    reported = second.json()
    assert set(reported) == ENVELOPE_KEYS
    assert reported[_CORRELATION_KEY]
    assert reported["fields"] == []

    # SEC-08: neither submitted value is echoed back
    assert POLICY_PASSWORD not in second.text
    assert unique_email not in second.text

    # the address holds exactly one account row
    assert _user_row_count(db_session, unique_email) == 1


def test_a_duplicate_address_is_refused_before_the_insert(
    client, db_session, unique_email
):
    """The duplicate is refused without attempting the write.

    The race branch answers the same 400, so only the write itself
    distinguishes the two defences. Without the pre-check every repeated
    attempt costs an insert and a rollback that an unauthenticated
    caller chooses freely, and on PostgreSQL the failed insert leaves
    the transaction unusable.
    """
    body = {"email": unique_email, "password": POLICY_PASSWORD}

    with _recorded_inserts("users") as accepted:
        assert client.post(REGISTER_PATH, json=body).status_code == 200
    assert len(accepted) == 1, accepted

    with _recorded_inserts("users") as attempted:
        second = client.post(REGISTER_PATH, json=body)

    _assert_rejected(second, 400)
    # the doomed write is never sent
    assert attempted == []
    assert _user_row_count(db_session, unique_email) == 1


# ---------------------------------------------------------------------
# The declared route table
# ---------------------------------------------------------------------
def test_the_route_table_matches_the_frozen_declaration():
    """The application declares exactly the frozen paths and verbs.

    An added route is reachable the moment it is declared, so the table
    is compared whole rather than probed path by path.
    """
    assert _application_route_table() == DECLARED_ROUTES


def test_no_route_declares_an_undeclared_verb():
    """No route serves a verb outside the declared set.

    The CORS policy advertises GET, POST and OPTIONS alone, so a route
    answering a destructive verb would be reachable without ever
    appearing in the advertised method list.
    """
    served = {method for _path, method in _application_route_table()}

    assert not served & UNDECLARED_METHODS, sorted(served)


# ---------------------------------------------------------------------
# The public read path paginates
# ---------------------------------------------------------------------
def test_public_listing_page_slices_by_skip_and_limit(client, db_session):
    """The public read path returns the slice its bounds ask for.

    No credentials are sent. Bounds that are accepted but ignored would
    return the whole table to every caller, which is a denial-of-service
    surface on a public path as the row count grows.

    The row counts hold in every dialect: LIMIT and OFFSET bound them.
    The disjointness and coverage below are scoped to the SQLite
    harness - the statement carries no ORDER BY, and separate statements
    against PostgreSQL are not ordered against each other.
    """
    seeded = _seed_listings(db_session, SEEDED_LISTING_COUNT)

    whole = _read_listings(client)
    assert whole.status_code == 200
    assert len(_listing_ids(whole)) == SEEDED_LISTING_COUNT

    pages = [
        _listing_ids(_read_listings(client, skip=offset, limit=PAGE_SIZE))
        for offset in (0, PAGE_SIZE, 2 * PAGE_SIZE)
    ]

    # the bounds decide the page size; the last page is short
    assert [len(page) for page in pages] == [PAGE_SIZE, PAGE_SIZE, 1]

    # every returned row is a seeded row, and no page repeats one
    for page in pages:
        assert set(page) <= set(seeded)
        assert len(set(page)) == len(page)

    # SQLite harness scope: the three pages partition the table here
    assert not set(pages[0]) & set(pages[1])
    assert not set(pages[1]) & set(pages[2])
    assert set(pages[0]) | set(pages[1]) | set(pages[2]) == set(seeded)

    # a zero limit is a valid empty page, not the whole table
    empty = _read_listings(client, limit=0)
    assert empty.status_code == 200
    assert _listing_ids(empty) == []


def test_the_public_read_statement_carries_no_ordering(db_session):
    """The frozen read statement binds both pages and orders nothing.

    Compiling against both dialects records the bound the endpoint
    applies and the ordering it leaves unspecified, without a
    PostgreSQL server.
    """
    query = (
        db_session.query(ListingModel)
        .offset(PAGE_SIZE)
        .limit(PAGE_SIZE)
    )

    for dialect in (sqlite.dialect(), postgresql.dialect()):
        compiled = str(query.statement.compile(dialect=dialect)).upper()
        assert "LIMIT" in compiled
        assert "OFFSET" in compiled
        assert "ORDER BY" not in compiled


@pytest.mark.parametrize("bounds,field", REFUSED_PAGINATION)
def test_public_listing_page_refuses_a_non_numeric_bound(
    client, bounds, field
):
    """A bound that is not an integer is refused at the boundary.

    The refusal names the bound, so a caller learns which one it sent
    wrongly without any statement text reaching the response.
    """
    response = _read_listings(client, **bounds)

    # SEC-05: refused at the request boundary, never as a 500
    _assert_rejected(response, 422, field)


@pytest.mark.parametrize("bounds", ADMITTED_PAGINATION)
def test_public_listing_page_admits_the_frozen_numeric_domain(
    client, db_session, bounds
):
    """Every integer bound inside the frozen domain answers a page.

    AAP 0.8.3 freezes the skip and limit contract, so this case fails if
    a narrower domain is reintroduced and starts refusing a bound the
    public read path accepted.
    """
    _seed_listings(db_session, SEEDED_LISTING_COUNT)

    response = _read_listings(client, **bounds)

    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list)


@pytest.mark.parametrize(
    "bounds",
    (
        pytest.param({"skip": UNBINDABLE_BOUND}, id="skip"),
        pytest.param({"limit": UNBINDABLE_BOUND}, id="limit"),
    ),
)
def test_an_unbindable_bound_answers_a_sanitized_fault(
    client, db_session, bounds
):
    """A bound past the driver's range answers the uniform envelope.

    The frozen contract declares no ceiling, so the value reaches the
    statement. SEC-08 is what keeps the failure from carrying the
    statement, the driver name or a traceback back to the caller.
    """
    _seed_listings(db_session, SEEDED_LISTING_COUNT)

    response = _read_listings(client, **bounds)

    assert response.status_code == 500
    body = response.json()
    # SEC-08: one envelope shape, a correlation identifier, no internals
    assert set(body) == ENVELOPE_KEYS
    assert body[_CORRELATION_KEY]
    leaked = response.text.lower()
    for fragment in ("select ", "sqlite", "sqlalchemy", "traceback", "offset"):
        assert fragment not in leaked


# ---------------------------------------------------------------------
# The filter route's declared response model
# ---------------------------------------------------------------------
def test_the_filter_routes_publish_the_declared_response_model(
    client, register_user, db_session
):
    """Both filter routes declare the model, and a read publishes it.

    AAP 0.8.3 freezes the response model these routes declare. The
    declaration is what filters the response, and dropping it would
    widen the body without moving any status code. The create route
    cannot write a row, so the published key set is read back from a
    seeded one.
    """
    account = register_user()

    # AAP 0.8.3: both routes still declare the model they always had
    assert _route_for(FILTER_PATH, "POST").response_model is Filter
    assert _route_for(FILTER_PATH, "GET").response_model == List[Filter]

    seed_filter(db_session, account["id"])

    response = client.get(
        FILTER_PATH, headers=_bearer(account["access_token"])
    )

    assert response.status_code == 200, response.text
    published = response.json()
    assert len(published) == 1
    assert set(published[0]) == DECLARED_FILTER_RESPONSE_KEYS
    # SEC-05: the nested criterion is read through the declared model,
    # so a wider mapped row cannot publish a column the model omits
    assert published[0]["criteria"] == [DECLARED_CRITERION]

    # AAP 0.8.3: the declared model publishes exactly the frozen key set.
    # A field added to Filter widens what this route returns, so it fails
    # here rather than passing because the expectation was read from it.
    assert frozenset(Filter.__fields__) == DECLARED_FILTER_RESPONSE_KEYS


def test_filter_creation_defect_answers_a_sanitized_fault(
    client, register_user
):
    """The create path's pre-existing defect discloses nothing.

    AAP 0.8.3 records that this route cannot write a row, for reasons
    outside the security scope: the endpoint hands a mapped relationship
    a request model and supplies no value for the non-null ``created_at``
    column. The strict schema still closes the mass-assignment vector,
    and the fault must surface as the uniform sanitized envelope.
    """
    account = register_user()

    response = client.post(
        FILTER_PATH,
        json=DECLARED_FILTER_BODY,
        headers=_bearer(account["access_token"]),
    )

    # SEC-08: one uniform envelope, no internal detail
    assert response.status_code == 500, response.text
    body = response.json()
    assert set(body) == ENVELOPE_KEYS
    assert body["detail"] == "Internal server error"
    assert body["fields"] == []
    assert body[_CORRELATION_KEY]

    served = response.text
    for leaked in (
        "Traceback",
        "_sa_instance_state",
        "sqlalchemy",
        "INSERT INTO",
        "filters.py",
        "site-packages",
    ):
        assert leaked not in served, served


def test_a_stored_script_payload_round_trips_inside_json(
    client, register_user, db_session
):
    """A script payload held as a filter name comes back verbatim.

    The response is JSON, so the value sits in no markup context on the
    server and nothing here executes server-side. Pinning it records
    where the escaping duty lies and fails if the same value were ever
    served as a document.
    """
    account = register_user()

    # SEC-05: the request boundary admits the payload as declared text,
    # with no server-side rewrite
    admitted = FilterCreate(**dict(DECLARED_FILTER_BODY, name=SCRIPT_PAYLOAD))
    assert admitted.name == SCRIPT_PAYLOAD

    seed_filter(db_session, account["id"], name=SCRIPT_PAYLOAD)

    read_back = client.get(
        FILTER_PATH, headers=_bearer(account["access_token"])
    )
    assert read_back.status_code == 200, read_back.text

    # SEC-05: the payload is carried as data, never as markup
    content_type = read_back.headers["content-type"]
    assert content_type.startswith("application/json"), content_type
    assert "html" not in content_type

    # SEC-05: stored and returned unchanged; no server-side rewrite
    # hides it from a caller that has to escape it
    assert [entry["name"] for entry in read_back.json()] == [SCRIPT_PAYLOAD]


def _validation_record(caplog, response):
    """Return the single record quoting one reply's correlation value."""
    error_id = response.json()[_CORRELATION_KEY]
    matching = [
        record
        for record in caplog.records
        if error_id in record.getMessage()
    ]
    assert len(matching) == 1, [
        record.getMessage() for record in caplog.records
    ]
    return matching[0].getMessage()


def test_an_undeclared_key_name_reaches_no_record(
    client, unique_email, caplog
):
    """The caller is told which key was refused; the record is not.

    Both channels are read in one case, because the two answers differ on
    purpose. The reply names the key so a client can correct the request.
    The record names its position, because the key itself is text the
    caller chose and a record is read by tooling that trusts it.
    """
    caplog.set_level(logging.WARNING)
    response = client.post(
        REGISTER_PATH,
        json={
            "email": unique_email,
            "password": POLICY_PASSWORD,
            UNDECLARED_KEY_NAME: "x",
        },
    )

    # SEC-05: the reply keeps the contract the client depends on
    _assert_rejected(response, 422, UNDECLARED_KEY_NAME)

    message = _validation_record(caplog, response)
    assert "validation rejected" in message
    assert REGISTER_PATH in message
    assert "fields={0}".format(_UNDECLARED_FIELD) in message
    assert "count=1" in message

    # SEC-05: nothing the caller named reaches the record
    assert UNDECLARED_KEY_NAME not in message
    assert UNDECLARED_KEY_NAME not in caplog.text
    assert unique_email not in caplog.text
    assert POLICY_PASSWORD not in caplog.text


def test_a_nested_undeclared_key_is_located_but_not_named(
    client, register_user, caplog
):
    """A nested rejection keeps the declared path and drops the leaf."""
    caplog.set_level(logging.WARNING)
    account = register_user()
    response = client.post(
        FILTER_PATH,
        json=dict(
            DECLARED_FILTER_BODY,
            criteria=[
                dict(DECLARED_CRITERION, **{UNDECLARED_NESTED_NAME: "x"})
            ],
        ),
        headers=_bearer(account["access_token"]),
    )

    _assert_rejected(
        response, 422, "criteria.0.{0}".format(UNDECLARED_NESTED_NAME)
    )

    message = _validation_record(caplog, response)
    # SEC-05: the declared path is a server fact and stays; the leaf is
    # the caller's word and goes
    assert "criteria.0.{0}".format(_UNDECLARED_FIELD) in message
    assert UNDECLARED_NESTED_NAME not in message
    assert UNDECLARED_NESTED_NAME not in caplog.text


def test_a_declared_field_name_reaches_the_record(client, unique_email,
                                                  caplog):
    """A refused declared field is named, so the record still diagnoses."""
    caplog.set_level(logging.WARNING)
    response = client.post(
        REGISTER_PATH, json={"email": unique_email}
    )

    _assert_rejected(response, 422, "password")

    message = _validation_record(caplog, response)
    # SEC-05: the name is declared by the schema, so it is the server's
    # own vocabulary and withholding it would remove the diagnosis
    assert "fields=password" in message
    assert _UNDECLARED_FIELD not in message


def test_many_rejections_bound_one_record(client, register_user, caplog):
    """A body full of rejections produces a bounded record."""
    caplog.set_level(logging.WARNING)
    account = register_user()
    response = client.post(
        FILTER_PATH,
        json=dict(
            DECLARED_FILTER_BODY,
            criteria=[
                _without(DECLARED_CRITERION, "field")
                for _ in range(FLOODING_CRITERION_COUNT)
            ],
        ),
        headers=_bearer(account["access_token"]),
    )

    assert response.status_code == 422, response.text
    assert len(_rejected_fields(response)) == FLOODING_CRITERION_COUNT

    message = _validation_record(caplog, response)
    named = message.split("fields=")[1].split(" count=")[0]
    withheld = FLOODING_CRITERION_COUNT - _MAX_LOGGED_FIELDS

    # SEC-05: the record names a fixed maximum and counts the rest, so a
    # large body cannot inflate one line without limit (CWE-532)
    assert named.endswith(",+{0}".format(withheld))
    assert named.count("criteria.") == _MAX_LOGGED_FIELDS
    assert "count={0}".format(FLOODING_CRITERION_COUNT) in message


@pytest.mark.parametrize(
    "error_type,expected",
    [
        ("value_error.missing", "{0}.leaf"),
        ("value_error.extra", "{0}." + _UNDECLARED_FIELD),
    ],
)
def test_a_long_field_path_is_truncated_in_the_record(error_type, expected):
    """Every part of a logged path is capped in length."""
    overlong = "z" * (_MAX_LOGGED_NAME_LENGTH * 5)
    rendered = _loggable_field_names(
        [{"loc": ("body", overlong, "leaf"), "type": error_type}]
    )

    capped = overlong[:_MAX_LOGGED_NAME_LENGTH]
    assert rendered == expected.format(capped)
    assert len(capped) == _MAX_LOGGED_NAME_LENGTH
    assert overlong not in rendered


# ---------------------------------------------------------------------
# The filter write path bounds what one request can store
# ---------------------------------------------------------------------
def test_filter_criteria_beyond_the_cap_are_refused(client, register_user):
    """A criteria list longer than the cap stops at the boundary.

    An unbounded list lets one authenticated request write arbitrarily
    many child rows, so the cap is the control and the boundary is where
    it has to be enforced (CWE-770).
    """
    account = register_user()
    oversized = dict(
        DECLARED_FILTER_BODY,
        criteria=[DECLARED_CRITERION] * (MAX_CRITERIA + 1),
    )

    response = client.post(
        FILTER_PATH, json=oversized, headers=_bearer(account["access_token"])
    )

    _assert_rejected(response, 422, "criteria")


def test_filter_criteria_at_the_cap_are_admitted(client, register_user):
    """A criteria list exactly at the cap clears the request boundary.

    The cap refuses one entry more, so the boundary case proves the cap is
    a bound rather than an off-by-one refusal. AAP 0.8.3 records that this
    route cannot write a row, so admission is asserted as the absence of a
    422 plus acceptance by the request model itself; the pre-existing write
    defect still answers the uniform sanitized 500.
    """
    account = register_user()
    at_cap = dict(
        DECLARED_FILTER_BODY, criteria=[DECLARED_CRITERION] * MAX_CRITERIA
    )

    # SEC-05: the request model admits the list at the cap
    admitted = FilterCreate(**at_cap)
    assert len(admitted.criteria) == MAX_CRITERIA

    response = client.post(
        FILTER_PATH, json=at_cap, headers=_bearer(account["access_token"])
    )

    # SEC-05: no field is rejected, so the cap did not refuse this list
    assert response.status_code != 422, response.text
    assert response.status_code == 500, response.text
    body = response.json()
    assert set(body) == ENVELOPE_KEYS
    assert body["fields"] == []


def test_filter_criterion_text_beyond_its_cap_is_refused(
    client, register_user
):
    """A criterion value longer than its cap stops at the boundary."""
    account = register_user()
    oversized = dict(
        DECLARED_FILTER_BODY,
        criteria=[
            dict(DECLARED_CRITERION, value="9" * (MAX_CRITERION_VALUE + 1))
        ],
    )

    response = client.post(
        FILTER_PATH, json=oversized, headers=_bearer(account["access_token"])
    )

    # the handler names the offending nested criterion, not a bare field
    _assert_rejected(response, 422, "criteria.0.value")


def test_filter_name_beyond_its_cap_is_refused(client, register_user):
    """A filter name longer than its cap stops at the boundary."""
    account = register_user()
    oversized = dict(DECLARED_FILTER_BODY, name="n" * (MAX_FILTER_NAME + 1))

    response = client.post(
        FILTER_PATH, json=oversized, headers=_bearer(account["access_token"])
    )

    _assert_rejected(response, 422, "name")


def test_an_empty_filter_name_still_answers_bad_request(
    client, register_user
):
    """The empty-name path is unchanged by the length cap.

    A maximum length must not acquire a minimum: the route answers 400
    for an empty name and that contract is asserted elsewhere too.
    """
    account = register_user()

    response = client.post(
        FILTER_PATH,
        json={"name": "", "criteria": []},
        headers=_bearer(account["access_token"]),
    )

    assert response.status_code == 400, response.text


# ---------------------------------------------------------------------
# Identifiers are served with the type their column declares
# ---------------------------------------------------------------------
def test_identifiers_are_served_as_integers(
    client, register_user, db_session
):
    """Every served identifier is a JSON number, not a string.

    The columns are INTEGER, so a string identifier would force a
    caller to coerce before comparing and would misreport the contract.
    """
    account = register_user()
    credentials = _bearer(account["access_token"])

    # AAP 0.8.3: the create route cannot write a row, so the read path is
    # seeded through the session and the served types are read from it
    seeded_id = seed_filter(db_session, account["id"])
    served = client.get(FILTER_PATH, headers=credentials)
    assert served.status_code == 200, served.text

    published = served.json()
    assert len(published) == 1
    filter_body = published[0]
    assert isinstance(filter_body["id"], int)
    assert filter_body["id"] == seeded_id
    assert isinstance(filter_body["user_id"], int)
    assert filter_body["user_id"] == account["id"]

    _seed_listings(db_session, 1)
    listings = _read_listings(client)
    assert listings.status_code == 200
    assert [isinstance(entry["id"], int) for entry in listings.json()] == [
        True
    ]


# ---------------------------------------------------------------------
# The harness enforces the foreign keys the models declare
# ---------------------------------------------------------------------
def test_declared_foreign_keys_are_enforced_under_test(db_session):
    """A child row naming no parent is refused by the database.

    SQLite ignores foreign keys unless the pragma is set per connection.
    Without it the four declared foreign keys are inert under test, so a
    harness that stands in for PostgreSQL would be weaker than what it
    replaces and an orphaned row would insert cleanly.
    """
    from sqlalchemy.exc import IntegrityError

    from backend.app.db.models import Criteria as CriteriaModel

    enabled = db_session.execute(text("PRAGMA foreign_keys")).scalar()
    assert enabled == 1, enabled

    # filter_id names no filters row, so the constraint has to refuse it
    db_session.add(
        CriteriaModel(
            filter_id=987654, field="rent", operator="lt", value="1"
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
