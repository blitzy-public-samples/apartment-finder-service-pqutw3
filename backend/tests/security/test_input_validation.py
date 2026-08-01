"""Request-validation regression tests for every write endpoint.

Each test proves one endpoint refuses a body it does not declare, so a
client cannot set a server-owned column by adding a key to the request.

The same file pins the contracts a validation change could quietly move:
the set of paths and verbs the application declares, the pagination the
public read path applies, the response model the filter route declares,
and the answer a duplicate address receives.
"""
from contextlib import contextmanager
from datetime import datetime

import pytest
from conftest import test_engine
from fastapi.routing import APIRoute
from pydantic import ValidationError
from sqlalchemy import event, text

from backend.app.db.models import Listing as ListingModel
from backend.app.main import _error_envelope, app
from backend.app.schema.filter import Filter, FilterCreate
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

# SEC-08: the sanitized envelope backend/app/main.py builds, read from
# the application rather than restated here
ENVELOPE_KEYS = frozenset(_error_envelope("a detail", "a correlation id"))

# SEC-08: the correlation key, located by the value it carries
_CORRELATION_PROBE = "correlation-key-probe"
_CORRELATION_KEY = next(
    key
    for key, value in _error_envelope("a detail", _CORRELATION_PROBE).items()
    if value == _CORRELATION_PROBE
)

# AAP 0.8.3: the frozen public read path - unauthenticated, trailing
# slash, no /api prefix
PUBLIC_READ_PATH = "/listings/"
FILTER_PATH = "/filters/"
REGISTER_PATH = "/auth/register"

# AAP 0.8.3: every path and verb the application declares. A verb absent
# from this table is also absent from the method list CORSMiddleware
# advertises, so declaring one would widen the surface silently.
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
# publishes, derived from the model so the two cannot drift
DECLARED_FILTER_RESPONSE_KEYS = frozenset(Filter.__fields__)

# AAP 0.8.3: enough rows for three pages of two
SEEDED_LISTING_COUNT = 5
PAGE_SIZE = 2

# SEC-05: the ceiling listings.py binds; one past it is refused
PAGINATION_CEILING = 2 ** 63 - 1

# SEC-05: pagination bounds the request boundary refuses
REFUSED_PAGINATION = (
    pytest.param({"skip": -1}, "skip", id="negative-skip"),
    pytest.param({"limit": -1}, "limit", id="negative-limit"),
    pytest.param({"skip": "abc"}, "skip", id="non-numeric-skip"),
    pytest.param({"limit": "abc"}, "limit", id="non-numeric-limit"),
    pytest.param(
        {"skip": PAGINATION_CEILING + 1}, "skip", id="skip-past-the-ceiling"
    ),
    pytest.param(
        {"limit": PAGINATION_CEILING + 1}, "limit", id="limit-past-the-ceiling"
    ),
)

# SEC-05: a payload that would execute in a document but not in JSON
SCRIPT_PAYLOAD = "<script>alert('filter-name')</script>"


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
    # instances, so they never enter the comparison
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
    # Listing.id is declared str, so the response spells it that way
    return [str(row.id) for row in rows]


def _read_listings(client, **bounds):
    """Read the public listing page, sending no credentials."""
    return client.get(PUBLIC_READ_PATH, params=bounds or None)


def _listing_ids(response):
    return [entry["id"] for entry in response.json()]


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
    """
    seeded = _seed_listings(db_session, SEEDED_LISTING_COUNT)

    whole = _read_listings(client)
    assert whole.status_code == 200
    assert len(_listing_ids(whole)) == SEEDED_LISTING_COUNT

    pages = [
        _listing_ids(_read_listings(client, skip=offset, limit=PAGE_SIZE))
        for offset in (0, PAGE_SIZE, 2 * PAGE_SIZE)
    ]

    # the bounds decide the page size, so the last page is short
    assert [len(page) for page in pages] == [PAGE_SIZE, PAGE_SIZE, 1]

    # the pages partition the table: disjoint, and covering it exactly
    assert not set(pages[0]) & set(pages[1])
    assert not set(pages[1]) & set(pages[2])
    assert set(pages[0]) | set(pages[1]) | set(pages[2]) == set(seeded)

    # a zero limit is a valid empty page, not the whole table
    empty = _read_listings(client, limit=0)
    assert empty.status_code == 200
    assert _listing_ids(empty) == []


@pytest.mark.parametrize("bounds,field", REFUSED_PAGINATION)
def test_public_listing_page_refuses_a_bound_outside_its_range(
    client, bounds, field
):
    """A negative, non-numeric or oversized bound is refused.

    A value the request boundary passes through reaches the OFFSET and
    LIMIT bindings, where the driver refuses it only once the statement
    runs and the failure surfaces as a server fault instead.
    """
    response = _read_listings(client, **bounds)

    # SEC-05: refused at the request boundary, never as a 500
    _assert_rejected(response, 422, field)


# ---------------------------------------------------------------------
# The filter route's declared response model
# ---------------------------------------------------------------------
def test_filter_creation_returns_the_declared_response_model(
    client, register_user
):
    """A successful filter creation returns the declared key set.

    The declaration is what filters the response, so the route object is
    asserted alongside the body: the handler already builds the model by
    hand, and a dropped declaration would return the same keys while
    filtering nothing.
    """
    account = register_user()

    response = client.post(
        FILTER_PATH,
        json=DECLARED_FILTER_BODY,
        headers=_bearer(account["access_token"]),
    )

    assert response.status_code == 200, response.text
    assert set(response.json()) == DECLARED_FILTER_RESPONSE_KEYS

    # AAP 0.8.3: the route still declares the model it published
    assert _route_for(FILTER_PATH, "POST").response_model is Filter


def test_a_stored_script_payload_round_trips_inside_json(
    client, register_user
):
    """A script payload stored as a filter name comes back verbatim.

    The response is JSON, so the value sits in no markup context on the
    server and nothing here executes server-side. Pinning it records
    where the escaping duty lies and fails if the same value were ever
    served as a document.
    """
    account = register_user()
    credentials = _bearer(account["access_token"])

    created = client.post(
        FILTER_PATH,
        json=dict(DECLARED_FILTER_BODY, name=SCRIPT_PAYLOAD),
        headers=credentials,
    )
    assert created.status_code == 200, created.text

    read_back = client.get(FILTER_PATH, headers=credentials)
    assert read_back.status_code == 200

    # SEC-05: the payload is carried as data, never as markup
    for response in (created, read_back):
        content_type = response.headers["content-type"]
        assert content_type.startswith("application/json"), content_type
        assert "html" not in content_type

    # SEC-05: stored and returned unchanged, so no server-side rewrite
    # hides it from a caller that has to escape it
    assert created.json()["name"] == SCRIPT_PAYLOAD
    assert [entry["name"] for entry in read_back.json()] == [SCRIPT_PAYLOAD]
