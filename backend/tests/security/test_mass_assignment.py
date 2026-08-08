"""Field-level authorization and privilege-escalation regression tests.

Every case here submits a hostile request body and asserts the hostile
field reaches no server-side state. Each refusal is asserted twice:
once on the response status and once on the stored rows read back from
the isolated session.

The properties covered are:

* ``POST /listings/`` refuses a body naming any field
  :class:`backend.app.schema.listing.ListingCreate` does not declare,
  and stores no ``listings`` row when it refuses one
* ``POST /listings/`` stores a body naming only declared fields, with
  the values that were submitted
* ``POST /auth/register`` refuses a body carrying a ``role`` field, and
  every registration that is stored carries
  :data:`backend.app.core.authorization.Role.REGISTERED`
* the seeded administrator count is unchanged by every registration
  attempt, and the surviving administrator is the seeded row
* no response body from ``/auth/register``, ``/auth/login`` or
  ``/listings/`` carries a stored password hash, under
  :data:`HASH_FIELD_NAME` or under any other key

The listing write is exercised with the administrator principal.
:func:`backend.app.api.endpoints.listings.create_listing` declares
``require_role(Role.ADMIN)``. Role admission across every route and
principal is covered in ``test_authorization.py``.

Each hash-exposure case also asserts that a bcrypt hash is present on
the stored row it reads.

Design rationale is recorded in ``docs/security/DECISION_LOG.md``.
"""

from datetime import datetime

import pytest
from conftest import VALID_TEST_PASSWORD

from backend.app.core.authorization import Role
from backend.app.db.models import Listing as ListingModel, User

#: Route the listing contract is exercised on. The trailing slash is
#: part of the path the router mounts.
LISTINGS_PATH = "/listings/"

REGISTER_PATH = "/auth/register"

LOGIN_PATH = "/auth/login"

#: Status a request-model validation failure is answered with.
VALIDATION_REFUSED = 422

#: Status a request both contracts accept is answered with.
ACCEPTED = 200

#: Administrators the fixtures seed: the single ``admin_user`` row.
SEEDED_ADMINISTRATORS = 1

#: Name the stored password hash is held under on ``users``.
HASH_FIELD_NAME = "hashed_password"

#: Prefixes a stored bcrypt hash can begin with. A response carrying any
#: of them carries a hash, under whatever key it appears.
BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")

#: Availability submitted by :data:`ALLOWLISTED_LISTING_BODY`, and the
#: value the stored row must carry back.
AVAILABLE_DATE = datetime(2026, 9, 1, 12, 30)

#: Address the escalation attempt registers under.
ESCALATION_EMAIL = "escalation.attempt@example.com"

#: Address the ordinary registrations register under.
ORDINARY_EMAIL = "ordinary.registration@example.com"

#: A listing body naming only the fields ``ListingCreate`` declares.
ALLOWLISTED_LISTING_BODY = {
    "rent": 3250.5,
    "broker_fee": 425.0,
    "square_footage": 780.0,
    "bedrooms": 2,
    "bathrooms": 1,
    "available_date": AVAILABLE_DATE.isoformat(),
    "street_address": "118 Bedford Avenue",
    "zillow_url": "https://www.zillow.com/homedetails/118-bedford",
}

#: Field names absent from the ``ListingCreate`` allowlist, each paired
#: with the value an attacker would submit for it. ``owner_id`` is the
#: name the previously vulnerable constructor injected and is no column
#: of ``listings``; ``id``, ``created_at`` and ``updated_at`` are
#: server-assigned columns; ``role`` belongs to another table; and
#: ``is_promoted`` names nothing at all.
HOSTILE_LISTING_FIELDS = [
    pytest.param("owner_id", 999, id="owner_id"),
    pytest.param("id", 424242, id="id"),
    pytest.param("created_at", "1999-01-01T00:00:00", id="created_at"),
    pytest.param("updated_at", "1999-01-01T00:00:00", id="updated_at"),
    pytest.param("role", Role.ADMIN.value, id="role"),
    pytest.param("is_promoted", True, id="invented_field"),
]


def nested_keys(payload):
    """Return every mapping key appearing at any depth of ``payload``.

    Mappings and sequences are both descended into, so the keys of the
    ``user`` object a registration nests are reported alongside the keys
    at the top level, and so are the keys of each entry in the list a
    listings page returns.
    """
    found = set()
    pending = [payload]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            for key, value in current.items():
                found.add(key)
                pending.append(value)
        elif isinstance(current, (list, tuple)):
            pending.extend(current)
    return found


def assert_no_stored_hash(response):
    """Assert ``response`` discloses no stored password hash.

    Three checks are applied: :data:`HASH_FIELD_NAME` appears as a key
    at no depth of the decoded body, the raw text names it nowhere, and
    the raw text carries no value beginning with a bcrypt prefix under
    any key at all.
    """
    assert HASH_FIELD_NAME not in nested_keys(response.json())
    assert HASH_FIELD_NAME not in response.text
    for prefix in BCRYPT_PREFIXES:
        assert prefix not in response.text


def administrator_count(session):
    """Return the number of stored rows holding ``Role.ADMIN``."""
    session.expire_all()
    return (
        session.query(User)
        .filter(User.role == Role.ADMIN.value)
        .count()
    )


def administrators(session):
    """Return every stored row holding ``Role.ADMIN``."""
    session.expire_all()
    return (
        session.query(User)
        .filter(User.role == Role.ADMIN.value)
        .order_by(User.id)
        .all()
    )


def stored_user(session, email):
    """Return the stored ``users`` row for ``email``, or ``None``."""
    session.expire_all()
    return (
        session.query(User)
        .filter(User.email == email)
        .one_or_none()
    )


def stored_listings(session):
    """Return every stored ``listings`` row, ordered by identifier."""
    session.expire_all()
    return session.query(ListingModel).order_by(ListingModel.id).all()


@pytest.mark.parametrize(
    "field_name, hostile_value", HOSTILE_LISTING_FIELDS
)
def test_a_listing_field_outside_the_allowlist_is_refused(
    client,
    db,
    admin_user,
    auth_header_factory,
    field_name,
    hostile_value,
):
    """Assert a hostile field is refused and that no row is stored.

    Every other field of the submitted body is one ``ListingCreate``
    declares, carrying a value that contract accepts.
    """
    body = dict(ALLOWLISTED_LISTING_BODY)
    body[field_name] = hostile_value

    response = client.post(
        LISTINGS_PATH,
        json=body,
        headers=auth_header_factory(admin_user),
    )

    assert response.status_code == VALIDATION_REFUSED
    assert stored_listings(db) == []


def test_an_allowlisted_listing_body_is_stored_as_submitted(
    client, db, admin_user, auth_header_factory
):
    """Assert a body naming only declared fields stores those values.

    This is the positive control for
    :func:`test_a_listing_field_outside_the_allowlist_is_refused`. All
    eight declared fields are submitted and each is read back from the
    stored row.
    """
    response = client.post(
        LISTINGS_PATH,
        json=ALLOWLISTED_LISTING_BODY,
        headers=auth_header_factory(admin_user),
    )

    assert response.status_code == ACCEPTED

    rows = stored_listings(db)
    assert len(rows) == 1

    stored = rows[0]
    assert stored.rent == ALLOWLISTED_LISTING_BODY["rent"]
    assert stored.broker_fee == ALLOWLISTED_LISTING_BODY["broker_fee"]
    assert stored.square_footage == (
        ALLOWLISTED_LISTING_BODY["square_footage"]
    )
    assert stored.bedrooms == ALLOWLISTED_LISTING_BODY["bedrooms"]
    assert stored.bathrooms == ALLOWLISTED_LISTING_BODY["bathrooms"]
    assert stored.available_date == AVAILABLE_DATE
    assert stored.street_address == (
        ALLOWLISTED_LISTING_BODY["street_address"]
    )
    assert stored.zillow_url == ALLOWLISTED_LISTING_BODY["zillow_url"]


def test_a_registration_carrying_a_role_field_does_not_grant_it(
    client, db, admin_user, reset_rate_limits
):
    """Assert a registration cannot grant itself the administrative role.

    A body carrying ``role`` set to the administrative value is refused
    and stores no account, and the administrator count is unchanged. The
    same address is then registered without the field, and the stored
    ``users.role`` column is asserted to hold
    ``Role.REGISTERED``.
    """
    assert administrator_count(db) == SEEDED_ADMINISTRATORS

    escalating = client.post(
        REGISTER_PATH,
        json={
            "email": ESCALATION_EMAIL,
            "password": VALID_TEST_PASSWORD,
            "role": Role.ADMIN.value,
        },
    )

    assert escalating.status_code == VALIDATION_REFUSED
    assert stored_user(db, ESCALATION_EMAIL) is None
    assert administrator_count(db) == SEEDED_ADMINISTRATORS

    accepted = client.post(
        REGISTER_PATH,
        json={
            "email": ESCALATION_EMAIL,
            "password": VALID_TEST_PASSWORD,
        },
    )

    assert accepted.status_code == ACCEPTED

    stored = stored_user(db, ESCALATION_EMAIL)
    assert stored is not None
    assert stored.role == Role.REGISTERED.value
    assert stored.role != Role.ADMIN.value
    assert administrator_count(db) == SEEDED_ADMINISTRATORS


def test_a_registration_without_a_role_field_stores_the_default_role(
    client, db, reset_rate_limits
):
    """Assert an ordinary registration stores ``Role.REGISTERED``.

    The submitted body names no ``role`` field at all, and the value
    asserted is the one read back from the stored ``users.role`` column.
    """
    response = client.post(
        REGISTER_PATH,
        json={
            "email": ORDINARY_EMAIL,
            "password": VALID_TEST_PASSWORD,
        },
    )

    assert response.status_code == ACCEPTED

    stored = stored_user(db, ORDINARY_EMAIL)
    assert stored is not None
    assert stored.role == Role.REGISTERED.value
    assert stored.role != Role.ADMIN.value


def test_the_only_administrator_is_the_seeded_account(
    client, db, admin_user, reset_rate_limits
):
    """Assert an escalating registration adds no administrator.

    Every administrative row is read back, and both the number of rows
    and the address each one holds are asserted.
    """
    client.post(
        REGISTER_PATH,
        json={
            "email": ESCALATION_EMAIL,
            "password": VALID_TEST_PASSWORD,
            "role": Role.ADMIN.value,
        },
    )

    holders = administrators(db)
    assert len(holders) == SEEDED_ADMINISTRATORS
    assert [holder.email for holder in holders] == [admin_user.email]


def test_no_credential_response_carries_a_stored_password_hash(
    client, db, reset_rate_limits
):
    """Assert the registration and login responses disclose no hash.

    The registration response nests a ``user`` object, which is walked to
    every depth, and the login response is asserted to carry exactly the
    two keys its frozen shape declares.
    """
    registered = client.post(
        REGISTER_PATH,
        json={
            "email": ORDINARY_EMAIL,
            "password": VALID_TEST_PASSWORD,
        },
    )

    assert registered.status_code == ACCEPTED
    assert set(registered.json()["user"]) == {"id", "email"}
    assert_no_stored_hash(registered)

    logged_in = client.post(
        LOGIN_PATH,
        json={
            "email": ORDINARY_EMAIL,
            "password": VALID_TEST_PASSWORD,
        },
    )

    assert logged_in.status_code == ACCEPTED
    assert set(logged_in.json()) == {"access_token", "token_type"}
    assert_no_stored_hash(logged_in)

    stored = stored_user(db, ORDINARY_EMAIL)
    assert stored is not None
    assert stored.hashed_password.startswith(BCRYPT_PREFIXES)


def test_no_listing_response_carries_a_stored_password_hash(
    client, db, admin_user, auth_header_factory
):
    """Assert the listing write and read responses disclose no hash.

    The write is performed by an authenticated principal whose own
    stored row carries a hash, and the page the read returns is walked
    to every depth.
    """
    assert admin_user.hashed_password.startswith(BCRYPT_PREFIXES)

    written = client.post(
        LISTINGS_PATH,
        json=ALLOWLISTED_LISTING_BODY,
        headers=auth_header_factory(admin_user),
    )

    assert written.status_code == ACCEPTED
    assert_no_stored_hash(written)

    page = client.get(LISTINGS_PATH)

    assert page.status_code == ACCEPTED
    assert len(page.json()) == 1
    assert_no_stored_hash(page)
