"""Field-level authorization and privilege escalation.

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
* the number of accounts holding
  :data:`backend.app.core.authorization.Role.ADMIN` is unchanged by
  every registration attempt, and the one that survives is the row the
  fixtures store
* on a database built by both Alembic revisions, exactly one account
  holds :data:`Role.ADMIN` and its address is
  :data:`MIGRATION_ADMIN_EMAIL`, every other account holds
  :data:`Role.REGISTERED`, and a registration body carrying a ``role``
  field is still refused
* no response body from ``/auth/register``, ``/auth/login`` or
  ``/listings/`` carries a stored password hash, under
  :data:`HASH_FIELD_NAME` or under any other key

Every principal here is a row ``backend/tests/conftest.py`` stores. The
administrator that the revision
``backend/migrations/versions/0002_seed_single_admin.py`` grants is a
different account, and that grant is covered in
``test_admin_seed_migration.py``.

The administrative role has one write site, the migration revision
``backend/migrations/versions/0002_seed_single_admin.py``, and the cases
naming ``run_admin_seed`` run that revision itself against the isolated
database rather than modelling it. They cover:

* the address the revision names, registered through ``/auth/register``
  first, is promoted, and exactly that one account holds the role
  afterwards
* the same address, absent, is stored by the revision holding the role
  and a credential no password verifies against, and a login attempt
  for it is refused
* a second run writes nothing and reports that it wrote nothing
* a run beside an administrator at any other address raises and changes
  no stored role
* the downgrade demotes that one account and reports whether it changed
  a row

Each of those cases also asserts the revision's own INFO audit record,
captured from the logger named by :data:`AUDIT_LOGGER_NAME`.

The listing write is exercised with the administrator principal.
:func:`backend.app.api.endpoints.listings.create_listing` declares
``require_role(Role.ADMIN)``. Role admission across every route and
principal is covered in ``test_rbac_matrix.py``.

Each hash-exposure case also asserts that a bcrypt hash is present on
the stored row it reads. A response is required to carry the members its
contract declares and is permitted to carry more, so each case asserts
the declared members are present rather than that no other member is.
"""

import logging
from datetime import datetime

import pytest
from sqlalchemy import text

from backend.app.core.authorization import Role
from backend.app.core.security import verify_password
from backend.app.db.models import Listing as ListingModel, User
from backend.app.schema.user import User as UserResponse
from backend.tests.support import VALID_TEST_PASSWORD

#: Route the listing contract is exercised on. The trailing slash is
#: part of the path the router mounts.
LISTINGS_PATH = "/listings/"

REGISTER_PATH = "/auth/register"

LOGIN_PATH = "/auth/login"

#: Status a request-model validation failure is answered with.
VALIDATION_REFUSED = 422

#: Status a request both contracts accept is answered with.
ACCEPTED = 200

#: Status a refused credential is answered with.
CREDENTIAL_REFUSED = 401

#: Administrators the fixtures store: the single ``admin_user`` row. The
#: administrator the seed revision grants the role to is a separate
#: account, asserted by the ``run_admin_seed`` cases below and in the
#: dedicated migration modules.
FIXTURE_ADMINISTRATORS = 1

#: Administrators the grant revision leaves stored.
SEEDED_ADMINISTRATORS = 1

#: Address revision 0002 leaves holding ``Role.ADMIN``.
MIGRATION_ADMIN_EMAIL = "test@blitzy.com"

#: Logger the grant revision records its outcome on.
AUDIT_LOGGER_NAME = "alembic.runtime.migration"

#: Members ``POST /auth/register`` nests under ``user``.
REGISTERED_USER_MEMBERS = frozenset({"id", "email"})

#: Every field :class:`backend.app.schema.user.User` declares. The
#: response model is the contract a user record is published under, and
#: the set is asserted exactly, so a column of ``users`` added to it --
#: the stored credential above all -- fails rather than reaching a body.
USER_RESPONSE_FIELDS = frozenset(
    {"id", "email", "created_at", "last_login"}
)

#: Members ``POST /auth/login`` returns.
LOGIN_MEMBERS = frozenset({"access_token", "token_type"})

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
#: with the value an attacker would submit for it. ``owner_id`` and
#: ``is_promoted`` name no column of ``listings``; ``id``,
#: ``created_at`` and ``updated_at`` are server-assigned columns; and
#: ``role`` belongs to another table.
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


def nested_text_values(payload):
    """Return every string appearing at any depth of ``payload``.

    Mappings and sequences are both descended into, so a value held
    under any key at any depth is reported.
    """
    found = []
    pending = [payload]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, (list, tuple)):
            pending.extend(current)
        elif isinstance(current, str):
            found.append(current)
    return found


def assert_no_stored_hash(response):
    """Assert ``response`` discloses no stored password hash.

    Four checks are applied: :data:`HASH_FIELD_NAME` appears as a key at
    no depth of the decoded body, no string value at any depth of the
    decoded body begins with a bcrypt prefix, the raw text names the
    field nowhere, and the raw text carries no bcrypt prefix under any
    key at all.
    """
    assert HASH_FIELD_NAME not in nested_keys(response.json())
    for value in nested_text_values(response.json()):
        assert not value.startswith(BCRYPT_PREFIXES)
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


def migrated_administrators(connection):
    """Return the addresses holding ``Role.ADMIN`` on ``connection``."""
    return [
        row[0]
        for row in connection.execute(
            text(
                "SELECT email FROM users WHERE role = :role"
                " ORDER BY email"
            ),
            {"role": Role.ADMIN.value},
        ).fetchall()
    ]


def migrated_role(connection, email):
    """Return the role stored under ``email``, or ``None``."""
    return connection.execute(
        text("SELECT role FROM users WHERE email = :email"),
        {"email": email},
    ).scalar()


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


def audit_record(captured):
    """Return the grant revision's captured records as one text block.

    Only records emitted on :data:`AUDIT_LOGGER_NAME` are included, and
    each one is rendered with its arguments applied, so the text is the
    line an operator reads.
    """
    lines = [
        record.getMessage()
        for record in captured.records
        if record.name == AUDIT_LOGGER_NAME
    ]
    assert lines, "the grant revision emitted no audit record"
    return "\n".join(lines)


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
    assert administrator_count(db) == FIXTURE_ADMINISTRATORS

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
    assert administrator_count(db) == FIXTURE_ADMINISTRATORS

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
    assert administrator_count(db) == FIXTURE_ADMINISTRATORS


def test_a_registration_without_a_role_field_stores_the_default_role(
    client, db, reset_rate_limits
):
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


def test_an_escalating_registration_adds_no_administrative_row(
    client, db, admin_user, reset_rate_limits
):
    """Assert an escalating registration adds no administrator.

    Every administrative row is read back, and both the number of rows
    and the address each one holds are asserted. The row asserted is the
    one ``admin_user`` stored; the migration's own grant is asserted in
    the dedicated migration modules.
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
    assert len(holders) == FIXTURE_ADMINISTRATORS
    assert [holder.email for holder in holders] == [admin_user.email]


def test_the_migrated_database_holds_one_administrator(
    migrated_client, migration_connection, reset_rate_limits
):
    """Assert the three properties the migrated grant must satisfy.

    The database is built by both Alembic revisions rather than from
    ``Base.metadata``. Read back afterwards: exactly one account holds
    :data:`backend.app.core.authorization.Role.ADMIN` and its address is
    :data:`MIGRATION_ADMIN_EMAIL`; a registration body carrying a
    ``role`` field is refused; and every account other than the seeded
    one holds :data:`Role.REGISTERED`.
    """
    assert migrated_administrators(migration_connection) == [
        MIGRATION_ADMIN_EMAIL
    ]

    refusal = migrated_client.post(
        REGISTER_PATH,
        json={
            "email": ESCALATION_EMAIL,
            "password": VALID_TEST_PASSWORD,
            "role": Role.ADMIN.value,
        },
    )
    assert refusal.status_code == VALIDATION_REFUSED

    accepted = migrated_client.post(
        REGISTER_PATH,
        json={
            "email": ORDINARY_EMAIL,
            "password": VALID_TEST_PASSWORD,
        },
    )
    assert accepted.status_code == ACCEPTED

    assert migrated_administrators(migration_connection) == [
        MIGRATION_ADMIN_EMAIL
    ]
    assert migrated_role(
        migration_connection, ORDINARY_EMAIL
    ) == Role.REGISTERED.value
    assert migrated_role(migration_connection, ESCALATION_EMAIL) is None


def test_the_seed_revision_grants_the_role_to_the_registered_target(
    client, db, run_admin_seed, admin_seed_revision, reset_rate_limits,
    caplog,
):
    """Assert the revision promotes the registered target account.

    The account is created by the registration endpoint, so it enters the
    revision holding the role a registration stores. The revision is then
    run, and the promotion, the resulting administrator set and the audit
    record are all asserted.
    """
    registered = client.post(
        REGISTER_PATH,
        json={
            "email": admin_seed_revision.ADMIN_EMAIL,
            "password": VALID_TEST_PASSWORD,
        },
    )
    assert registered.status_code == ACCEPTED

    before = stored_user(db, admin_seed_revision.ADMIN_EMAIL)
    assert before is not None
    assert before.role == Role.REGISTERED.value
    assert administrators(db) == []

    with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER_NAME):
        run_admin_seed()

    holders = administrators(db)
    assert [holder.email for holder in holders] == [
        admin_seed_revision.ADMIN_EMAIL
    ]
    assert len(holders) == SEEDED_ADMINISTRATORS
    assert holders[0].id == before.id

    record = audit_record(caplog)
    assert admin_seed_revision.ADMIN_EMAIL in record
    assert "granted the role to the stored account" in record
    assert "administrator count is 1" in record


def test_the_seed_revision_seeds_the_target_when_it_is_absent(
    client, db, run_admin_seed, admin_seed_revision, reset_rate_limits,
    caplog,
):
    """Assert the revision stores the target when it is absent.

    The stored row is asserted to hold the administrative role and a
    credential no password verifies against, and a login attempt for it
    is asserted to be refused.
    """
    assert stored_user(db, admin_seed_revision.ADMIN_EMAIL) is None

    with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER_NAME):
        run_admin_seed()

    seeded = stored_user(db, admin_seed_revision.ADMIN_EMAIL)
    assert seeded is not None
    assert seeded.role == Role.ADMIN.value
    assert administrator_count(db) == SEEDED_ADMINISTRATORS

    assert not seeded.hashed_password.startswith(BCRYPT_PREFIXES)
    assert not verify_password(
        VALID_TEST_PASSWORD, seeded.hashed_password
    )
    assert not verify_password(
        admin_seed_revision.LOCKED_CREDENTIAL, seeded.hashed_password
    )

    refused = client.post(
        LOGIN_PATH,
        json={
            "email": admin_seed_revision.ADMIN_EMAIL,
            "password": VALID_TEST_PASSWORD,
        },
    )
    assert refused.status_code == CREDENTIAL_REFUSED

    record = audit_record(caplog)
    assert "inserted the account and granted it the role" in record


def test_the_seed_revision_is_idempotent(
    db, run_admin_seed, admin_seed_revision, caplog
):
    """Assert a second run writes nothing and still holds the shape."""
    run_admin_seed()
    first = administrators(db)
    assert len(first) == SEEDED_ADMINISTRATORS

    with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER_NAME):
        run_admin_seed()

    second = administrators(db)
    assert [holder.id for holder in second] == [
        holder.id for holder in first
    ]
    assert len(second) == SEEDED_ADMINISTRATORS

    record = audit_record(caplog)
    assert "left the account holding the role it already held" in record


def test_the_seed_revision_refuses_a_foreign_administrator(
    db, admin_user, run_admin_seed, admin_seed_revision
):
    """Assert the revision refuses to run beside another administrator.

    The fixture-seeded administrator holds an address the revision does
    not name. The run is asserted to raise and to leave every stored role
    as it was.
    """
    with pytest.raises(RuntimeError) as refusal:
        run_admin_seed()

    assert Role.ADMIN.value in str(refusal.value)
    assert [holder.email for holder in administrators(db)] == [
        admin_user.email
    ]
    assert stored_user(db, admin_seed_revision.ADMIN_EMAIL) is None


def test_the_seed_revision_downgrade_returns_the_account_to_registered(
    db, run_admin_seed, admin_seed_revision, caplog
):
    """Assert the downgrade demotes that one account and reports it.

    The demotion is asserted on the stored row, and the second downgrade
    is asserted to report that it changed nothing.
    """
    run_admin_seed()
    assert administrator_count(db) == SEEDED_ADMINISTRATORS

    with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER_NAME):
        run_admin_seed("downgrade")

    demoted = stored_user(db, admin_seed_revision.ADMIN_EMAIL)
    assert demoted is not None
    assert demoted.role == Role.REGISTERED.value
    assert administrator_count(db) == 0
    assert "Returned" in audit_record(caplog)

    caplog.clear()
    with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER_NAME):
        run_admin_seed("downgrade")

    assert administrator_count(db) == 0
    assert "unchanged" in audit_record(caplog)


def test_no_credential_response_carries_a_stored_password_hash(
    client, db, reset_rate_limits
):

    """Assert the registration and login responses disclose no hash.

    Both bodies are walked to every depth. Each is asserted to carry the
    members its contract declares, and to disclose no stored hash under
    any key at any depth. A member the contract does not declare is
    permitted; a stored hash is not.
    """
    registered = client.post(
        REGISTER_PATH,
        json={
            "email": ORDINARY_EMAIL,
            "password": VALID_TEST_PASSWORD,
        },
    )

    assert registered.status_code == ACCEPTED
    assert REGISTERED_USER_MEMBERS <= set(registered.json()["user"])
    assert_no_stored_hash(registered)

    logged_in = client.post(
        LOGIN_PATH,
        json={
            "email": ORDINARY_EMAIL,
            "password": VALID_TEST_PASSWORD,
        },
    )

    assert logged_in.status_code == ACCEPTED
    assert LOGIN_MEMBERS <= set(logged_in.json())
    assert_no_stored_hash(logged_in)

    stored = stored_user(db, ORDINARY_EMAIL)
    assert stored is not None
    assert stored.hashed_password.startswith(BCRYPT_PREFIXES)


def test_the_user_response_contract_declares_no_credential_field():
    """Assert the user response model cannot carry a stored credential.

    The endpoints build their credential responses as explicit
    dictionaries, so the cases above cover what those routes actually
    return. This case covers the declared contract itself, which no route
    currently returns: it is the model a later response would be built
    from, and a hash field added to it would otherwise reach a body with
    nothing failing.

    The assertion is on the exact declared field set rather than on the
    absence of one name, so a credential added under any name -- and any
    other column of ``users`` added by accident -- fails here.
    """
    assert set(UserResponse.__fields__) == USER_RESPONSE_FIELDS
    assert HASH_FIELD_NAME not in UserResponse.__fields__
    for name in UserResponse.__fields__:
        assert "password" not in name
        assert "secret" not in name
    assert UserResponse.Config.orm_mode is True


def test_the_user_response_contract_covers_the_credential_responses():
    """Assert the declared contract carries what the routes return.

    ``POST /auth/register`` nests :data:`REGISTERED_USER_MEMBERS` under
    ``user``. Those members are declared by the model, so the model is
    the wider contract and the routes disclose a subset of it.
    """
    assert REGISTERED_USER_MEMBERS <= set(UserResponse.__fields__)


def test_no_listing_response_carries_a_stored_password_hash(
    client, db, admin_user, auth_header_factory
):
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
