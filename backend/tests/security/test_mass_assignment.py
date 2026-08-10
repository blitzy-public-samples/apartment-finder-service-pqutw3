import logging
from datetime import datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from backend.app.api.endpoints import listings as listings_module
from backend.app.core.authorization import Role
from backend.app.core.logging import BASE_LOGGER_NAME, configure_logging
from backend.app.db.database import get_db
from backend.app.main import app
from backend.app.core.security import verify_password
from backend.app.db.models import Listing as ListingModel, User
from backend.app.schema.user import User as UserResponse
from backend.tests.support import (
    VALID_TEST_PASSWORD,
    migration_records_reach,
)

LISTINGS_PATH = "/listings/"


REGISTER_PATH = "/auth/register"

LOGIN_PATH = "/auth/login"

VALIDATION_REFUSED = 422

ACCEPTED = 200

CREDENTIAL_REFUSED = 401

FIXTURE_ADMINISTRATORS = 1

SEEDED_ADMINISTRATORS = 1

MIGRATION_ADMIN_EMAIL = "test@blitzy.com"

AUDIT_LOGGER_NAME = "alembic.runtime.migration"

REGISTERED_USER_MEMBERS = frozenset({"id", "email"})

USER_RESPONSE_FIELDS = frozenset(
    {"id", "email", "created_at", "last_login"}
)

LOGIN_MEMBERS = frozenset({"access_token", "token_type"})

HASH_FIELD_NAME = "hashed_password"

BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")

AVAILABLE_DATE = datetime(2026, 9, 1, 12, 30)

ESCALATION_EMAIL = "escalation.attempt@example.com"

ORDINARY_EMAIL = "ordinary.registration@example.com"

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

HOSTILE_LISTING_FIELDS = [
    pytest.param("owner_id", 999, id="owner_id"),
    pytest.param("id", 424242, id="id"),
    pytest.param("created_at", "1999-01-01T00:00:00", id="created_at"),
    pytest.param("updated_at", "1999-01-01T00:00:00", id="updated_at"),
    pytest.param("role", Role.ADMIN.value, id="role"),
    pytest.param("is_promoted", True, id="invented_field"),
]


@pytest.fixture(autouse=True)
def _migration_records(caplog):
    """Route the migration namespace's records to the capture handler.

    The namespace carries the redacting handler and does not propagate,
    so the handler ``caplog`` installs on the root logger receives none
    of its records unless it is attached to the namespace itself.
    """
    with migration_records_reach(caplog.handler):
        yield


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
    session.expire_all()
    return (
        session.query(User)
        .filter(User.role == Role.ADMIN.value)
        .count()
    )


def administrators(session):
    session.expire_all()
    return (
        session.query(User)
        .filter(User.role == Role.ADMIN.value)
        .order_by(User.id)
        .all()
    )


def migrated_administrators(connection):
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
    return connection.execute(
        text("SELECT role FROM users WHERE email = :email"),
        {"email": email},
    ).scalar()


def stored_user(session, email):
    session.expire_all()
    return (
        session.query(User)
        .filter(User.email == email)
        .one_or_none()
    )


def stored_listings(session):
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
    assert admin_seed_revision.ADMIN_REFERENCE in record
    assert admin_seed_revision.ADMIN_EMAIL not in record
    assert "granted the role to the stored account" in record
    assert "administrator count is 1" in record


def test_the_seed_revision_seeds_the_target_when_it_is_absent(
    client, db, run_admin_seed, admin_seed_revision, reset_rate_limits,
    caplog,
):
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
    assert set(UserResponse.__fields__) == USER_RESPONSE_FIELDS
    assert HASH_FIELD_NAME not in UserResponse.__fields__
    for name in UserResponse.__fields__:
        assert "password" not in name
        assert "secret" not in name
    assert UserResponse.Config.orm_mode is True


def test_the_user_response_contract_covers_the_credential_responses():
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


@pytest.fixture
def application_records():
    """Collect every record the application logger emits.

    The namespace carries the redacting handler and does not propagate,
    so a collector must be attached to it rather than to the root logger
    where ``caplog`` installs its own.
    """
    configure_logging()
    collected = []

    class Collector(logging.Handler):
        def emit(self, record):
            collected.append(record)

    handler = Collector(level=logging.DEBUG)
    logger = logging.getLogger(BASE_LOGGER_NAME)
    logger.addHandler(handler)
    try:
        yield collected
    finally:
        logger.removeHandler(handler)


@pytest.fixture
def refusing_commit(session_factory):
    """Make every request session refuse its commit.

    Returns a callable taking the text the refusal carries. The
    application's session dependency is replaced for the duration, so the
    session the handler commits is the one that refuses -- the ``db``
    fixture's session is a different one and patching it would change
    nothing. The ``client`` fixture clears the override afterwards.
    """

    def refuse_with(detail):
        def override_get_db():
            session = session_factory()

            def refuse():
                raise SQLAlchemyError(detail)

            session.commit = refuse
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_db] = override_get_db

    return refuse_with


def test_a_refused_listing_write_records_no_traceback(
    client,
    db,
    admin_user,
    auth_header_factory,
    refusing_commit,
    application_records,
):
    header = auth_header_factory(admin_user)
    refusing_commit("INSERT INTO listings ... refused")
    response = client.post(
        LISTINGS_PATH, json=ALLOWLISTED_LISTING_BODY, headers=header
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": listings_module.LISTING_NOT_STORED_DETAIL
    }

    refusals = [
        record
        for record in application_records
        if record.getMessage()
        == listings_module.LISTING_NOT_STORED_MESSAGE
    ]
    assert refusals
    for record in refusals:
        assert record.levelno == logging.ERROR
        assert record.exc_info is None
        assert "Traceback" not in repr(vars(record))
        assert record.exception_type == "SQLAlchemyError"
        assert record.reason == listings_module.REASON_NOT_STORED
        assert record.user_id == admin_user.id


def test_a_refused_listing_write_answers_without_the_statement(
    client,
    db,
    admin_user,
    auth_header_factory,
    refusing_commit,
    application_records,
):
    address = ALLOWLISTED_LISTING_BODY["street_address"]
    header = auth_header_factory(admin_user)
    refusing_commit(
        "duplicate key value violates unique constraint for " + address
    )
    response = client.post(
        LISTINGS_PATH, json=ALLOWLISTED_LISTING_BODY, headers=header
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": listings_module.LISTING_NOT_STORED_DETAIL
    }
    assert address not in response.text
    assert "duplicate key" not in response.text
    assert stored_listings(db) == []
    for record in application_records:
        assert "Traceback" not in repr(vars(record))
        assert record.exc_info is None
