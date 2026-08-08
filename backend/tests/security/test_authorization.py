"""Regression tests for the centralized authorization decision point.

The cases here cover three properties that the module previously did not
hold: an unrecognised stored role must satisfy no minimum, a refusal must
record the role the caller claimed alongside the role the row carries,
and an ownership refusal must not disclose whether the row exists.
"""

import logging
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI, Depends, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core import authorization
from backend.app.core.authorization import (
    DECISION_OBJECT_MISSING,
    DECISION_OWNERSHIP_DENIED,
    DECISION_PRINCIPAL_MISSING,
    DECISION_ROLE_DENIED,
    DECISION_ROLE_INVALID,
    REFUSAL_MESSAGE,
    Role,
    load_owned,
    parse_role,
    require_ownership,
    require_role,
    resolve_role,
    role_satisfies,
)
from backend.app.core.logging import BASE_LOGGER_NAME
from backend.app.core.security import (
    CLAIMED_ROLE_ATTRIBUTE,
    claimed_role,
    create_access_token,
    get_password_hash,
)
from backend.app.db.models import Base, Filter, User
from backend.tests.support import enforce_sqlite_foreign_keys

PASSWORD = "Str0ng-Passphrase-9"

# Values a stored role column could hold that name no member of Role.
INVALID_ROLES = [
    None,
    "",
    "   ",
    "superuser",
    "Administrator",
    "guest ish",
    "admin;--",
    0,
    3,
    True,
    ["admin"],
    {"role": "admin"},
]


class Principal:
    """A stand-in for a stored user row carrying an arbitrary role."""

    def __init__(self, role, identifier=1):
        self.role = role
        self.id = identifier


@pytest.fixture
def records():
    """Collects every record the application logger emits."""
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


def refusals(records):
    """Returns the authorization refusal records among ``records``."""
    return [
        record
        for record in records
        if record.getMessage() == REFUSAL_MESSAGE
    ]


class TestInvalidRoleSatisfiesNoMinimum:
    """An unrecognised stored role is refused, never ranked."""

    @pytest.mark.parametrize("stored", INVALID_ROLES)
    def test_resolution_reports_no_role(self, stored):
        assert resolve_role(Principal(stored)) is None

    def test_resolution_reports_no_role_for_an_absent_principal(self):
        assert resolve_role(None) is None

    def test_resolution_reports_no_role_without_the_attribute(self):
        assert resolve_role(object()) is None

    @pytest.mark.parametrize("stored", INVALID_ROLES)
    @pytest.mark.parametrize("minimum", list(Role))
    def test_no_minimum_is_satisfied(self, stored, minimum):
        """Including the lowest minimum, which GUEST would satisfy."""
        assert role_satisfies(stored, minimum) is False

    @pytest.mark.parametrize("stored", ["guest", " Admin ", "PREMIUM"])
    def test_recognised_roles_still_resolve(self, stored):
        assert resolve_role(Principal(stored)) is parse_role(stored)


class TestRequireRoleDependency:
    """The dependency denies by default at every minimum."""

    def build(self, minimum):
        """Returns a client over one route guarded on ``minimum``."""
        app = FastAPI()
        dependency = require_role(minimum)

        @app.get("/guarded")
        def guarded(user: User = Depends(dependency)):
            return {"role": user.role}

        return app

    def client_for(self, minimum, principal):
        app = self.build(minimum)
        from backend.app.core.security import get_current_user

        app.dependency_overrides[get_current_user] = (
            lambda: principal
        )
        return TestClient(app, raise_server_exceptions=False)

    @pytest.mark.parametrize("stored", INVALID_ROLES)
    @pytest.mark.parametrize("minimum", list(Role))
    def test_invalid_role_is_refused_at_every_minimum(
        self, stored, minimum, records
    ):
        client = self.client_for(minimum, Principal(stored))
        response = client.get("/guarded")
        assert response.status_code == 403
        emitted = refusals(records)
        assert emitted
        assert emitted[-1].__dict__["decision"] == (
            DECISION_ROLE_INVALID
        )
        assert emitted[-1].__dict__["effective_role"] is None

    def test_absent_principal_is_refused(self, records):
        client = self.client_for(Role.GUEST, None)
        assert client.get("/guarded").status_code == 403
        assert refusals(records)[-1].__dict__["decision"] == (
            DECISION_PRINCIPAL_MISSING
        )

    def test_lower_role_is_refused_with_its_own_decision(
        self, records
    ):
        client = self.client_for(Role.ADMIN, Principal("registered"))
        assert client.get("/guarded").status_code == 403
        record = refusals(records)[-1].__dict__
        assert record["decision"] == DECISION_ROLE_DENIED
        assert record["effective_role"] == "registered"
        assert record["required_role"] == "admin"

    @pytest.mark.parametrize(
        "stored, minimum",
        [
            ("guest", Role.GUEST),
            ("registered", Role.GUEST),
            ("registered", Role.REGISTERED),
            ("premium", Role.REGISTERED),
            ("admin", Role.ADMIN),
            ("admin", Role.PREMIUM),
        ],
    )
    def test_sufficient_role_is_admitted(self, stored, minimum):
        client = self.client_for(minimum, Principal(stored))
        assert client.get("/guarded").status_code == 200

    @pytest.mark.parametrize(
        "stored", [" Admin ", "Admin", "ADMIN", "admin ", " admin"]
    )
    def test_a_non_canonical_high_privilege_value_is_refused(
        self, stored
    ):
        """Matching is exact, so a padded or recased value grants nothing.

        The value is refused whatever minimum the route declares, because
        an unrecognised stored role satisfies no minimum at all.
        """
        client = self.client_for(Role.PREMIUM, Principal(stored))
        assert client.get("/guarded").status_code == 403

    def test_an_unknown_minimum_is_refused_at_declaration(self):
        with pytest.raises(ValueError):
            require_role("superuser")


class TestClaimedRoleIsAuditable:
    """A refusal records the claimed role beside the effective one."""

    def test_claim_is_recorded_on_the_request_state(self):
        app = FastAPI()

        @app.get("/probe")
        def probe(request: Request):
            return {"claimed": claimed_role(request)}

        with TestClient(app) as client:
            assert client.get("/probe").json()["claimed"] is None

    def test_claim_reader_tolerates_an_absent_request(self):
        assert claimed_role(None) is None

    def test_refusal_names_both_the_claimed_and_effective_role(
        self, records
    ):
        """The claim is recorded even when it disagrees with the row.

        A token minted while the account held one role, presented after
        the stored role changed, is the case this makes auditable.
        """
        app = FastAPI()
        dependency = require_role(Role.ADMIN)

        @app.get("/guarded")
        def guarded(user: User = Depends(dependency)):
            return {"ok": True}

        from backend.app.core.security import get_current_user

        def override(request: Request):
            setattr(request.state, CLAIMED_ROLE_ATTRIBUTE, "admin")
            return Principal("registered")

        app.dependency_overrides[get_current_user] = override
        client = TestClient(app, raise_server_exceptions=False)
        assert client.get("/guarded").status_code == 403
        record = refusals(records)[-1].__dict__
        assert record["claimed_role"] == "admin"
        assert record["effective_role"] == "registered"

    def test_claim_never_decides_the_outcome(self, records):
        """An admin claim over a registered row is still refused."""
        app = FastAPI()
        dependency = require_role(Role.ADMIN)

        @app.get("/guarded")
        def guarded(user: User = Depends(dependency)):
            return {"ok": True}

        from backend.app.core.security import get_current_user

        def override(request: Request):
            setattr(request.state, CLAIMED_ROLE_ATTRIBUTE, "admin")
            return Principal("registered")

        app.dependency_overrides[get_current_user] = override
        client = TestClient(app, raise_server_exceptions=False)
        assert client.get("/guarded").status_code == 403

    def test_a_minted_token_carries_the_role_claim(self):
        import jwt

        from backend.app.core import security
        from backend.app.core.config import settings

        token = create_access_token(
            {"sub": "1", "role": "premium"}
        )
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=list(security.JWT_ALGORITHMS),
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
        )
        assert payload[security.ROLE_CLAIM] == "premium"


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
def two_users(db):
    users = []
    for address in ("owner@example.com", "other@example.com"):
        user = User(
            email=address,
            hashed_password=get_password_hash(PASSWORD),
            created_at=datetime.now(timezone.utc),
            role="registered",
        )
        db.add(user)
        users.append(user)
    db.commit()
    for user in users:
        db.refresh(user)
    return users


class TestOwnershipRefusalIsIndistinguishable:
    """A missing row and a foreign row answer identically."""

    def _status_and_detail(self, call):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as raised:
            call()
        return raised.value.status_code, raised.value.detail

    def test_missing_and_foreign_rows_answer_the_same(
        self, db, two_users, records
    ):
        owner, other = two_users
        owned = Filter(
            name="theirs",
            created_at=datetime.now(timezone.utc),
            user_id=other.id,
        )
        db.add(owned)
        db.commit()
        db.refresh(owned)

        missing = self._status_and_detail(
            lambda: load_owned(db, Filter, owner, id=999999)
        )
        foreign = self._status_and_detail(
            lambda: load_owned(db, Filter, owner, id=owned.id)
        )
        assert missing == foreign
        assert missing[0] == 404

    def test_the_two_cases_stay_distinct_in_the_record(
        self, db, two_users, records
    ):
        owner, other = two_users
        owned = Filter(
            name="theirs",
            created_at=datetime.now(timezone.utc),
            user_id=other.id,
        )
        db.add(owned)
        db.commit()
        db.refresh(owned)

        self._status_and_detail(
            lambda: load_owned(db, Filter, owner, id=999999)
        )
        self._status_and_detail(
            lambda: load_owned(db, Filter, owner, id=owned.id)
        )
        decisions = [
            record.__dict__["decision"] for record in refusals(records)
        ]
        assert DECISION_OBJECT_MISSING in decisions
        assert DECISION_OWNERSHIP_DENIED in decisions

    def test_an_owned_row_is_returned(self, db, two_users):
        owner, _ = two_users
        mine = Filter(
            name="mine",
            created_at=datetime.now(timezone.utc),
            user_id=owner.id,
        )
        db.add(mine)
        db.commit()
        db.refresh(mine)
        assert load_owned(db, Filter, owner, id=mine.id) is mine

    def test_a_principal_without_an_identifier_is_refused(self):
        from fastapi import HTTPException

        row = Principal("registered")
        row.user_id = 5
        with pytest.raises(HTTPException) as raised:
            require_ownership(row, None)
        assert raised.value.status_code == 404

    def test_an_unmapped_criterion_is_refused_at_the_call(
        self, db, two_users
    ):
        owner, _ = two_users
        with pytest.raises(ValueError):
            load_owned(db, Filter, owner, not_a_column=1)
        with pytest.raises(ValueError):
            load_owned(db, Filter, owner)

    def test_the_lookup_leaves_no_change_behind(self, db, two_users):
        from fastapi import HTTPException

        owner, _ = two_users
        with pytest.raises(HTTPException):
            load_owned(db, Filter, owner, id=999999)
        assert db.query(Filter).count() == 0


def test_module_publishes_the_invalid_role_decision():
    assert "DECISION_ROLE_INVALID" in authorization.__all__
    assert DECISION_ROLE_INVALID not in (
        DECISION_ROLE_DENIED,
        DECISION_OBJECT_MISSING,
        DECISION_OWNERSHIP_DENIED,
        DECISION_PRINCIPAL_MISSING,
    )
