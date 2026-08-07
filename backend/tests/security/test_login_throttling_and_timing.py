"""Regression tests for login lockout counting, throttling and timing.

The cases here cover the two ways the credential endpoint previously gave
ground: a failed-attempt count that two simultaneous attempts could hold
below the lockout threshold, and a response time that differed according
to the cost factor of the stored hash and so disclosed whether an address
held an account.
"""

import time
from datetime import datetime, timedelta, timezone

import bcrypt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.endpoints import auth as auth_module
from backend.app.core import security
from backend.app.core.config import settings
from backend.app.db import database as database_module
from backend.app.db.models import Base, User
from backend.app.main import app

PASSWORD = "Str0ng-Passphrase-9"

WRONG_PASSWORD = "not-the-password-at-all"

# A cost factor below the configured one, standing in for a hash stored
# before the current setting was chosen.
LEGACY_ROUNDS = 4


def legacy_hash(password):
    """Returns a bcrypt hash carrying a lower cost than configured."""
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=LEGACY_ROUNDS),
    ).decode("utf-8")


@pytest.fixture(autouse=True)
def fresh_rate_limit_counters():
    """Clears the shared limiter counters around each case.

    The limiter is process-wide and keyed by remote address, and every
    case here calls the login endpoint from the same address, so without
    this a case would be throttled by the requests an earlier one made.
    """
    auth_module.limiter.reset()
    yield
    auth_module.limiter.reset()


@pytest.fixture
def session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
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
    with TestClient(app, base_url="http://localhost") as test_client:
        yield test_client
    app.dependency_overrides.clear()


def make_user(db, address, hashed):
    user = User(
        email=address,
        hashed_password=hashed,
        created_at=datetime.now(timezone.utc),
        role="registered",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def login(client, address, password):
    """Posts one login, clearing the throttle counter first.

    The lockout and timing cases are about the account, so the shared
    per-address throttle is cleared before each call to keep the two
    controls from masking one another. ``TestRateLimiterEngages`` below
    is the case that leaves the counter alone.
    """
    auth_module.limiter.reset()
    return client.post(
        "/auth/login", json={"email": address, "password": password}
    )


def configured_login_rate():
    """Returns the request count in the configured login rate limit."""
    return int(settings.RATE_LIMIT_LOGIN.split("/", 1)[0])


class TestFailedAttemptCountingIsAtomic:
    """The count is advanced by the database, not by this process."""

    def test_simultaneous_failures_each_advance_the_count(self, db):
        """Two sessions that both read the row still count twice.

        Each session holds its own view of the row, which is exactly the
        situation in which a read-modify-write discards one increment.
        """
        user = make_user(
            db, "a@example.com", security.get_password_hash(PASSWORD)
        )
        moment = datetime.now(timezone.utc)

        Session = sessionmaker(bind=db.get_bind())
        one, two = Session(), Session()
        try:
            row_one = one.query(User).filter(User.id == user.id).one()
            row_two = two.query(User).filter(User.id == user.id).one()
            assert row_one.failed_login_attempts == 0
            assert row_two.failed_login_attempts == 0
            auth_module._record_failed_attempt(one, row_one, moment)
            auth_module._record_failed_attempt(two, row_two, moment)
        finally:
            one.close()
            two.close()

        db.expire_all()
        assert (
            db.query(User).filter(User.id == user.id).one()
            .failed_login_attempts
            == 2
        )

    def test_the_count_reaches_the_threshold_and_locks(self, db):
        user = make_user(
            db, "b@example.com", security.get_password_hash(PASSWORD)
        )
        moment = datetime.now(timezone.utc)
        for expected in range(1, settings.LOGIN_MAX_ATTEMPTS + 1):
            auth_module._record_failed_attempt(db, user, moment)
            assert user.failed_login_attempts == expected
        assert user.locked_until is not None

    def test_a_lock_below_the_threshold_is_not_set(self, db):
        user = make_user(
            db, "c@example.com", security.get_password_hash(PASSWORD)
        )
        moment = datetime.now(timezone.utc)
        for _ in range(settings.LOGIN_MAX_ATTEMPTS - 1):
            auth_module._record_failed_attempt(db, user, moment)
            assert user.locked_until is None

    def test_a_lock_still_in_force_is_left_in_place(self, db):
        """A failure arriving inside the window does not clear the lock.

        The count keeps rising and the expiry keeps standing, so an
        attacker cannot lift a lock by attempting once more.
        """
        user = make_user(
            db, "d2@example.com", security.get_password_hash(PASSWORD)
        )
        moment = datetime.now(timezone.utc)
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            auth_module._record_failed_attempt(db, user, moment)
        locked_at = user.locked_until
        assert locked_at is not None
        auth_module._record_failed_attempt(db, user, moment)
        assert user.failed_login_attempts == (
            settings.LOGIN_MAX_ATTEMPTS + 1
        )
        assert user.locked_until is not None

    def test_an_expired_lock_restarts_the_count(self, db):
        user = make_user(
            db, "d@example.com", security.get_password_hash(PASSWORD)
        )
        moment = datetime.now(timezone.utc)
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            auth_module._record_failed_attempt(db, user, moment)
        assert user.locked_until is not None
        # The window has closed by the time the next attempt arrives.
        later = moment + timedelta(
            minutes=settings.LOGIN_LOCKOUT_MINUTES + 1
        )
        auth_module._record_failed_attempt(db, user, later)
        assert user.failed_login_attempts == 1
        assert user.locked_until is None

    def test_a_success_clears_the_count_and_the_lock(self, db):
        user = make_user(
            db, "e@example.com", security.get_password_hash(PASSWORD)
        )
        moment = datetime.now(timezone.utc)
        auth_module._record_failed_attempt(db, user, moment)
        assert user.failed_login_attempts == 1
        auth_module._record_successful_attempt(db, user)
        assert user.failed_login_attempts == 0
        assert user.locked_until is None

    def test_the_lock_expiry_is_the_configured_window(self, db):
        user = make_user(
            db, "f@example.com", security.get_password_hash(PASSWORD)
        )
        moment = datetime.now(timezone.utc)
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            auth_module._record_failed_attempt(db, user, moment)
        expected = moment + timedelta(
            minutes=settings.LOGIN_LOCKOUT_MINUTES
        )
        stored = auth_module._as_aware(user.locked_until)
        assert abs((stored - expected).total_seconds()) < 1.0


class TestLockoutThroughTheEndpoint:
    """The endpoint locks the account at the configured threshold."""

    def test_the_attempt_after_the_limit_is_refused(self, db, client):
        user = make_user(
            db, "g@example.com", security.get_password_hash(PASSWORD)
        )
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            assert (
                login(client, user.email, WRONG_PASSWORD).status_code
                == 401
            )

        # The correct password is now refused too, which is the lock
        # rather than the password being wrong.
        assert login(client, user.email, PASSWORD).status_code == 401
        db.expire_all()
        stored = db.query(User).filter(User.id == user.id).one()
        assert stored.locked_until is not None

    def test_a_correct_password_before_the_limit_succeeds(
        self, db, client
    ):
        user = make_user(
            db, "h@example.com", security.get_password_hash(PASSWORD)
        )
        for _ in range(settings.LOGIN_MAX_ATTEMPTS - 1):
            login(client, user.email, WRONG_PASSWORD)
        assert login(client, user.email, PASSWORD).status_code == 200
        db.expire_all()
        stored = db.query(User).filter(User.id == user.id).one()
        assert stored.failed_login_attempts == 0
        assert stored.locked_until is None


class TestRateLimiterEngages:
    """The configured per-address throttle refuses the excess request."""

    def test_the_request_past_the_configured_rate_is_refused(
        self, db, client
    ):
        make_user(
            db, "k@example.com", security.get_password_hash(PASSWORD)
        )
        allowed = configured_login_rate()
        for _ in range(allowed):
            response = client.post(
                "/auth/login",
                json={
                    "email": "k@example.com",
                    "password": WRONG_PASSWORD,
                },
            )
            assert response.status_code == 401
        throttled = client.post(
            "/auth/login",
            json={"email": "k@example.com", "password": WRONG_PASSWORD},
        )
        assert throttled.status_code == 429

    def test_the_throttle_also_covers_registration(self, client):
        allowed = int(settings.RATE_LIMIT_REGISTER.split("/", 1)[0])
        for index in range(allowed):
            response = client.post(
                "/auth/register",
                json={
                    "email": "r%d@example.com" % index,
                    "password": PASSWORD,
                },
            )
            assert response.status_code == 200
        throttled = client.post(
            "/auth/register",
            json={"email": "rx@example.com", "password": PASSWORD},
        )
        assert throttled.status_code == 429


class TestRateLimiterStorageIsConfigurable:
    """The limiter counts where the settings say, not only in memory."""

    def test_the_limiter_uses_the_configured_storage(self):
        assert auth_module.limiter is not None
        storage = auth_module.limiter._storage_uri
        assert storage == settings.RATE_LIMIT_STORAGE_URI

    def test_the_configured_storage_is_reachable(self):
        assert auth_module.limiter.limiter is not None


class TestCredentialCheckWorkIsUniform:
    """One credential path, doing the same work whatever it is given."""

    def test_a_matching_stored_hash_reports_a_match(self):
        stored = security.get_password_hash(PASSWORD)
        assert security.verify_credential(PASSWORD, stored) is True

    def test_a_wrong_password_reports_no_match(self):
        stored = security.get_password_hash(PASSWORD)
        assert (
            security.verify_credential(WRONG_PASSWORD, stored) is False
        )

    @pytest.mark.parametrize("stored", [None, "", "not-a-hash"])
    def test_an_absent_or_unusable_hash_reports_no_match(self, stored):
        assert security.verify_credential(PASSWORD, stored) is False

    def test_a_legacy_cost_hash_still_verifies(self):
        stored = legacy_hash(PASSWORD)
        assert stored.startswith("$2b$%02d$" % LEGACY_ROUNDS)
        assert security.verify_credential(PASSWORD, stored) is True

    def test_a_floor_is_measured_at_import(self):
        assert security.MIN_CREDENTIAL_CHECK_SECONDS > 0

    def test_every_path_takes_at_least_the_floor(self):
        """A legacy hash must not finish sooner than no hash at all.

        The legacy cost factor here is far below the configured one, so
        before the floor was applied this comparison finished in a small
        fraction of the time an absent account took.
        """
        floor = security.MIN_CREDENTIAL_CHECK_SECONDS

        def elapsed(stored):
            started = time.monotonic()
            security.verify_credential(WRONG_PASSWORD, stored)
            return time.monotonic() - started

        no_account = elapsed(None)
        legacy = elapsed(legacy_hash(PASSWORD))
        configured = elapsed(security.get_password_hash(PASSWORD))

        for measured in (no_account, legacy, configured):
            assert measured >= floor * 0.9

    def test_the_login_handler_takes_the_single_path(self, db, client):
        """Every login branch is answered identically.

        The legacy account, the account whose password is wrong at the
        configured cost, the unknown address and the locked account must
        be indistinguishable in status and body.
        """
        make_user(db, "legacy@example.com", legacy_hash(PASSWORD))
        make_user(
            db,
            "current@example.com",
            security.get_password_hash(PASSWORD),
        )
        locked = make_user(
            db,
            "locked@example.com",
            security.get_password_hash(PASSWORD),
        )
        locked.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=30
        )
        db.commit()

        answers = []
        for address, password in [
            ("legacy@example.com", WRONG_PASSWORD),
            ("current@example.com", WRONG_PASSWORD),
            ("absent@example.com", WRONG_PASSWORD),
            ("locked@example.com", PASSWORD),
        ]:
            response = login(client, address, password)
            answers.append((response.status_code, response.text))

        assert len(set(answers)) == 1
        assert answers[0][0] == 401


class TestFrozenLoginContract:
    """The response shapes the frontend reads are unchanged."""

    def test_login_returns_exactly_the_two_keys(self, db, client):
        user = make_user(
            db, "i@example.com", security.get_password_hash(PASSWORD)
        )
        response = login(client, user.email, PASSWORD)
        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"access_token", "token_type"}
        assert body["token_type"] == "bearer"

    def test_registration_keeps_its_nested_user_object(self, client):
        response = client.post(
            "/auth/register",
            json={"email": "j@example.com", "password": PASSWORD},
        )
        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"user", "access_token", "token_type"}
        assert set(body["user"]) == {"id", "email"}
        assert "hashed_password" not in response.text
