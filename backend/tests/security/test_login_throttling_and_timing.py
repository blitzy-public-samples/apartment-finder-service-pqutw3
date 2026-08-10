"""Regression tests for login lockout counting, throttling and timing.

The cases here cover three ways the credential endpoint gave ground: a
failed-attempt count that two simultaneous attempts could hold below the
lockout threshold, a response time that differed according to the cost
factor of the stored hash, and a refusal branch whose attempt-counting
statements made it slower than the branch that found no account.

The refusal branches are covered at two levels. The primary gate counts
work rather than time: each branch is driven through the endpoint while
the credential check, the hash comparisons inside it and the call that
holds the refusal to its budget are counted, so a branch that
short-circuits fails whatever the host is doing. Alongside it, a
confidence measurement carries the ``timing`` mark and reads a wall
clock -- it measures the elapsed time of complete requests and compares
each branch against the others. Because every refusal is padded out to
one budget, the time a branch takes is a floor that the machine can only
add to, so the branches are sampled round-robin and each is read at its
shortest: the reading that carries the least noise and therefore the
clearest view of the work the branch does. Deselecting the mark loses no
coverage of the control, because the counted case asserts the same
property without a clock.

The rate limiter's storage is covered by operating it -- a health probe
answered, a counter incremented, read back and released -- rather than by
finding the object in place, so a storage that constructed but could not
be reached fails here.

The frozen login and registration contracts are asserted as a floor
rather than as an exact set: every required member must be present and
carry its required value, and no member the response must never carry may
appear. The AAP permits a field to be added and forbids one being
removed, so an exact-equality assertion would fail on a permitted change
while an added credential field would pass one that only counted keys.
"""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest import mock

import bcrypt
import pytest
from fastapi.testclient import TestClient
from limits import RateLimitItemPerMinute
from sqlalchemy import create_engine, event
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.endpoints import auth as auth_module
from backend.app.core import security
from backend.app.core.config import settings
from backend.app.db import database as database_module
from backend.app.db.models import (
    LOGIN_ATTEMPT_SLOT_COUNT,
    Base,
    LoginAttemptSlot,
    User,
)
from backend.app.main import app
from backend.tests.support import enforce_sqlite_foreign_keys

PASSWORD = "Str0ng-Passphrase-9"

WRONG_PASSWORD = "not-the-password-at-all"

#: A signing key other than the configured one, used to show the
#: throttling bucket is keyed rather than a bare digest.
OTHER_SIGNING_KEY = "a-different-signing-key-of-length"

# A cost factor below the configured one, standing in for a hash stored
# before the current setting was chosen.
LEGACY_ROUNDS = 4

# A cost factor above the supported ceiling.
UNSUPPORTED_ROUNDS = security.MAX_SUPPORTED_BCRYPT_COST + 1

# Rounds measured. Each round issues one request per refusal branch, so a
# slowdown lasting part of the measurement reaches every branch rather
# than whichever one was being sampled at the time, and each branch has
# this many chances at an unhindered reading.
TIMING_SAMPLES = 7

# Seconds two branch readings may differ by. It is below the cost of one
# comparison at the supported ceiling, so an extra or missing comparison
# fails the case.
TIMING_TOLERANCE_SECONDS = max(
    0.15, security.MIN_LOGIN_REFUSAL_SECONDS * 0.35
)

#: Members the login response must carry. The frozen contract fixes these
#: as a floor rather than as the whole body: a field may be added, none
#: may be removed, so the assertions below test containment.
REQUIRED_LOGIN_FIELDS = frozenset({"access_token", "token_type"})

#: Members the registration response must carry.
REQUIRED_REGISTRATION_FIELDS = frozenset(
    {"user", "access_token", "token_type"}
)

#: Members the nested user object must carry.
REQUIRED_USER_FIELDS = frozenset({"id", "email"})

#: Names no authentication response may carry at any depth. Each would
#: either disclose a credential or expose lockout state an attacker uses
#: to time its next attempt, so an added field bearing one of these is a
#: regression even though adding fields is otherwise permitted.
FORBIDDEN_RESPONSE_FIELDS = (
    "hashed_password",
    "password",
    "salt",
    "secret",
    "secret_key",
    "failed_login_attempts",
    "locked_until",
)


#: Key the storage cases operate on. It is namespaced away from every key
#: the application uses and is released in a ``finally``, so operating it
#: leaves the shared counters as they were found.
STORAGE_PROBE_KEY = "blitzy-storage-probe"

#: Seconds the probe key is allowed to live, had it not been released.
STORAGE_PROBE_EXPIRY_SECONDS = 60

#: Identity and allowance the strategy case counts against.
STORAGE_PROBE_IDENTITY = "blitzy-storage-probe-identity"

STORAGE_PROBE_LIMIT = 5


def assert_carries_no_sensitive_field(payload):
    """Fails if ``payload`` names a forbidden field at any depth."""
    pending = [payload]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            for name, value in current.items():
                assert name not in FORBIDDEN_RESPONSE_FIELDS, name
                pending.append(value)
        elif isinstance(current, list):
            pending.extend(current)


# Samples taken when one credential check is measured against another.
# The shortest is kept, for the reason
# TestRefusalBranchesTakeTheSameTime._measure_branches records: each check
# is padded out to a floor the machine can only add to.
COST_SAMPLES = 3

# How much longer a refused check may take than the most expensive
# supported one. Both are held to the same budget, so the ratio between
# them isolates the work each does rather than the budget they share. A
# refusal that compared the stored hash would take about half again as
# long, because UNSUPPORTED_ROUNDS is one above the ceiling and so costs
# twice a comparison at it.
REFUSAL_COST_TOLERANCE = 1.3


def hash_at(password, rounds):
    """Returns a bcrypt hash of ``password`` at ``rounds``."""
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=rounds),
    ).decode("utf-8")


def shortest_credential_check(stored, expected):
    """Returns the shortest of several checks of PASSWORD against ``stored``.

    The result of every check is asserted as it is measured, so a check
    that stopped returning what it should cannot be read as a fast one.
    """
    readings = []
    for _ in range(COST_SAMPLES):
        started = time.monotonic()
        assert security.verify_credential(PASSWORD, stored) is expected
        readings.append(time.monotonic() - started)
    return min(readings)


def legacy_hash(password):
    """Returns a bcrypt hash carrying a lower cost than configured."""
    return hash_at(password, LEGACY_ROUNDS)


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
    """The limiter counts where the settings say, not only in memory.

    Reachability is established by operating the storage rather than by
    finding an object in place: a health probe is answered, and a counter
    is incremented, read back and released. A storage that constructed but
    could not be reached would satisfy the object check and fail these.
    """

    def storage(self):
        """Returns the backend the limiter's strategy counts through."""
        strategy = auth_module.limiter.limiter
        assert strategy is not None
        backend = strategy.storage
        assert backend is not None
        return backend

    def test_the_limiter_uses_the_configured_storage(self):
        assert auth_module.limiter is not None
        storage = auth_module.limiter._storage_uri
        assert storage == settings.RATE_LIMIT_STORAGE_URI

    def test_the_configured_storage_answers_a_health_probe(self):
        assert self.storage().check() is True

    def test_the_configured_storage_counts_and_releases_a_key(self):
        backend = self.storage()
        key = STORAGE_PROBE_KEY
        backend.clear(key)
        try:
            assert backend.get(key) == 0
            assert backend.incr(key, STORAGE_PROBE_EXPIRY_SECONDS) == 1
            assert backend.get(key) == 1
            assert backend.incr(key, STORAGE_PROBE_EXPIRY_SECONDS) == 2
            assert backend.get(key) == 2
        finally:
            backend.clear(key)
        assert backend.get(key) == 0

    def test_the_strategy_records_a_hit_through_that_storage(self):
        """The strategy the limiter holds counts against the backend."""
        backend = self.storage()
        item = RateLimitItemPerMinute(STORAGE_PROBE_LIMIT)
        strategy = auth_module.limiter.limiter
        strategy.clear(item, STORAGE_PROBE_IDENTITY)
        try:
            assert strategy.hit(item, STORAGE_PROBE_IDENTITY) is True
            assert backend.get(item.key_for(STORAGE_PROBE_IDENTITY)) == 1
        finally:
            strategy.clear(item, STORAGE_PROBE_IDENTITY)
        assert backend.get(item.key_for(STORAGE_PROBE_IDENTITY)) == 0


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

    @pytest.mark.parametrize(
        "shape", ["absent", "legacy", "configured", "unusable"]
    )
    def test_every_path_is_held_to_the_floor(self, shape, monkeypatch):
        """The floor is applied on every path, counted not timed.

        This is the deterministic form of the measurement below: whatever
        it is given, the check ends by holding itself to the credential
        budget, so a path that returned early would not reach the call and
        would fail here on any machine.
        """
        stored = {
            "absent": None,
            "legacy": legacy_hash(PASSWORD),
            "configured": security.get_password_hash(PASSWORD),
            "unusable": "not-a-hash",
        }[shape]
        budgets = []
        real_pad = security._pad_until

        def pad(started, budget):
            budgets.append(budget)
            return real_pad(started, budget)

        monkeypatch.setattr(security, "_pad_until", pad)
        security.verify_credential(WRONG_PASSWORD, stored)

        assert budgets == [security.MIN_CREDENTIAL_CHECK_SECONDS], shape

    @pytest.mark.timing
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


class TestStoredCostRangeIsBounded:
    """A stored cost factor outside the supported range is refused."""

    def test_the_ceiling_covers_the_configured_cost(self):
        assert security.MAX_SUPPORTED_BCRYPT_COST >= (
            settings.BCRYPT_ROUNDS
        )
        assert security.MAX_SUPPORTED_BCRYPT_COST >= (
            security.INHERITED_BCRYPT_COST
        )
        assert security.MIN_SUPPORTED_BCRYPT_COST <= LEGACY_ROUNDS

    def test_the_decoy_carries_the_ceiling(self):
        assert security.stored_bcrypt_cost(security.DECOY_HASH) == (
            security.MAX_SUPPORTED_BCRYPT_COST
        )

    def test_a_hash_at_the_ceiling_still_verifies(self):
        stored = hash_at(
            PASSWORD, security.MAX_SUPPORTED_BCRYPT_COST
        )
        assert security.verify_credential(PASSWORD, stored) is True

    def test_a_hash_above_the_ceiling_is_refused(self):
        stored = hash_at(PASSWORD, UNSUPPORTED_ROUNDS)
        assert security.stored_bcrypt_cost(stored) == UNSUPPORTED_ROUNDS
        assert security.verify_password(PASSWORD, stored) is False
        assert security.verify_credential(PASSWORD, stored) is False

    def test_a_hash_above_the_ceiling_is_recorded(self):
        stored = hash_at(PASSWORD, UNSUPPORTED_ROUNDS)
        records = []
        with mock.patch.object(
            security.logger,
            "error",
            lambda message, **kwargs: records.append((message, kwargs)),
        ):
            security.verify_password(PASSWORD, stored)
        assert [message for message, _ in records] == [
            security.UNSUPPORTED_COST_MESSAGE
        ]
        fields = records[0][1]["extra"]
        assert fields["stored_cost"] == UNSUPPORTED_ROUNDS
        assert fields["max_supported_cost"] == (
            security.MAX_SUPPORTED_BCRYPT_COST
        )
        assert stored not in str(records)

    @pytest.mark.parametrize(
        "cost,expected",
        [
            (None, 2),
            (UNSUPPORTED_ROUNDS, 1),
        ],
    )
    def test_a_hash_above_the_ceiling_is_never_compared(
        self, cost, expected, monkeypatch
    ):
        """The over-ceiling hash is refused rather than compared.

        This is the deterministic form of the measurement below. A
        credential check performs two comparisons -- one against the stored
        hash and one against the decoy -- and a stored hash whose cost is
        above the supported ceiling is refused before the first of them, so
        exactly one comparison is made. Counting them proves the expensive
        comparison never runs, without asserting anything about how long
        the machine took.
        """
        stored = (
            security.get_password_hash(PASSWORD)
            if cost is None
            else hash_at(PASSWORD, cost)
        )
        comparisons = []
        real_checkpw = bcrypt.checkpw

        def checkpw(candidate, stored_hash):
            comparisons.append(stored_hash)
            return real_checkpw(candidate, stored_hash)

        monkeypatch.setattr(bcrypt, "checkpw", checkpw)
        security.verify_credential(PASSWORD, stored)

        assert len(comparisons) == expected, comparisons
        if expected == 1:
            assert comparisons[0] == security.DECOY_HASH.encode("utf-8")

    @pytest.mark.timing
    def test_a_hash_above_the_ceiling_costs_no_more_than_a_supported_one(

        self,
    ):
        """Refusing an unsupported cost is not slower than accepting one.

        The refusal is reached without comparing against the stored hash,
        so it performs one comparison and then waits out the same budget a
        supported check waits out. That is the property: an unsupported
        cost factor neither costs the server more nor reveals itself in
        the time the check takes.

        The reference is measured in this run rather than read from
        ``MIN_CREDENTIAL_CHECK_SECONDS``, which is calibrated once when
        the module is imported. A comparison on a loaded host can cost
        several times what it did at import, so an assertion against that
        constant compares a later measurement with an earlier calibration
        and fails while the property still holds. Comparing two checks
        taken together removes the machine from the comparison, because
        both carry whatever the host is doing at the time.
        """
        supported = hash_at(PASSWORD, security.MAX_SUPPORTED_BCRYPT_COST)
        refused = hash_at(PASSWORD, UNSUPPORTED_ROUNDS)

        reference = shortest_credential_check(supported, True)
        measured = shortest_credential_check(refused, False)

        assert measured < reference * REFUSAL_COST_TOLERANCE, (
            measured,
            reference,
        )

    @pytest.mark.parametrize(
        "cost", [LEGACY_ROUNDS, security.MIN_SUPPORTED_BCRYPT_COST]
    )
    def test_a_lower_cost_hash_still_verifies(self, cost):
        stored = hash_at(PASSWORD, cost)
        assert security.verify_credential(PASSWORD, stored) is True


class TestRefusalBranchesDoTheSameWork:
    """Every login refusal performs the same work, counted not timed.

    This is the primary gate on the refusal branches, and it reads no
    clock. Each branch is driven through the endpoint while the three
    calls that make the branches indistinguishable are counted: the single
    credential check, the two hash comparisons inside it, and the single
    call that holds the refusal to its budget. A branch that short-circuits
    -- the defect M-1 named, where an unknown address skipped the
    comparison an existing one performed -- changes one of these counts
    and fails here regardless of how loaded the host is.

    The wall-clock case that follows measures the same property end to end
    and is classified separately, because a measurement of elapsed time
    cannot be made independent of the machine taking it.
    """

    #: How many times one refusal calls the credential check.
    EXPECTED_CREDENTIAL_CHECKS = 1

    #: How many hash comparisons one credential check performs: one
    #: against the stored or stand-in hash, one against the decoy.
    EXPECTED_COMPARISONS = 2

    #: How many times one refusal holds itself to the refusal budget.
    EXPECTED_EQUALIZATIONS = 1

    @staticmethod
    def counted(monkeypatch):
        """Counts the calls that make the refusal branches uniform."""
        counts = {
            "credential_checks": 0,
            "comparisons": 0,
            "equalizations": 0,
        }
        real_credential = security.verify_credential
        real_password = security.verify_password
        real_equalize = security.equalize_login_refusal

        def credential(plain, stored):
            counts["credential_checks"] += 1
            return real_credential(plain, stored)

        def password(plain, stored):
            counts["comparisons"] += 1
            return real_password(plain, stored)

        def equalize(started):
            counts["equalizations"] += 1
            return real_equalize(started)

        # The endpoint module binds these names at import, so both the
        # module that defines them and the module that calls them are
        # patched.
        monkeypatch.setattr(security, "verify_password", password)
        monkeypatch.setattr(security, "verify_credential", credential)
        monkeypatch.setattr(auth_module, "verify_credential", credential)
        monkeypatch.setattr(
            auth_module, "equalize_login_refusal", equalize
        )
        return counts

    def branches(self, db):
        """Seeds the four refusal branches and returns their credentials."""
        make_user(
            db,
            "current@example.com",
            security.get_password_hash(PASSWORD),
        )
        make_user(
            db,
            "expensive@example.com",
            hash_at(PASSWORD, UNSUPPORTED_ROUNDS),
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
        return {
            "unknown": ("absent@example.com", WRONG_PASSWORD),
            "wrong_password": ("current@example.com", WRONG_PASSWORD),
            "locked": ("locked@example.com", PASSWORD),
            "unsupported_cost": (
                "expensive@example.com",
                WRONG_PASSWORD,
            ),
        }

    @pytest.mark.parametrize(
        "branch",
        ["unknown", "wrong_password", "locked", "unsupported_cost"],
    )
    def test_each_refusal_branch_does_the_counted_work(
        self, branch, db, client, monkeypatch
    ):
        credentials = self.branches(db)
        address, password = credentials[branch]
        counts = self.counted(monkeypatch)

        response = login(client, address, password)

        assert response.status_code == 401, response.text
        assert counts["credential_checks"] == (
            self.EXPECTED_CREDENTIAL_CHECKS
        ), (branch, counts)
        assert counts["comparisons"] == self.EXPECTED_COMPARISONS, (
            branch,
            counts,
        )
        assert counts["equalizations"] == (
            self.EXPECTED_EQUALIZATIONS
        ), (branch, counts)

    def test_every_branch_answers_with_one_identical_refusal(
        self, db, client
    ):
        """No branch is distinguishable by its status, body or headers."""
        credentials = self.branches(db)
        answers = {}
        for name, (address, password) in credentials.items():
            response = login(client, address, password)
            answers[name] = (
                response.status_code,
                response.json(),
                response.headers.get("content-type"),
            )

        distinct = set(
            (status, repr(body), content_type)
            for status, body, content_type in answers.values()
        )
        assert len(distinct) == 1, answers
        status, body, _ = list(answers.values())[0]
        assert status == 401
        assert body == {"detail": auth_module.INVALID_CREDENTIALS_DETAIL}

    def test_the_refusal_budget_covers_the_credential_budget(self):
        """The refusal budget is the wider of the two, deterministically."""
        assert security.MIN_LOGIN_REFUSAL_SECONDS > (
            security.MIN_CREDENTIAL_CHECK_SECONDS
        )
        assert security.REFUSAL_WORK_ALLOWANCE > 0

    #: Selects one refusal issues: the account lookup, then the read of
    #: the row it takes its write lock on.
    EXPECTED_SELECTS = 2

    #: Writes one refusal issues: the single update it commits.
    EXPECTED_UPDATES = 1

    @staticmethod
    def counted_statements(session_factory):
        """Counts the statements issued against the case's database.

        The listener records the verb of every statement the engine
        executes. ``FOR UPDATE`` is not counted separately: SQLite accepts
        the clause and emits nothing for it, so the shape is counted in a
        form both engines report identically, and
        ``test_the_throttle_reads_take_a_write_lock`` asserts the clause
        itself against the dialect that implements it.
        """
        engine = session_factory.kw["bind"]
        counts = {"selects": 0, "updates": 0, "inserts": 0, "deletes": 0}
        verbs = {
            "SELECT": "selects",
            "UPDATE": "updates",
            "INSERT": "inserts",
            "DELETE": "deletes",
        }

        def record(conn, cursor, statement, parameters, context, many):
            """Records the verb of one executed statement."""
            head = statement.lstrip().split(None, 1)
            if head and head[0].upper() in verbs:
                counts[verbs[head[0].upper()]] += 1

        event.listen(engine, "before_cursor_execute", record)
        counts["_stop"] = lambda: event.remove(
            engine, "before_cursor_execute", record
        )
        return counts

    @pytest.mark.parametrize(
        "branch",
        ["unknown", "wrong_password", "locked", "unsupported_cost"],
    )
    def test_each_refusal_branch_issues_the_same_database_work(
        self, branch, db, client, session_factory
    ):
        """Every branch reads one row under lock, updates it and commits.

        This is the F6 control. The branch that found no account and the
        branch whose account is already locked previously issued no write
        at all, while the wrong-password branch took a write lock on the
        account row and updated it. A wait on a row lock is unbounded and
        the refusal budget can only add time, so the branch that wrote was
        distinguishable by elapsed time whenever its row was contended.
        Each branch now issues the same statements; only the table
        differs, because the failed-attempt count belongs to an account
        while the other branches have none to count against.
        """
        credentials = self.branches(db)
        address, password = credentials[branch]
        counts = self.counted_statements(session_factory)
        try:
            response = login(client, address, password)
        finally:
            counts.pop("_stop")()

        assert response.status_code == 401, response.text
        assert counts["selects"] == self.EXPECTED_SELECTS, (branch, counts)
        assert counts["updates"] == self.EXPECTED_UPDATES, (branch, counts)
        assert counts["inserts"] == 0, (branch, counts)
        assert counts["deletes"] == 0, (branch, counts)

    def test_the_throttle_reads_take_a_write_lock(self):
        """Both throttle reads request the same row-level lock.

        Asserted against the PostgreSQL dialect, which is the deployed one
        and the one that implements the clause.
        """
        dialect = postgresql.dialect()
        account = (
            Session().query(User).filter(User.id == 1).with_for_update()
        )
        slot = (
            Session()
            .query(LoginAttemptSlot)
            .filter(LoginAttemptSlot.bucket == 1)
            .with_for_update()
        )

        for statement in (account, slot):
            compiled = str(statement.statement.compile(dialect=dialect))
            assert "FOR UPDATE" in compiled.upper(), compiled

    def test_no_refusal_branch_inserts_or_removes_a_throttle_row(
        self, db, client
    ):
        """The throttle table is a fixed set of rows, never grown.

        A branch that inserted its own row would be distinguishable from
        one that updated an existing row, and an address would be able to
        grow the table.
        """
        credentials = self.branches(db)
        before = db.query(LoginAttemptSlot).count()
        assert before == LOGIN_ATTEMPT_SLOT_COUNT

        for address, password in credentials.values():
            assert login(client, address, password).status_code == 401

        db.expire_all()
        assert db.query(LoginAttemptSlot).count() == before

    def test_a_locked_account_advances_the_bucket_not_the_account(
        self, db, client
    ):
        """The locked branch writes, and writes nowhere countable.

        The account's failed-attempt count and lock expiry are both left
        exactly as the lockout set them, so the write that equalizes the
        branch cannot extend a lock or advance a count.
        """
        credentials = self.branches(db)
        address, password = credentials["locked"]
        locked = db.query(User).filter(User.email == address).one()
        attempts_before = locked.failed_login_attempts
        locked_until_before = locked.locked_until
        bucket = security.login_attempt_slot(address)
        slot_before = (
            db.query(LoginAttemptSlot)
            .filter(LoginAttemptSlot.bucket == bucket)
            .one()
            .attempts
        )

        assert login(client, address, password).status_code == 401

        db.expire_all()
        after = db.query(User).filter(User.email == address).one()
        assert after.failed_login_attempts == attempts_before
        assert after.locked_until == locked_until_before
        slot_after = (
            db.query(LoginAttemptSlot)
            .filter(LoginAttemptSlot.bucket == bucket)
            .one()
        )
        assert slot_after.attempts == slot_before + 1
        assert slot_after.observed_at is not None

    def test_the_bucket_is_keyed_normalized_and_in_range(self):
        """The bucket is a keyed digest of the normalized address.

        Keying it means which addresses share a bucket is not computable
        without the signing key, so a caller cannot choose two addresses
        that contend with one another.
        """
        address = "Mixed.Case@Example.COM"
        bucket = security.login_attempt_slot(address)

        assert bucket == security.login_attempt_slot(
            "  mixed.case@example.com  "
        )
        assert 0 <= bucket < LOGIN_ATTEMPT_SLOT_COUNT

        with mock.patch.object(
            security.settings, "SECRET_KEY", OTHER_SIGNING_KEY
        ):
            rekeyed = security.login_attempt_slot(address)
        moved = [
            security.login_attempt_slot("user%d@example.com" % index)
            for index in range(64)
        ]
        with mock.patch.object(
            security.settings, "SECRET_KEY", OTHER_SIGNING_KEY
        ):
            moved_again = [
                security.login_attempt_slot("user%d@example.com" % index)
                for index in range(64)
            ]
        assert (bucket, moved) != (rekeyed, moved_again)

    def test_the_throttle_row_stores_no_address_or_credential(self):
        """The table carries a bucket, a count and an instant, and no more."""
        columns = set(LoginAttemptSlot.__table__.columns.keys())

        assert columns == {"bucket", "attempts", "observed_at"}

    @pytest.mark.postgres
    @pytest.mark.parametrize("branch", ["unknown", "wrong_password"])
    def test_two_simultaneous_refusals_serialise_on_postgres(
        self, branch, postgres_client, postgres_db, monkeypatch
    ):
        """Two refusals for one address are answered identically.

        Both branches now take a write lock, so two requests for the same
        address serialise against each other whether that address holds an
        account or not. Each request is still answered with the same
        refusal, and each write lands exactly once: the counter the branch
        advances moves by two, so neither request's update was lost to the
        other.
        """
        monkeypatch.setattr(auth_module.limiter, "enabled", False)
        address = "contended@example.com"
        password = WRONG_PASSWORD
        if branch == "wrong_password":
            account = User(
                email=address,
                hashed_password=security.get_password_hash(PASSWORD),
                created_at=datetime.now(timezone.utc),
                role="registered",
            )
            postgres_db.add(account)
            postgres_db.commit()

        bucket = security.login_attempt_slot(address)

        def refuse():
            """Posts one login against the shared address."""
            return postgres_client.post(
                "/auth/login",
                json={"email": address, "password": password},
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = [
                task.result()
                for task in [pool.submit(refuse), pool.submit(refuse)]
            ]

        assert first.status_code == 401, first.text
        assert second.status_code == 401, second.text
        assert first.content == second.content
        assert first.json() == {
            "detail": auth_module.INVALID_CREDENTIALS_DETAIL
        }

        postgres_db.rollback()
        postgres_db.expire_all()
        if branch == "wrong_password":
            stored = (
                postgres_db.query(User)
                .filter(User.email == address)
                .one()
            )
            assert stored.failed_login_attempts == 2
        else:
            slot = (
                postgres_db.query(LoginAttemptSlot)
                .filter(LoginAttemptSlot.bucket == bucket)
                .one()
            )
            assert slot.attempts == 2


@pytest.mark.timing
class TestRefusalBranchesTakeTheSameTime:
    """Every login refusal is held to one budget, measured end to end.

    This is a confidence measurement rather than the primary gate, and it
    is classified as such: it reads a wall clock, so an adverse pattern of
    host contention can move a reading even though the branches perform
    identical work. Deselect it with ``-m "not timing"`` where that
    matters; the counted case above proves the same property
    deterministically and is never deselected.
    """

    @staticmethod
    def _measure_branches(client, branches, before_round=None):
        """Returns the shortest complete request each branch answered in.

        ``branches`` maps a name to the address and password that reach
        that refusal branch. One request per branch is issued per round,
        in the same order each time, so a slowdown lasting part of the
        measurement is shared by every branch instead of falling entirely
        on whichever one was being sampled when it occurred.

        ``before_round`` is called once at the start of each round, outside
        the measured window, and is where a case restores state its own
        requests consume -- keeping the number of rounds independent of any
        threshold the endpoint enforces against repeated attempts.

        The reading kept for each branch is the **shortest** of its
        requests rather than the median. Each refusal is padded out to
        :data:`backend.app.core.security.MIN_LOGIN_REFUSAL_SECONDS`, so
        the time a branch takes is a floor that the machine can only add
        to: scheduling, garbage collection and input-output make a request
        longer and never shorter. The shortest reading is therefore the
        closest estimate of the work the branch actually does, and the
        difference between two branches' shortest readings is the
        difference in that work rather than in the noise around it.

        Every response is asserted to be a refusal as it is measured, so a
        branch that stopped refusing cannot be read as a fast one.
        """
        readings = dict((name, []) for name in branches)
        for _ in range(TIMING_SAMPLES):
            if before_round is not None:
                before_round()
            for name, (address, password) in branches.items():
                started = time.monotonic()
                response = login(client, address, password)
                elapsed = time.monotonic() - started
                assert response.status_code == 401, (name, response.text)
                readings[name].append(elapsed)
        return dict(
            (name, min(measured)) for name, measured in readings.items()
        )

    def test_the_branch_timings_agree_and_reach_the_budget(
        self, db, client
    ):
        """The four refusals are indistinguishable in elapsed time.

        The branches are an unknown address, which issues no write; a
        wrong password, which locks the row and counts the attempt; a lock
        already in force, which counts nothing; and a wrong password
        against a stored hash above the supported cost ceiling, which is
        refused without a comparison.
        """
        make_user(
            db,
            "current@example.com",
            security.get_password_hash(PASSWORD),
        )
        make_user(
            db,
            "expensive@example.com",
            hash_at(PASSWORD, UNSUPPORTED_ROUNDS),
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

        def clear_the_counted_attempts():
            """Returns the counting branch to an unlocked row each round.

            The wrong-password branch counts one failed attempt per
            request, and ``settings.LOGIN_MAX_ATTEMPTS`` of them lock the
            account -- which would carry that branch onto the locked path
            partway through the measurement and quietly stop measuring the
            branch this case names. Clearing the count keeps every round on
            that branch whatever the configured threshold is and however
            many rounds are taken. The write is issued between rounds, not
            inside a measured request.
            """
            db.query(User).filter(
                User.email == "current@example.com"
            ).update(
                {"failed_login_attempts": 0, "locked_until": None},
                synchronize_session=False,
            )
            db.commit()

        readings = self._measure_branches(
            client,
            {
                "unknown": ("absent@example.com", WRONG_PASSWORD),
                "wrong_password": (
                    "current@example.com",
                    WRONG_PASSWORD,
                ),
                "locked": ("locked@example.com", PASSWORD),
                "unsupported_cost": (
                    "expensive@example.com",
                    WRONG_PASSWORD,
                ),
            },
            before_round=clear_the_counted_attempts,
        )

        budget = security.MIN_LOGIN_REFUSAL_SECONDS
        for name, measured in readings.items():
            assert measured >= budget * 0.9, (name, measured, budget)
        spread = max(readings.values()) - min(readings.values())
        assert spread <= TIMING_TOLERANCE_SECONDS, readings

        # The counting branch is the one that could have drifted onto
        # another path during the measurement, so the row it counts
        # against is read back: one attempt stands from the final round
        # and no lock was reached, which holds only if every round was
        # answered by the branch this case names.
        db.expire_all()
        counting = db.query(User).filter(
            User.email == "current@example.com"
        ).one()
        assert counting.failed_login_attempts == 1, (
            counting.failed_login_attempts
        )
        assert counting.locked_until is None, counting.locked_until

    def test_the_padding_helper_returns_at_once_past_the_budget(self):
        started = time.monotonic() - (
            security.MIN_LOGIN_REFUSAL_SECONDS + 1.0
        )
        entered = time.monotonic()
        security.equalize_login_refusal(started)
        assert time.monotonic() - entered < 0.05


class TestFrozenLoginContract:
    """The response shapes the frontend reads are unchanged.

    The contract fixes a floor, not the whole body: a field may be added
    and none may be removed. Each case therefore asserts that every
    required member is present and carries its required value, and that
    no member the response must never carry has appeared -- rather than
    asserting the body equals one exact set, which would fail on an
    addition the contract permits.
    """

    def test_login_carries_the_two_required_keys(self, db, client):
        user = make_user(
            db, "i@example.com", security.get_password_hash(PASSWORD)
        )
        response = login(client, user.email, PASSWORD)
        assert response.status_code == 200
        body = response.json()
        assert REQUIRED_LOGIN_FIELDS <= set(body)
        assert body["token_type"] == "bearer"
        assert isinstance(body["access_token"], str)
        assert body["access_token"]

    def test_login_carries_no_sensitive_key(self, db, client):
        user = make_user(
            db, "k@example.com", security.get_password_hash(PASSWORD)
        )
        response = login(client, user.email, PASSWORD)
        assert response.status_code == 200
        assert_carries_no_sensitive_field(response.json())
        for name in FORBIDDEN_RESPONSE_FIELDS:
            assert name not in response.text

    def test_registration_keeps_its_nested_user_object(self, client):
        response = client.post(
            "/auth/register",
            json={"email": "j@example.com", "password": PASSWORD},
        )
        assert response.status_code == 200
        body = response.json()
        assert REQUIRED_REGISTRATION_FIELDS <= set(body)
        assert REQUIRED_USER_FIELDS <= set(body["user"])
        assert body["token_type"] == "bearer"
        assert_carries_no_sensitive_field(body)
        assert "hashed_password" not in response.text
