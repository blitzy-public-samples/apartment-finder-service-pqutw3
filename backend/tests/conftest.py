"""Pytest harness shared by every module under ``backend/tests``.

Wires the four things the security suite depends on: the import roots
that resolve the application package, the settings the application reads
at import time, a SQLite database bound to the route dependency the
application actually uses, and an HTTPS test client.

Module surface
--------------
``TEST_BASE_URL``, ``ALLOWED_ORIGIN``, ``FOREIGN_ORIGIN``,
``VALID_PASSWORD``
    Constants describing the harness HTTP identity and a password that
    satisfies the server-side policy.
``test_engine``, ``TestingSessionLocal``
    The SQLite engine and session factory every request is routed to.
``reset_login_throttle()``
    Empties the login-attempt counters and the rate-limiter storage.
``collect_ignore``
    The pre-existing modules that abort collection for the whole
    session, so the project's own coverage command reaches this suite.

Fixtures
--------
``isolated_state``
    Autouse. Recreates the schema, empties the login counters, checks
    the override targets the test engine and installs the ``get_db``
    override for the span of one test.
``db_session``
    A session on ``test_engine`` for direct row inspection or seeding.
``client``
    A ``TestClient`` on ``TEST_BASE_URL`` carrying a per-test client
    address, with server exceptions delivered as responses.
``unique_email``
    One email address no other test has registered.
``register_user``
    Callable factory returning ``{"id", "email", "password",
    "access_token"}`` for a freshly registered account.
``registered_user``
    A single account produced by ``register_user``.
"""
import itertools
import json
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------
# Import roots
# ---------------------------------------------------------------------
_TESTS_DIR = Path(__file__).resolve().parent
_BACKEND_DIR = _TESTS_DIR.parent
_REPO_ROOT = _BACKEND_DIR.parent

# The repository root resolves the absolute ``backend.app.*`` imports the
# application uses. The backend directory resolves the short ``app.*``
# imports the pre-existing test modules use. pytest runs from either
# directory, and no package marker exists under ``backend``.
for _import_root in (str(_BACKEND_DIR), str(_REPO_ROOT)):
    if _import_root not in sys.path:
        sys.path.insert(0, _import_root)

# ---------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------
# The three modules below predate this suite and none of them imports:
# they name top-level ``main``, ``services`` and ``app.tasks`` modules
# that the package layout does not provide. pytest aborts the entire
# session on a collection error, so leaving them collectable means the
# project's own coverage command - `pytest --cov=./ --cov-report=xml`,
# run verbatim by .github/workflows/ci.yml - executes zero tests and
# publishes no coverage artifact, and this suite guards nothing in the
# pipeline. Repairing them is out of scope, so they are excluded from
# collection here instead. Each still fails the same way when named
# directly, so nothing about their state is hidden.
collect_ignore = [
    "test_api.py",
    "test_services.py",
    "test_tasks.py",
]

# ---------------------------------------------------------------------
# Harness HTTP identity and credentials
# ---------------------------------------------------------------------
# SEC-06: an HTTPS base URL; a Secure cookie is dropped over plain http
TEST_BASE_URL = "https://testserver"

# SEC-03: the origin the harness sends, carried by ALLOWED_ORIGINS
ALLOWED_ORIGIN = TEST_BASE_URL

# SEC-03: an origin absent from ALLOWED_ORIGINS
FOREIGN_ORIGIN = "https://foreign.example.com"

# SEC-04: clears every rule in backend/app/schema/user.py - twelve
# characters, one uppercase, one lowercase, one digit, one special
VALID_PASSWORD = "Harness1!Passphrase"

# ---------------------------------------------------------------------
# Settings injection. Every name below is present in os.environ before
# the first application import, which builds Settings() at module scope
# in backend/app/core/config.py and opens a database connection through
# create_tables() in backend/app/main.py.
#
# Two kinds of assignment appear below and the difference matters. The
# four names the suite asserts against - the database URL, its transport
# mode, the origin allow-list and the cookie Secure attribute - are
# assigned outright, so a hostile ambient value cannot redirect a test
# at a real database or widen the allow-list. Every remaining name uses
# setdefault and therefore yields to an ambient value; assertions read
# settings.* rather than the literals here, so an inherited value is
# honoured rather than contradicted. One ambient value fails closed
# instead: a SECRET_KEY below the configured floor is refused while
# Settings() is built, which surfaces as a collection error rather than
# a silently weak key.
# ---------------------------------------------------------------------
# SEC-10: a SQLite URL, for which database.py builds no sslmode
# connect argument; the SQLite driver rejects that keyword
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["DB_SSLMODE"] = "disable"

# SEC-03: the fail-closed allow-list, in the JSON array form pydantic v1
# parses for a list-typed environment value
os.environ["ALLOWED_ORIGINS"] = json.dumps([ALLOWED_ORIGIN])

# SEC-06: the session cookie carries the Secure attribute under test
os.environ["COOKIE_SECURE"] = "true"

# SEC-12: 64 bytes clears the RFC 7518 sec. 3.2 floor for HS256, HS384
# and HS512 alike
os.environ.setdefault("SECRET_KEY", "x" * 64)
os.environ.setdefault("ALGORITHM", "HS256")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "30")

# SEC-07: the login throttle threshold and window
os.environ.setdefault("LOGIN_RATE_LIMIT_ATTEMPTS", "5")
os.environ.setdefault("LOGIN_RATE_LIMIT_WINDOW_MINUTES", "15")

# SEC-09: the payment environment domain
os.environ.setdefault("PAYPAL_MODE", "sandbox")

# Placeholders for the settings the service layer reads at import time.
# No test reaches these providers over the network.
os.environ.setdefault("PAYPAL_CLIENT_ID", "harness-paypal-client-id")
os.environ.setdefault("PAYPAL_CLIENT_SECRET", "harness-paypal-token")
os.environ.setdefault("ZILLOW_API_KEY", "harness-zillow-key")
os.environ.setdefault("ZILLOW_API_URL", "https://api.zillow.invalid/v1")
os.environ.setdefault("SENDGRID_API_KEY", "harness-sendgrid-key")
os.environ.setdefault("FROM_EMAIL", "harness@example.com")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from backend.app.db.database import get_db  # noqa: E402
from backend.app.db.models import Base  # noqa: E402
from backend.app.main import app  # noqa: E402

# ---------------------------------------------------------------------
# Test database
# ---------------------------------------------------------------------
# StaticPool with check_same_thread disabled shares one in-memory
# connection between the test thread and the portal thread TestClient
# runs route handlers on.
test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=test_engine
)
Base.metadata.create_all(bind=test_engine)


def _override_get_db():
    # Matches the generator shape of backend.app.db.database.get_db
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def _assert_override_targets_the_test_database():
    """Check requests reach the database the tests inspect.

    Without this the guarantee is incidental: only the handful of tests
    that cross-check a row through ``db_session`` would notice an
    override pointing somewhere else, so most of the suite would pass
    against a database it never reads.
    """
    installed = app.dependency_overrides.get(get_db)
    assert installed is _override_get_db, (
        "the get_db override is {0!r}, not the harness override".format(
            installed
        )
    )
    session = next(installed())
    try:
        bound = session.get_bind()
    finally:
        session.close()
    assert bound is test_engine, (
        "the override yields a session bound to {0!r}, not the engine "
        "the tests inspect".format(bound)
    )


# ---------------------------------------------------------------------
# Login throttle state
# ---------------------------------------------------------------------
# SEC-07: the login-attempt counters live in the module namespace of the
# registered login route, keyed one per account and one per client
# address. The account-keyed counter outlives a new client address, so
# every test empties both.
_THROTTLE_STATE_NAMES = ("_login_failures",)


def _discover_throttle_state():
    discovered = []
    for route in getattr(app, "routes", ()):
        endpoint = getattr(route, "endpoint", None)
        namespace = getattr(endpoint, "__globals__", None)
        if not isinstance(namespace, dict):
            continue
        for name in _THROTTLE_STATE_NAMES:
            counter = namespace.get(name)
            if not isinstance(counter, dict):
                continue
            if not any(counter is seen for seen in discovered):
                discovered.append(counter)
    return discovered


_THROTTLE_STATE = _discover_throttle_state()
if not _THROTTLE_STATE:
    raise RuntimeError(
        "no login-attempt counter named one of {0} was found on a "
        "registered route module, so per-test isolation of the login "
        "throttle is not in force".format(", ".join(_THROTTLE_STATE_NAMES))
    )


def reset_login_throttle():
    """Empty every login-attempt counter and the limiter storage."""
    for counter in _THROTTLE_STATE:
        counter.clear()
    limiter = getattr(app.state, "limiter", None)
    limiter_reset = getattr(limiter, "reset", None)
    if callable(limiter_reset):
        limiter_reset()


# ---------------------------------------------------------------------
# Per-test identities
# ---------------------------------------------------------------------
# SEC-07: a distinct client address and email per test keeps an
# exhausted counter scoped to the test that exhausted it
_CLIENT_HOSTS = itertools.count(1)
_EMAILS = itertools.count(1)


def _next_client_address():
    return ("harness-{0}".format(next(_CLIENT_HOSTS)), 50000)


def _next_email():
    # EmailStr rejects the reserved .invalid and .test suffixes
    return "harness-user-{0}@example.com".format(next(_EMAILS))


# ---------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------
@pytest.fixture(autouse=True)
def isolated_state():
    """Give one test an empty database and empty login counters."""
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    reset_login_throttle()
    # SEC-02/SEC-05: routes and get_current_user both resolve
    # backend.app.db.database.get_db, which is the only key FastAPI
    # matches; the duplicate in backend/app/main.py reaches no route.
    app.dependency_overrides[get_db] = _override_get_db
    _assert_override_targets_the_test_database()
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_db, None)
        reset_login_throttle()


@pytest.fixture
def db_session(isolated_state):
    """Yield a session on the SQLite test database."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(isolated_state):
    """Yield an HTTPS test client reaching the SQLite test database."""
    # SEC-08: raise_server_exceptions disabled, so the registered
    # handlers deliver the sanitized envelope to the caller
    with TestClient(
        app,
        base_url=TEST_BASE_URL,
        client=_next_client_address(),
        raise_server_exceptions=False,
    ) as test_client:
        yield test_client


@pytest.fixture
def unique_email():
    """Return one email address no other test has registered."""
    return _next_email()


@pytest.fixture
def register_user(client):
    """Return a callable that registers one account through the API."""
    def _register(email=None, password=VALID_PASSWORD):
        address = _next_email() if email is None else email
        response = client.post(
            "/auth/register",
            json={"email": address, "password": password},
        )
        if response.status_code != 200:
            raise AssertionError(
                "harness registration failed with {0}: {1}".format(
                    response.status_code, response.text
                )
            )
        body = response.json()
        # SEC-06: the route sets the session cookie. The client is
        # handed back unauthenticated, so a test opts in explicitly.
        client.cookies.clear()
        return {
            "id": body["user"]["id"],
            "email": address,
            "password": password,
            "access_token": body["access_token"],
        }

    return _register


@pytest.fixture
def registered_user(register_user):
    """Return one registered account."""
    return register_user()
