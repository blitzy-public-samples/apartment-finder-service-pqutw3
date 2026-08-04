"""Configure import paths, required settings, isolated SQLite state, and
an HTTPS TestClient for backend tests.

Wires six things the security suite depends on. One canonical module
object per application source file, the settings the application reads at
import time, and a SQLite database bound to the route dependency the
application uses. Then foreign-key enforcement on every SQLite connection,
an HTTPS test client, and per-test isolation of the schema and the
login-attempt counters.

Collection is not filtered. ``test_api.py``, ``test_services.py`` and
``test_tasks.py`` name top-level ``main``, ``services`` and ``app.tasks``
modules the package layout does not provide, so a full-suite run reports
three collection errors.

Rationale for this harness is indexed in
``documentation/security/decision-log.md``, section 7, and in DL-376,
DL-377, and DL-399.

Module surface
--------------
``TEST_BASE_URL``, ``TEST_HOST``, ``ALLOWED_ORIGIN``, ``FOREIGN_ORIGIN``,
``VALID_PASSWORD``
    Constants describing the harness HTTP identity and a password that
    satisfies the server-side policy.
``test_engine``, ``TestingSessionLocal``
    The SQLite engine and session factory every request is routed to.
``reset_login_throttle()``
    Empties the login-attempt counters and the rate-limiter storage.
    ``backend.app.main.reset_error_diagnostics()`` empties the diagnostic
    budget alongside it, and its presence is checked at import.
``_assert_harness_integrity()``
    Checks one module object per application source file, shared
    settings, limiter, counter and ``get_db`` across both import paths,
    and that no declared setting is left to the ambient environment.
    Runs at import and again before every test.

Fixtures
--------
``isolated_state``
    Autouse. Recreates the schema, empties the login counters and the
    diagnostic budget, installs the ``get_db`` override and re-checks the
    harness invariants for the span of one test.
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
import importlib
import itertools
import json
import os
import sys
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent
_BACKEND_DIR = _TESTS_DIR.parent
_REPO_ROOT = _BACKEND_DIR.parent
_APP_DIR = _BACKEND_DIR / "app"

# Both import roots: the repository root resolves ``backend.app.*`` and the
# backend directory resolves the short ``app.*`` path. The short path is an
# alias of the canonical one, installed below.
_CANONICAL_PACKAGE = "backend.app"
_SHORT_PACKAGE = "app"
for _import_root in (str(_BACKEND_DIR), str(_REPO_ROOT)):
    if _import_root not in sys.path:
        sys.path.insert(0, _import_root)

# SEC-06: an HTTPS base URL; a Secure cookie is dropped over plain http
TEST_BASE_URL = "https://testserver"

# QA-03: the Host the test client sends, carried by ALLOWED_HOSTS
TEST_HOST = "testserver"

# SEC-03: the origin the harness sends, carried by ALLOWED_ORIGINS
ALLOWED_ORIGIN = TEST_BASE_URL

# SEC-03: an origin absent from ALLOWED_ORIGINS
FOREIGN_ORIGIN = "https://foreign.example.com"

# SEC-04: clears every rule in backend/app/schema/user.py
VALID_PASSWORD = "Harness1!Passphrase"  # blitzy-scan-allow: test fixture

# Every setting the application declares, assigned unconditionally before
# the first application import below. Every value is a test-only sentinel
# that reaches no provider and signs no token outside this process.
_HARNESS_ENVIRONMENT = {
    # SEC-10: a SQLite URL, for which database.py builds no sslmode
    # connect argument; the SQLite driver rejects that keyword
    "DATABASE_URL": "sqlite://",
    "DB_SSLMODE": "disable",
    # SEC-03: the fail-closed allow-list, in the JSON array form pydantic
    # v1 parses for a list-typed environment value
    "ALLOWED_ORIGINS": json.dumps([ALLOWED_ORIGIN]),
    # QA-03: the Host the test client sends, and the only host the
    # application answers on under test
    "ALLOWED_HOSTS": json.dumps([TEST_HOST]),
    # SEC-06: the session cookie carries the Secure attribute under test
    "COOKIE_SECURE": "true",
    # SEC-12: 64 bytes, clearing the RFC 7518 sec. 3.2 floor of every
    # accepted algorithm. A harness literal, never a deployable key.
    "SECRET_KEY": "harness-only-signing-key-" + "x" * 39,
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_EXPIRE_MINUTES": "30",
    # SEC-07: the budget the throttle tests read back from Settings
    "LOGIN_RATE_LIMIT_ATTEMPTS": "5",
    "LOGIN_RATE_LIMIT_WINDOW_MINUTES": "15",
    # SEC-09: the validated payment environment
    "PAYPAL_MODE": "sandbox",
    # Sentinels for the settings the service layer reads at import time.
    # No test reaches any of these providers over the network.
    "PAYPAL_CLIENT_ID": "harness-paypal-client-id",
    "PAYPAL_CLIENT_SECRET": "harness-paypal-token",
    "ZILLOW_API_KEY": "harness-zillow-key",
    "ZILLOW_API_URL": "https://api.zillow.invalid/v1",
    "SENDGRID_API_KEY": "harness-sendgrid-key",
    "FROM_EMAIL": "harness@example.com",
}

# Declared optional and read by no test; removed from the environment
_SCRUBBED_ENVIRONMENT = ("SENTRY_DSN",)

os.environ.update(_HARNESS_ENVIRONMENT)
for _scrubbed in _SCRUBBED_ENVIRONMENT:
    os.environ.pop(_scrubbed, None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, event, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402


def _install_canonical_aliases():
    """Bind every short ``app.*`` name to its canonical module object.

    Imports the application entry point, then binds every loaded module
    in sys.modules under its short name.
    _assert_one_module_object_per_source_file checks the result. DL-376
    """
    importlib.import_module("{0}.main".format(_CANONICAL_PACKAGE))
    for name, module in list(sys.modules.items()):
        if name != _CANONICAL_PACKAGE and not name.startswith(
            _CANONICAL_PACKAGE + "."
        ):
            continue
        alias = _SHORT_PACKAGE + name[len(_CANONICAL_PACKAGE):]
        sys.modules.setdefault(alias, module)


_install_canonical_aliases()

from backend.app import main as application_main  # noqa: E402
from backend.app.core.config import settings  # noqa: E402
from backend.app.db.database import get_db  # noqa: E402
from backend.app.db.models import Base  # noqa: E402
from backend.app.main import app  # noqa: E402

# The state one module object per source file keeps single: settings,
# limiter, account-keyed failure counter and session dependency. DL-376
_SHARED_OBJECTS = (
    ("core.config", "settings"),
    ("api.endpoints.auth", "limiter"),
    ("api.endpoints.auth", "_login_failures"),
    ("db.database", "get_db"),
)

# Resolved source paths, cached by the __file__ string sys.modules
# keeps. DL-377
_RESOLVED_SOURCES = {}


def _resolve_once(source):
    resolved = _RESOLVED_SOURCES.get(source)
    if resolved is None:
        resolved = Path(source).resolve()
        _RESOLVED_SOURCES[source] = resolved
    return resolved


def _assert_one_module_object_per_source_file():
    """Check no application source file is loaded under two names."""
    by_source = {}
    for name, module in list(sys.modules.items()):
        source = getattr(module, "__file__", None)
        if not source:
            continue
        resolved = _resolve_once(source)
        if _APP_DIR not in resolved.parents:
            continue
        first_name, first_module = by_source.setdefault(
            resolved, (name, module)
        )
        assert first_module is module, (
            "{0} is loaded as both {1} and {2}, so the two names hold "
            "separate settings, counters and dependencies".format(
                resolved, *sorted((first_name, name))
            )
        )


def _assert_short_imports_reach_the_canonical_objects():
    """Check ``app.x`` and ``backend.app.x`` share their state."""
    for suffix, attribute in _SHARED_OBJECTS:
        canonical = importlib.import_module(
            "{0}.{1}".format(_CANONICAL_PACKAGE, suffix)
        )
        short = importlib.import_module(
            "{0}.{1}".format(_SHORT_PACKAGE, suffix)
        )
        assert short is canonical, (
            "{0}.{1} and {2}.{1} are separate module objects".format(
                _SHORT_PACKAGE, suffix, _CANONICAL_PACKAGE
            )
        )
        assert getattr(short, attribute) is getattr(canonical, attribute), (
            "{0} differs between {1}.{2} and {3}.{2}".format(
                attribute, _SHORT_PACKAGE, suffix, _CANONICAL_PACKAGE
            )
        )
    assert app.state.limiter is importlib.import_module(
        "{0}.api.endpoints.auth".format(_CANONICAL_PACKAGE)
    ).limiter, (
        "the limiter registered on the application is not the limiter the "
        "login route module holds"
    )


def _assert_every_setting_is_harness_controlled():
    """Check no declared setting is left to the ambient environment."""
    uncontrolled = sorted(
        set(type(settings).__fields__)
        - set(_HARNESS_ENVIRONMENT)
        - set(_SCRUBBED_ENVIRONMENT)
    )
    assert not uncontrolled, (
        "{0} reach Settings from the ambient environment; assign a "
        "sentinel in _HARNESS_ENVIRONMENT or name them in "
        "_SCRUBBED_ENVIRONMENT".format(", ".join(uncontrolled))
    )


def _assert_harness_integrity():
    """Run every harness invariant the suite's conclusions rest on."""
    _assert_one_module_object_per_source_file()
    _assert_short_imports_reach_the_canonical_objects()
    _assert_every_setting_is_harness_controlled()


_assert_harness_integrity()

# StaticPool with check_same_thread disabled shares one in-memory
# connection between the test thread and the TestClient portal thread.
test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@event.listens_for(test_engine, "connect")
def _enforce_sqlite_foreign_keys(dbapi_connection, connection_record):
    """Turn on foreign-key enforcement for every SQLite connection.

    SQLite applies the four foreign keys the models declare only when the
    pragma is set per connection.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def _assert_foreign_keys_are_enforced():
    """Check the pragma took effect on the shared connection."""
    with test_engine.connect() as connection:
        enabled = connection.execute(text("PRAGMA foreign_keys")).scalar()
    assert enabled == 1, (
        "SQLite foreign-key enforcement is off (PRAGMA foreign_keys="
        "{0!r}), so the declared foreign keys are inert under "
        "test".format(enabled)
    )


TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=test_engine
)
Base.metadata.create_all(bind=test_engine)
_assert_foreign_keys_are_enforced()


def _override_get_db():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def _assert_override_targets_the_test_database():
    """Check requests reach the database the tests inspect."""
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


# SEC-07: account-keyed login-failure counter names in the login route
# module namespace; the route limiter holds the address-keyed state
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


# SEC-08: the error boundary renders a bounded number of full diagnostic
# reports per route and exception type per window. Emptying that budget
# between cases keeps one case's failures from deciding what the next
# case's record carries.
if not callable(getattr(application_main, "reset_error_diagnostics", None)):
    raise RuntimeError(
        "backend.app.main exposes no reset_error_diagnostics(), so "
        "per-test isolation of the diagnostic budget is not in force"
    )


# SEC-07: a distinct client address and email per test keeps an
# exhausted counter scoped to the test that exhausted it
_CLIENT_HOSTS = itertools.count(1)
_EMAILS = itertools.count(1)


def _next_client_address():
    return ("harness-{0}".format(next(_CLIENT_HOSTS)), 50000)


def _next_email():
    # EmailStr rejects the reserved .invalid and .test suffixes
    return "harness-user-{0}@example.com".format(next(_EMAILS))


@pytest.fixture(autouse=True)
def isolated_state():
    """Give one test an empty database and empty counters."""
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    reset_login_throttle()
    application_main.reset_error_diagnostics()
    # SEC-02/SEC-05: overrides backend.app.db.database.get_db, the
    # dependency every route and get_current_user resolve
    app.dependency_overrides[get_db] = _override_get_db
    _assert_harness_integrity()
    _assert_override_targets_the_test_database()
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_db, None)
        reset_login_throttle()
        application_main.reset_error_diagnostics()


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
    # SEC-08: raise_server_exceptions disabled; handlers deliver the
    # sanitized envelope as a response
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
        # SEC-06: the route sets the session cookie; the client is
        # handed back with an empty cookie jar
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
