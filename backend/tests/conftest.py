"""Shared fixtures for the backend test suite.

This module is imported before any test module in ``backend/tests`` and
in ``backend/tests/security``. It performs two bootstrap steps at import
time and then publishes the fixtures the suite draws on.

The bootstrap steps are:

* the repository root is prepended to ``sys.path`` when it is absent
  from it
* every setting :class:`backend.app.core.config.Settings` declares is
  assigned in the process environment from
  :data:`backend.tests.support.TEST_SETTINGS`, after any variable
  already carrying that name in any letter case has been removed, and
  environment-file loading is switched off through
  :data:`ENV_FILE_VARIABLE`, so neither an ambient value nor a file
  contributes a setting. The replaced values are held in
  :data:`REPLACED_ENVIRONMENT` and restored by
  :func:`pytest_unconfigure`
* the resolved configuration is measured against
  :data:`ISOLATED_SETTINGS` and collection stops when any of them names
  something other than the isolated value

Both steps run at import time, so pytest started from the repository
root and pytest started from ``backend`` reach the same state, and
neither an ambient variable nor an environment file can alter it. The
coverage of :data:`TEST_SETTINGS` is checked against the settings class
once the application has been imported, so a setting added to that class
without a value there stops the suite instead of silently reading one
from elsewhere.

The values and helpers the test modules share are published by
:mod:`backend.tests.support`, which is imported under that one name
here and in every module that needs one of them.

The schema these fixtures build comes from ``Base.metadata``, and the
rows come from the fixtures below. Alembic is not involved unless a
fixture named below runs a revision, so the administrator seeded by
revision ``0002`` is not the account :func:`admin_user` returns, and a
test asserting on :func:`admin_user` says nothing about that revision.

The fixtures published are:

* :func:`session_factory` and :func:`db` -- an isolated in-memory
  database whose schema is built from ``Base.metadata``, with foreign
  keys enforced on every connection
* :func:`client` and :func:`anonymous_client` -- a test client whose
  request-scoped session comes from the same factory :func:`db` draws
  on, so a request and the test that made it read one database through
  two sessions
* :func:`guest_user`, :func:`registered_user`, :func:`premium_user`,
  :func:`admin_user` and :func:`second_registered_user` -- one stored
  row per role, plus a second row at :data:`Role.REGISTERED`
* :func:`token_factory` and :func:`auth_header_factory` -- valid access
  tokens and the header that carries them
* :func:`forged_token_factory` -- a valid reference token and the
  deliberately defective tokens that must fail verification
* :func:`login_json` and :func:`reset_rate_limits` -- the credential
  endpoint and the counters it is throttled by
* :func:`fresh_rate_limit_storage` -- an autouse fixture clearing those
  counters around every test in the suite
* :func:`migration_connection`, :func:`alembic_config`,
  :func:`migrated_client` and :func:`pre_revision_schema` -- an empty
  isolated database, the Alembic configuration bound to it, a test client
  whose schema the revisions built, and the schema preceding revision
  0001
* :func:`admin_seed_revision` and :func:`run_admin_seed` -- the
  administrative-grant migration and a callable that runs it on the
  isolated database

Usage::

    def test_a_page_is_public(anonymous_client):
        assert anonymous_client.get("/listings/").status_code == 200

    def test_a_write_needs_an_administrator(
        client, auth_header_factory, registered_user
    ):
        response = client.post(
            "/listings/",
            json={"rent": 1000.0},
            headers=auth_header_factory(registered_user),
        )
        assert response.status_code == 403
"""

import asyncio
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.tests.support import (  # noqa: E402
    CLIENT_BASE_URL,
    FOREIGN_AUDIENCE,
    FOREIGN_ISSUER,
    FOREIGN_SIGNING_KEY,
    REPO_ROOT,
    ROLE_EMAILS,
    SECOND_REGISTERED_EMAIL,
    TEST_SETTINGS,
    VALID_TEST_PASSWORD,
    apply_test_settings,
    bearer_header,
)

#: Environment variable :mod:`backend.app.core.config` reads the
#: environment file path from. It is set to an empty value below, so the
#: repository's own file contributes no setting.
ENV_FILE_VARIABLE = "ENV_FILE"

#: Value each of those names carried before this module replaced it, or
#: ``None`` where the name was absent. :func:`pytest_unconfigure` and
#: :func:`restored_process_environment` restore them when the session
#: ends.
REPLACED_ENVIRONMENT = dict(
    (_name, os.environ.get(_name)) for _name in TEST_SETTINGS
)

#: The same recording, under the name the isolation cases read it by.
PRIOR_ENVIRONMENT = REPLACED_ENVIRONMENT

#: Value :data:`ENV_FILE_VARIABLE` carried before this module cleared
#: it, or ``None`` where it was absent.
REPLACED_ENV_FILE = os.environ.get(ENV_FILE_VARIABLE)

os.environ[ENV_FILE_VARIABLE] = ""

apply_test_settings()

import base64  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import uuid  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402
from typing import (  # noqa: E402
    Any,
    Dict,
    Iterable,
    Optional,
    Tuple,
    Union,
)

import jwt  # noqa: E402
import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from alembic.operations import Operations  # noqa: E402
from alembic.runtime.migration import MigrationContext  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, event, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from backend.app.core.authorization import Role  # noqa: E402
from backend.app.core.config import (  # noqa: E402
    IN_PROCESS_RATE_LIMIT_SCHEMES,
    rate_limit_storage_scheme,
    settings,
)
from backend.app.core.plans import (  # noqa: E402
    PREMIUM_MONTHLY,
    STATUS_ACTIVE,
    get_plan,
)
from backend.app.core.security import (  # noqa: E402
    JWT_ALGORITHMS,
    REQUIRED_CLAIMS,
    SIGNING_ALGORITHM,
    create_access_token,
    get_password_hash,
)
from backend.app.db.database import get_db  # noqa: E402
from backend.app.db.models import (  # noqa: E402
    Base,
    Subscription,
    User,
)
from backend.app.main import app, limiter  # noqa: E402

#: Names the settings class and :data:`TEST_SETTINGS` disagree on.
_SETTINGS_COVERAGE_GAP = sorted(
    set(type(settings).__fields__) ^ set(TEST_SETTINGS)
)

#: Settings whose resolved value must equal the isolated one before any
#: test runs.
ISOLATED_SETTINGS = (
    "ENVIRONMENT",
    "DATABASE_URL",
    "SECRET_KEY",
    "RATE_LIMIT_STORAGE_URI",
    "ZILLOW_API_URL",
    "PAYPAL_API_BASE",
)

#: Reported when a resolved setting is not the isolated one.
UNISOLATED_SETTING_MESSAGE = (
    "the test suite refuses to run against a setting it did not place "
    "in the process environment"
)

#: Reported when the limiter counters are not held in this process
#: alone.
SHARED_LIMITER_MESSAGE = (
    "the test suite refuses to clear rate-limit counters held outside "
    "this process"
)


def _refuse_unisolated_configuration() -> None:
    """Raise unless the resolved settings are the isolated ones.

    Each name in :data:`ISOLATED_SETTINGS` is compared with the value
    :data:`TEST_SETTINGS` placed in the environment, and the rate-limit
    storage is additionally required to name a scheme in
    :data:`IN_PROCESS_RATE_LIMIT_SCHEMES`. Collection stops rather than
    a deployed target being read or written.
    """
    for name in ISOLATED_SETTINGS:
        expected = TEST_SETTINGS[name]
        resolved = getattr(settings, name)
        if str(resolved) != expected:
            raise RuntimeError(
                "{0}: {1} resolved to {2!r} rather than {3!r}".format(
                    UNISOLATED_SETTING_MESSAGE, name, resolved, expected
                )
            )
    scheme = rate_limit_storage_scheme(settings.RATE_LIMIT_STORAGE_URI)
    if scheme not in IN_PROCESS_RATE_LIMIT_SCHEMES:
        raise RuntimeError(
            "{0}: RATE_LIMIT_STORAGE_URI names {1!r}, which is shared "
            "with other processes".format(
                UNISOLATED_SETTING_MESSAGE, scheme
            )
        )


_refuse_unisolated_configuration()

#: Whether the limiter counters live in this process alone, measured
#: once from the configuration the limiter was built against.
LIMITER_IS_IN_PROCESS = (
    rate_limit_storage_scheme(settings.RATE_LIMIT_STORAGE_URI)
    in IN_PROCESS_RATE_LIMIT_SCHEMES
)


def reset_limiter_counters() -> None:
    """Clear the limiter counters this process holds.

    Raises ``RuntimeError`` when the counters are not held in this
    process alone, so a store another process reads is never cleared.
    """
    if not LIMITER_IS_IN_PROCESS:
        raise RuntimeError(SHARED_LIMITER_MESSAGE)
    limiter.reset()


if _SETTINGS_COVERAGE_GAP:
    raise RuntimeError(
        "TEST_SETTINGS and the settings class name different settings: "
        + ", ".join(_SETTINGS_COVERAGE_GAP)
    )

assert set(ROLE_EMAILS) == set(
    role.value for role in Role
), "ROLE_EMAILS must name every role the Role model defines"

#: Order identifier carried by the subscription that entitles
#: :func:`premium_user`. The column is unique, and one such row exists
#: per test database.
PREMIUM_ENTITLEMENT_ORDER_ID = "ORDER-PREMIUM-ENTITLEMENT"

#: Subject :class:`ForgedTokenFactory` mints when none is given.
DEFAULT_FORGED_SUBJECT = "1"

#: Lifetime a forged token receives when its expiry is not displaced.
FORGED_TOKEN_LIFETIME = timedelta(minutes=5)

#: Interval by which :class:`ForgedTokenFactory` displaces a timestamp
#: it is placing outside the window of validity.
FORGED_TOKEN_SKEW = timedelta(minutes=30)

#: Algorithms tried, in order, when a token must be signed with one the
#: configuration does not accept.
UNLISTED_ALGORITHM_CANDIDATES = ("HS512", "HS384", "HS256")

#: Absolute path of the Alembic configuration the migration fixtures
#: read.
ALEMBIC_INI = REPO_ROOT / "backend" / "alembic.ini"

#: Database the migration fixtures apply the revisions to. It is held in
#: memory by a single connection and outlives no test.
MIGRATION_DATABASE_URL = "sqlite://"

#: The six tables the application carried before revision 0001. Each is
#: written without the columns, uniqueness constraints and table that
#: revision adds, so a revision applied over them exercises its
#: alter-in-place path rather than its create path.
PRE_REVISION_TABLES = (
    "CREATE TABLE users ("
    " id INTEGER NOT NULL PRIMARY KEY,"
    " email VARCHAR NOT NULL UNIQUE,"
    " hashed_password VARCHAR NOT NULL,"
    " created_at DATETIME NOT NULL,"
    " last_login DATETIME"
    ")",
    "CREATE TABLE listings ("
    " id INTEGER NOT NULL PRIMARY KEY,"
    " created_at DATETIME NOT NULL,"
    " updated_at DATETIME NOT NULL,"
    " rent FLOAT NOT NULL,"
    " broker_fee FLOAT,"
    " square_footage FLOAT,"
    " bedrooms INTEGER,"
    " bathrooms INTEGER,"
    " available_date DATETIME,"
    " street_address VARCHAR,"
    " zillow_url VARCHAR"
    ")",
    "CREATE TABLE filters ("
    " id INTEGER NOT NULL PRIMARY KEY,"
    " user_id INTEGER NOT NULL REFERENCES users (id),"
    " name VARCHAR NOT NULL,"
    " created_at DATETIME NOT NULL,"
    " last_used DATETIME"
    ")",
    "CREATE TABLE zip_codes ("
    " id INTEGER NOT NULL PRIMARY KEY,"
    " filter_id INTEGER NOT NULL REFERENCES filters (id),"
    " code VARCHAR NOT NULL"
    ")",
    "CREATE TABLE criteria ("
    " id INTEGER NOT NULL PRIMARY KEY,"
    " filter_id INTEGER NOT NULL REFERENCES filters (id),"
    " field VARCHAR NOT NULL,"
    " operator VARCHAR NOT NULL,"
    " value VARCHAR NOT NULL"
    ")",
    "CREATE TABLE subscriptions ("
    " id INTEGER NOT NULL PRIMARY KEY,"
    " user_id INTEGER NOT NULL REFERENCES users (id),"
    " start_date DATETIME NOT NULL,"
    " end_date DATETIME,"
    " status VARCHAR NOT NULL"
    ")",
)

#: Path of the revision that grants the administrative role.
ADMIN_SEED_REVISION_PATH = (
    REPO_ROOT
    / "backend"
    / "migrations"
    / "versions"
    / "0002_seed_single_admin.py"
)

#: Name the revision is loaded under by :func:`admin_seed_revision`. It
#: sits outside every package in the repository, so the load adds no
#: importable module to ``backend``.
ADMIN_SEED_MODULE_NAME = "blitzy_admin_seed_revision_0002"


def pytest_unconfigure(config: Any) -> None:
    """Restore the environment values this module replaced."""
    replaced = dict(REPLACED_ENVIRONMENT)
    replaced[ENV_FILE_VARIABLE] = REPLACED_ENV_FILE
    for name, value in replaced.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


# ---------------------------------------------------------------------
# The outbound PayPal wire contract. Every provider stand-in in the suite
# validates the request it is handed through
# :func:`assert_paypal_contract` before it serves a response, so a call
# that departs from the contract fails the case that made it instead of
# receiving a plausible answer.
# ---------------------------------------------------------------------

#: Path of PayPal's credential-exchange endpoint.
PAYPAL_OAUTH_PATH = "/v1/oauth2/token"

#: Path of PayPal's orders collection.
PAYPAL_ORDERS_PATH = "/v2/checkout/orders"

#: Suffix appended to an order's path to settle it.
PAYPAL_CAPTURE_SUFFIX = "/capture"

#: Path of PayPal's signature verifier.
PAYPAL_VERIFY_PATH = "/v1/notifications/verify-webhook-signature"

#: Grant the credential exchange requests.
PAYPAL_GRANT_TYPE = "client_credentials"

#: Header the settle call carries its representation preference in.
PAYPAL_PREFER_HEADER = "Prefer"

#: Fields the verifier document carries, and no others.
PAYPAL_VERIFY_FIELDS = frozenset(
    {
        "auth_algo",
        "cert_url",
        "transmission_id",
        "transmission_sig",
        "transmission_time",
        "webhook_id",
        "webhook_event",
    }
)

#: Route name returned for each recognised request.
PAYPAL_ROUTE_TOKEN = "token"
PAYPAL_ROUTE_CREATE_ORDER = "create_order"
PAYPAL_ROUTE_CAPTURE_ORDER = "capture_order"
PAYPAL_ROUTE_READ_ORDER = "read_order"
PAYPAL_ROUTE_VERIFY = "verify_webhook_signature"


class PayPalContractError(AssertionError):
    """Raised for an outbound request outside the provider contract."""


def _header(headers: Any, name: str) -> Optional[str]:
    """Return one header value, matched without regard to case."""
    if not headers:
        return None
    for key, value in dict(headers).items():
        if str(key).lower() == name.lower():
            return value
    return None


def _refuse(detail: str, method: Any, url: Any) -> None:
    """Raise :class:`PayPalContractError` naming the request refused."""
    raise PayPalContractError(
        "{0}: {1} {2}".format(detail, method, url)
    )


def _assert_paypal_timeout(timeout: Any, method: Any, url: Any) -> None:
    """Assert one call carries the configured timeout.

    A scalar is compared directly; the mapping ``httpx`` records in a
    request's extensions is compared phase by phase.
    """
    expected = settings.HTTP_TIMEOUT_SECONDS
    if isinstance(timeout, dict):
        if not timeout:
            _refuse("call carries no timeout", method, url)
        for phase, bound in timeout.items():
            if bound != expected:
                _refuse(
                    "timeout phase {0} is {1}".format(phase, bound),
                    method,
                    url,
                )
        return
    if timeout is None:
        _refuse("call carries no timeout", method, url)
    if timeout != expected:
        _refuse("timeout is {0}".format(timeout), method, url)


def _paypal_route(path: str, method: str, url: Any) -> str:
    """Return the contract route ``path`` addresses."""
    if path == PAYPAL_OAUTH_PATH:
        return PAYPAL_ROUTE_TOKEN
    if path == PAYPAL_VERIFY_PATH:
        return PAYPAL_ROUTE_VERIFY
    if path == PAYPAL_ORDERS_PATH:
        return PAYPAL_ROUTE_CREATE_ORDER
    if path.startswith(PAYPAL_ORDERS_PATH + "/"):
        remainder = path[len(PAYPAL_ORDERS_PATH) + 1:]
        if remainder.endswith(PAYPAL_CAPTURE_SUFFIX):
            remainder = remainder[: -len(PAYPAL_CAPTURE_SUFFIX)]
            if remainder and "/" not in remainder:
                return PAYPAL_ROUTE_CAPTURE_ORDER
        elif remainder and "/" not in remainder:
            return PAYPAL_ROUTE_READ_ORDER
    _refuse("path is outside the provider contract", method, url)
    raise AssertionError("unreachable")


def assert_paypal_contract(
    method: str,
    url: str,
    headers: Any = None,
    json_body: Any = None,
    content: Any = None,
    data: Any = None,
    auth: Any = None,
    timeout: Any = None,
) -> str:
    """Assert one outbound provider request and return its route.

    Raises :class:`PayPalContractError` when the request departs from the
    contract in any of these respects: the target does not begin with
    ``settings.PAYPAL_API_BASE``; the path is not one the service
    addresses; the method is not the one that path takes; the credential
    exchange does not carry the client-credentials grant as form data
    under HTTP Basic credentials; an authenticated call does not carry a
    Bearer grant, ``Accept: application/json`` and, when it writes,
    ``Content-Type: application/json`` and a body; the settle call omits
    its representation preference; the verifier document does not carry
    exactly the documented fields with the configured webhook identifier;
    or the call carries no timeout, or one other than
    ``settings.HTTP_TIMEOUT_SECONDS``.
    """
    target = str(url)
    base = settings.PAYPAL_API_BASE
    if not target.startswith(base + "/"):
        _refuse("target is not the configured PayPal host", method, url)

    verb = str(method).upper()
    path = target[len(base):].split("?")[0]
    route = _paypal_route(path, verb, url)
    authorization = _header(headers, "Authorization")
    accept = _header(headers, "Accept")
    content_type = _header(headers, "Content-Type")

    if route == PAYPAL_ROUTE_TOKEN:
        if verb != "POST":
            _refuse("credential exchange is not a POST", method, url)
        if dict(data or {}) != {"grant_type": PAYPAL_GRANT_TYPE}:
            _refuse("credential exchange sent no grant", method, url)
        if tuple(auth or ()) != (
            settings.PAYPAL_CLIENT_ID,
            settings.PAYPAL_CLIENT_SECRET,
        ):
            _refuse(
                "credential exchange sent no Basic credentials",
                method,
                url,
            )
        if authorization is not None:
            _refuse(
                "credential exchange sent a Bearer grant", method, url
            )
        if json_body is not None or content is not None:
            _refuse("credential exchange sent a body", method, url)
    else:
        if not isinstance(authorization, str) or not (
            authorization.startswith("Bearer ")
        ):
            _refuse("call carries no Bearer grant", method, url)
        if len(authorization.split("Bearer ", 1)[1].strip()) == 0:
            _refuse("call carries an empty Bearer grant", method, url)
        if data:
            _refuse("authenticated call sent form data", method, url)
        if auth:
            _refuse("authenticated call sent Basic credentials", method,
                    url)

    if accept != "application/json":
        _refuse("call does not accept JSON", method, url)

    if route == PAYPAL_ROUTE_READ_ORDER:
        if verb != "GET":
            _refuse("order read is not a GET", method, url)
        if json_body is not None or content:
            _refuse("order read sent a body", method, url)
    elif route != PAYPAL_ROUTE_TOKEN:
        if verb != "POST":
            _refuse("write call is not a POST", method, url)
        if content_type != "application/json":
            _refuse("write call does not send JSON", method, url)
        if json_body is None and not content:
            _refuse("write call sent no body", method, url)

    if route == PAYPAL_ROUTE_CAPTURE_ORDER:
        if not _header(headers, PAYPAL_PREFER_HEADER):
            _refuse(
                "settle call carries no representation preference",
                method,
                url,
            )

    if route == PAYPAL_ROUTE_VERIFY:
        document = json_body
        if document is None and content:
            document = json.loads(bytes(content).decode("utf-8"))
        if not isinstance(document, dict):
            _refuse("verifier document is not an object", method, url)
        if set(document) != set(PAYPAL_VERIFY_FIELDS):
            _refuse(
                "verifier document fields are {0}".format(
                    sorted(document)
                ),
                method,
                url,
            )
        if document["webhook_id"] != settings.PAYPAL_WEBHOOK_ID:
            _refuse(
                "verifier document names another webhook", method, url
            )

    _assert_paypal_timeout(timeout, method, url)
    return route


def assert_paypal_call(method: str, url: str, **kwargs: Any) -> str:
    """Assert one call made on the provider client and return its route.

    The keyword arguments are the ones the service hands its client, so a
    stand-in installed in place of that client asserts the same contract
    as one installed as a transport.
    """
    return assert_paypal_contract(
        method,
        url,
        headers=kwargs.get("headers"),
        json_body=kwargs.get("json"),
        content=kwargs.get("content"),
        data=kwargs.get("data"),
        auth=kwargs.get("auth"),
        timeout=kwargs.get("timeout"),
    )


def assert_paypal_request(outbound: Any) -> str:
    """Assert one ``httpx`` request and return its contract route.

    The request's own method, target, headers, body and recorded timeout
    are handed to :func:`assert_paypal_contract`, so a stand-in installed
    as a transport asserts the same contract as one installed as a
    client.
    """
    try:
        body = bytes(outbound.content)
    except Exception:
        body = b""
    payload = None
    form = None
    if body:
        if (
            _header(outbound.headers, "Content-Type")
            == "application/json"
        ):
            payload = json.loads(body.decode("utf-8"))
        else:
            form = dict(
                item.split("=", 1)
                for item in body.decode("utf-8").split("&")
                if "=" in item
            )
    credentials = None
    basic = _header(outbound.headers, "Authorization")
    if isinstance(basic, str) and basic.startswith("Basic "):
        decoded = base64.b64decode(
            basic.split("Basic ", 1)[1]
        ).decode("utf-8")
        credentials = tuple(decoded.split(":", 1))
        basic = None
    headers = dict(outbound.headers)
    if credentials is not None:
        headers.pop("authorization", None)
        headers.pop("Authorization", None)
    unparsed = body if (payload is None and form is None) else None
    return assert_paypal_contract(
        outbound.method,
        str(outbound.url),
        headers=headers,
        json_body=payload,
        content=unparsed,
        data=form,
        auth=credentials,
        timeout=dict(outbound.extensions.get("timeout") or {}),
    )


def _as_tuple(
    value: Optional[Union[str, Iterable[str]]],
) -> Tuple[str, ...]:
    """Return ``value`` as a tuple of names.

    ``None`` becomes an empty tuple and a single string becomes a
    one-element tuple. A caller may therefore name one claim or several.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def _epoch(value: Any) -> Any:
    """Return ``value`` as a POSIX timestamp when it is a datetime."""
    if isinstance(value, datetime):
        return int(value.timestamp())
    return value


def _b64url(raw: bytes) -> str:
    """Return ``raw`` base64url-encoded with its padding removed."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _segment(payload: Dict[str, Any]) -> str:
    """Return ``payload`` as one encoded, compact JSON token segment."""
    encoded = json.dumps(
        dict((name, _epoch(value)) for name, value in payload.items()),
        separators=(",", ":"),
        sort_keys=True,
    )
    return _b64url(encoded.encode("utf-8"))


def _subject_of(principal: Any) -> str:
    """Return the token subject naming ``principal``.

    A stored row is named by the string form of its integer primary
    key, and any other value is converted to its own string form.
    """
    identifier = getattr(principal, "id", None)
    if identifier is not None:
        return str(identifier)
    return str(principal)


def unlisted_algorithm() -> str:
    """Return an algorithm name absent from the accepted algorithms."""
    for candidate in UNLISTED_ALGORITHM_CANDIDATES:
        if candidate not in JWT_ALGORITHMS:
            return candidate
    raise AssertionError(
        "every candidate algorithm is accepted, so none is unlisted"
    )


def _enforce_sqlite_foreign_keys(engine):
    """Enforce foreign keys on every connection ``engine`` opens.

    SQLite accepts a foreign key in a table definition but does not
    enforce it until ``PRAGMA foreign_keys`` is set, and the setting is
    per connection. Registering it on connect is what makes the four
    foreign keys the models declare hold in a test.
    """

    @event.listens_for(engine, "connect")
    def _set_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()


@pytest.fixture(autouse=True)
def fresh_rate_limit_storage():
    """Clear the shared limiter counters around every test.

    The limiter belongs to the process rather than to a test, and it is
    keyed by caller address, which every test client shares. Clearing it
    before and after each test means no test starts with counts another
    test made and none leaves counts behind. A test that drives the
    throttle accumulates its own requests inside its own body, which
    this fixture does not touch.
    """
    reset_limiter_counters()
    try:
        yield
    finally:
        reset_limiter_counters()


SESSION_EVENT_LOOP = []


def session_event_loop():
    """Returns the one open event loop this session drives cases on.

    A loop is created on the first call and reused after it, and is
    replaced only once it has been closed, so the caller always receives
    an open loop and only one exists at a time.
    """
    if not SESSION_EVENT_LOOP or SESSION_EVENT_LOOP[0].is_closed():
        SESSION_EVENT_LOOP[:] = [asyncio.new_event_loop()]
    return SESSION_EVENT_LOOP[0]


@pytest.fixture(autouse=True)
def current_event_loop():
    """Leave this thread carrying an open current event loop.

    ``asyncio.run`` closes the loop it created and clears the current
    loop when it returns, so without this a case that calls it leaves the
    thread carrying none and every later case that reads the current loop
    is refused with ``RuntimeError``. The session loop is made current
    before the case and again after it, so the order cases run in does not
    decide whether they pass, and no loop is left unreferenced.
    """
    asyncio.set_event_loop(session_event_loop())
    try:
        yield
    finally:
        asyncio.set_event_loop(session_event_loop())


@pytest.fixture(scope="session", autouse=True)
def closed_session_event_loop():
    """Closes the session event loop once the session ends."""
    yield
    if SESSION_EVENT_LOOP:
        loop = SESSION_EVENT_LOOP[0]
        asyncio.set_event_loop(None)
        if not loop.is_closed():
            loop.close()
        SESSION_EVENT_LOOP[:] = []


@pytest.fixture(scope="session", autouse=True)
def restored_process_environment():
    """Restore the environment the session started with, once it ends.

    Each name :data:`TEST_SETTINGS` set is returned to the value
    :data:`PRIOR_ENVIRONMENT` recorded for it, and removed when it was
    absent.
    """
    try:
        yield
    finally:
        for name, previous in PRIOR_ENVIRONMENT.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous


@pytest.fixture
def session_factory():
    """Yield a session factory bound to an isolated database.

    The database is held in memory by a single connection, and its
    schema is built from ``Base.metadata`` before the factory is
    yielded and dropped afterwards. No row outlives one test. Foreign
    keys are enforced on every connection the engine opens.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    _enforce_sqlite_foreign_keys(engine)
    Base.metadata.create_all(bind=engine)
    try:
        yield sessionmaker(
            autocommit=False, autoflush=False, bind=engine
        )
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def db(session_factory):
    """Yield one session on the isolated database.

    The session is rolled back and closed once the test ends, whether
    it passed or failed.
    """
    session = session_factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def client(session_factory):
    """Yield a test client whose sessions share the test database.

    The application's request-scoped session dependency is overridden
    for the duration of the test and the overrides are cleared
    afterwards.
    """

    def override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(
            app, base_url=CLIENT_BASE_URL
        ) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def anonymous_client(client):
    """Return the test client carrying no ``Authorization`` header."""
    return client


@pytest.fixture(scope="session")
def password_hash() -> str:
    """Return the stored hash of :data:`VALID_TEST_PASSWORD`.

    The hash is computed once for the whole session and reused by every
    seeded row.
    """
    return get_password_hash(VALID_TEST_PASSWORD)


@pytest.fixture
def user_factory(db, password_hash):
    """Return a callable that stores one user row and returns it.

    The callable takes an address and, optionally, a role given either
    as a :class:`Role` member or as the string it stores. Any further
    keyword is passed to the model as a column value. ``created_at`` is
    always set, and the password is the shared test password.
    """

    def create(
        email: str,
        role: Union[Role, str] = Role.REGISTERED,
        **columns: Any
    ) -> User:
        stored_role = role.value if isinstance(role, Role) else str(role)
        user = User(
            email=email,
            hashed_password=password_hash,
            created_at=datetime.now(timezone.utc),
            role=stored_role,
            **columns
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    return create


@pytest.fixture
def guest_user(user_factory) -> User:
    """Return the stored row holding :data:`Role.GUEST`."""
    return user_factory(ROLE_EMAILS[Role.GUEST.value], Role.GUEST)


@pytest.fixture
def registered_user(user_factory) -> User:
    """Return the stored row holding :data:`Role.REGISTERED`."""
    return user_factory(
        ROLE_EMAILS[Role.REGISTERED.value], Role.REGISTERED
    )


@pytest.fixture
def premium_user(db, user_factory) -> User:
    """Return the stored row holding :data:`Role.PREMIUM`.

    An active subscription is stored alongside the row, naming the plan
    whose ``required_role`` is :data:`Role.PREMIUM` and carrying an
    entitlement window that ends one plan period ahead of the current
    instant. :func:`backend.app.core.authorization.effective_role`
    credits a stored subscriber role only while such a row grants it, so
    without one the principal would resolve at
    :data:`Role.REGISTERED`.
    """
    user = user_factory(ROLE_EMAILS[Role.PREMIUM.value], Role.PREMIUM)
    plan = get_plan(PREMIUM_MONTHLY)
    started = datetime.now(timezone.utc)
    db.add(
        Subscription(
            user_id=user.id,
            plan_id=plan.plan_id,
            amount=plan.amount,
            currency=plan.currency,
            status=STATUS_ACTIVE,
            start_date=started,
            end_date=started + timedelta(days=plan.period_days),
            paypal_order_id=PREMIUM_ENTITLEMENT_ORDER_ID,
        )
    )
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def admin_user(user_factory) -> User:
    """Return the stored row holding :data:`Role.ADMIN`.

    This row is written by this fixture, under the address in
    :data:`ROLE_EMAILS`. It is not the account the administrator-seed
    revision grants the role to, which
    :mod:`backend.tests.security.test_migration_gate` covers.
    """
    return user_factory(ROLE_EMAILS[Role.ADMIN.value], Role.ADMIN)


@pytest.fixture
def second_registered_user(user_factory) -> User:
    """Return a second stored row holding :data:`Role.REGISTERED`.

    It is a distinct account from :func:`registered_user`: the two are
    a pair of valid principals at the same role, holding separate rows.
    """
    return user_factory(SECOND_REGISTERED_EMAIL, Role.REGISTERED)


@pytest.fixture
def seeded_users(
    guest_user, registered_user, premium_user, admin_user
) -> Dict[str, User]:
    """Return the stored row for each role, keyed by the role string."""
    return {
        Role.GUEST.value: guest_user,
        Role.REGISTERED.value: registered_user,
        Role.PREMIUM.value: premium_user,
        Role.ADMIN.value: admin_user,
    }


@pytest.fixture(scope="session")
def admin_seed_revision():
    """Return revision ``0002`` loaded from its own file.

    The revision is loaded by path rather than imported, because
    ``backend/migrations/versions`` is not a package. It is loaded once
    for the whole session.
    """
    specification = importlib.util.spec_from_file_location(
        ADMIN_SEED_MODULE_NAME, str(ADMIN_SEED_REVISION_PATH)
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


@pytest.fixture
def run_admin_seed(db, admin_seed_revision):
    """Return a callable that runs revision ``0002`` on the database.

    The callable takes the direction to run, ``"upgrade"`` or
    ``"downgrade"``, and runs that function of the revision against the
    connection :func:`db` holds, through the same operations proxy
    Alembic installs. A completed run is committed and a failed one is
    rolled back, as Alembic does with the transaction it wraps a
    revision in, and the session's identity map is expired either way so
    a following query reads the stored rows.
    """

    def run(direction: str = "upgrade") -> None:
        context = MigrationContext.configure(db.connection())
        try:
            with Operations.context(context):
                getattr(admin_seed_revision, direction)()
        except Exception:
            db.rollback()
            raise
        else:
            db.commit()
        finally:
            db.expire_all()

    return run


@pytest.fixture
def token_factory():
    """Return a callable that mints one valid access token.

    The callable takes a stored row, or any value naming a subject, and
    mints a token whose ``sub`` claim is the string form of that row's
    integer primary key. The row's role travels as the descriptive role
    claim. ``expires_delta`` shortens the lifetime, and any further
    keyword replaces a claim in the data the token is built from.
    """

    def issue(
        principal: Any,
        expires_delta: Optional[timedelta] = None,
        **claims: Any
    ) -> str:
        data = {"sub": _subject_of(principal)}
        role = getattr(principal, "role", None)
        if role is not None:
            data["role"] = role
        data.update(claims)
        return create_access_token(data, expires_delta=expires_delta)

    return issue


@pytest.fixture
def auth_header_factory(token_factory):
    """Return a callable producing a bearer header for a principal.

    The callable takes the same arguments as :func:`token_factory` and
    returns the ``Authorization`` header mapping carrying the token it
    mints.
    """

    def headers(principal: Any, **kwargs: Any) -> Dict[str, str]:
        return bearer_header(token_factory(principal, **kwargs))

    return headers


class ForgedTokenFactory(object):
    """Mints a valid reference token and defective tokens.

    :meth:`forge` is the single point every signed token is built at,
    and each named method below is one call to it with the claims, key
    or algorithm that produces its defect. Every method accepts further
    keyword arguments that replace a claim, so ``sub=str(user.id)``
    aims any forgery at a particular stored row, and any claim may be
    displaced in combination with any other.

    :meth:`valid` mints the one token here that must verify. It differs
    from each forgery in that forgery's defect and in nothing else.
    """

    #: The claims a token must carry to be accepted.
    required_claims: Tuple[str, ...] = tuple(REQUIRED_CLAIMS)

    def __init__(self, subject: str = DEFAULT_FORGED_SUBJECT) -> None:
        self.subject = subject

    def claims(self, **overrides: Any) -> Dict[str, Any]:
        """Return a complete, currently valid claim set.

        Every claim in :attr:`required_claims` is present and the
        descriptive role claim carries :data:`Role.REGISTERED`. Each
        keyword argument replaces the claim it names.
        """
        issued = datetime.now(timezone.utc)
        payload = {
            "sub": self.subject,
            "role": Role.REGISTERED.value,
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "iat": issued,
            "nbf": issued,
            "exp": issued + FORGED_TOKEN_LIFETIME,
            "jti": uuid.uuid4().hex,
        }
        payload.update(overrides)
        return payload

    def forge(
        self,
        key: Optional[str] = None,
        algorithm: Optional[str] = None,
        drop: Optional[Union[str, Iterable[str]]] = None,
        headers: Optional[Dict[str, Any]] = None,
        **overrides: Any
    ) -> str:
        """Return a signed token over the claim set plus ``overrides``.

        ``key`` and ``algorithm`` default to the configured signing key
        and the algorithm this process signs with. ``drop`` names one
        claim or several to omit. ``headers`` replaces entries in the
        token header.
        """
        payload = self.claims(**overrides)
        for name in _as_tuple(drop):
            payload.pop(name, None)
        return jwt.encode(
            payload,
            settings.SECRET_KEY if key is None else key,
            algorithm=(
                SIGNING_ALGORITHM if algorithm is None else algorithm
            ),
            headers=headers,
        )

    def valid(self, **overrides: Any) -> str:
        """Return a token that must verify."""
        return self.forge(**overrides)

    def unsigned(
        self,
        algorithm_name: str = "none",
        drop: Optional[Union[str, Iterable[str]]] = None,
        **overrides: Any
    ) -> str:
        """Return a token whose header names ``algorithm_name``.

        The three segments are assembled directly and the signature
        segment is empty. ``algorithm_name`` accepts any letter case:
        ``"none"``, ``"NoNe"`` and ``"NONE"`` are all available.
        """
        payload = self.claims(**overrides)
        for name in _as_tuple(drop):
            payload.pop(name, None)
        header = {"alg": algorithm_name, "typ": "JWT"}
        return "{0}.{1}.".format(_segment(header), _segment(payload))

    def wrong_key(self, **overrides: Any) -> str:
        """Return a token signed with :data:`FOREIGN_SIGNING_KEY`."""
        return self.forge(key=FOREIGN_SIGNING_KEY, **overrides)

    def wrong_audience(self, **overrides: Any) -> str:
        """Return a token whose ``aud`` is not the configured one."""
        overrides.setdefault("aud", FOREIGN_AUDIENCE)
        return self.forge(**overrides)

    def wrong_issuer(self, **overrides: Any) -> str:
        """Return a token whose ``iss`` is not the configured one."""
        overrides.setdefault("iss", FOREIGN_ISSUER)
        return self.forge(**overrides)

    def expired(self, **overrides: Any) -> str:
        """Return a token whose validity ended before now."""
        issued = datetime.now(timezone.utc) - FORGED_TOKEN_SKEW
        claims = {
            "iat": issued,
            "nbf": issued,
            "exp": issued + FORGED_TOKEN_LIFETIME,
        }
        claims.update(overrides)
        return self.forge(**claims)

    def future_not_before(self, **overrides: Any) -> str:
        """Return a token whose validity has not yet begun."""
        ahead = datetime.now(timezone.utc) + FORGED_TOKEN_SKEW
        claims = {
            "iat": ahead,
            "nbf": ahead,
            "exp": ahead + FORGED_TOKEN_LIFETIME,
        }
        claims.update(overrides)
        return self.forge(**claims)

    def without_claim(self, name: str, **overrides: Any) -> str:
        """Return a token carrying every claim except ``name``."""
        return self.forge(drop=name, **overrides)

    def unlisted_algorithm(self, **overrides: Any) -> str:
        """Return a token signed with an unaccepted algorithm.

        The algorithm is the one :func:`unlisted_algorithm` reports. The
        token is well formed and its signature is correct for that
        algorithm.
        """
        return self.forge(algorithm=unlisted_algorithm(), **overrides)

    def legacy_email_subject(
        self, email: str = None, **overrides: Any
    ) -> str:
        """Return a token whose ``sub`` is an address, not an id."""
        address = (
            ROLE_EMAILS[Role.REGISTERED.value] if email is None else email
        )
        overrides["sub"] = address
        return self.forge(**overrides)


@pytest.fixture
def forged_token_factory() -> ForgedTokenFactory:
    """Return the factory that mints reference and defective tokens.

    :meth:`ForgedTokenFactory.valid` mints a token that verifies, and
    every other method mints one carrying a single defect. The factory
    reads no fixture and touches no database, so a case may use it on
    its own. It mints for :data:`DEFAULT_FORGED_SUBJECT` unless a call
    passes ``sub``.
    """
    return ForgedTokenFactory()


@pytest.fixture
def login_json():
    """Return a callable that posts one login as a JSON body.

    The callable takes a client and an address, and defaults the
    password to :data:`VALID_TEST_PASSWORD`. The shared per-address
    throttle counter is cleared first unless ``reset`` is ``False``.
    """

    def post_login(
        test_client: Any,
        email: str,
        password: str = VALID_TEST_PASSWORD,
        reset: bool = True,
    ):
        if reset:
            reset_limiter_counters()
        return test_client.post(
            "/auth/login", json={"email": email, "password": password}
        )

    return post_login


@pytest.fixture
def reset_rate_limits(fresh_rate_limit_storage):
    """Name the clearing :func:`fresh_rate_limit_storage` performs.

    The counters are cleared around every test in the suite. A test
    requesting this fixture states at its own declaration that it
    depends on that clearing.
    """
    return None


@pytest.fixture
def migration_connection():
    """Yield an open connection to an empty isolated database.

    The database carries no table, so a revision applied through
    :func:`alembic_config` runs against the state a first deployment
    presents. The connection is held open for the whole test and is
    closed with the engine afterwards.
    """
    engine = create_engine(
        MIGRATION_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    connection = engine.connect()
    try:
        yield connection
    finally:
        connection.close()
        engine.dispose()


@pytest.fixture
def alembic_config():
    """Return a callable building an Alembic configuration.

    The callable takes the connection the migrations are to run on and
    returns a :class:`alembic.config.Config` reading
    ``backend/alembic.ini``. The connection is placed under
    ``backend.migrations.env.CONNECTION_ATTRIBUTE`` and the configuration
    file's logging section is left unapplied, so the handlers pytest
    installed stay in place.
    """

    def build(connection: Any) -> Config:
        config = Config(str(ALEMBIC_INI))
        config.attributes["connection"] = connection
        config.attributes["configure_logger"] = False
        return config

    return build


@pytest.fixture
def migrated_client(migration_connection, alembic_config):
    """Yield a test client whose schema the revisions built.

    Both revisions are applied to the isolated database before the client
    is yielded, so the rows the client reads and writes include the
    account revision 0002 leaves holding the administrative role. The
    application's request-scoped session dependency is overridden for the
    duration of the test and the overrides are cleared afterwards.
    """
    command.upgrade(alembic_config(migration_connection), "head")
    factory = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=migration_connection.engine,
    )

    def override_get_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(
            app, base_url=CLIENT_BASE_URL
        ) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def pre_revision_schema():
    """Return a callable creating the schema preceding revision 0001.

    The callable takes a connection and issues the six tables the
    application carried before the revisions were introduced: ``users``,
    ``listings``, ``filters``, ``zip_codes``, ``criteria`` and
    ``subscriptions``, each without the columns, uniqueness constraints
    or table revision 0001 adds.
    """

    def create(connection: Any) -> None:
        for statement in PRE_REVISION_TABLES:
            connection.execute(text(statement))

    return create
