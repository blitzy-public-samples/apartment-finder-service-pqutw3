"""Shared fixtures for the backend test suite.

This module is imported before any test module in ``backend/tests`` and
in ``backend/tests/security``. It performs two bootstrap steps at import
time and then publishes the fixtures the suite draws on.

The bootstrap steps are:

* the repository root is prepended to ``sys.path`` when it is absent
  from it
* every setting :class:`backend.app.core.config.Settings` requires is
  placed in the process environment when it is absent from it, using
  the values in :data:`TEST_SETTINGS`

Both steps run at import time, so pytest started from the repository
root and pytest started from ``backend`` reach the same state.

The fixtures published are:

* :func:`session_factory` and :func:`db` -- an isolated in-memory
  database whose schema is built from ``Base.metadata``
* :func:`client` and :func:`anonymous_client` -- a test client whose
  request-scoped session is the one :func:`db` yields
* :func:`guest_user`, :func:`registered_user`, :func:`premium_user`,
  :func:`admin_user` and :func:`second_registered_user` -- one stored
  row per role, plus a second row at :data:`Role.REGISTERED`
* :func:`token_factory` and :func:`auth_header_factory` -- valid access
  tokens and the header that carries them
* :func:`forged_token_factory` -- tokens that must fail verification
* :func:`login_json` and :func:`reset_rate_limits` -- the credential
  endpoint and the counters it is throttled by

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

import os
import sys
from pathlib import Path

#: Absolute path of the repository root, two directories above this
#: file.
REPO_ROOT = Path(__file__).resolve().parents[2]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

#: Settings placed in the process environment when absent from it. Every
#: value is a local test value: none is read from a deployed
#: environment and none is a credential.
TEST_SETTINGS = {
    "ENVIRONMENT": "local",
    "DATABASE_URL": (
        "postgresql://localhost:5432/apartment_finder_test"
    ),
    "SECRET_KEY": "tZ4mQ7vK2pR9wB6nD3jS8xF5hL0cY1gA",
    "JWT_ALGORITHMS": "HS256",
    "ZILLOW_API_KEY": "listing-provider-test-key",
    "PAYPAL_MODE": "sandbox",
    "PAYPAL_CLIENT_ID": "paypal-test-client-id",
    "PAYPAL_CLIENT_SECRET": "paypal-test-client-secret",
    "PAYPAL_WEBHOOK_ID": "paypal-test-webhook-id",
    "SENDGRID_API_KEY": "sendgrid-test-key",
}

for _name, _value in TEST_SETTINGS.items():
    os.environ.setdefault(_name, _value)

del _name, _value

import asyncio  # noqa: E402
import base64  # noqa: E402
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
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from backend.app.core.authorization import Role  # noqa: E402
from backend.app.core.config import settings  # noqa: E402
from backend.app.core.security import (  # noqa: E402
    JWT_ALGORITHMS,
    REQUIRED_CLAIMS,
    SIGNING_ALGORITHM,
    create_access_token,
    get_password_hash,
)
from backend.app.db.database import get_db  # noqa: E402
from backend.app.db.models import Base, User  # noqa: E402
from backend.app.main import app, limiter  # noqa: E402

#: Password every seeded row is created with. It satisfies the policy
#: :class:`backend.app.schema.user.UserCreate` applies: at least twelve
#: characters carrying an upper-case letter, a lower-case letter, a
#: digit and a special character, within seventy-two UTF-8 bytes.
VALID_TEST_PASSWORD = "TestPassw0rd!2024"

#: Address of the seeded row holding each role.
ROLE_EMAILS = {
    Role.GUEST.value: "guest@example.com",
    Role.REGISTERED.value: "registered@example.com",
    Role.PREMIUM.value: "premium@example.com",
    Role.ADMIN.value: "admin@example.com",
}

#: Address of the second row holding :data:`Role.REGISTERED`.
SECOND_REGISTERED_EMAIL = "second.registered@example.com"

#: Signing key used by :meth:`ForgedTokenFactory.wrong_key`. It is
#: never the configured key.
FOREIGN_SIGNING_KEY = "pW3sJ8fH1nT6bC9mZ4vG7kR0dY2xQ5aL"

#: Audience used by :meth:`ForgedTokenFactory.wrong_audience`.
FOREIGN_AUDIENCE = "apartment-finder-other-audience"

#: Issuer used by :meth:`ForgedTokenFactory.wrong_issuer`.
FOREIGN_ISSUER = "apartment-finder-other-issuer"

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

#: Base URL every client is opened on. It names a host present in
#: ``settings.ALLOWED_HOSTS``.
CLIENT_BASE_URL = "http://localhost"


def bearer_header(token: str) -> Dict[str, str]:
    """Return the ``Authorization`` header mapping carrying ``token``."""
    return {"Authorization": "Bearer {0}".format(token)}


def _as_tuple(
    value: Optional[Union[str, Iterable[str]]],
) -> Tuple[str, ...]:
    """Return ``value`` as a tuple of names.

    ``None`` becomes an empty tuple and a single string becomes a
    one-element tuple, so a caller may name one claim or several.
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
    key, and any other value is used as given.
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


def pytest_pyfunc_call(pyfuncitem):
    """Run a coroutine test function that no plugin has claimed.

    Returns ``True`` once such a coroutine has been driven to
    completion on a loop of its own. It returns ``None`` for every
    other function, leaving the default call in place. A test carrying
    ``@pytest.mark.asyncio`` reaches this hook as the synchronous
    wrapper the asyncio plugin installed, and takes that second path.
    """
    function = pyfuncitem.obj
    if not asyncio.iscoroutinefunction(function):
        return None
    supplied = pyfuncitem.funcargs
    arguments = dict(
        (name, supplied[name])
        for name in pyfuncitem._fixtureinfo.argnames
        if name in supplied
    )
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(function(**arguments))
    finally:
        loop.close()
    return True


@pytest.fixture
def session_factory():
    """Yield a session factory bound to an isolated database.

    The database is held in memory by a single connection, and its
    schema is built from ``Base.metadata`` before the factory is
    yielded and dropped afterwards. No row outlives one test.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
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
def premium_user(user_factory) -> User:
    """Return the stored row holding :data:`Role.PREMIUM`."""
    return user_factory(ROLE_EMAILS[Role.PREMIUM.value], Role.PREMIUM)


@pytest.fixture
def admin_user(user_factory) -> User:
    """Return the stored row holding :data:`Role.ADMIN`."""
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
    """Mints tokens that carry a deliberate defect.

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
    """Return the factory that mints tokens carrying a defect.

    The factory reads no fixture and touches no database, so a case may
    use it on its own. It mints for :data:`DEFAULT_FORGED_SUBJECT`
    unless a call passes ``sub``.
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
            limiter.reset()
        return test_client.post(
            "/auth/login", json={"email": email, "password": password}
        )

    return post_login


@pytest.fixture
def reset_rate_limits():
    """Clear the shared limiter counters before and after the test."""
    limiter.reset()
    try:
        yield
    finally:
        limiter.reset()
