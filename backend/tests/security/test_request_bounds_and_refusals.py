"""Regression tests for the paged-read bounds and the refusal shapes.

The cases here cover four behaviours a runtime review found missing from
the assembled application. A paged read accepted an offset above the
value the database can bind, so the statement failed and the request
ended as an unhandled server error. A saved filter accepted exactly one
predicate, so the two-input price range the client renders could not be
stored. A throttled request answered with a body shape no other status
uses and named no retry interval, and a request naming a host outside the
allowed list answered in plain text. One content-security policy governed
both the API responses and the documentation pages, so a published page
could not load the viewer it names.

Each case asserts the behaviour through the application, so a change that
reintroduces any of the four fails here rather than at a later review.
"""

import base64
import hashlib
import re
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.endpoints import filters as filters_module
from backend.app.api.endpoints import listings as listings_module
from backend.app.core.config import MAX_PAGINATION_OFFSET, settings
from backend.app.core.rate_limit import (
    RATE_LIMIT_HEADERS,
    RATE_LIMIT_RESET_HEADER,
    RETRY_AFTER_HEADER,
)
from backend.app.core.security import (
    create_access_token,
    get_password_hash,
)
from backend.app.db import database as database_module
from backend.app.db.models import Base, Criteria, Filter, User
from backend.app.main import (
    DOCS_PATH,
    DOCUMENTATION_ENABLED,
    DOCUMENTATION_PATHS,
    DOCUMENTATION_VIEWER_ORIGIN,
    DOCUMENTATION_WORKER_SOURCE,
    INVALID_HOST_DETAIL,
    INVALID_REQUEST_DETAIL,
    OAUTH2_REDIRECT_PATH,
    REDOC_PATH,
    SECURITY_HEADERS,
    TOO_MANY_REQUESTS_DETAIL,
    app,
)
from backend.app.schema.filter import (
    MAX_CRITERIA,
    MAX_ZIP_CODES,
    MIN_CRITERIA,
)

#: Password the fixtures hash and the login cases send.
PASSWORD = "testpassword123"

#: Header carrying the policy under test.
CSP_HEADER = "content-security-policy"

#: Policy the application serves on every response that is not a
#: documentation page.
API_POLICY = SECURITY_HEADERS["Content-Security-Policy"]

# Offsets a paged read must refuse: the first value above the one the
# database can bind, and three further values above that.
REFUSED_OFFSETS = (
    str(2 ** 63),
    str(2 ** 64),
    str(10 ** 20 - 1),
    "9" * 200,
)

# Script elements carrying their own content rather than a source.
INLINE_SCRIPT = re.compile(
    r"<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>",
    re.DOTALL | re.IGNORECASE,
)

documentation_published = pytest.mark.skipif(
    not DOCUMENTATION_ENABLED,
    reason="the documentation pages are published only in local runs",
)


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


@pytest.fixture
def registered_user(db):
    user = User(
        email="bounds@example.com",
        hashed_password=get_password_hash(PASSWORD),
        created_at=datetime.now(timezone.utc),
        role="registered",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def limiter():
    """Yields the application limiter with its counters cleared."""
    instance = app.state.limiter
    instance.reset()
    try:
        yield instance
    finally:
        instance.reset()


def bearer(user):
    token = create_access_token(
        data={"sub": str(user.id), "role": user.role}
    )
    return {"Authorization": "Bearer " + token}


def criteria_body(count, name="Bounded filter"):
    """Returns a creation body carrying ``count`` predicates."""
    return {
        "name": name,
        "zip_codes": [{"code": "02139"}],
        "criteria": [
            {
                "field": "rent",
                "operator": "lte",
                "value": str(3000 + index),
            }
            for index in range(count)
        ],
    }


def zip_code_body(count):
    """Returns a creation body carrying ``count`` postal codes."""
    return {
        "name": "Postal codes",
        "zip_codes": [
            {"code": "0213%d" % index} for index in range(count)
        ],
        "criteria": [
            {"field": "rent", "operator": "lte", "value": "3000"}
        ],
    }


def paged_parameters(path):
    """Returns the published schema of one paged read's parameters."""
    schema = app.openapi()
    parameters = schema["paths"][path]["get"]["parameters"]
    return {
        parameter["name"]: parameter["schema"]
        for parameter in parameters
    }


class TestPagedOffsetIsBounded:
    """A paged read refuses an offset it could not execute."""

    def test_the_bound_is_the_value_the_database_can_bind(self):
        assert MAX_PAGINATION_OFFSET == 2 ** 63 - 1

    @pytest.mark.parametrize("offset", REFUSED_OFFSETS)
    def test_the_public_read_refuses_an_offset_above_it(
        self, client, offset
    ):
        response = client.get("/listings/", params={"skip": offset})
        assert response.status_code == 422
        assert response.json() == {"detail": INVALID_REQUEST_DETAIL}

    @pytest.mark.parametrize("offset", REFUSED_OFFSETS)
    def test_the_owned_read_refuses_an_offset_above_it(
        self, client, registered_user, offset
    ):
        response = client.get(
            "/filters/",
            params={"skip": offset},
            headers=bearer(registered_user),
        )
        assert response.status_code == 422
        assert response.json() == {"detail": INVALID_REQUEST_DETAIL}

    def test_the_public_read_still_serves_the_bound_itself(
        self, client
    ):
        response = client.get(
            "/listings/", params={"skip": str(MAX_PAGINATION_OFFSET)}
        )
        assert response.status_code == 200
        assert response.json() == []

    def test_the_owned_read_still_serves_the_bound_itself(
        self, client, registered_user
    ):
        response = client.get(
            "/filters/",
            params={"skip": str(MAX_PAGINATION_OFFSET)},
            headers=bearer(registered_user),
        )
        assert response.status_code == 200
        assert response.json() == []

    def test_the_public_read_stays_reachable_without_a_credential(
        self, client
    ):
        response = client.get("/listings/")
        assert response.status_code == 200

    def test_a_negative_offset_is_still_refused(self, client):
        response = client.get("/listings/", params={"skip": "-1"})
        assert response.status_code == 422

    @pytest.mark.parametrize("path", ("/listings/", "/filters/"))
    def test_the_published_schema_advertises_the_bound(self, path):
        parameters = paged_parameters(path)
        assert "maximum" in parameters["skip"]
        assert parameters["skip"]["minimum"] == 0
        assert parameters["limit"]["maximum"] == settings.MAX_PAGE_SIZE

    @pytest.mark.parametrize(
        "module", (listings_module, filters_module)
    )
    def test_both_reads_share_one_declared_ceiling(self, module):
        assert module.MAX_PAGINATION_OFFSET is MAX_PAGINATION_OFFSET


class TestSavedFilterHoldsSeveralPredicates:
    """A saved filter carries a range of predicates, not exactly one."""

    def test_the_ceiling_admits_a_two_ended_range(self):
        assert MIN_CRITERIA == 1
        assert MAX_CRITERIA >= 2

    def test_the_two_collections_are_bounded_alike(self):
        assert MAX_CRITERIA == MAX_ZIP_CODES

    def test_a_price_range_is_accepted_and_stored(
        self, client, registered_user, db
    ):
        response = client.post(
            "/filters/",
            json={
                "name": "Rent range",
                "zip_codes": [{"code": "02139"}],
                "criteria": [
                    {
                        "field": "rent",
                        "operator": "gte",
                        "value": "1500",
                    },
                    {
                        "field": "rent",
                        "operator": "lte",
                        "value": "2500",
                    },
                ],
            },
            headers=bearer(registered_user),
        )
        assert response.status_code == 200
        body = response.json()
        assert [
            (entry["field"], entry["operator"], entry["value"])
            for entry in body["criteria"]
        ] == [
            ("rent", "gte", "1500"),
            ("rent", "lte", "2500"),
        ]
        stored = (
            db.query(Criteria)
            .filter(Criteria.filter_id == body["id"])
            .order_by(Criteria.id)
            .all()
        )
        assert [
            (row.field, row.operator, row.value) for row in stored
        ] == [
            ("rent", "gte", "1500"),
            ("rent", "lte", "2500"),
        ]

    def test_the_read_projects_every_stored_predicate(
        self, client, registered_user
    ):
        created = client.post(
            "/filters/",
            json=criteria_body(MAX_CRITERIA),
            headers=bearer(registered_user),
        )
        assert created.status_code == 200
        listed = client.get(
            "/filters/", headers=bearer(registered_user)
        )
        assert listed.status_code == 200
        assert len(listed.json()[0]["criteria"]) == MAX_CRITERIA

    @pytest.mark.parametrize(
        "count, expected",
        (
            (0, 422),
            (MIN_CRITERIA, 200),
            (MAX_CRITERIA, 200),
            (MAX_CRITERIA + 1, 422),
        ),
    )
    def test_the_predicate_count_is_bounded_at_both_ends(
        self, client, registered_user, count, expected
    ):
        response = client.post(
            "/filters/",
            json=criteria_body(count, name="Count %d" % count),
            headers=bearer(registered_user),
        )
        assert response.status_code == expected

    @pytest.mark.parametrize(
        "count, expected",
        ((MAX_ZIP_CODES, 200), (MAX_ZIP_CODES + 1, 422)),
    )
    def test_the_postal_code_bound_is_unchanged(
        self, client, registered_user, count, expected
    ):
        response = client.post(
            "/filters/",
            json=zip_code_body(count),
            headers=bearer(registered_user),
        )
        assert response.status_code == expected

    def test_a_filter_stays_scoped_to_the_account_that_saved_it(
        self, client, registered_user, db
    ):
        created = client.post(
            "/filters/",
            json=criteria_body(2),
            headers=bearer(registered_user),
        )
        assert created.status_code == 200
        other = User(
            email="other-bounds@example.com",
            hashed_password=get_password_hash(PASSWORD),
            created_at=datetime.now(timezone.utc),
            role="registered",
        )
        db.add(other)
        db.commit()
        db.refresh(other)
        listed = client.get("/filters/", headers=bearer(other))
        assert listed.status_code == 200
        assert listed.json() == []
        assert db.query(Filter).count() == 1


class TestRefusalsShareOneShape:
    """Every refusal answers with the shape the service uses."""

    def _exhaust_login(self, client, limiter):
        allowed = int(settings.RATE_LIMIT_LOGIN.split("/", 1)[0])
        response = None
        for _ in range(allowed + 1):
            response = client.post(
                "/auth/login",
                json={
                    "email": "absent-bounds@example.com",
                    "password": "WrongPass#123",
                },
            )
            if response.status_code == 429:
                return response
        raise AssertionError(
            "the limit was not reached: last status %d"
            % response.status_code
        )

    def test_a_throttled_request_uses_the_service_envelope(
        self, client, limiter
    ):
        throttled = self._exhaust_login(client, limiter)
        assert throttled.json() == {
            "detail": TOO_MANY_REQUESTS_DETAIL
        }
        assert throttled.headers["content-type"].startswith(
            "application/json"
        )

    def test_a_throttled_request_names_its_retry_interval(
        self, client, limiter
    ):
        throttled = self._exhaust_login(client, limiter)
        assert int(throttled.headers[RETRY_AFTER_HEADER]) > 0

    def test_a_throttled_request_carries_the_policy_headers(
        self, client, limiter
    ):
        throttled = self._exhaust_login(client, limiter)
        for header in RATE_LIMIT_HEADERS:
            assert header in throttled.headers
        assert throttled.headers[RATE_LIMIT_RESET_HEADER].isdigit()

    def test_a_throttled_request_keeps_the_security_headers(
        self, client, limiter
    ):
        throttled = self._exhaust_login(client, limiter)
        for name, value in SECURITY_HEADERS.items():
            assert throttled.headers[name] == value

    def test_a_counted_call_that_succeeds_is_unaffected(
        self, client, registered_user, limiter
    ):
        response = client.post(
            "/auth/login",
            json={
                "email": registered_user.email,
                "password": PASSWORD,
            },
        )
        assert response.status_code == 200
        assert list(response.json()) == ["access_token", "token_type"]
        for header in RATE_LIMIT_HEADERS + (RETRY_AFTER_HEADER,):
            assert header not in response.headers

    def test_a_refused_host_uses_the_service_envelope(self, client):
        response = client.get(
            "/health", headers={"Host": "evil.example.com"}
        )
        assert response.status_code == 400
        assert response.headers["content-type"].startswith(
            "application/json"
        )
        assert response.json() == {"detail": INVALID_HOST_DETAIL}

    def test_an_allowed_host_is_still_served(self, client):
        for host in settings.ALLOWED_HOSTS:
            response = client.get("/health", headers={"Host": host})
            assert response.status_code == 200


class TestDocumentationPolicyIsScopedToItsPages:
    """A documentation page and an API response carry own policies."""

    @pytest.mark.parametrize(
        "path", ("/health", "/listings/", "/nothing-here")
    )
    def test_an_api_response_keeps_the_strict_policy(
        self, client, path
    ):
        response = client.get(path)
        assert response.headers[CSP_HEADER] == API_POLICY

    @documentation_published
    @pytest.mark.parametrize("path", DOCUMENTATION_PATHS)
    def test_a_page_carries_exactly_one_policy(self, client, path):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers[CSP_HEADER] != API_POLICY
        assert (
            response.headers.get_list(CSP_HEADER).__len__() == 1
        )

    @documentation_published
    @pytest.mark.parametrize("path", (DOCS_PATH, REDOC_PATH))
    def test_a_page_admits_only_what_its_viewer_needs(
        self, client, path
    ):
        policy = client.get(path).headers[CSP_HEADER]
        directives = {
            entry.split(" ", 1)[0]: entry.split(" ", 1)[-1]
            for entry in policy.split("; ")
        }
        assert directives["default-src"] == "'none'"
        assert directives["connect-src"] == "'self'"
        assert (
            directives["worker-src"] == DOCUMENTATION_WORKER_SOURCE
        )
        assert DOCUMENTATION_VIEWER_ORIGIN in directives["script-src"]
        assert "'unsafe-inline'" not in directives["script-src"]
        for denied in ("frame-ancestors", "base-uri", "form-action"):
            assert directives[denied] == "'none'"

    @documentation_published
    @pytest.mark.parametrize("path", (DOCS_PATH, OAUTH2_REDIRECT_PATH))
    def test_an_inline_script_is_admitted_by_its_own_digest(
        self, client, path
    ):
        response = client.get(path)
        policy = response.headers[CSP_HEADER]
        scripts = INLINE_SCRIPT.findall(response.text)
        assert scripts
        for script in scripts:
            digest = hashlib.sha256(script.encode("utf-8")).digest()
            encoded = base64.b64encode(digest).decode("ascii")
            assert "'sha256-" + encoded + "'" in policy

    @documentation_published
    def test_the_schema_itself_is_not_treated_as_a_page(self, client):
        response = client.get("/openapi.json")
        assert response.status_code == 200
        assert response.headers[CSP_HEADER] == API_POLICY
