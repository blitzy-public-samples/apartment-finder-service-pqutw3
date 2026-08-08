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
import sys
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.endpoints import filters as filters_module
from backend.app.api.endpoints import listings as listings_module
from backend.app.services import zillow_service
from backend.app.core.config import (
    MAX_PAGINATION_OFFSET_CEILING,
    settings,
)
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
from backend.app.db.models import Listing as ListingModel
from backend.tests.support import enforce_sqlite_foreign_keys
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
from backend.app.schema.listing import (
    COUNT_FIELDS,
    LISTING_URL_DOMAINS,
    LISTING_URL_SCHEMES,
    MEASUREMENT_FIELDS,
    NUMERIC_FIELDS,
    Listing,
    ListingCreate,
)

#: Password the fixtures hash and the login cases send.
PASSWORD = "testpassword123"

#: Header carrying the policy under test.
CSP_HEADER = "content-security-policy"

#: Policy the application serves on every response that is not a
#: documentation page.
API_POLICY = SECURITY_HEADERS["Content-Security-Policy"]

# Offsets a paged read must refuse: the first value above the configured
# cap, the ceiling that cap may itself be raised to, the first value the
# database could not bind, and two further values above that.
REFUSED_OFFSETS = (
    str(settings.MAX_PAGINATION_OFFSET + 1),
    str(MAX_PAGINATION_OFFSET_CEILING + 1),
    str(2 ** 63),
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

# Smallest creation body the listing contract accepts, which each
# measurement case replaces exactly one field of.
BASE_LISTING = {"rent": 2400.0}

# Smallest response body the listing contract accepts, built from the
# non-null columns, which each measurement case replaces one field of.
BASE_LISTING_RESPONSE = {
    "id": 1,
    "created_at": "2026-01-01T00:00:00+00:00",
    "updated_at": "2026-01-01T00:00:00+00:00",
    "rent": 2400.0,
}


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
def admin_user(db):
    user = User(
        email="bounds-admin@example.com",
        hashed_password=get_password_hash(PASSWORD),
        created_at=datetime.now(timezone.utc),
        role="admin",
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
    """A paged read refuses an offset above the configured cap."""

    def test_the_bound_is_an_operational_cap(self):
        assert settings.MAX_PAGINATION_OFFSET <= (
            MAX_PAGINATION_OFFSET_CEILING
        )
        assert MAX_PAGINATION_OFFSET_CEILING < 2 ** 63 - 1
        assert settings.MAX_PAGINATION_OFFSET >= 1

    def test_the_cap_cannot_be_configured_above_the_ceiling(self):
        with pytest.raises(PydanticValidationError):
            settings.__class__(
                **dict(
                    settings.dict(),
                    MAX_PAGINATION_OFFSET=(
                        MAX_PAGINATION_OFFSET_CEILING + 1
                    ),
                )
            )

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
            "/listings/",
            params={"skip": str(settings.MAX_PAGINATION_OFFSET)},
        )
        assert response.status_code == 200
        assert response.json() == []

    def test_the_owned_read_still_serves_the_bound_itself(
        self, client, registered_user
    ):
        response = client.get(
            "/filters/",
            params={"skip": str(settings.MAX_PAGINATION_OFFSET)},
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
        assert parameters["skip"]["maximum"] == (
            settings.MAX_PAGINATION_OFFSET
        )
        assert parameters["skip"]["minimum"] == 0
        assert parameters["limit"]["maximum"] == settings.MAX_PAGE_SIZE

    @pytest.mark.parametrize(
        "module", (listings_module, filters_module)
    )
    def test_neither_read_declares_a_ceiling_of_its_own(self, module):
        assert not hasattr(module, "MAX_PAGINATION_OFFSET")


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


class TestMeasurementsMustBeFiniteAndRepresentable:
    """A measurement no response can carry is refused at the contract.

    Every case here writes through the admin route and reads through the
    public one, because the value that prompted them was accepted by the
    contract, committed by the write, and then broke the read for every
    caller until the row was deleted by hand.
    """

    @pytest.mark.parametrize("field", MEASUREMENT_FIELDS)
    @pytest.mark.parametrize(
        "value", [float("inf"), float("-inf"), float("nan")]
    )
    def test_the_contract_refuses_a_non_finite_measurement(
        self, field, value
    ):
        body = dict(BASE_LISTING)
        body[field] = value
        with pytest.raises(PydanticValidationError):
            ListingCreate(**body)

    @pytest.mark.parametrize("field", MEASUREMENT_FIELDS)
    def test_the_contract_refuses_an_unrepresentable_whole_number(
        self, field
    ):
        body = dict(BASE_LISTING)
        body[field] = int("9" * 309)
        with pytest.raises(PydanticValidationError):
            ListingCreate(**body)

    @pytest.mark.parametrize("field", MEASUREMENT_FIELDS)
    @pytest.mark.parametrize("value", ["inf", "Infinity", "1e400", "nan"])
    def test_the_contract_refuses_a_non_finite_text_measurement(
        self, field, value
    ):
        body = dict(BASE_LISTING)
        body[field] = value
        with pytest.raises(PydanticValidationError):
            ListingCreate(**body)

    def test_a_finite_measurement_is_still_accepted(self):
        accepted = ListingCreate(
            rent=2400.5, broker_fee=0, square_footage=850
        )
        assert accepted.rent == 2400.5
        assert accepted.broker_fee == 0
        assert accepted.square_footage == 850

    def test_the_largest_representable_measurement_is_accepted(self):
        assert ListingCreate(rent=sys.float_info.max).rent == (
            sys.float_info.max
        )

    def test_a_non_numeric_measurement_still_fails_on_its_type(self):
        with pytest.raises(PydanticValidationError) as raised:
            ListingCreate(rent="not a number")
        assert any(
            "float" in str(entry.get("type", ""))
            or "float" in str(entry.get("msg", ""))
            for entry in raised.value.errors()
        )


class TestNumericFieldsRefuseBooleans:
    """A boolean must not become listing data.

    A boolean is a numeric type in Python, so a declared float or integer
    field converts ``true`` to 1 and ``false`` to 0. Every numeric field
    of both contracts refuses one instead.
    """

    @pytest.mark.parametrize("field", NUMERIC_FIELDS)
    @pytest.mark.parametrize("value", [True, False])
    def test_the_request_contract_refuses_a_boolean(self, field, value):
        body = dict(BASE_LISTING)
        body[field] = value
        with pytest.raises(PydanticValidationError):
            ListingCreate(**body)

    @pytest.mark.parametrize("field", NUMERIC_FIELDS)
    @pytest.mark.parametrize("value", [True, False])
    def test_the_response_contract_refuses_a_boolean(self, field, value):
        body = dict(BASE_LISTING_RESPONSE)
        body[field] = value
        with pytest.raises(PydanticValidationError):
            Listing(**body)

    @pytest.mark.parametrize("field", COUNT_FIELDS)
    @pytest.mark.parametrize("value", [0, 1, 4])
    def test_a_whole_number_count_is_still_accepted(self, field, value):
        body = dict(BASE_LISTING)
        body[field] = value
        assert getattr(ListingCreate(**body), field) == value

    def test_the_write_route_refuses_a_boolean_and_stores_nothing(
        self, client, db, admin_user
    ):
        response = client.post(
            "/listings/",
            json=dict(BASE_LISTING, bedrooms=True),
            headers=bearer(admin_user),
        )
        assert response.status_code == 422
        assert response.json() == {"detail": INVALID_REQUEST_DETAIL}
        assert db.query(ListingModel).count() == 0

    def test_every_declared_numeric_field_is_covered(self):
        assert set(NUMERIC_FIELDS) == set(MEASUREMENT_FIELDS) | set(
            COUNT_FIELDS
        )
        assert set(NUMERIC_FIELDS) <= set(ListingCreate.__fields__)
        assert set(NUMERIC_FIELDS) <= set(Listing.__fields__)


class TestListingUrlMustAddressTheProvider:
    """A stored listing address must be a provider address over TLS.

    The read endpoint's response is rendered by the frontend as a link
    labelled for the provider, so an address outside the allowlist would
    be presented under the provider's name. Both the admin write route
    and the ingestion contract are governed by the same model, so a
    provider record carrying an outside address is discarded rather than
    stored.
    """

    @pytest.mark.parametrize(
        "url",
        [
            "https://zillow.com/homedetails/1",
            "https://www.zillow.com/homedetails/1",
            "https://ZILLOW.COM/homedetails/1",
            "https://www.zillow.com./homedetails/1",
            "https://newyork.zillow.com/homedetails/1",
        ],
    )
    def test_an_allowlisted_address_is_accepted(self, url):
        assert ListingCreate(rent=2400.0, zillow_url=url).zillow_url == (
            url
        )

    @pytest.mark.parametrize(
        "url",
        [
            "http://www.zillow.com/homedetails/1",
            "http://zillow.com/homedetails/1",
        ],
    )
    def test_a_plaintext_address_is_refused(self, url):
        with pytest.raises(PydanticValidationError):
            ListingCreate(rent=2400.0, zillow_url=url)

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example.com/homedetails/1",
            "https://notzillow.com/homedetails/1",
            "https://xzillow.com/homedetails/1",
            "https://zillow.com.evil.example.net/homedetails/1",
            "https://evil.example.com/?u=https://www.zillow.com/1",
            "https://evil.example.com/#www.zillow.com",
            "https://www.zillow.com@evil.example.com/homedetails/1",
            "//www.zillow.com/homedetails/1",
            "javascript:alert(1)",
            "ftp://www.zillow.com/homedetails/1",
        ],
    )
    def test_an_address_outside_the_allowlist_is_refused(self, url):
        with pytest.raises(PydanticValidationError):
            ListingCreate(rent=2400.0, zillow_url=url)

    def test_the_allowlist_admits_tls_and_the_provider_only(self):
        assert LISTING_URL_SCHEMES == ("https",)
        assert LISTING_URL_DOMAINS == ("zillow.com",)

    def test_the_write_route_refuses_an_outside_address(
        self, client, db, admin_user
    ):
        response = client.post(
            "/listings/",
            json=dict(
                BASE_LISTING, zillow_url="https://evil.example.com/1"
            ),
            headers=bearer(admin_user),
        )
        assert response.status_code == 422
        assert response.json() == {"detail": INVALID_REQUEST_DETAIL}
        assert db.query(ListingModel).count() == 0

    def test_the_provider_mapper_discards_an_outside_address(self):
        with pytest.raises(zillow_service.ListingMappingError) as raised:
            zillow_service.process_listing(
                {
                    "price": 2400.0,
                    "square_feet": 900.0,
                    "address": "1 Ingest Way",
                    "listing_url": "https://evil.example.com/1",
                }
            )
        assert "zillow_url" in raised.value.fields

    def test_a_stored_outside_address_still_projects(self):
        projected = Listing(
            **dict(
                BASE_LISTING_RESPONSE,
                zillow_url="https://legacy.example.net/1",
            )
        )
        assert projected.zillow_url == "https://legacy.example.net/1"


class TestAListingRefusedByTheDatabaseIsOneFixedError:
    """Every database refusal on the write path answers the same way.

    Revision 0001 adds no uniqueness over the address column, and a
    repeated address is stored rather than refused. Whatever the
    database does refuse -- an integrity violation included -- is rolled
    back and answered with the one recorded detail, and the response
    names neither the constraint nor the statement.
    """

    #: Address both write attempts carry.
    ADDRESS = "https://www.zillow.com/homedetails/duplicate"

    def _create(self, client, admin_user, **overrides):
        return client.post(
            "/listings/",
            json=dict(BASE_LISTING, zillow_url=self.ADDRESS, **overrides),
            headers=bearer(admin_user),
        )

    def test_a_repeated_address_is_stored_rather_than_refused(
        self, client, db, admin_user
    ):
        first = self._create(client, admin_user)
        assert first.status_code == 200

        second = self._create(client, admin_user, rent=9999.0)
        assert second.status_code == 200

        stored = db.query(ListingModel).all()
        assert len(stored) == 2
        assert sorted(row.rent for row in stored) == [
            BASE_LISTING["rent"],
            9999.0,
        ]
        assert {row.zillow_url for row in stored} == {self.ADDRESS}

    def test_an_integrity_violation_is_refused_as_a_server_error(
        self, client, db, admin_user, monkeypatch
    ):
        def refuse(self_, *args, **kwargs):
            raise IntegrityError("insert", {}, Exception("unique"))

        monkeypatch.setattr(Session, "commit", refuse)
        response = self._create(client, admin_user)
        assert response.status_code == 500
        assert response.json() == {
            "detail": listings_module.LISTING_NOT_STORED_DETAIL
        }

    def test_no_refusal_names_the_constraint_the_database_refused(
        self, client, db, admin_user, monkeypatch
    ):
        def refuse(self_, *args, **kwargs):
            raise IntegrityError(
                "insert", {}, Exception("uq_listings_zillow_url")
            )

        monkeypatch.setattr(Session, "commit", refuse)
        response = self._create(client, admin_user)
        body = response.text
        assert "uq_listings_zillow_url" not in body
        assert "insert" not in body
        assert response.json() == {
            "detail": listings_module.LISTING_NOT_STORED_DETAIL
        }

    def test_the_module_publishes_no_duplicate_specific_refusal(self):
        assert not hasattr(listings_module, "LISTING_DUPLICATE_DETAIL")

    def test_a_distinct_address_is_still_accepted(
        self, client, db, admin_user
    ):
        assert self._create(client, admin_user).status_code == 200
        other = client.post(
            "/listings/",
            json=dict(
                BASE_LISTING,
                zillow_url="https://www.zillow.com/homedetails/other",
            ),
            headers=bearer(admin_user),
        )
        assert other.status_code == 200
        assert db.query(ListingModel).count() == 2

    def test_a_database_failure_is_still_a_server_error(
        self, client, db, admin_user, monkeypatch
    ):
        def refuse(self_, *args, **kwargs):
            raise SQLAlchemyError("disk full")

        monkeypatch.setattr(Session, "commit", refuse)
        response = self._create(client, admin_user)
        assert response.status_code == 500
        assert response.json() == {
            "detail": listings_module.LISTING_NOT_STORED_DETAIL
        }

    @pytest.mark.parametrize("field", MEASUREMENT_FIELDS)
    def test_the_response_contract_refuses_a_non_finite_measurement(
        self, field
    ):
        body = dict(BASE_LISTING_RESPONSE)
        body[field] = float("inf")
        with pytest.raises(PydanticValidationError):
            Listing(**body)

    @pytest.mark.parametrize(
        "field", MEASUREMENT_FIELDS + COUNT_FIELDS
    )
    @pytest.mark.parametrize("value", [True, False])
    def test_the_contract_refuses_a_boolean_numeric(self, field, value):
        body = dict(BASE_LISTING)
        body[field] = value
        with pytest.raises(PydanticValidationError):
            ListingCreate(**body)

    @pytest.mark.parametrize(
        "field", MEASUREMENT_FIELDS + COUNT_FIELDS
    )
    def test_the_response_contract_refuses_a_boolean_numeric(
        self, field
    ):
        body = dict(BASE_LISTING_RESPONSE)
        body[field] = True
        with pytest.raises(PydanticValidationError):
            Listing(**body)

    @pytest.mark.parametrize(
        "literal",
        [
            '{"rent": true}',
            '{"rent": 1000, "bedrooms": true}',
            '{"rent": 1000, "bathrooms": false}',
            '{"rent": 1000, "broker_fee": true}',
        ],
    )
    def test_the_write_route_refuses_a_boolean_and_stores_nothing(
        self, client, db, admin_user, literal
    ):
        response = client.post(
            "/listings/",
            content=literal,
            headers=dict(
                bearer(admin_user), **{"Content-Type": "application/json"}
            ),
        )
        assert response.status_code == 422
        assert response.json() == {"detail": INVALID_REQUEST_DETAIL}
        assert db.query(ListingModel).count() == 0

    @pytest.mark.parametrize(
        "literal",
        [
            '{"rent": 1e400}',
            '{"rent": 1e999}',
            '{"rent": Infinity}',
            '{"rent": 1000, "broker_fee": 1e400}',
            '{"rent": 1000, "square_footage": 1e400}',
            '{"rent": %s}' % ("9" * 309),
        ],
    )
    def test_the_write_route_refuses_the_literal_and_stores_nothing(
        self, client, db, admin_user, literal
    ):
        response = client.post(
            "/listings/",
            content=literal,
            headers=dict(
                bearer(admin_user), **{"Content-Type": "application/json"}
            ),
        )
        assert response.status_code == 422
        assert response.json() == {"detail": INVALID_REQUEST_DETAIL}
        assert db.query(ListingModel).count() == 0
        assert client.get("/listings/").status_code == 200

    def test_the_public_read_refuses_a_page_carrying_an_unusable_row(
        self, client, db, admin_user
    ):
        recorded = datetime.now(timezone.utc)
        for rent in (1000.0, float("inf"), 3000.0):
            db.add(
                ListingModel(
                    created_at=recorded,
                    updated_at=recorded,
                    rent=rent,
                    street_address="row %r" % rent,
                )
            )
        db.commit()
        assert db.query(ListingModel).count() == 3

        # The whole corpus, and the single-row window over the unusable
        # row, are both refused rather than silently shortened.
        for query in ("", "?skip=1&limit=1"):
            response = client.get("/listings/" + query)
            assert response.status_code == 500
            assert response.json() == {
                "detail": listings_module.LISTING_NOT_PROJECTABLE_DETAIL
            }

        # A window that excludes the unusable row is unaffected, and each
        # page carries every row its window selects.
        first = client.get("/listings/?skip=0&limit=1")
        assert first.status_code == 200
        assert [row["rent"] for row in first.json()] == [1000.0]

        last = client.get("/listings/?skip=2&limit=1")
        assert last.status_code == 200
        assert [row["rent"] for row in last.json()] == [3000.0]

    def test_a_short_page_means_the_corpus_ended(
        self, client, db, admin_user
    ):
        recorded = datetime.now(timezone.utc)
        for rent in (1000.0, 2000.0, 3000.0):
            db.add(
                ListingModel(
                    created_at=recorded, updated_at=recorded, rent=rent
                )
            )
        db.commit()

        page = client.get("/listings/?skip=0&limit=10")
        assert page.status_code == 200
        assert [row["rent"] for row in page.json()] == [
            1000.0,
            2000.0,
            3000.0,
        ]

        beyond = client.get("/listings/?skip=3&limit=10")
        assert beyond.status_code == 200
        assert beyond.json() == []

    def test_the_write_route_still_accepts_every_allowed_field(
        self, client, db, admin_user
    ):
        response = client.post(
            "/listings/",
            json={
                "rent": 2400.0,
                "broker_fee": 1200.0,
                "square_footage": 850.0,
                "bedrooms": 2,
                "bathrooms": 1,
                "available_date": "2026-09-01T00:00:00+00:00",
                "street_address": "1 Finite Way",
                "zillow_url": "https://www.zillow.com/homedetails/finite",
            },
            headers=bearer(admin_user),
        )
        assert response.status_code == 200
        stored = db.query(ListingModel).one()
        assert stored.rent == 2400.0
        assert stored.broker_fee == 1200.0
        assert stored.square_footage == 850.0

    def test_the_provider_mapper_discards_a_non_finite_measurement(self):
        with pytest.raises(zillow_service.ListingMappingError) as raised:
            zillow_service.process_listing(
                {
                    "price": float("inf"),
                    "square_feet": 900.0,
                    "address": "1 Ingest Way",
                    "listing_url": "https://www.zillow.com/homedetails/x",
                }
            )
        assert "rent" in raised.value.fields

    def test_the_provider_mapper_still_accepts_a_finite_measurement(self):
        mapped = zillow_service.process_listing(
            {
                "price": 2400.0,
                "square_feet": 900.0,
                "address": "1 Ingest Way",
                "listing_url": "https://www.zillow.com/homedetails/x",
            }
        )
        assert mapped.rent == 2400.0
        assert mapped.square_footage == 900.0
