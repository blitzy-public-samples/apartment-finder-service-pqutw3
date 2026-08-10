import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, patch

import pytest

from backend.app import main as main_module
from backend.app.core.authorization import (
    Role,
    effective_role,
    resolve_role,
)
from backend.app.core.config import settings
from backend.app.core.plans import (
    PREMIUM_MONTHLY,
    STATUS_ACTIVE,
    get_plan,
)
from backend.app.db.models import Subscription as SubscriptionModel
from backend.app.main import app
from backend.app.services import paypal_service
from backend.tests.support import ROLE_EMAILS, VALID_TEST_PASSWORD

SUBSCRIPTIONS_MODULE = "backend.app.api.endpoints.subscriptions"


ANONYMOUS = "anonymous"

GUEST = Role.GUEST.value

REGISTERED = Role.REGISTERED.value

PREMIUM = Role.PREMIUM.value

ADMIN = Role.ADMIN.value

PRINCIPALS = (ANONYMOUS, GUEST, REGISTERED, PREMIUM, ADMIN)


ALLOWED = 200

UNAUTHENTICATED = 401

FORBIDDEN = 403

WEBHOOK_REFUSED = 400

THROTTLED = 429

SIGNATURE_GATED = "signature_gated"


ROUTE_REGISTER = "01_auth_register"

ROUTE_LOGIN = "02_auth_login"

ROUTE_LISTINGS_READ = "03_listings_read"

ROUTE_LISTINGS_WRITE = "04_listings_write"

ROUTE_FILTERS_CREATE = "05_filters_create"

ROUTE_FILTERS_LIST = "06_filters_list"

ROUTE_SUBSCRIPTIONS_CREATE = "07_subscriptions_create"

ROUTE_SUBSCRIPTIONS_READ = "08_subscriptions_read"

ROUTE_SUBSCRIPTIONS_WEBHOOK = "09_subscriptions_webhook"


REGISTER_PATH = "/auth/register"

LOGIN_PATH = "/auth/login"

LISTINGS_PATH = "/listings/"

FILTERS_PATH = "/filters/"

SUBSCRIPTIONS_PATH = "/subscriptions/"

WEBHOOK_PATH = "/subscriptions/webhook"

MOUNTED_PREFIXES = (
    "/auth/",
    "/listings/",
    "/filters/",
    "/subscriptions/",
)

HEALTH_PATH = "/health"

HEALTH_ROUTE = ("GET", HEALTH_PATH)

HEALTH_ROUTE_SLUG = "health"

HEALTH_BODY = {"status": "ok"}

READINESS_PATH = "/health/ready"

READINESS_ROUTE = ("GET", READINESS_PATH)

READINESS_ROUTE_SLUG = "readiness"

READINESS_BODY = {"status": "ready"}

NOT_READY_BODY = {"status": "unavailable"}

READINESS_BOUNDS = (
    "RATE_LIMIT_READINESS",
    "READINESS_CACHE_SECONDS",
    "READINESS_TIMEOUT_SECONDS",
)

READINESS_REUSED_PROBES = 4

OPERATIONAL_ROUTES = frozenset((HEALTH_ROUTE, READINESS_ROUTE))

DOCUMENTATION_PATHS = frozenset(
    (
        "/openapi.json",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
    )
)


ROUTE_MATRIX = (
    (
        ROUTE_REGISTER,
        "POST",
        REGISTER_PATH,
        {
            ANONYMOUS: ALLOWED,
            GUEST: ALLOWED,
            REGISTERED: ALLOWED,
            PREMIUM: ALLOWED,
            ADMIN: ALLOWED,
        },
    ),
    (
        ROUTE_LOGIN,
        "POST",
        LOGIN_PATH,
        {
            ANONYMOUS: ALLOWED,
            GUEST: ALLOWED,
            REGISTERED: ALLOWED,
            PREMIUM: ALLOWED,
            ADMIN: ALLOWED,
        },
    ),
    (
        ROUTE_LISTINGS_READ,
        "GET",
        LISTINGS_PATH,
        {
            ANONYMOUS: ALLOWED,
            GUEST: ALLOWED,
            REGISTERED: ALLOWED,
            PREMIUM: ALLOWED,
            ADMIN: ALLOWED,
        },
    ),
    (
        ROUTE_LISTINGS_WRITE,
        "POST",
        LISTINGS_PATH,
        {
            ANONYMOUS: UNAUTHENTICATED,
            GUEST: FORBIDDEN,
            REGISTERED: FORBIDDEN,
            PREMIUM: FORBIDDEN,
            ADMIN: ALLOWED,
        },
    ),
    (
        ROUTE_FILTERS_CREATE,
        "POST",
        FILTERS_PATH,
        {
            ANONYMOUS: UNAUTHENTICATED,
            GUEST: FORBIDDEN,
            REGISTERED: ALLOWED,
            PREMIUM: ALLOWED,
            ADMIN: ALLOWED,
        },
    ),
    (
        ROUTE_FILTERS_LIST,
        "GET",
        FILTERS_PATH,
        {
            ANONYMOUS: UNAUTHENTICATED,
            GUEST: FORBIDDEN,
            REGISTERED: ALLOWED,
            PREMIUM: ALLOWED,
            ADMIN: ALLOWED,
        },
    ),
    (
        ROUTE_SUBSCRIPTIONS_CREATE,
        "POST",
        SUBSCRIPTIONS_PATH,
        {
            ANONYMOUS: UNAUTHENTICATED,
            GUEST: FORBIDDEN,
            REGISTERED: ALLOWED,
            PREMIUM: ALLOWED,
            ADMIN: ALLOWED,
        },
    ),
    (
        ROUTE_SUBSCRIPTIONS_READ,
        "GET",
        SUBSCRIPTIONS_PATH,
        {
            ANONYMOUS: UNAUTHENTICATED,
            GUEST: FORBIDDEN,
            REGISTERED: ALLOWED,
            PREMIUM: ALLOWED,
            ADMIN: ALLOWED,
        },
    ),
    (
        ROUTE_SUBSCRIPTIONS_WEBHOOK,
        "POST",
        WEBHOOK_PATH,
        {
            ANONYMOUS: SIGNATURE_GATED,
            GUEST: SIGNATURE_GATED,
            REGISTERED: SIGNATURE_GATED,
            PREMIUM: SIGNATURE_GATED,
            ADMIN: SIGNATURE_GATED,
        },
    ),
)

EXPECTED_ROUTE_COUNT = 9

EXPECTED_PRINCIPAL_COUNT = 5

EXPECTED_CELL_COUNT = EXPECTED_ROUTE_COUNT * EXPECTED_PRINCIPAL_COUNT

MATRIX_CASES = tuple(
    (slug, method, path, principal, expectations[principal])
    for slug, method, path, expectations in ROUTE_MATRIX
    for principal in PRINCIPALS
)

MATRIX_CASE_IDS = tuple(
    "{0}__{1}".format(slug, principal)
    for slug, _method, _path, principal, _expected in MATRIX_CASES
)


LOGIN_FALLBACK_EMAIL = ROLE_EMAILS[REGISTERED]

LISTING_BODY = {
    "rent": 2400.0,
    "bedrooms": 2,
    "street_address": "1 Matrix Way",
}

FILTER_BODY = {
    "name": "rbac matrix filter",
    "zip_codes": [{"code": "10001"}],
    "criteria": [{"field": "rent", "operator": "lte", "value": "3000"}],
}

SUBSCRIPTION_BODY = {"plan_id": PREMIUM_MONTHLY}

APPROVAL_URL = "https://www.sandbox.paypal.com/checkoutnow?token=RBAC"

CERT_URL = (
    "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-RBAC"
)

NOTIFICATION = {
    "id": "WH-RBAC-1",
    "event_type": "CUSTOMER.DISPUTE.CREATED",
    "resource": {"id": "ORDER-RBAC-UNMATCHED"},
}

ENTITLEMENT_WINDOW = timedelta(days=30)


def register_body(principal: str) -> Dict[str, Any]:
    return {
        "email": "rbac-matrix-{0}@example.com".format(principal),
        "password": VALID_TEST_PASSWORD,
    }


def login_body(principal: str) -> Dict[str, Any]:
    """Returns the principal-specific login body one cell submits.

    The credentials are correct for a stored account.
    """
    return {
        "email": ROLE_EMAILS.get(principal, LOGIN_FALLBACK_EMAIL),
        "password": VALID_TEST_PASSWORD,
    }


def order_response(principal: str) -> Dict[str, Any]:
    """Returns a created-order response shaped like PayPal's.

    The order identifier is distinct per principal.
    """
    return {
        "id": "ORDER-RBAC-{0}".format(principal.upper()),
        "status": "PAYER_ACTION_REQUIRED",
        "links": [{"rel": "payer-action", "href": APPROVAL_URL}],
    }


def transmission_id(principal: str) -> str:
    return "TRANSMISSION-RBAC-{0}".format(principal.upper())


def webhook_headers(principal: str) -> Dict[str, str]:
    return {
        paypal_service.AUTH_ALGO_HEADER: "SHA256withRSA",
        paypal_service.CERT_URL_HEADER: CERT_URL,
        paypal_service.TRANSMISSION_ID_HEADER: transmission_id(
            principal
        ),
        paypal_service.TRANSMISSION_SIG_HEADER: "c2lnbmF0dXJl",
        paypal_service.TRANSMISSION_TIME_HEADER: (
            "2026-08-07T10:00:00Z"
        ),
        "Content-Type": "application/json",
    }


def headers_for(
    principal: str,
    seeded_users: Dict[str, Any],
    auth_header_factory: Any,
) -> Dict[str, str]:
    """Returns the headers one principal presents.

    The anonymous principal presents no ``Authorization`` header at all;
    every other principal presents a bearer token minted for the stored
    row holding its role.
    """
    if principal == ANONYMOUS:
        return {}
    return auth_header_factory(seeded_users[principal])


def _report(
    route: str, principal: str, expected: Any, response: Any
) -> str:
    return "cell {0}__{1} expected {2}, answered {3}: {4}".format(
        route, principal, expected, response.status_code,
        response.text[:200],
    )


def _send(
    client: Any,
    method: str,
    path: str,
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]],
) -> Any:
    if method == "GET":
        return client.get(path, headers=headers)
    return client.post(path, json=body, headers=headers)


def request_for_cell(
    client: Any,
    route: str,
    method: str,
    path: str,
    headers: Dict[str, str],
    principal: str,
) -> Any:
    """Returns the response one non-notification cell provokes.

    The order call is stood in for on the subscription-creation route,
    on refused cells as well as admitted ones, and no cell reaches
    PayPal.
    """
    if route == ROUTE_REGISTER:
        return _send(
            client, method, path, headers, register_body(principal)
        )
    if route == ROUTE_LOGIN:
        return _send(
            client, method, path, headers, login_body(principal)
        )
    if route == ROUTE_LISTINGS_WRITE:
        return _send(client, method, path, headers, LISTING_BODY)
    if route == ROUTE_FILTERS_CREATE:
        return _send(client, method, path, headers, FILTER_BODY)
    if route == ROUTE_SUBSCRIPTIONS_CREATE:
        with patch(
            SUBSCRIPTIONS_MODULE + ".create_order",
            new=AsyncMock(return_value=order_response(principal)),
        ):
            return _send(
                client, method, path, headers, SUBSCRIPTION_BODY
            )
    return _send(client, method, path, headers, None)


def deliver(
    client: Any,
    headers: Dict[str, str],
    principal: str,
    verified: bool,
) -> Any:
    """Returns the response to one notification delivery.

    The signature check is stood in for, and nothing here reaches
    PayPal. A verified outcome carries the delivery identifier and the
    event type, matching what the real check reports from the body it
    verified.
    """
    if verified:
        outcome = paypal_service.WebhookVerification(
            verified=True,
            transmission_id=transmission_id(principal),
            event_type=NOTIFICATION["event_type"],
        )
    else:
        outcome = paypal_service.WebhookVerification(
            verified=False,
            reason=paypal_service.REASON_SIGNATURE,
        )
    with patch(
        SUBSCRIPTIONS_MODULE + ".verify_webhook_signature",
        new=AsyncMock(return_value=outcome),
    ):
        return client.post(
            WEBHOOK_PATH,
            content=json.dumps(NOTIFICATION).encode("utf-8"),
            headers=dict(webhook_headers(principal), **headers),
        )


def _route_pairs(documented: bool) -> set:
    """Returns ``(method, path)`` for routes on one side of the flag.

    ``app.routes`` is the authority. Passing ``True`` selects the routes
    the framework mounts for its own documentation, each registered with
    ``include_in_schema`` cleared; passing ``False`` selects the routes
    this service publishes.
    """
    pairs = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path is None or not methods:
            continue
        in_schema = bool(getattr(route, "include_in_schema", False))
        if in_schema is documented:
            continue
        for method in methods:
            pairs.add((method, path))
    return pairs


def published_routes() -> set:
    return _route_pairs(documented=False)


def documentation_routes() -> set:
    return _route_pairs(documented=True)


@pytest.fixture(autouse=True)
def clear_throttle_counters(reset_rate_limits):
    """Clears the shared limiter counters around every case here.

    The configured limits are not altered; only the counters they are
    evaluated against are cleared, before the case and again after it.
    """
    return None


def test_the_matrix_covers_every_route_the_application_publishes():
    recorded = set(
        (method, path) for _slug, method, path, _cells in ROUTE_MATRIX
    )
    published = published_routes()

    assert len(recorded) == EXPECTED_ROUTE_COUNT
    assert recorded.isdisjoint(OPERATIONAL_ROUTES)
    assert OPERATIONAL_ROUTES <= published
    assert recorded | OPERATIONAL_ROUTES == published

    excluded = documentation_routes()
    assert excluded
    assert excluded.isdisjoint(published)
    assert set(path for _method, path in excluded) == DOCUMENTATION_PATHS
    assert DOCUMENTATION_PATHS.isdisjoint(
        set(path for _method, path in published)
    )


@pytest.mark.parametrize("principal", PRINCIPALS)
def test_the_health_route_answers_every_principal(
    principal, client, seeded_users, auth_header_factory
):
    headers = headers_for(principal, seeded_users, auth_header_factory)
    method, path = HEALTH_ROUTE

    response = _send(client, method, path, headers, None)

    assert response.status_code == ALLOWED, _report(
        HEALTH_ROUTE_SLUG, principal, ALLOWED, response
    )
    assert response.json() == HEALTH_BODY


@pytest.mark.parametrize("principal", PRINCIPALS)
def test_the_readiness_route_is_bounded_for_every_principal(
    principal, client, seeded_users, auth_header_factory
):
    headers = headers_for(principal, seeded_users, auth_header_factory)
    method, path = READINESS_ROUTE

    for name in READINESS_BOUNDS:
        assert name in type(settings).__fields__, name

    permitted = int(settings.RATE_LIMIT_READINESS.split("/")[0])
    assert permitted >= READINESS_REUSED_PROBES

    reads = []
    original = main_module._read_database

    def counted(db):
        reads.append(db)
        return original(db)

    main_module.reset_readiness_cache()
    with patch.object(main_module, "_read_database", counted):
        answers = [
            _send(client, method, path, headers, None)
            for _ in range(permitted + 1)
        ]

    for response in answers[:permitted]:
        assert response.status_code == ALLOWED, _report(
            READINESS_ROUTE_SLUG, principal, ALLOWED, response
        )
        assert response.json() == READINESS_BODY

    assert answers[-1].status_code == THROTTLED, _report(
        READINESS_ROUTE_SLUG, principal, THROTTLED, answers[-1]
    )

    assert len(reads) == 1, (
        "one recorded outcome must serve every probe inside its window, "
        f"but the database was read {len(reads)} times"
    )


def test_the_matrix_is_nine_routes_by_five_principals():
    assert len(ROUTE_MATRIX) == EXPECTED_ROUTE_COUNT
    assert len(PRINCIPALS) == EXPECTED_PRINCIPAL_COUNT
    assert len(set(PRINCIPALS)) == EXPECTED_PRINCIPAL_COUNT
    assert len(MATRIX_CASES) == EXPECTED_CELL_COUNT
    assert len(set(MATRIX_CASE_IDS)) == EXPECTED_CELL_COUNT

    slugs = [row[0] for row in ROUTE_MATRIX]
    assert len(set(slugs)) == EXPECTED_ROUTE_COUNT
    for slug, method, path, expectations in ROUTE_MATRIX:
        assert method in ("GET", "POST"), slug
        assert path.startswith(MOUNTED_PREFIXES), slug
        assert tuple(expectations) == PRINCIPALS, slug


def test_the_matrix_records_the_listings_write_as_admin_only():
    recorded = dict(
        (slug, expectations)
        for slug, _method, _path, expectations in ROUTE_MATRIX
    )[ROUTE_LISTINGS_WRITE]
    assert recorded[ANONYMOUS] == UNAUTHENTICATED
    assert recorded[GUEST] == FORBIDDEN
    assert recorded[REGISTERED] == FORBIDDEN
    assert recorded[PREMIUM] == FORBIDDEN
    assert recorded[ADMIN] == ALLOWED


EXPECTED_EFFECTIVE_ROLES = {
    GUEST: Role.GUEST,
    REGISTERED: Role.REGISTERED,
    PREMIUM: Role.PREMIUM,
    ADMIN: Role.ADMIN,
}


def test_every_principal_resolves_at_the_role_it_stands_for(
    db, seeded_users
):
    assert set(EXPECTED_EFFECTIVE_ROLES) == set(PRINCIPALS) - {
        ANONYMOUS
    }
    for principal, expected in EXPECTED_EFFECTIVE_ROLES.items():
        row = seeded_users[principal]
        assert resolve_role(row) is expected, principal
        assert effective_role(db, row) is expected, principal


@pytest.mark.parametrize(
    ("route", "method", "path", "principal", "expected"),
    MATRIX_CASES,
    ids=MATRIX_CASE_IDS,
)
def test_rbac_matrix_cell(
    route,
    method,
    path,
    principal,
    expected,
    client,
    seeded_users,
    auth_header_factory,
):
    headers = headers_for(
        principal, seeded_users, auth_header_factory
    )

    if expected == SIGNATURE_GATED:
        refused = deliver(client, headers, principal, verified=False)
        assert refused.status_code == WEBHOOK_REFUSED, _report(
            route, principal, WEBHOOK_REFUSED, refused
        )
        accepted = deliver(client, headers, principal, verified=True)
        assert accepted.status_code == ALLOWED, _report(
            route, principal, ALLOWED, accepted
        )
        return

    response = request_for_cell(
        client, route, method, path, headers, principal
    )
    assert response.status_code == expected, _report(
        route, principal, expected, response
    )


FIRST_FILTER_NAME = "first principal filter"

SECOND_FILTER_NAME = "second principal filter"


def _create_filter(
    client: Any, headers: Dict[str, str], name: str
) -> Dict[str, Any]:
    body = dict(FILTER_BODY, name=name)
    response = client.post(FILTERS_PATH, json=body, headers=headers)
    assert response.status_code == ALLOWED, response.text
    return response.json()


def _listed_filter_names(
    client: Any, headers: Dict[str, str]
) -> List[str]:
    response = client.get(FILTERS_PATH, headers=headers)
    assert response.status_code == ALLOWED, response.text
    return [entry["name"] for entry in response.json()]


def _store_active_subscription(
    db: Any, user: Any, label: str
) -> Any:
    opened = datetime.now(timezone.utc)
    subscription = SubscriptionModel(
        user_id=user.id,
        start_date=opened,
        end_date=opened + ENTITLEMENT_WINDOW,
        status=STATUS_ACTIVE,
        plan_id=PREMIUM_MONTHLY,
        currency=get_plan(PREMIUM_MONTHLY).currency,
        paypal_order_id="ORDER-RBAC-TENANT-{0}".format(label),
    )
    db.add(subscription)
    db.commit()
    db.refresh(subscription)
    return subscription


def _read_subscription(
    client: Any, headers: Dict[str, str]
) -> Optional[Dict[str, Any]]:
    response = client.get(SUBSCRIPTIONS_PATH, headers=headers)
    assert response.status_code == ALLOWED, response.text
    return response.json()


def test_a_filter_is_absent_from_the_other_principals_page(
    client,
    registered_user,
    second_registered_user,
    auth_header_factory,
):
    owner = auth_header_factory(registered_user)
    other = auth_header_factory(second_registered_user)

    stored = _create_filter(client, owner, FIRST_FILTER_NAME)
    assert stored["user_id"] == registered_user.id

    assert FIRST_FILTER_NAME in _listed_filter_names(client, owner)
    assert FIRST_FILTER_NAME not in _listed_filter_names(client, other)
    assert _listed_filter_names(client, other) == []


def test_the_second_principals_filter_is_absent_from_the_first_page(
    client,
    registered_user,
    second_registered_user,
    auth_header_factory,
):
    owner = auth_header_factory(registered_user)
    other = auth_header_factory(second_registered_user)

    stored = _create_filter(client, other, SECOND_FILTER_NAME)
    assert stored["user_id"] == second_registered_user.id

    assert SECOND_FILTER_NAME in _listed_filter_names(client, other)
    assert SECOND_FILTER_NAME not in _listed_filter_names(client, owner)
    assert _listed_filter_names(client, owner) == []


def test_a_subscription_is_absent_from_the_other_principals_row(
    client,
    db,
    registered_user,
    second_registered_user,
    auth_header_factory,
):
    owned = _store_active_subscription(db, registered_user, "first")
    owner = auth_header_factory(registered_user)
    other = auth_header_factory(second_registered_user)

    mine = _read_subscription(client, owner)
    assert mine is not None
    assert mine["id"] == owned.id
    assert mine["user_id"] == registered_user.id

    assert _read_subscription(client, other) is None


def test_the_second_principals_subscription_is_absent_from_the_first(
    client,
    db,
    registered_user,
    second_registered_user,
    auth_header_factory,
):
    owned = _store_active_subscription(
        db, second_registered_user, "second"
    )
    owner = auth_header_factory(registered_user)
    other = auth_header_factory(second_registered_user)

    theirs = _read_subscription(client, other)
    assert theirs is not None
    assert theirs["id"] == owned.id
    assert theirs["user_id"] == second_registered_user.id

    assert _read_subscription(client, owner) is None
