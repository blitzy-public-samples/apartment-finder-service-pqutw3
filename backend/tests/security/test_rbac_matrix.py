"""The exhaustive deny-by-default authorization matrix.

Every route the service publishes is exercised against every principal
the role model admits. The status each cell must answer is written down
as literal data in :data:`ROUTE_MATRIX`, so the grid reads as a table
and no expectation is computed.

The unit under test is :mod:`backend.app.core.authorization` --
:class:`backend.app.core.authorization.Role`,
:func:`backend.app.core.authorization.require_role` and
:func:`backend.app.core.authorization.resolve_role` -- reached through
the routes that declare it rather than called directly.

This module is the verifier recorded for the finding that the service
carried no role-based access control and no ``role`` column, and for the
object-level half of the authorization cluster.

The grid is the nine published routes by the five principals, so
:data:`MATRIX_CASES` holds forty-five cells and
:func:`test_rbac_matrix_cell` reports one case per cell. Every case is
identified as ``<route-slug>__<principal>``, so a cell named in
``docs/security/TRACEABILITY_MATRIX.md`` is locatable by that
identifier, and
:func:`test_the_matrix_is_nine_routes_by_five_principals` asserts the
shape that count rests on. The nine route slugs and the five principal
names are the stable halves of every identifier.

What each row records:

* ``01_auth_register`` and ``02_auth_login`` answer every principal,
  including one presenting no credential.
* ``03_listings_read`` answers every principal, including one
  presenting no credential.
* ``04_listings_write`` answers ``admin`` alone. This row records the
  one authorization level that changed: ``registered`` and ``premium``
  are refused where they were formerly admitted.
* ``05_filters_create``, ``06_filters_list``,
  ``07_subscriptions_create`` and ``08_subscriptions_read`` answer
  ``registered`` and above, and refuse ``guest`` and the anonymous
  caller.
* ``09_subscriptions_webhook`` answers on the signature alone. All five
  principals are recorded against it: an unverifiable notification is
  refused and a verified one is accepted whichever credential
  accompanies it, so a role token confers nothing there.

A refused principal presenting no credential is answered ``401`` and a
refused principal presenting one is answered ``403``. Every cell names
the status it expects, so neither a ``404`` nor a ``422`` stands in for
an authorization refusal.

The four cross-tenant cases assert that two valid principals holding
:data:`backend.app.core.authorization.Role.REGISTERED` reach neither
each other's filters nor each other's subscriptions, in both
directions. They sit outside :data:`MATRIX_CASES` so the reported cell
count stays at forty-five.

Signature verification, certificate-host allowlisting and replay
detection are asserted in ``test_payment_lifecycle.py`` and are not
repeated here. No provider call leaves this module: both routes that
reach PayPal have that boundary stood in for.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, patch

import pytest

from backend.app.core.authorization import Role
from backend.app.core.plans import (
    PREMIUM_MONTHLY,
    STATUS_ACTIVE,
    get_plan,
)
from backend.app.db.models import Subscription as SubscriptionModel
from backend.app.services import paypal_service
from backend.tests.conftest import ROLE_EMAILS, VALID_TEST_PASSWORD

#: Import path the two provider-facing names are patched on. They are
#: patched where the endpoint module bound them, not where they are
#: defined.
SUBSCRIPTIONS_MODULE = "backend.app.api.endpoints.subscriptions"

# ---------------------------------------------------------------------
# Principals
# ---------------------------------------------------------------------

#: The principal presenting no ``Authorization`` header at all.
ANONYMOUS = "anonymous"

GUEST = Role.GUEST.value

REGISTERED = Role.REGISTERED.value

PREMIUM = Role.PREMIUM.value

ADMIN = Role.ADMIN.value

#: The five principals, in increasing order of privilege after the
#: anonymous caller. The four named roles are the keys the ``client``
#: fixtures seed one stored row under.
PRINCIPALS = (ANONYMOUS, GUEST, REGISTERED, PREMIUM, ADMIN)

# ---------------------------------------------------------------------
# Expectations
# ---------------------------------------------------------------------

#: Status a cell expects when the route admits the principal.
ALLOWED = 200

#: Status a cell expects when the refused principal presented no
#: credential.
UNAUTHENTICATED = 401

#: Status a cell expects when the refused principal presented a
#: credential whose stored role ranks below the route's minimum.
FORBIDDEN = 403

#: Status the notification route answers a delivery it could not verify.
WEBHOOK_REFUSED = 400

#: Expectation recorded for the route admitted on a signature alone: an
#: unverifiable delivery is answered :data:`WEBHOOK_REFUSED` and a
#: verified one is answered :data:`ALLOWED`.
SIGNATURE_GATED = "signature_gated"

# ---------------------------------------------------------------------
# Route slugs, used verbatim in the reported case identifiers
# ---------------------------------------------------------------------

ROUTE_REGISTER = "01_auth_register"

ROUTE_LOGIN = "02_auth_login"

ROUTE_LISTINGS_READ = "03_listings_read"

ROUTE_LISTINGS_WRITE = "04_listings_write"

ROUTE_FILTERS_CREATE = "05_filters_create"

ROUTE_FILTERS_LIST = "06_filters_list"

ROUTE_SUBSCRIPTIONS_CREATE = "07_subscriptions_create"

ROUTE_SUBSCRIPTIONS_READ = "08_subscriptions_read"

ROUTE_SUBSCRIPTIONS_WEBHOOK = "09_subscriptions_webhook"

# ---------------------------------------------------------------------
# Paths. The trailing slash is part of the path the router publishes.
# ---------------------------------------------------------------------

REGISTER_PATH = "/auth/register"

LOGIN_PATH = "/auth/login"

LISTINGS_PATH = "/listings/"

FILTERS_PATH = "/filters/"

SUBSCRIPTIONS_PATH = "/subscriptions/"

WEBHOOK_PATH = "/subscriptions/webhook"

#: The four prefixes ``backend.app.api.router`` mounts. The application
#: includes that router under no further prefix, so every path in
#: :data:`ROUTE_MATRIX` sits directly under one of these.
MOUNTED_PREFIXES = (
    "/auth/",
    "/listings/",
    "/filters/",
    "/subscriptions/",
)

# ---------------------------------------------------------------------
# The matrix. Nine rows of (slug, method, path, expectation per
# principal). Each row lists all five principals together.
# ---------------------------------------------------------------------

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

#: Routes the matrix covers.
EXPECTED_ROUTE_COUNT = 9

#: Principals the matrix covers.
EXPECTED_PRINCIPAL_COUNT = 5

#: Cells the matrix holds, and the number of cases
#: :func:`test_rbac_matrix_cell` must report.
EXPECTED_CELL_COUNT = EXPECTED_ROUTE_COUNT * EXPECTED_PRINCIPAL_COUNT

#: One flattened cell per (route, principal) pair.
MATRIX_CASES = tuple(
    (slug, method, path, principal, expectations[principal])
    for slug, method, path, expectations in ROUTE_MATRIX
    for principal in PRINCIPALS
)

#: Identifier pytest reports each cell under.
MATRIX_CASE_IDS = tuple(
    "{0}__{1}".format(slug, principal)
    for slug, _method, _path, principal, _expected in MATRIX_CASES
)

# ---------------------------------------------------------------------
# Request bodies. Each one satisfies its route's contract exactly.
# ---------------------------------------------------------------------

#: Account the anonymous login cell authenticates as.
LOGIN_FALLBACK_EMAIL = ROLE_EMAILS[REGISTERED]

#: Body accepted by ``backend.app.schema.listing.ListingCreate``.
LISTING_BODY = {
    "rent": 2400.0,
    "bedrooms": 2,
    "street_address": "1 Matrix Way",
}

#: Body accepted by ``backend.app.schema.filter.FilterCreate``, within
#: the bounds it places on both collections.
FILTER_BODY = {
    "name": "rbac matrix filter",
    "zip_codes": [{"code": "10001"}],
    "criteria": [{"field": "rent", "operator": "lte", "value": "3000"}],
}

#: Body accepted by
#: ``backend.app.schema.subscription.SubscriptionCreate``. That contract
#: declares ``plan_id`` alone and forbids every other field.
SUBSCRIPTION_BODY = {"plan_id": PREMIUM_MONTHLY}

#: Payer-approval target a stood-in order carries. Its host sits under a
#: registrable domain in ``settings.PAYPAL_CERT_HOST_ALLOWLIST``.
APPROVAL_URL = "https://www.sandbox.paypal.com/checkoutnow?token=RBAC"

#: Certificate target the notification headers carry.
CERT_URL = (
    "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-RBAC"
)

#: Notification the webhook cells deliver. Its event type is outside the
#: set the endpoint transitions on, and a verified delivery of it is
#: acknowledged without any provider call.
NOTIFICATION = {
    "id": "WH-RBAC-1",
    "event_type": "CUSTOMER.DISPUTE.CREATED",
    "resource": {"id": "ORDER-RBAC-UNMATCHED"},
}

#: Window a stored entitling subscription spans.
ENTITLEMENT_WINDOW = timedelta(days=30)


def register_body(principal: str) -> Dict[str, Any]:
    """Returns the registration body one cell submits.

    The address is distinct per principal, so an admitted cell stores a
    new account rather than colliding with a stored one.
    """
    return {
        "email": "rbac-matrix-{0}@example.com".format(principal),
        "password": VALID_TEST_PASSWORD,
    }


def login_body(principal: str) -> Dict[str, Any]:
    """Returns the login body one cell submits.

    The credentials are correct for a stored account, so no cell leaves
    a failed attempt behind for the lockout counter.
    """
    return {
        "email": ROLE_EMAILS.get(principal, LOGIN_FALLBACK_EMAIL),
        "password": VALID_TEST_PASSWORD,
    }


def order_response(principal: str) -> Dict[str, Any]:
    """Returns a created-order response shaped like PayPal's.

    The order identifier is distinct per principal, so the uniqueness
    constraint on the stored column cannot refuse an admitted cell.
    """
    return {
        "id": "ORDER-RBAC-{0}".format(principal.upper()),
        "status": "PAYER_ACTION_REQUIRED",
        "links": [{"rel": "payer-action", "href": APPROVAL_URL}],
    }


def transmission_id(principal: str) -> str:
    """Returns the delivery identifier one webhook cell presents."""
    return "TRANSMISSION-RBAC-{0}".format(principal.upper())


def webhook_headers(principal: str) -> Dict[str, str]:
    """Returns the five headers a PayPal notification must carry."""
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
    """Returns the message a failed cell reports."""
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
    """Returns the response to one request, sending JSON when posting."""
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
    on refused cells as well as admitted ones, so no cell can reach
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

    The signature check is stood in for, so nothing here reaches
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


@pytest.fixture(autouse=True)
def clear_throttle_counters(reset_rate_limits):
    """Clears the shared limiter counters around every case here.

    The configured limits are not altered; only the counters they are
    evaluated against are cleared, before the case and again after it.
    """
    return None


def test_the_matrix_is_nine_routes_by_five_principals():
    """Asserts the grid's shape and that every row names all five.

    The reported cell count rests on this shape, so a row that lost a
    principal or a duplicated identifier fails here rather than
    silently reducing the number of cells that run. Every path is
    asserted to sit under one of :data:`MOUNTED_PREFIXES`, so no cell
    can address a prefix the router does not mount.
    """
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
    """Asserts row four admits ``admin`` and refuses the other four.

    The row is read straight out of :data:`ROUTE_MATRIX`, so this is the
    recorded expectation rather than a second copy of it.
    """
    recorded = dict(
        (slug, expectations)
        for slug, _method, _path, expectations in ROUTE_MATRIX
    )[ROUTE_LISTINGS_WRITE]
    assert recorded[ANONYMOUS] == UNAUTHENTICATED
    assert recorded[GUEST] == FORBIDDEN
    assert recorded[REGISTERED] == FORBIDDEN
    assert recorded[PREMIUM] == FORBIDDEN
    assert recorded[ADMIN] == ALLOWED


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
    """Asserts one cell of :data:`ROUTE_MATRIX` answers its status.

    A cell whose expectation is :data:`SIGNATURE_GATED` asserts both
    halves of that expectation: the unverifiable delivery is refused and
    the verified one is accepted.
    """
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


# ---------------------------------------------------------------------
# Cross-tenant negatives. Two valid principals at the same role, in both
# directions. These sit outside MATRIX_CASES.
# ---------------------------------------------------------------------

#: Name of the filter the first principal stores.
FIRST_FILTER_NAME = "first principal filter"

#: Name of the filter the second principal stores.
SECOND_FILTER_NAME = "second principal filter"


def _create_filter(
    client: Any, headers: Dict[str, str], name: str
) -> Dict[str, Any]:
    """Stores one filter for the principal the headers name."""
    body = dict(FILTER_BODY, name=name)
    response = client.post(FILTERS_PATH, json=body, headers=headers)
    assert response.status_code == ALLOWED, response.text
    return response.json()


def _listed_filter_names(
    client: Any, headers: Dict[str, str]
) -> List[str]:
    """Returns the names of the filters one principal can read."""
    response = client.get(FILTERS_PATH, headers=headers)
    assert response.status_code == ALLOWED, response.text
    return [entry["name"] for entry in response.json()]


def _store_active_subscription(
    db: Any, user: Any, label: str
) -> Any:
    """Stores one entitling subscription belonging to ``user``."""
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
    """Returns the subscription one principal can read, or ``None``."""
    response = client.get(SUBSCRIPTIONS_PATH, headers=headers)
    assert response.status_code == ALLOWED, response.text
    return response.json()


def test_a_filter_is_absent_from_the_other_principals_page(
    client,
    registered_user,
    second_registered_user,
    auth_header_factory,
):
    """Asserts the first principal's filter is absent from the second's.

    The stored filter is scoped to its owner's identifier, and the
    second principal's page carries the filters it owns and no other.
    """
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
    """Asserts the second principal's filter is absent from the first's.

    This is the reverse direction of
    :func:`test_a_filter_is_absent_from_the_other_principals_page`.
    """
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
    """Asserts the first principal's subscription is not the second's.

    The stored row entitles its owner alone, and the second principal
    reads nothing from it.
    """
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
    """Asserts the second principal's subscription is not the first's.

    This is the reverse direction of
    :func:`test_a_subscription_is_absent_from_the_other_principals_row`.
    """
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
