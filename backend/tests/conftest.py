"""Shared isolated database, client, token, and migration fixtures for
backend tests.
"""

import asyncio
import os
import sys
import time
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
    enforce_sqlite_foreign_keys,
)

ENV_FILE_VARIABLE = "ENV_FILE"

REPLACED_ENVIRONMENT = dict(
    (_name, os.environ.get(_name)) for _name in TEST_SETTINGS
)

PRIOR_ENVIRONMENT = REPLACED_ENVIRONMENT

REPLACED_ENV_FILE = os.environ.get(ENV_FILE_VARIABLE)

os.environ[ENV_FILE_VARIABLE] = ""

apply_test_settings()

import base64  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import uuid  # noqa: E402
from urllib.parse import urlsplit  # noqa: E402
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
from sqlalchemy import (  # noqa: E402
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from backend.app.core.authorization import Role  # noqa: E402
from backend.app.core.config import (  # noqa: E402
    IN_PROCESS_RATE_LIMIT_SCHEMES,
    rate_limit_storage_scheme,
    settings,
)
from backend.app.core.plans import (  # noqa: E402
    PLAN_IDS,
    PREMIUM_MONTHLY,
    STATUS_ACTIVE,
    format_amount,
    get_plan,
)
from backend.app.core.security import (  # noqa: E402
    JWT_ALGORITHMS,
    REQUIRED_CLAIMS,
    SIGNING_ALGORITHM,
    create_access_token,
    get_password_hash,
)
from backend.app.db import database as database_module  # noqa: E402
from backend.app.db.database import get_db  # noqa: E402
from backend.app.db.models import (  # noqa: E402
    Base,
    Subscription,
    User,
)
from backend.app.main import (  # noqa: E402
    app,
    limiter,
    reset_readiness_cache,
)

_SETTINGS_COVERAGE_GAP = sorted(
    set(type(settings).__fields__) ^ set(TEST_SETTINGS)
)

ISOLATED_SETTINGS = (
    "ENVIRONMENT",
    "DATABASE_URL",
    "SECRET_KEY",
    "RATE_LIMIT_STORAGE_URI",
    "ZILLOW_API_URL",
    "PAYPAL_API_BASE",
)

UNISOLATED_SETTING_MESSAGE = (
    "the test suite refuses to run against a setting it did not place "
    "in the process environment"
)

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

PREMIUM_ENTITLEMENT_ORDER_ID = "ORDER-PREMIUM-ENTITLEMENT"

DEFAULT_FORGED_SUBJECT = "1"

FORGED_TOKEN_LIFETIME = timedelta(minutes=5)

FORGED_TOKEN_SKEW = timedelta(minutes=30)

UNLISTED_ALGORITHM_CANDIDATES = ("HS512", "HS384", "HS256")

ALEMBIC_INI = REPO_ROOT / "backend" / "alembic.ini"

MIGRATION_DATABASE_URL = "sqlite://"

POSTGRES_URL_VARIABLE_ALIASES = ("POSTGRES_TEST_DATABASE_URL",)

POSTGRES_REQUIRED_VARIABLE_ALIASES = ("POSTGRES_TEST_REQUIRED",)

POSTGRES_REQUIRED_VALUE = "true"

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

ADMIN_SEED_REVISION_PATH = (
    REPO_ROOT
    / "backend"
    / "migrations"
    / "versions"
    / "0002_seed_single_admin.py"
)

ADMIN_SEED_MODULE_NAME = "blitzy_admin_seed_revision_0002"


def pytest_unconfigure(config: Any) -> None:
    replaced = dict(REPLACED_ENVIRONMENT)
    replaced[ENV_FILE_VARIABLE] = REPLACED_ENV_FILE
    for name, value in replaced.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


PAYPAL_OAUTH_PATH = "/v1/oauth2/token"

PAYPAL_ORDERS_PATH = "/v2/checkout/orders"

PAYPAL_CAPTURE_SUFFIX = "/capture"

PAYPAL_VERIFY_PATH = "/v1/notifications/verify-webhook-signature"

PAYPAL_GRANT_TYPE = "client_credentials"

PAYPAL_PREFER_HEADER = "Prefer"

PAYPAL_VERIFY_EVENT_FIELD = "webhook_event"

PAYPAL_ORDER_INTENT = "CAPTURE"

PAYPAL_ORDER_DESCRIPTION = "Subscription Payment"

PAYPAL_ORDER_FIELDS = frozenset(
    {"intent", "purchase_units", "payment_source"}
)

PAYPAL_PURCHASE_UNIT_FIELDS = frozenset({"amount", "description"})

PAYPAL_AMOUNT_FIELDS = frozenset({"currency_code", "value"})

PAYPAL_EXPERIENCE_VALUES = {
    "user_action": "PAY_NOW",
    "shipping_preference": "NO_SHIPPING",
    "payment_method_preference": "IMMEDIATE_PAYMENT_REQUIRED",
}

PAYPAL_REDIRECT_FIELDS = ("return_url", "cancel_url")

PAYPAL_EXPERIENCE_FIELDS = frozenset(
    set(PAYPAL_EXPERIENCE_VALUES) | set(PAYPAL_REDIRECT_FIELDS)
)

PAYPAL_CATALOG_PRICES = frozenset(
    (
        format_amount(get_plan(plan_id).amount),
        get_plan(plan_id).currency,
    )
    for plan_id in PLAN_IDS
)

PAYPAL_CAPTURE_BODY = {}

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

PAYPAL_ROUTE_TOKEN = "token"
PAYPAL_ROUTE_CREATE_ORDER = "create_order"
PAYPAL_ROUTE_CAPTURE_ORDER = "capture_order"
PAYPAL_ROUTE_READ_ORDER = "read_order"
PAYPAL_ROUTE_VERIFY = "verify_webhook_signature"


class PayPalContractError(AssertionError):
    pass


def _header(headers: Any, name: str) -> Optional[str]:
    if not headers:
        return None
    for key, value in dict(headers).items():
        if str(key).lower() == name.lower():
            return value
    return None


def _refuse(detail: str, method: Any, url: Any) -> None:
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


def _decoded_body(
    json_body: Any, content: Any, method: Any, url: Any
) -> Any:
    """Returns the body one call sent, decoded.

    A caller that handed over a decoded body supplies it directly; one
    that handed over raw content has those bytes decoded here, so both
    call shapes reach the same assertions.
    """
    if json_body is not None:
        return json_body
    if not content:
        return None
    try:
        return json.loads(bytes(content).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        _refuse("body is not readable JSON", method, url)
        return None


def _assert_absolute_target(
    value: Any, field: str, method: Any, url: Any
) -> None:
    if not isinstance(value, str) or not value.strip():
        _refuse(
            "experience context {0} is {1!r}".format(field, value),
            method,
            url,
        )
        return
    parts = urlsplit(value.strip())
    if not parts.scheme or not parts.netloc:
        _refuse(
            "experience context {0} is not absolute".format(field),
            method,
            url,
        )


def _assert_experience_context(
    context: Any, method: Any, url: Any
) -> None:
    if not isinstance(context, dict):
        _refuse("order carries no experience context", method, url)
        return
    if set(context) != set(PAYPAL_EXPERIENCE_FIELDS):
        _refuse(
            "experience context fields are {0}".format(
                sorted(context)
            ),
            method,
            url,
        )
    for field, expected in PAYPAL_EXPERIENCE_VALUES.items():
        if context.get(field) != expected:
            _refuse(
                "experience context {0} is {1!r}".format(
                    field, context.get(field)
                ),
                method,
                url,
            )
    for field in PAYPAL_REDIRECT_FIELDS:
        _assert_absolute_target(context.get(field), field, method, url)


def _assert_purchase_unit(unit: Any, method: Any, url: Any) -> None:
    if not isinstance(unit, dict):
        _refuse("purchase unit is not an object", method, url)
        return
    if set(unit) != set(PAYPAL_PURCHASE_UNIT_FIELDS):
        _refuse(
            "purchase unit fields are {0}".format(sorted(unit)),
            method,
            url,
        )
    if unit.get("description") != PAYPAL_ORDER_DESCRIPTION:
        _refuse(
            "purchase unit description is {0!r}".format(
                unit.get("description")
            ),
            method,
            url,
        )
    amount = unit.get("amount")
    if not isinstance(amount, dict):
        _refuse("purchase unit carries no amount", method, url)
        return
    if set(amount) != set(PAYPAL_AMOUNT_FIELDS):
        _refuse(
            "amount fields are {0}".format(sorted(amount)),
            method,
            url,
        )
    priced = (amount.get("value"), amount.get("currency_code"))
    if priced not in PAYPAL_CATALOG_PRICES:
        _refuse(
            "order prices {0[0]!r} {0[1]!r}, which no plan "
            "publishes".format(priced),
            method,
            url,
        )


def assert_create_order_body(
    document: Any, method: Any = "POST", url: Any = PAYPAL_ORDERS_PATH
) -> None:
    """Assert one created order carries the complete documented body.

    Every field is checked and no field is optional: the intent, exactly
    one purchase unit carrying exactly an amount and a description, an
    amount naming a price the plan catalog publishes, and a payer
    experience context carrying exactly the two absolute redirect targets
    and the three fixed values. A field outside any of those sets fails,
    so a field added to the outbound document cannot pass unasserted.
    """
    if not isinstance(document, dict):
        _refuse("order body is not an object", method, url)
        return
    if set(document) != set(PAYPAL_ORDER_FIELDS):
        _refuse(
            "order body fields are {0}".format(sorted(document)),
            method,
            url,
        )
    if document.get("intent") != PAYPAL_ORDER_INTENT:
        _refuse(
            "order intent is {0!r}".format(document.get("intent")),
            method,
            url,
        )
    units = document.get("purchase_units")
    if not isinstance(units, list) or len(units) != 1:
        _refuse("order carries no single purchase unit", method, url)
        return
    _assert_purchase_unit(units[0], method, url)
    source = document.get("payment_source")
    if not isinstance(source, dict) or set(source) != {"paypal"}:
        _refuse("order payment source is not the wallet", method, url)
        return
    wallet = source["paypal"]
    if not isinstance(wallet, dict) or set(wallet) != {
        "experience_context"
    }:
        _refuse("order wallet carries no single context", method, url)
        return
    _assert_experience_context(
        wallet["experience_context"], method, url
    )


def assert_capture_body(
    document: Any, method: Any = "POST", url: Any = PAYPAL_ORDERS_PATH
) -> None:
    """Assert the settle call's body is exactly the documented one.

    The call carries its idempotency key and its representation
    preference as headers, so the body carries nothing at all. A body
    holding any member fails.
    """
    if document != PAYPAL_CAPTURE_BODY:
        _refuse(
            "settle body is {0!r} rather than {1!r}".format(
                document, PAYPAL_CAPTURE_BODY
            ),
            method,
            url,
        )


def embedded_event_bytes(document: Any) -> bytes:
    """Return the bytes a verifier document carries under the event field.

    ``document`` is the **raw postback body as it was transmitted**. The
    value is taken as a byte slice: the bytes between the event field's
    key and the closing brace of the document are returned exactly as
    they were sent, with no decode and no re-encode anywhere in the path.
    A caller can therefore compare them with the notification bytes that
    arrived and prove the two are identical rather than merely
    equivalent.

    Raises :class:`PayPalContractError` when the document does not carry
    the event field as its final member.
    """
    try:
        raw = bytes(document)
    except (TypeError, ValueError):
        raise PayPalContractError(
            "verifier document is not raw bytes"
        )
    key = b'"' + PAYPAL_VERIFY_EVENT_FIELD.encode("utf-8") + b'":'
    marker = raw.find(key)
    if marker < 0:
        raise PayPalContractError(
            "verifier document carries no {0} field".format(
                PAYPAL_VERIFY_EVENT_FIELD
            )
        )
    if not raw.rstrip().endswith(b"}"):
        raise PayPalContractError(
            "verifier document does not close with an object brace"
        )
    return raw[marker + len(key):raw.rstrip().rfind(b"}")]


def assert_verifier_embeds_event(
    document: Any, event: Any
) -> None:
    """Assert a verifier document carries ``event`` byte for byte.

    ``document`` is the raw postback body and ``event`` is the raw
    notification body that arrived. The comparison is on bytes, so a
    document that parsed the notification and re-serialised it fails even
    when the re-serialisation is an equivalent JSON value.
    """
    embedded = embedded_event_bytes(document)
    expected = bytes(event)
    if embedded != expected:
        raise PayPalContractError(
            "verifier document embedded {0!r} rather than the "
            "{1!r} that arrived".format(embedded, expected)
        )


def _assert_embedded_event(
    document: bytes, method: Any, url: Any
) -> None:
    """Assert the transmitted event field is a verbatim byte slice.

    The slice is required to be non-empty and to be a JSON object in its
    own right, so a document whose event field was rebuilt from parsed
    values still carries a notification, and a caller holding the
    notification bytes can compare them with
    :func:`assert_verifier_embeds_event`.
    """
    try:
        embedded = embedded_event_bytes(document)
    except PayPalContractError as failure:
        _refuse(str(failure), method, url)
        return
    if not embedded.strip():
        _refuse("verifier document embedded no event", method, url)
    try:
        notification = json.loads(embedded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        _refuse(
            "verifier document embedded an unreadable event",
            method,
            url,
        )
        return
    if not isinstance(notification, dict):
        _refuse(
            "verifier document embedded a non-object event", method, url
        )


def assert_paypal_contract(
    method: str,
    url: str,
    headers: Any = None,
    json_body: Any = None,
    content: Any = None,
    data: Any = None,
    auth: Any = None,
    timeout: Any = None,
    raw_body: Any = None,
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
    the verifier document does not carry the notification as a verbatim
    byte slice under its event field; or the call carries no timeout, or
    one other than ``settings.HTTP_TIMEOUT_SECONDS``.

    ``raw_body`` is the request body exactly as it was transmitted, which
    a caller supplies when it also supplies a decoded ``json_body``. The
    verifier document's event field is checked against those bytes, so
    the check cannot be satisfied by a document that was parsed and
    rebuilt.
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

    if route == PAYPAL_ROUTE_CREATE_ORDER:
        assert_create_order_body(
            _decoded_body(json_body, content, method, url), method, url
        )

    if route == PAYPAL_ROUTE_CAPTURE_ORDER:
        if not _header(headers, PAYPAL_PREFER_HEADER):
            _refuse(
                "settle call carries no representation preference",
                method,
                url,
            )
        assert_capture_body(
            _decoded_body(json_body, content, method, url), method, url
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
        transmitted = raw_body if raw_body else content
        if transmitted:
            _assert_embedded_event(bytes(transmitted), method, url)

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
        raw_body=kwargs.get("content"),
    )


def assert_paypal_request(outbound: Any) -> str:
    """Assert one ``httpx`` request and return its contract route.

    The request's own method, target, headers, body and recorded timeout
    are handed to :func:`assert_paypal_contract`, so a stand-in installed
    as a transport asserts the same contract as one installed as a
    client. The body is handed over twice: decoded, and as the bytes that
    were transmitted, so the verifier document's event field is checked
    against those bytes rather than against a decoded copy of them.
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
        raw_body=body,
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
    if isinstance(value, datetime):
        return int(value.timestamp())
    return value


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _segment(payload: Dict[str, Any]) -> str:
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
    for candidate in UNLISTED_ALGORITHM_CANDIDATES:
        if candidate not in JWT_ALGORITHMS:
            return candidate
    raise AssertionError(
        "every candidate algorithm is accepted, so none is unlisted"
    )


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


@pytest.fixture(autouse=True)
def fresh_readiness_outcome():
    """Discard the recorded readiness outcome around every test.

    The readiness route reuses one outcome for
    ``settings.READINESS_CACHE_SECONDS``, which spans many tests. Clearing
    it before and after each test means no test reads an outcome another
    test produced, and a test that drives the reuse deliberately records
    its own outcome inside its own body.
    """
    reset_readiness_cache()
    try:
        yield
    finally:
        reset_readiness_cache()


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
    engine = enforce_sqlite_foreign_keys(
        create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
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
        return self.forge(key=FOREIGN_SIGNING_KEY, **overrides)

    def wrong_audience(self, **overrides: Any) -> str:
        overrides.setdefault("aud", FOREIGN_AUDIENCE)
        return self.forge(**overrides)

    def wrong_issuer(self, **overrides: Any) -> str:
        overrides.setdefault("iss", FOREIGN_ISSUER)
        return self.forge(**overrides)

    def expired(self, **overrides: Any) -> str:
        issued = datetime.now(timezone.utc) - FORGED_TOKEN_SKEW
        claims = {
            "iat": issued,
            "nbf": issued,
            "exp": issued + FORGED_TOKEN_LIFETIME,
        }
        claims.update(overrides)
        return self.forge(**claims)

    def future_not_before(self, **overrides: Any) -> str:
        ahead = datetime.now(timezone.utc) + FORGED_TOKEN_SKEW
        claims = {
            "iat": ahead,
            "nbf": ahead,
            "exp": ahead + FORGED_TOKEN_LIFETIME,
        }
        claims.update(overrides)
        return self.forge(**claims)

    def without_claim(self, name: str, **overrides: Any) -> str:
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
    presents. Foreign keys are enforced on every connection the engine
    opens, and the schema a revision leaves behind refuses a row naming a
    parent that is not stored. The connection is held open for the whole
    test and is closed with the engine afterwards.
    """
    engine = enforce_sqlite_foreign_keys(
        create_engine(
            MIGRATION_DATABASE_URL,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
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

    The whole revision chain is applied to the isolated database before the
    client is yielded, so the rows the client reads and writes include the
    account revision 0002 leaves holding the administrative role, and the
    indexes revision 0003 creates are in place. The application's
    request-scoped session dependency is overridden for the duration of the
    test and the overrides are cleared afterwards.
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


POSTGRES_URL_VARIABLE = "POSTGRES_TEST_URL"

POSTGRES_REQUIRED_VARIABLE = "REQUIRE_POSTGRES_TESTS"

POSTGRES_REQUIRED_VALUES = ("1", "true", "yes", "on")

POSTGRES_ABSENT_MESSAGE = (
    "no PostgreSQL server is named by " + POSTGRES_URL_VARIABLE
)

POSTGRES_NO_CREATEDB_MESSAGE = (
    "the role named by "
    + POSTGRES_URL_VARIABLE
    + " cannot create a database, so no case can be isolated in one"
)

POSTGRES_REQUIRED_SUFFIX = (
    ", and "
    + POSTGRES_REQUIRED_VARIABLE
    + " requires the production-dialect cases to run"
)

POSTGRES_SCHEMES = ("postgresql://", "postgresql+psycopg2://")

POSTGRES_DATABASE_PREFIX = "blitzy_case_"

POSTGRES_WAIT_SECONDS = 30.0

POSTGRES_POLL_SECONDS = 0.05

BLOCKED_BACKENDS = text(
    "SELECT count(*) FROM pg_stat_activity "
    "WHERE datname = :name AND wait_event_type = 'Lock'"
)

ROLE_MAY_CREATE_DATABASE = text(
    "SELECT rolcreatedb OR rolsuper FROM pg_roles "
    "WHERE rolname = current_user"
)


def postgres_url_from_environment() -> Optional[str]:
    """Return the URL of the integration server, or ``None``.

    A value that names no PostgreSQL scheme is treated as absent, so a
    misspelled URL skips rather than failing to connect later.
    """
    declared = ""
    for name in (POSTGRES_URL_VARIABLE,) + POSTGRES_URL_VARIABLE_ALIASES:
        declared = os.environ.get(name, "").strip()
        if declared:
            break
    if not declared:
        return None
    if not declared.startswith(POSTGRES_SCHEMES):
        return None
    return declared


def postgres_is_required() -> bool:
    for name in (
        POSTGRES_REQUIRED_VARIABLE,
    ) + POSTGRES_REQUIRED_VARIABLE_ALIASES:
        if (
            os.environ.get(name, "").strip().lower()
            in POSTGRES_REQUIRED_VALUES
        ):
            return True
    return False


def _withhold_postgres(reason: str) -> None:
    if postgres_is_required():
        raise AssertionError(reason + POSTGRES_REQUIRED_SUFFIX)
    pytest.skip(reason)


def _case_database_url(server_url: str, database: str) -> str:
    """Return ``server_url`` addressing ``database`` instead.

    Only the path is replaced, so the credentials, host, port and any
    query the server URL carries are preserved.
    """
    parts = urlsplit(server_url)
    replaced = parts._replace(path="/" + database)
    return replaced.geturl()


@pytest.fixture(scope="session")
def postgres_base_url() -> str:
    """Return the integration server's URL, or stop the case.

    The case is skipped when no server is named or when the named role
    cannot create a database, and failed instead of skipped when
    :data:`POSTGRES_REQUIRED_VARIABLE` requires the server.
    """
    declared = postgres_url_from_environment()
    if declared is None:
        _withhold_postgres(POSTGRES_ABSENT_MESSAGE)
    engine = create_engine(declared)
    try:
        with engine.connect() as connection:
            allowed = connection.execute(
                ROLE_MAY_CREATE_DATABASE
            ).scalar()
    finally:
        engine.dispose()
    if not allowed:
        _withhold_postgres(POSTGRES_NO_CREATEDB_MESSAGE)
    return declared


@pytest.fixture
def postgres_database(postgres_base_url) -> str:
    """Yield the name of a database created for one case.

    It is dropped with everything in it once the case ends, whether it
    passed or failed, so no object outlives one case. ``WITH (FORCE)``
    closes a connection the case left open rather than refusing the drop.
    """
    name = POSTGRES_DATABASE_PREFIX + uuid.uuid4().hex[:16]
    engine = create_engine(postgres_base_url)
    administer = engine.connect().execution_options(
        isolation_level="AUTOCOMMIT"
    )
    try:
        administer.execute(text("CREATE DATABASE " + name))
        yield name
    finally:
        administer.execute(
            text("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
        )
        administer.close()


def _legacy_metadata() -> MetaData:
    """Build the six tables that precede revision 0001, portably.

    The definitions carry SQLAlchemy types rather than the literal DDL
    :data:`PRE_REVISION_TABLES` holds, so the same declaration is issued
    against PostgreSQL and against SQLite. The columns, the keys and the
    absence of the columns revision 0001 adds match that literal DDL
    exactly.
    """
    metadata = MetaData()
    Table(
        "users",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("email", String, nullable=False, unique=True),
        Column("hashed_password", String, nullable=False),
        Column("created_at", DateTime, nullable=False),
        Column("last_login", DateTime, nullable=True),
    )
    Table(
        "listings",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("created_at", DateTime, nullable=False),
        Column("updated_at", DateTime, nullable=False),
        Column("rent", Float, nullable=False),
        Column("broker_fee", Float, nullable=True),
        Column("square_footage", Float, nullable=True),
        Column("bedrooms", Integer, nullable=True),
        Column("bathrooms", Integer, nullable=True),
        Column("available_date", DateTime, nullable=True),
        Column("street_address", String, nullable=True),
        Column("zillow_url", String, nullable=True),
    )
    Table(
        "filters",
        metadata,
        Column("id", Integer, primary_key=True),
        Column(
            "user_id", Integer, ForeignKey("users.id"), nullable=False
        ),
        Column("name", String, nullable=False),
        Column("created_at", DateTime, nullable=False),
        Column("last_used", DateTime, nullable=True),
    )
    Table(
        "zip_codes",
        metadata,
        Column("id", Integer, primary_key=True),
        Column(
            "filter_id", Integer, ForeignKey("filters.id"), nullable=False
        ),
        Column("code", String, nullable=False),
    )
    Table(
        "criteria",
        metadata,
        Column("id", Integer, primary_key=True),
        Column(
            "filter_id", Integer, ForeignKey("filters.id"), nullable=False
        ),
        Column("field", String, nullable=False),
        Column("operator", String, nullable=False),
        Column("value", String, nullable=False),
    )
    Table(
        "subscriptions",
        metadata,
        Column("id", Integer, primary_key=True),
        Column(
            "user_id", Integer, ForeignKey("users.id"), nullable=False
        ),
        Column("start_date", DateTime, nullable=False),
        Column("end_date", DateTime, nullable=True),
        Column("status", String, nullable=False),
    )
    return metadata


def _drop_every_table(engine: Any) -> None:
    """Drop every table the connected schema holds.

    The names come from the schema itself, so a table a revision created
    is removed whether or not this suite declares it -- the Alembic
    version table and the bookkeeping table revision 0001 writes among
    them. Each name is quoted by the dialect's own preparer.
    """
    preparer = engine.dialect.identifier_preparer
    with engine.begin() as connection:
        for name in inspect(connection).get_table_names():
            connection.execute(
                text(
                    "DROP TABLE IF EXISTS {0} CASCADE".format(
                        preparer.quote(name)
                    )
                )
            )
        engine.dispose()


@pytest.fixture
def postgres_url(postgres_base_url, postgres_database) -> str:
    """Return the URL of the database created for this case."""
    return _case_database_url(postgres_base_url, postgres_database)


def production_connect_args(url, statement_timeout_seconds=None):
    """Return the connect arguments the application opens ``url`` with.

    The mapping is the one
    :func:`backend.app.db.database._connect_args` builds, so a case using
    it reaches the server under the same three bounds a deployed
    connection carries: the libpq handshake bound, the server-side
    statement bound and the socket bound. ``statement_timeout_seconds``
    replaces the statement bound alone, which lets a case observe a
    contended write being ended by the server inside the case.
    """
    arguments = dict(database_module._connect_args(url))
    if statement_timeout_seconds is not None and "options" in arguments:
        arguments["options"] = (
            database_module.POSTGRESQL_SESSION_OPTIONS_TEMPLATE.format(
                statement_timeout_ms=(
                    int(statement_timeout_seconds)
                    * database_module.MILLISECONDS_PER_SECOND
                )
            )
        )
    return arguments


#: Statement bound, in seconds, a case carries when it needs the server
#: to end a contended write while the case is still running. It is below
#: the configured application bound rather than above it, so the
#: cancellation the case observes is the one a deployed connection would
#: reach later.
POSTGRES_SHORT_STATEMENT_TIMEOUT_SECONDS = 1


@pytest.fixture
def postgres_engine(postgres_url, postgres_database):
    """Yield an engine on this case's database, pooling connections.

    The pool is the default one rather than a single shared connection,
    so two sessions drawn from it are two independent transactions on the
    server and can contend with each other. The connect arguments are the
    application's own, so a case contends under the same statement,
    handshake and socket bounds a deployed connection carries.
    """
    engine = create_engine(
        postgres_url,
        hide_parameters=True,
        connect_args=production_connect_args(postgres_url),
        pool_pre_ping=True,
    )
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def postgres_short_timeout_session_factory(postgres_mapped_engine):
    """Return a session factory whose statement bound is deliberately low.

    The engine carries the application's connect arguments with the
    statement bound replaced by
    :data:`POSTGRES_SHORT_STATEMENT_TIMEOUT_SECONDS`, and it addresses the
    database :func:`postgres_mapped_engine` built, so a session from this
    factory contends with one from the ordinary factory over the same
    rows.
    """
    url = str(postgres_mapped_engine.url.render_as_string(hide_password=False))
    engine = create_engine(
        url,
        hide_parameters=True,
        connect_args=production_connect_args(
            url, POSTGRES_SHORT_STATEMENT_TIMEOUT_SECONDS
        ),
        pool_pre_ping=True,
    )
    try:
        yield sessionmaker(
            autocommit=False, autoflush=False, bind=engine
        )
    finally:
        engine.dispose()


@pytest.fixture
def postgres_mapped_engine(postgres_engine):
    """Yield an engine whose database the mapped metadata built."""
    Base.metadata.create_all(bind=postgres_engine)
    return postgres_engine


@pytest.fixture
def postgres_session_factory(postgres_mapped_engine):
    """Return a session factory bound to this case's database."""
    return sessionmaker(
        autocommit=False, autoflush=False, bind=postgres_mapped_engine
    )


@pytest.fixture
def postgres_db(postgres_session_factory):
    """Yield one session on this case's database."""
    session = postgres_session_factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def postgres_client(postgres_session_factory):
    """Yield a test client whose requests reach this case's database.

    Each request is served by a session of its own, drawn from the pooled
    engine, so two requests in flight together hold two transactions.
    """

    def override_get_db():
        session = postgres_session_factory()
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
def postgres_observer(postgres_base_url, postgres_database):
    """Yield a callable reporting when a case backend waits on a lock.

    The observer holds a connection to the server database rather than to
    this case's, so reading the activity view is never blocked by the
    contention it is watching. The connection commits each read on its
    own: PostgreSQL holds the statistics views stable for the duration of
    a transaction, so a connection that stayed in one would return its
    first reading over and over and never see a wait begin.

    The callable waits up to :data:`POSTGRES_WAIT_SECONDS` for the
    requested number of backends to be seen waiting, and returns whether
    they were.
    """
    engine = create_engine(postgres_base_url)
    connection = engine.connect().execution_options(
        isolation_level="AUTOCOMMIT"
    )

    def blocked(count: int = 1) -> bool:
        deadline = time.monotonic() + POSTGRES_WAIT_SECONDS
        while time.monotonic() < deadline:
            waiting = connection.execute(
                BLOCKED_BACKENDS, {"name": postgres_database}
            ).scalar()
            if (waiting or 0) >= count:
                return True
            time.sleep(POSTGRES_POLL_SECONDS)
        return False

    try:
        yield blocked
    finally:
        connection.close()
        engine.dispose()


@pytest.fixture
def postgres_alembic_config(postgres_url):
    """Return a callable building an Alembic configuration.

    It mirrors :func:`alembic_config` and is bound to a connection opened
    on this case's database, so a revision applied through it installs
    its objects there.
    """

    def build(connection: Any) -> Config:
        config = Config(str(ALEMBIC_INI))
        config.attributes["connection"] = connection
        config.attributes["configure_logger"] = False
        return config

    return build


@pytest.fixture
def postgres_migration_connection(postgres_engine):
    """Yield an open connection to this case's empty database.

    The database carries no table, so a revision applied through
    :func:`postgres_alembic_config` runs against the state a first
    deployment presents.
    """
    connection = postgres_engine.connect()
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def postgres_legacy_schema():
    """Return a callable creating the pre-revision schema portably.

    The callable takes a connection and issues the six tables that
    precede revision 0001 from :func:`_legacy_metadata`, so the
    declaration is the same one SQLite receives while the DDL is the
    dialect's own.
    """

    def create(connection: Any) -> None:
        _legacy_metadata().create_all(bind=connection)

    return create
