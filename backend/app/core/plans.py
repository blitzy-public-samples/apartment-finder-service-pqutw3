"""Server-owned subscription plan and price catalog.

Maps each plan identifier to its amount, currency, period and the role a
subscriber holds. The catalog is fixed at import time and is published as
a read-only mapping.

This module also holds every value the ``subscriptions.status`` column
takes, published together as :data:`STATUS_VALUES`. They are read by the
endpoint that writes the column and by the authorization module that
reads it. This module imports nothing from the application.
"""

import decimal
import types
import typing

__all__ = [
    "CATALOG",
    "CURRENCY_USD",
    "PLAN_IDS",
    "PREMIUM_ANNUAL",
    "PREMIUM_MONTHLY",
    "STATUS_ACTIVE",
    "STATUS_CANCELLED",
    "STATUS_FAILED",
    "STATUS_PENDING",
    "STATUS_REFUNDED",
    "STATUS_VALUES",
    "Plan",
    "ROLE_PREMIUM",
    "UnknownPlanError",
    "format_amount",
    "get_plan",
]

PREMIUM_MONTHLY = "premium_monthly"
PREMIUM_ANNUAL = "premium_annual"

CURRENCY_USD = "USD"

ROLE_PREMIUM = "premium"

#: Status of a row recorded before its payment is captured. It grants no
#: entitlement.
STATUS_PENDING = "pending"

#: Status of a row whose payment was captured. It is the only status that
#: grants an entitlement.
STATUS_ACTIVE = "active"

#: Status of a row whose payment did not complete. It grants no
#: entitlement and is retained for reconciliation.
STATUS_FAILED = "failed"

#: Status of a row the provider reported as not settled. It grants no
#: entitlement and is closed to a further attempt.
STATUS_CANCELLED = "cancelled"

#: Status of a row whose settled payment was returned. It grants no
#: entitlement and is closed to a further attempt.
STATUS_REFUNDED = "refunded"

#: Every value the status column takes. :data:`STATUS_ACTIVE` is the
#: only one that grants an entitlement.
STATUS_VALUES: typing.FrozenSet[str] = frozenset(
    {
        STATUS_PENDING,
        STATUS_ACTIVE,
        STATUS_FAILED,
        STATUS_CANCELLED,
        STATUS_REFUNDED,
    }
)

_AMOUNT_QUANTUM = decimal.Decimal("0.01")
_AMOUNT_ROUNDING = decimal.ROUND_HALF_UP

_AmountInput = typing.Union[decimal.Decimal, int, str]


class UnknownPlanError(LookupError):
    """Raised when an identifier is absent from the catalog.

    The rejected identifier is retained on the ``plan_id`` attribute.
    """

    def __init__(self, plan_id: typing.Any) -> None:
        self.plan_id = plan_id
        super().__init__(
            f"Unknown subscription plan identifier: {plan_id!r}"
        )


class Plan(typing.NamedTuple):
    """One catalog entry.

    ``amount`` is a Decimal carrying exactly two places and ``currency``
    is its ISO 4217 code. ``period_days`` is the length of the
    entitlement the plan buys.

    ``required_role`` is the role name a subscriber on the plan holds. It
    is granted by
    :func:`backend.app.core.authorization.entitled_role` for as long as
    the subscriber holds a row carrying :data:`STATUS_ACTIVE` whose
    entitlement window is still open, so it lapses with that row. The
    endpoint that activates the row also records the name on
    ``User.role``, which happens only after a capture has settled for
    this amount and currency and which no authorization decision reads
    as more than the baseline on its own.
    """

    plan_id: str
    amount: decimal.Decimal
    currency: str
    period_days: int
    required_role: str


def _to_amount(value: _AmountInput) -> decimal.Decimal:
    """Return value quantized to two decimal places.

    Accepts Decimal, int and str. Raises TypeError for any other type,
    including bool and float, and ValueError when the value is not a
    finite decimal number that fits two places. The returned amount
    always equals the value supplied.
    """
    if isinstance(value, decimal.Decimal):
        candidate = value
    elif isinstance(value, int) and not isinstance(value, bool):
        candidate = decimal.Decimal(value)
    elif isinstance(value, str):
        try:
            candidate = decimal.Decimal(value.strip())
        except decimal.InvalidOperation:
            raise ValueError(f"Not a decimal amount: {value!r}") from None
    else:
        raise TypeError(
            "Monetary amounts must be Decimal, int or str, not "
            f"{type(value).__name__}"
        )
    if not candidate.is_finite():
        raise ValueError(f"Not a finite amount: {value!r}")
    try:
        quantized = candidate.quantize(
            _AMOUNT_QUANTUM, rounding=_AMOUNT_ROUNDING
        )
    except decimal.InvalidOperation:
        raise ValueError(
            f"Amount exceeds two-place precision: {value!r}"
        ) from None
    if quantized != candidate:
        raise ValueError(
            f"Amount exceeds two-place precision: {value!r}"
        )
    return quantized


def _build_catalog() -> typing.Mapping[str, Plan]:
    """Return the read-only identifier-to-plan mapping."""
    entries: typing.Dict[str, Plan] = {}
    for plan_id, amount, period_days in (
        (PREMIUM_MONTHLY, "9.99", 30),
        (PREMIUM_ANNUAL, "99.99", 365),
    ):
        entries[plan_id] = Plan(
            plan_id=plan_id,
            amount=_to_amount(amount),
            currency=CURRENCY_USD,
            period_days=period_days,
            required_role=ROLE_PREMIUM,
        )
    return types.MappingProxyType(entries)


CATALOG: typing.Mapping[str, Plan] = _build_catalog()

PLAN_IDS: typing.FrozenSet[str] = frozenset(CATALOG)


def get_plan(plan_id: str) -> Plan:
    """Return the catalog entry registered under plan_id.

    Raises UnknownPlanError when plan_id is not a catalog identifier.
    """
    try:
        return CATALOG[plan_id]
    except (KeyError, TypeError):
        raise UnknownPlanError(plan_id) from None


def format_amount(amount: _AmountInput) -> str:
    """Return amount as a string carrying exactly two decimal places."""
    return str(_to_amount(amount))
