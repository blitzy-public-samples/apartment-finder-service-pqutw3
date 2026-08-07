"""Centralized role and ownership authorization for the API surface.

This module is the application's single authorization decision point.
It publishes an ordered four-role model, a dependency factory that
guards a route on a minimum role, and two helpers that bind a stored row
to the principal that owns it.

The role every decision is taken against is read from the
:data:`ROLE_ATTRIBUTE` of the stored user row that authentication
returned, raised by any paid entitlement the principal's own stored
``subscriptions`` rows carry. No request body field, query parameter,
header or token claim is consulted, and no function here writes a role.

A paid entitlement is resolved by :func:`entitled_role`: a subscription
row belonging to the principal, carrying the active status and not yet
past its end date, grants the role its plan registers in
:mod:`backend.app.core.plans`. Because the grant is derived from the row
rather than stored on the user, it lapses when the row expires and
nothing has to demote the account. The stored role is never lowered by
it. :func:`require_role` resolves it only when the stored role does not
already satisfy the minimum, so a route no entitlement can affect costs
no extra query.

Resolution denies by default. A stored value is matched only when it
equals a :class:`Role` member's value exactly: no whitespace is stripped
and no letter case is folded. Every other value -- absent, ``None``,
blank, whitespace-padded such as ``" admin"``, differently cased such as
``"Admin"`` or ``"ADMIN"``, unrecognised, or of an unexpected type --
resolves to no role at all, and the request is refused before any rank
comparison is made. Such a value satisfies no minimum, including
:data:`LOWEST_ROLE`. Resolution raises nothing.

An unrecognised minimum handed to :func:`require_role` raises
``ValueError`` while the route is being declared.

Refusals carry these statuses:

* an absent or invalid credential is answered ``401`` by
  :func:`backend.app.core.security.get_current_user`, and that response
  passes through unchanged
* an authenticated principal whose role is unrecognised, or which ranks
  below the minimum role, is answered ``403``
* every ownership refusal is answered ``404``, whether the lookup
  matched no row or the matching row carries another owner

Every refusal emits one structured record through
:func:`backend.app.core.logging.get_logger` carrying the request method
and path, the principal identifier, the required, effective and claimed
role names and the decision. The method and the path are read from
``request.scope``. The claimed role is the verified token's own role
claim and decides nothing. Emitting a record raises nothing into the
request path and touches no database session.

No refusal is ever emitted silently. When the structured record cannot
be written, the same fields are written to standard error through
:func:`backend.app.core.logging.log_audit_fallback` and
:data:`AUDIT_FAILURE_MESSAGE` is counted;
:func:`audit_failure_count` reports that count as a health signal, and a
non-zero value means the primary audit sink degraded even though no
denial event was lost. The exception each refusal raises is marked
audited, so a generic handler further out leaves the refusal at the one
record emitted here.

This module installs no middleware and guards no route on its own: a
route is guarded where it declares the dependency, and a route
declaring none stays reachable.

Design rationale is recorded in ``docs/security/DECISION_LOG.md``.

Usage::

    @router.post('/')
    def create_listing(
        current_user: User = Depends(require_role(Role.ADMIN)),
    ) -> Listing:
        ...

    subscription = load_owned(
        db, Subscription, current_user, paypal_order_id=order_id
    )
"""

import threading
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Tuple,
    Type,
    TypeVar,
)

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import inspect as sqlalchemy_inspect
from sqlalchemy.exc import NoInspectionAvailable
from sqlalchemy.orm import Session

from backend.app.core.logging import (
    exception_fields,
    get_logger,
    log_audit_fallback,
    mark_audited,
)
from backend.app.core.plans import STATUS_ACTIVE, UnknownPlanError, get_plan
from backend.app.core.security import claimed_role, get_current_user
from backend.app.db.database import get_db
from backend.app.db.models import Subscription, User

__all__ = [
    "AUDIT_FAILURE_MESSAGE",
    "AUDIT_SINK_FALLBACK",
    "DECISION_OBJECT_MISSING",
    "DECISION_OWNERSHIP_DENIED",
    "DECISION_PRINCIPAL_MISSING",
    "DECISION_ROLE_DENIED",
    "DECISION_ROLE_INVALID",
    "FORBIDDEN_DETAIL",
    "LOOKUP_CANDIDATE_LIMIT",
    "LOWEST_ROLE",
    "NOT_FOUND_DETAIL",
    "OWNER_ATTRIBUTE",
    "REFUSAL_MESSAGE",
    "ROLE_ATTRIBUTE",
    "ROLE_ORDER",
    "ROLE_RANKS",
    "Role",
    "effective_role",
    "entitled_role",
    "load_owned",
    "parse_role",
    "require_ownership",
    "require_role",
    "reset_audit_failure_count",
    "resolve_role",
    "role_satisfies",
]

logger = get_logger(__name__)


class Role(str, Enum):
    """A role a principal may hold.

    Each member's value is the string the ``role`` column stores, so a
    member is usable anywhere that string is.
    """

    GUEST = "guest"
    REGISTERED = "registered"
    PREMIUM = "premium"
    ADMIN = "admin"


#: The roles in increasing order of privilege.
ROLE_ORDER: Tuple[Role, ...] = (
    Role.GUEST,
    Role.REGISTERED,
    Role.PREMIUM,
    Role.ADMIN,
)

#: Rank of each role, taken from its position in :data:`ROLE_ORDER`. A
#: role satisfies a minimum when its rank is greater than or equal to
#: the minimum's rank.
ROLE_RANKS: Mapping[Role, int] = MappingProxyType(
    dict((role, rank) for rank, role in enumerate(ROLE_ORDER))
)

#: The least privileged role. A value naming no member resolves to no
#: role at all rather than to this one, and satisfies no minimum.
LOWEST_ROLE = Role.GUEST

ROLE_ATTRIBUTE = "role"

OWNER_ATTRIBUTE = "user_id"

#: Most rows an ownership lookup reads before selecting one. It bounds
#: the work a lookup whose criteria are not unique can do.
LOOKUP_CANDIDATE_LIMIT = 100

#: Detail returned with every ``403``.
FORBIDDEN_DETAIL = "Insufficient permissions"

NOT_FOUND_DETAIL = "Resource not found"

REFUSAL_MESSAGE = "Authorization refused"

#: Message of the fallback record written when the structured record
#: could not be emitted.
AUDIT_FAILURE_MESSAGE = "Authorization refused, primary audit sink failed"

#: Value recorded on the ``audit_sink`` field of a fallback record.
AUDIT_SINK_FALLBACK = "stderr"

# Serialises reads and writes of the audit failure count.
_AUDIT_FAILURE_LOCK = threading.Lock()

# Refusals the structured logger rejected. Read through
# :func:`audit_failure_count`.
_audit_failures = 0

#: Decision recorded when a principal ranks below the minimum role.
DECISION_ROLE_DENIED = "role_denied"

#: Decision recorded when a stored role names no member of :class:`Role`.
DECISION_ROLE_INVALID = "role_invalid"

#: Decision recorded when a row carries another principal's owner.
DECISION_OWNERSHIP_DENIED = "ownership_denied"

DECISION_OBJECT_MISSING = "object_missing"

DECISION_PRINCIPAL_MISSING = "principal_missing"

_ROLES_BY_VALUE: Mapping[str, Role] = MappingProxyType(
    dict((role.value, role) for role in ROLE_ORDER)
)

_ModelT = TypeVar("_ModelT")


def parse_role(value: Any) -> Optional[Role]:
    """Returns the role ``value`` names, or ``None`` when it names none.

    A :class:`Role` is returned unchanged. A string is matched only when
    it equals a member's stored value exactly: no whitespace is stripped
    and no letter case is folded, so ``"admin"`` matches while
    ``" admin"``, ``"admin "``, ``"Admin"`` and ``"ADMIN"`` each return
    ``None``. Every other value returns ``None``, including ``None``
    itself, a blank string, a numeric rank and a boolean.
    """
    if isinstance(value, Role):
        return value
    if not isinstance(value, str):
        return None
    return _ROLES_BY_VALUE.get(value)


def resolve_role(user: Any) -> Optional[Role]:
    """Returns the role the stored user row carries, or ``None``.

    The value is read from the row's :data:`ROLE_ATTRIBUTE` and matched
    exactly by :func:`parse_role`. ``None`` is returned for a row that is
    ``None``, that carries no such attribute, or that carries a value
    naming no member -- including one that would name a member after
    whitespace stripping or case folding -- and that outcome is refused
    by every caller rather than being treated as :data:`LOWEST_ROLE`.
    Reading the attribute never raises.
    """
    if user is None:
        return None
    try:
        stored = getattr(user, ROLE_ATTRIBUTE, None)
    except Exception:
        return None
    return parse_role(stored)


def entitled_role(
    db: Session,
    user: Any,
    moment: Optional[datetime] = None,
) -> Optional[Role]:
    """Returns the role a paid entitlement grants ``user``.

    A ``subscriptions`` row grants an entitlement when it belongs to the
    principal, carries :data:`backend.app.core.plans.STATUS_ACTIVE`, and
    has an ``end_date`` still ahead of ``moment`` -- which defaults to
    the current UTC instant. The role granted is the ``required_role``
    the plan catalog registers for that row's plan, and the highest
    ranking role across the qualifying rows is returned.

    The decision reads stored rows only. No token claim, request field
    or catalog value supplied by a client takes part in it, and an
    expired row grants nothing without anything having to demote it.

    ``None`` is returned when the principal carries no identifier, when
    no row qualifies, and when no qualifying row names a plan the
    catalog publishes.
    """
    principal_id = _principal_id(user)
    if principal_id is None:
        return None
    if moment is None:
        moment = datetime.now(timezone.utc)
    plan_ids = (
        db.query(Subscription.plan_id)
        .filter(
            Subscription.user_id == principal_id,
            Subscription.status == STATUS_ACTIVE,
            Subscription.end_date > moment,
        )
        .all()
    )
    granted: Optional[Role] = None
    for (plan_id,) in plan_ids:
        try:
            plan = get_plan(plan_id)
        except UnknownPlanError:
            continue
        candidate = parse_role(plan.required_role)
        if candidate is None:
            continue
        if granted is None or ROLE_RANKS[candidate] > ROLE_RANKS[granted]:
            granted = candidate
    return granted


def effective_role(
    db: Session,
    user: Any,
    moment: Optional[datetime] = None,
) -> Optional[Role]:
    """Returns the role every decision about ``user`` is taken against.

    The role stored on the row is resolved by :func:`resolve_role`, and
    a paid entitlement resolved by :func:`entitled_role` raises it when
    the entitlement ranks higher. The stored role is never lowered, so a
    principal cannot lose privilege by holding a subscription.

    Resolution still denies by default: a row whose stored role names no
    member resolves to ``None``, which satisfies no minimum, and an
    entitlement is an addition to a recognised stored role, never a
    substitute for one.
    """
    stored = resolve_role(user)
    if stored is None:
        # A stored role naming no member satisfies no minimum, and an
        # entitlement is never a substitute for it.
        return None
    granted = entitled_role(db, user, moment)
    if granted is not None and ROLE_RANKS[granted] > ROLE_RANKS[stored]:
        return granted
    return stored


def role_satisfies(role: Any, minimum: Any) -> bool:
    """Reports whether ``role`` ranks at or above ``minimum``.

    Both arguments are matched by :func:`parse_role`, and an argument
    naming no member makes the comparison ``False``.
    """
    held = parse_role(role)
    required = parse_role(minimum)
    if held is None or required is None:
        return False
    return ROLE_RANKS[held] >= ROLE_RANKS[required]


def _coerce_minimum(minimum: Any) -> Role:
    """Returns ``minimum`` as a :class:`Role`.

    Raises ``ValueError`` when ``minimum`` names no member.
    """
    resolved = parse_role(minimum)
    if resolved is None:
        raise ValueError(
            "Unknown minimum role {0!r}; expected one of {1}".format(
                minimum, ", ".join(role.value for role in ROLE_ORDER)
            )
        )
    return resolved


def _request_fields(request: Optional[Request]) -> Dict[str, Any]:
    """Returns the method and path of ``request`` as record fields.

    Both values are read from ``request.scope``. Each is ``None`` when
    no request is supplied or when the scope carries no such key.
    """
    absent = {"method": None, "path": None}
    if request is None:
        return absent
    try:
        scope = request.scope
        return {
            "method": scope.get("method"),
            "path": scope.get("path"),
        }
    except Exception:
        return absent


def _principal_id(current_user: Any) -> Optional[Any]:
    if current_user is None:
        return None
    try:
        return getattr(current_user, "id", None)
    except Exception:
        return None


def _role_name(role: Optional[Role]) -> Optional[str]:
    if role is None:
        return None
    return role.value


def _log_refusal(
    decision: str,
    current_user: Any,
    required: Optional[Role],
    effective: Optional[Role],
    request: Optional[Request],
    context: Optional[Dict[str, Any]] = None,
) -> None:
    """Attempts one record describing a refused request.

    The record carries the request method and path, the principal
    identifier, the required, effective and claimed role names and the
    decision, followed by any fields ``context`` supplies.

    ``required`` is ``None`` for a decision that names no minimum role,
    and ``effective`` is ``None`` when the stored role names no member of
    :class:`Role`. ``claimed_role`` is the role claim of the verified
    token, read through
    :func:`backend.app.core.security.claimed_role`; it records what the
    caller asserted, so a record where it differs from ``effective_role``
    shows a token issued before the stored role changed. It takes part in
    no decision.

    No token, no credential and no request body value is included.

    Nothing here reads from or writes to a database session. When the
    structured record cannot be written, the same fields are written to
    standard error and :func:`audit_failure_count` is incremented, so
    the refusal is recorded on every path. No exception leaves this
    function.
    """
    fields = _request_fields(request)
    fields["principal_id"] = _principal_id(current_user)
    fields["required_role"] = _role_name(required)
    fields["effective_role"] = _role_name(effective)
    fields["claimed_role"] = claimed_role(request)
    fields["decision"] = decision
    if context:
        for name, value in context.items():
            fields.setdefault(name, value)
    try:
        logger.warning(REFUSAL_MESSAGE, extra=fields)
        return
    except Exception as error:
        _count_audit_failure()
        fields["audit_sink"] = AUDIT_SINK_FALLBACK
        fields["audit_failures"] = audit_failure_count()
        fields.update(exception_fields(error))
    try:
        log_audit_fallback(AUDIT_FAILURE_MESSAGE, fields)
    except Exception:
        return


def _count_audit_failure() -> None:
    """Increments the count of refusals the primary sink rejected."""
    global _audit_failures
    with _AUDIT_FAILURE_LOCK:
        _audit_failures += 1


def audit_failure_count() -> int:
    """Returns how many refusals the primary audit sink rejected.

    A non-zero value means at least one refusal reached the fallback
    sink instead of the structured logger. The refusal itself was still
    recorded; the count reports that the primary sink degraded.
    """
    with _AUDIT_FAILURE_LOCK:
        return _audit_failures


def reset_audit_failure_count() -> int:
    """Clears the count and returns the value it held."""
    global _audit_failures
    with _AUDIT_FAILURE_LOCK:
        previous = _audit_failures
        _audit_failures = 0
        return previous


def _forbidden() -> HTTPException:
    """Returns the response raised for every refused principal.

    The exception is marked audited, so a handler further out leaves the
    refusal at the one record :func:`_log_refusal` emitted.
    """
    return mark_audited(
        HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=FORBIDDEN_DETAIL,
        )
    )


def _not_found() -> HTTPException:
    """Returns the response raised for a lookup matching no row.

    The exception is marked audited, so a handler further out leaves the
    refusal at the one record :func:`_log_refusal` emitted.
    """
    return mark_audited(
        HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=NOT_FOUND_DETAIL,
        )
    )


def require_role(minimum: Any) -> Callable[..., User]:
    """Returns a dependency admitting ``minimum`` and every role above.

    ``minimum`` accepts a :class:`Role` or the value the column stores,
    and ``ValueError`` is raised here when it names no member.

    The returned dependency resolves the principal through
    :func:`backend.app.core.security.get_current_user`, so an absent or
    invalid credential is answered ``401`` by that function before this
    check runs. The role stored on that row is read by
    :func:`resolve_role` and compared with ``minimum`` by
    :func:`role_satisfies`. Only when the stored role alone falls short
    is :func:`effective_role` consulted, so a paid entitlement can raise
    a principal to the declared minimum without a query being spent on
    the principals the stored role already admits.

    The stored row is returned unchanged when the comparison passes, so
    a route may declare this dependency in place of
    ``Depends(get_current_user)`` without altering its body.

    Three outcomes are refused with ``403`` and
    :data:`FORBIDDEN_DETAIL`, each after one record is emitted: a
    principal that resolution finds absent, a stored role that names no
    member of :class:`Role`, and a recognised role ranking below
    ``minimum``. The invalid-role outcome is refused before any rank
    comparison is made, so an unrecognised value satisfies no minimum,
    not even :data:`LOWEST_ROLE`.

    The request is read only to build that record, and no value carried
    by the request takes part in the decision.
    """
    required = _coerce_minimum(minimum)

    async def dependency(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user is None:
            _log_refusal(
                DECISION_PRINCIPAL_MISSING,
                None,
                required,
                None,
                request,
            )
            raise _forbidden()
        stored = resolve_role(current_user)
        if stored is None:
            _log_refusal(
                DECISION_ROLE_INVALID,
                current_user,
                required,
                None,
                request,
            )
            raise _forbidden()
        if role_satisfies(stored, required):
            return current_user
        # The stored role alone does not satisfy the minimum, so the
        # paid entitlement is resolved as well.
        effective = effective_role(db, current_user)
        if not role_satisfies(effective, required):
            _log_refusal(
                DECISION_ROLE_DENIED,
                current_user,
                required,
                effective,
                request,
            )
            raise _forbidden()
        return current_user

    dependency.__name__ = "require_role_" + required.value
    dependency.__qualname__ = dependency.__name__
    dependency.__doc__ = (
        "Returns the authenticated user when the role stored on its row"
        " ranks at or above " + required.value + "."
    )
    return dependency


def require_ownership(
    obj: Optional[_ModelT],
    current_user: Any,
    *,
    owner_attribute: str = OWNER_ATTRIBUTE,
    request: Optional[Request] = None,
    context: Optional[Dict[str, Any]] = None,
) -> _ModelT:
    """Returns ``obj`` when ``current_user`` owns it.

    ``obj`` is a row already loaded from the database, and its owner is
    read from ``owner_attribute``. The row is returned unchanged when
    that value equals the principal's identifier.

    Every refusal answers ``404`` with :data:`NOT_FOUND_DETAIL`, whatever
    the reason: no row matched, the row carries a different owner, the
    row carries no such attribute, or the principal carries no
    identifier. A caller therefore cannot tell a row that does not exist
    from one it is not entitled to, so the response discloses no
    identifier belonging to another principal. The two cases stay
    distinguishable in the emitted record, which names either
    :data:`DECISION_OBJECT_MISSING` or
    :data:`DECISION_OWNERSHIP_DENIED` and is extended by any fields
    ``context`` supplies.

    The comparison reads attributes only. No session is queried,
    flushed or committed here, so a refusal leaves no change behind.
    """
    details: Dict[str, Any] = {"owner_attribute": owner_attribute}
    if obj is not None:
        details["object_type"] = type(obj).__name__
    if context:
        for name, value in context.items():
            details.setdefault(name, value)

    if obj is None:
        _log_refusal(
            DECISION_OBJECT_MISSING,
            current_user,
            None,
            resolve_role(current_user),
            request,
            details,
        )
        raise _not_found()

    principal_id = _principal_id(current_user)
    owner_id = getattr(obj, owner_attribute, None)
    owned = (
        principal_id is not None
        and owner_id is not None
        and owner_id == principal_id
    )
    if not owned:
        _log_refusal(
            DECISION_OWNERSHIP_DENIED,
            current_user,
            None,
            resolve_role(current_user),
            request,
            details,
        )
        raise _not_found()
    return obj


def _preferred_row(
    rows: List[_ModelT],
    principal_id: Optional[Any],
    owner_attribute: str,
) -> Optional[_ModelT]:
    """Returns the row the principal owns, else the first, else ``None``.

    Preferring an owned row is what keeps a non-unique lookup from
    refusing a row the caller owns because another owner's row was
    ordered ahead of it. Returning the first unowned row when none is
    owned is what lets :func:`require_ownership` still tell ``403``
    apart from ``404``.
    """
    if not rows:
        return None
    if principal_id is not None:
        for row in rows:
            owner_id = getattr(row, owner_attribute, None)
            if owner_id is not None and owner_id == principal_id:
                return row
    return rows[0]


def _column_attribute_names(model: Type[_ModelT]) -> FrozenSet[str]:
    """Returns the names of the mapped columns of ``model``.

    The names come from the mapper's ``column_attrs``, so only column
    properties are included. A relationship such as ``User.filters`` or
    ``Filter.criteria`` is an ``InstrumentedAttribute`` too but is not a
    column property, and is therefore absent from this set.

    Raises ``ValueError`` when ``model`` is not a mapped class.
    """
    try:
        mapper = sqlalchemy_inspect(model)
        return frozenset(
            attribute.key for attribute in mapper.column_attrs
        )
    except (NoInspectionAvailable, AttributeError):
        raise ValueError(
            "{0!r} is not a mapped class".format(model)
        ) from None


def _lookup_conditions(
    model: Type[_ModelT],
    criteria: Dict[str, Any],
) -> List[Any]:
    """Returns the equality conditions ``criteria`` describes.

    Each key names an instrumented attribute of ``model`` -- a mapped
    column or a relationship -- and each value is what that attribute
    must equal. Keys are applied in sorted order.

    Raises ``ValueError`` when ``criteria`` is empty, when ``model`` is
    not a mapped class, and when a key names anything other than one of
    that model's mapped columns -- including a relationship, which the
    mapper's column properties exclude.
    """
    if not criteria:
        raise ValueError("at least one lookup criterion is required")
    model_name = getattr(model, "__name__", repr(model))
    columns = _column_attribute_names(model)
    conditions: List[Any] = []
    for name in sorted(criteria):
        if name not in columns:
            raise ValueError(
                "{0} has no instrumented attribute named {1!r}".format(
                    model_name, name
                )
            )
        conditions.append(getattr(model, name) == criteria[name])
    return conditions


def load_owned(
    db: Session,
    model: Type[_ModelT],
    current_user: Any,
    *,
    owner_attribute: str = OWNER_ATTRIBUTE,
    request: Optional[Request] = None,
    **criteria: Any
) -> _ModelT:
    """Loads the row matching ``criteria`` and returns it when owned.

    ``criteria`` names mapped columns of ``model`` and the values they
    must equal; at least one is required, and a name that is not one of
    that model's mapped columns raises ``ValueError``. The identifier of
    the owner is never taken from ``criteria``: it is read from
    ``current_user`` alone.

    ``criteria`` that is not unique can match more than one row. Up to
    :data:`LOOKUP_CANDIDATE_LIMIT` matches are read and the one the
    principal owns is preferred, so a row the caller owns is never
    refused because a row belonging to somebody else was ordered ahead
    of it. When no match is owned, the first is handed on so the record
    still distinguishes the two cases.

    The selected row is handed to :func:`require_ownership`, which
    answers ``404`` whether no row matched or the selected row carries
    another owner, so a caller cannot tell the two apart. The record
    either refusal emits names the model, the criteria fields and how
    many rows matched; the criteria values are not recorded.

    The lookup is read-only. Nothing is added, flushed or committed
    here, so a refusal leaves no change behind and every caller may run
    it before it mutates anything.
    """
    conditions = _lookup_conditions(model, criteria)
    rows = (
        db.query(model)
        .filter(*conditions)
        .limit(LOOKUP_CANDIDATE_LIMIT)
        .all()
    )
    principal_id = _principal_id(current_user)
    row = _preferred_row(rows, principal_id, owner_attribute)
    return require_ownership(
        row,
        current_user,
        owner_attribute=owner_attribute,
        request=request,
        context={
            "object_type": getattr(model, "__name__", repr(model)),
            "criteria_fields": sorted(criteria),
            "matched_rows": len(rows),
        },
    )
