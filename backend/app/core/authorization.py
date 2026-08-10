"""Centralized role and ownership authorization dependencies."""

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
from sqlalchemy.exc import NoInspectionAvailable, SQLAlchemyError
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
    "BASELINE_ROLE",
    "DECISION_OBJECT_MISSING",
    "DECISION_OWNERSHIP_DENIED",
    "DECISION_PRINCIPAL_MISSING",
    "DECISION_ROLE_DENIED",
    "DECISION_ROLE_INVALID",
    "ENTITLEMENT_UNRESOLVED_MESSAGE",
    "FORBIDDEN_DETAIL",
    "LOOKUP_CANDIDATE_LIMIT",
    "LOWEST_ROLE",
    "NOT_FOUND_DETAIL",
    "OWNER_ATTRIBUTE",
    "REFUSAL_MESSAGE",
    "ROLE_ATTRIBUTE",
    "ROLE_ORDER",
    "ROLE_RANKS",
    "SUBSCRIPTION_DERIVED_ROLES",
    "Role",
    "audit_failure_count",
    "effective_role",
    "entitled_role",
    "load_owned",
    "parse_role",
    "require_ownership",
    "require_role",
    "reset_audit_failure_count",
    "resolve_role",
    "role_satisfies",
    "stored_credit",
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

#: Roles a paid entitlement grants. A stored value naming one of these
#: is credited as :data:`BASELINE_ROLE` on its own, and reaches its own
#: rank only while :func:`entitled_role` resolves it from an unexpired
#: active subscription.
SUBSCRIPTION_DERIVED_ROLES: FrozenSet[Role] = frozenset({Role.PREMIUM})

#: Role a stored subscription-derived value is credited as when no
#: entitlement grants it.
BASELINE_ROLE = Role.REGISTERED

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

#: Message recorded when a paid entitlement could not be read. The
#: decision then rests on the credited stored role alone.
ENTITLEMENT_UNRESOLVED_MESSAGE = "Paid entitlement could not be resolved"

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


def stored_credit(value: Any) -> Optional[Role]:
    """Returns the role a stored value carries without an entitlement.

    A value naming a member of :data:`SUBSCRIPTION_DERIVED_ROLES` is
    credited as :data:`BASELINE_ROLE`, so the column alone never carries
    a rank a paid entitlement grants. Every other value
    :func:`parse_role` recognises is returned unchanged, and a value
    naming no member returns ``None``.
    """
    resolved = parse_role(value)
    if resolved is None:
        return None
    if resolved in SUBSCRIPTION_DERIVED_ROLES:
        return BASELINE_ROLE
    return resolved


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
    """Return the highest role granted by the user's active, unexpired
    subscriptions; return None on lookup failure or no entitlement.
    """
    principal_id = _principal_id(user)
    if principal_id is None:
        return None
    if moment is None:
        moment = datetime.now(timezone.utc)
    try:
        plan_ids = (
            db.query(Subscription.plan_id)
            .filter(
                Subscription.user_id == principal_id,
                Subscription.status == STATUS_ACTIVE,
                Subscription.end_date > moment,
            )
            .all()
        )
    except SQLAlchemyError as error:
        fields = {"principal_id": principal_id}
        fields.update(exception_fields(error))
        logger.error(ENTITLEMENT_UNRESOLVED_MESSAGE, extra=fields)
        return None
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
    """Resolve the recognized stored role and raise it with any active
    subscription entitlement.
    """
    stored = resolve_role(user)
    if stored is None:
        return None
    credited = stored_credit(stored)
    granted = entitled_role(db, user, moment)
    if granted is not None and ROLE_RANKS[granted] > ROLE_RANKS[credited]:
        return granted
    return credited


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
    """Emit one sanitized authorization-refusal record, falling back to
    stderr on logger failure.
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
    """Return a dependency that authenticates the user and enforces the
    minimum database-backed role.
    """
    required = _coerce_minimum(minimum)

    def dependency(
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
        if role_satisfies(stored_credit(stored), required):
            return current_user
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
    """Return the object when owned; otherwise audit and raise the
    uniform 404 response.
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
    """Return an owned row when present, otherwise the first match or None.

    Returning an unowned match preserves the audit distinction while both
    HTTP refusals remain 404.
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
    """Load bounded candidates by mapped-column criteria, prefer the
    caller-owned row, and apply uniform ownership refusal.
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
