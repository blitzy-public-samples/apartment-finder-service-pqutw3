"""Centralized role and ownership authorization for the API surface.

This module is the application's single authorization decision point. It
publishes an ordered four-role model, a dependency factory that guards a
route on a minimum role, and two helpers that bind a stored row to the
principal that owns it.

The role every decision is taken against is read from the
:data:`ROLE_ATTRIBUTE` of the stored user row that authentication
returned. No request body field, query parameter, header or token claim
is consulted, and no function here writes a role.

Resolution denies by default. A row whose role is absent, ``None``,
blank, unrecognised or of an unexpected type resolves to
:data:`LOWEST_ROLE` and the request is refused. Matching removes
surrounding whitespace and folds letter case, so a stored ``" Admin "``
resolves to :attr:`Role.ADMIN`, while a value naming no member resolves
to :data:`LOWEST_ROLE` rather than raising.

An unrecognised minimum handed to :func:`require_role` raises
``ValueError`` while the route is being declared.

Refusals carry these statuses:

* an absent or invalid credential is answered ``401`` by
  :func:`backend.app.core.security.get_current_user`, and that response
  passes through unchanged
* an authenticated principal below the minimum role is answered ``403``
* a lookup matching no row is answered ``404``, and a row carrying
  another owner is answered ``403``

Every refusal emits one structured record through
:func:`backend.app.core.logging.get_logger` carrying the request method
and path, the principal identifier, the required and effective role
names and the decision. The method and the path are read from
``request.scope``. Emitting a record raises nothing into the request
path and touches no database session.

This module installs no middleware and guards no route on its own: a
route is guarded where it declares the dependency, and a route
declaring none stays reachable.

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

from enum import Enum
from types import MappingProxyType
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Tuple,
    Type,
    TypeVar,
)

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import InstrumentedAttribute

from backend.app.core.logging import get_logger
from backend.app.core.security import get_current_user
from backend.app.db.models import User

__all__ = [
    "DECISION_OBJECT_MISSING",
    "DECISION_OWNERSHIP_DENIED",
    "DECISION_PRINCIPAL_MISSING",
    "DECISION_ROLE_DENIED",
    "FORBIDDEN_DETAIL",
    "LOWEST_ROLE",
    "NOT_FOUND_DETAIL",
    "OWNER_ATTRIBUTE",
    "REFUSAL_MESSAGE",
    "ROLE_ATTRIBUTE",
    "ROLE_ORDER",
    "ROLE_RANKS",
    "Role",
    "load_owned",
    "parse_role",
    "require_ownership",
    "require_role",
    "resolve_role",
    "role_satisfies",
]

logger = get_logger(__name__)


class Role(str, Enum):
    """A role a principal may hold.

    Each member's value is the string the ``role`` column stores, so a
    member is usable anywhere that string is, including as a log field.
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

#: The least privileged role, and the outcome of every resolution that
#: does not match a member.
LOWEST_ROLE = Role.GUEST

#: Attribute of the stored user row that carries the role.
ROLE_ATTRIBUTE = "role"

#: Attribute an owned row carries its owner's identifier on.
OWNER_ATTRIBUTE = "user_id"

#: Detail returned with every ``403``.
FORBIDDEN_DETAIL = "Insufficient permissions"

#: Detail returned with every ``404``.
NOT_FOUND_DETAIL = "Resource not found"

#: Message of the record emitted for a refused request.
REFUSAL_MESSAGE = "Authorization refused"

#: Decision recorded when a principal ranks below the minimum role.
DECISION_ROLE_DENIED = "role_denied"

#: Decision recorded when a row carries another principal's owner.
DECISION_OWNERSHIP_DENIED = "ownership_denied"

#: Decision recorded when an ownership lookup matches no row.
DECISION_OBJECT_MISSING = "object_missing"

#: Decision recorded when no principal reached the check.
DECISION_PRINCIPAL_MISSING = "principal_missing"

# Roles keyed by the value the column stores.
_ROLES_BY_VALUE: Mapping[str, Role] = MappingProxyType(
    dict((role.value, role) for role in ROLE_ORDER)
)

# Row type returned by the ownership helpers.
_ModelT = TypeVar("_ModelT")


def parse_role(value: Any) -> Optional[Role]:
    """Returns the role ``value`` names, or ``None`` when it names none.

    A :class:`Role` is returned unchanged. A string is matched once
    surrounding whitespace is removed and letter case is folded. Every
    other value returns ``None``, including ``None`` itself, a blank
    string, a numeric rank and a boolean.
    """
    if isinstance(value, Role):
        return value
    if not isinstance(value, str):
        return None
    return _ROLES_BY_VALUE.get(value.strip().lower())


def resolve_role(user: Any) -> Role:
    """Returns the role the stored user row carries.

    The value is read from the row's :data:`ROLE_ATTRIBUTE` and matched
    by :func:`parse_role`. A row that is ``None``, that carries no such
    attribute, or that carries a value naming no member resolves to
    :data:`LOWEST_ROLE`. Reading the attribute never raises.
    """
    if user is None:
        return LOWEST_ROLE
    try:
        stored = getattr(user, ROLE_ATTRIBUTE, None)
    except Exception:
        return LOWEST_ROLE
    resolved = parse_role(stored)
    if resolved is None:
        return LOWEST_ROLE
    return resolved


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
    """Returns the identifier of ``current_user``, or ``None``."""
    if current_user is None:
        return None
    try:
        return getattr(current_user, "id", None)
    except Exception:
        return None


def _role_name(role: Optional[Role]) -> Optional[str]:
    """Returns the stored value of ``role``, or ``None``."""
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
    """Emits one record describing a refused request.

    The record carries the request method and path, the principal
    identifier, the required and effective role names and the decision,
    followed by any fields ``context`` supplies. ``required`` is
    ``None`` for a decision that names no minimum role. No token, no
    credential and no request body value is included.

    Nothing here reads from or writes to a database session, and a
    failure to emit the record is discarded rather than raised.
    """
    fields = _request_fields(request)
    fields["principal_id"] = _principal_id(current_user)
    fields["required_role"] = _role_name(required)
    fields["effective_role"] = _role_name(effective)
    fields["decision"] = decision
    if context:
        for name, value in context.items():
            fields.setdefault(name, value)
    try:
        logger.warning(REFUSAL_MESSAGE, extra=fields)
    except Exception:
        return


def _forbidden() -> HTTPException:
    """Returns the response raised for every refused principal."""
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=FORBIDDEN_DETAIL,
    )


def _not_found() -> HTTPException:
    """Returns the response raised for a lookup matching no row."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=NOT_FOUND_DETAIL,
    )


def require_role(minimum: Any) -> Callable[..., User]:
    """Returns a dependency admitting ``minimum`` and every role above.

    ``minimum`` accepts a :class:`Role` or the value the column stores,
    and ``ValueError`` is raised here when it names no member.

    The returned dependency resolves the principal through
    :func:`backend.app.core.security.get_current_user`, so an absent or
    invalid credential is answered ``401`` by that function before this
    check runs. The effective role is then resolved from the stored row
    by :func:`resolve_role` and compared with ``minimum`` by
    :func:`role_satisfies`.

    The stored row is returned unchanged when the comparison passes, so
    a route may declare this dependency in place of
    ``Depends(get_current_user)`` without altering its body. A principal
    ranking below ``minimum``, and a principal that resolution finds
    absent, are refused with ``403`` and :data:`FORBIDDEN_DETAIL` after
    one record is emitted.

    The request is read only to build that record, and no value carried
    by the request takes part in the decision.
    """
    required = _coerce_minimum(minimum)

    async def dependency(
        request: Request,
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
        effective = resolve_role(current_user)
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

    ``obj`` being ``None`` is refused with ``404`` and
    :data:`NOT_FOUND_DETAIL`. A row carrying a different owner, a row
    carrying no such attribute, and a principal carrying no identifier
    are each refused with ``403`` and :data:`FORBIDDEN_DETAIL`. Both
    refusals emit one record first, extended by any fields ``context``
    supplies.

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
        raise _forbidden()
    return obj


def _lookup_conditions(
    model: Type[_ModelT],
    criteria: Dict[str, Any],
) -> List[Any]:
    """Returns the equality conditions ``criteria`` describes.

    Each key names a mapped column of ``model`` and each value is what
    that column must equal. Keys are applied in sorted order.

    Raises ``ValueError`` when ``criteria`` is empty and when a key
    names an attribute of ``model`` that is not a mapped column.
    """
    if not criteria:
        raise ValueError("at least one lookup criterion is required")
    model_name = getattr(model, "__name__", repr(model))
    conditions: List[Any] = []
    for name in sorted(criteria):
        column = getattr(model, name, None)
        if not isinstance(column, InstrumentedAttribute):
            raise ValueError(
                "{0} has no mapped column named {1!r}".format(
                    model_name, name
                )
            )
        conditions.append(column == criteria[name])
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
    must equal; at least one is required, and a name that is not a
    mapped column of ``model`` raises ``ValueError``. The identifier of
    the owner is never taken from ``criteria``: it is read from
    ``current_user`` alone.

    The first matching row is handed to :func:`require_ownership`, which
    answers ``404`` when no row matched and ``403`` when the matching
    row carries another owner. The record either refusal emits names the
    model and the criteria fields; the criteria values are not recorded.

    The lookup is read-only. Nothing is added, flushed or committed
    here, so a refusal leaves no change behind and every caller may run
    it before it mutates anything.
    """
    conditions = _lookup_conditions(model, criteria)
    row = db.query(model).filter(*conditions).first()
    return require_ownership(
        row,
        current_user,
        owner_attribute=owner_attribute,
        request=request,
        context={
            "object_type": getattr(model, "__name__", repr(model)),
            "criteria_fields": sorted(criteria),
        },
    )
