"""HTTP Cloud Function published by ``infrastructure/terraform/main.tf``.

The function reports that the deployed function surface is reachable and
which revision of this repository it was packaged from. It reads no
secret, opens no network connection and touches no database, so it can be
invoked as a reachability probe without side effects.

Invocation is restricted to the single IAM principal named by
``var.cloud_function_invoker_member``; the function itself performs no
authorization of its own and must not be relied on for any.

The entry point is :func:`hello_world`, which is the value
``google_cloudfunctions_function.function.entry_point`` carries, and the
runtime is Python 3.9, which is the value its ``runtime`` argument
carries. Both names are part of the deployment contract: renaming either
breaks the deployment.
"""

import json
import os
from typing import Any, Dict, Tuple

#: Value the ``status`` member of a successful response carries.
STATUS_OK = "ok"

#: Value the ``status`` member carries when the request method is refused.
STATUS_REFUSED = "method_not_allowed"

#: Request methods the function answers. Every other method is refused
#: with 405 and the ``Allow`` header below.
ALLOWED_METHODS = ("GET", "HEAD")

#: Value of the ``Allow`` header sent with a refusal.
ALLOW_HEADER = ", ".join(ALLOWED_METHODS)

#: Environment variables the response reports, mapped to the response
#: member each is reported under. Every one is set by the platform and
#: none is a credential.
REPORTED_ENVIRONMENT = {
    "K_SERVICE": "service",
    "K_REVISION": "revision",
    "FUNCTION_REGION": "region",
}

#: Value reported for a member whose variable is absent.
UNREPORTED = "unknown"

#: Response headers sent with every answer. The body is JSON, and no
#: intermediary may store it.
RESPONSE_HEADERS = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


def _reported_environment() -> Dict[str, str]:
    """Collect the platform values :data:`REPORTED_ENVIRONMENT` names.

    A variable that is absent or blank is reported as
    :data:`UNREPORTED`, so every member of the response is present
    whatever the platform supplied.
    """
    reported = {}
    for variable, member in REPORTED_ENVIRONMENT.items():
        value = (os.environ.get(variable) or "").strip()
        reported[member] = value or UNREPORTED
    return reported


def _refusal() -> Tuple[str, int, Dict[str, str]]:
    """Build the answer to a request whose method is not answered."""
    headers = dict(RESPONSE_HEADERS)
    headers["Allow"] = ALLOW_HEADER
    body = json.dumps({"status": STATUS_REFUSED, "allow": ALLOW_HEADER})
    return body, 405, headers


def hello_world(request: Any) -> Tuple[str, int, Dict[str, str]]:
    """Answer a reachability probe.

    ``request`` is the framework request object the Python runtime
    supplies. Only its ``method`` attribute is read; no header, query
    parameter or body is read, so nothing a caller sends reaches the
    response.

    Returns the triple of body, status code and headers the Python
    runtime accepts. A method outside :data:`ALLOWED_METHODS` is answered
    with 405 and the ``Allow`` header.
    """
    method = str(getattr(request, "method", "") or "").upper()
    if method not in ALLOWED_METHODS:
        return _refusal()

    payload = {"status": STATUS_OK}
    payload.update(_reported_environment())
    return json.dumps(payload), 200, dict(RESPONSE_HEADERS)
