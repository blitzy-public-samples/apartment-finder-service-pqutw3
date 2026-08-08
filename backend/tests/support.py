"""Shared values and helpers for the backend test suite.

This module is imported under exactly one name,
``backend.tests.support``, by ``backend/tests/conftest.py`` and by the
test modules that need one of the values below. It imports nothing from
``backend.app``, so importing it never constructs the application
settings.

It publishes:

* :data:`REPO_ROOT` -- the absolute path of the repository root
* :data:`TEST_SETTINGS` and :func:`apply_test_settings` -- the complete
  settings the suite runs under, and the call that places them in the
  process environment
* :data:`VALID_TEST_PASSWORD` -- the password every seeded account is
  created with
* :data:`ROLE_EMAILS` and :data:`SECOND_REGISTERED_EMAIL` -- the address
  of each seeded account
* :data:`FOREIGN_SIGNING_KEY`, :data:`FOREIGN_AUDIENCE` and
  :data:`FOREIGN_ISSUER` -- the values a forged token carries in place of
  a configured one
* :data:`CLIENT_BASE_URL` -- the base URL every test client is opened on
* :func:`bearer_header` -- the ``Authorization`` header carrying a token
* :func:`enforce_sqlite_foreign_keys` -- the registration that makes a
  SQLite engine enforce the foreign keys the models declare

Usage::

    from backend.tests.support import VALID_TEST_PASSWORD
"""

import os
from pathlib import Path
from typing import Any, Dict

from sqlalchemy import event

#: Absolute path of the repository root, two directories above this
#: file.
REPO_ROOT = Path(__file__).resolve().parents[2]

#: Every setting :class:`backend.app.core.config.Settings` declares,
#: with the value the suite runs under. :func:`apply_test_settings`
#: assigns each one, so the resolved settings are these values and only
#: these values. Every entry is a local test value: none names a real
#: host, a real account or a real credential.
TEST_SETTINGS: Dict[str, str] = {
    "ENVIRONMENT": "local",
    "DATABASE_URL": "sqlite://",
    "SECRET_KEY": "tZ4mQ7vK2pR9wB6nD3jS8xF5hL0cY1gA",
    "JWT_ALGORITHMS": "HS256",
    "JWT_ISSUER": "apartment-finder-service",
    "JWT_AUDIENCE": "apartment-finder-web",
    "ACCESS_TOKEN_EXPIRE_MINUTES": "30",
    "BCRYPT_ROUNDS": "12",
    "ALLOWED_ORIGINS": "http://localhost:3000,http://localhost:80",
    "ALLOWED_HOSTS": "localhost,127.0.0.1",
    "MAX_REQUEST_BODY_BYTES": "1048576",
    "MAX_REQUEST_BODY_CHUNKS": "2048",
    "MAX_PAGE_SIZE": "100",
    "MAX_PAGINATION_OFFSET": "10000",
    "RATE_LIMIT_LOGIN": "5/minute",
    "RATE_LIMIT_REGISTER": "3/minute",
    "RATE_LIMIT_WEBHOOK": "60/minute",
    "RATE_LIMIT_STORAGE_URI": "bounded-memory://",
    "RATE_LIMIT_MAX_TRACKED_KEYS": "4096",
    "LOGIN_MAX_ATTEMPTS": "5",
    "LOGIN_LOCKOUT_MINUTES": "15",
    "ZILLOW_API_URL": "https://zillow-api.example.com/v2/listings",
    "ZILLOW_API_KEY": "listing-provider-test-key",
    "HTTP_TIMEOUT_SECONDS": "10.0",
    "PAYPAL_MODE": "sandbox",
    "PAYPAL_API_BASE": "https://api-m.sandbox.paypal.com",
    "PAYPAL_CLIENT_ID": "paypal-test-client-id",
    "PAYPAL_CLIENT_SECRET": "paypal-test-client-secret",
    "PAYPAL_WEBHOOK_ID": "paypal-test-webhook-id",
    "PAYPAL_CERT_HOST_ALLOWLIST": (
        "api.paypal.com,api.sandbox.paypal.com,"
        "api-m.paypal.com,api-m.sandbox.paypal.com"
    ),
    "PAYPAL_MAX_CONNECTIONS": "20",
    "PAYPAL_RETURN_URL": (
        "http://localhost:3000/subscription?paypal=return"
    ),
    "PAYPAL_CANCEL_URL": (
        "http://localhost:3000/subscription?paypal=cancel"
    ),
    "SENDGRID_API_KEY": "sendgrid-test-key",
    "FROM_EMAIL": "no-reply@example.com",
    "SECRET_BACKEND": "env",
    "SENTRY_DSN": "",
}

#: Password every seeded row is created with. It satisfies the policy
#: :class:`backend.app.schema.user.UserCreate` applies: at least twelve
#: characters carrying an upper-case letter, a lower-case letter, a
#: digit and a special character, within seventy-two UTF-8 bytes.
VALID_TEST_PASSWORD = "TestPassw0rd!2024"

#: Address of the seeded row holding each role, keyed by the string the
#: ``users.role`` column stores. ``backend/tests/conftest.py`` asserts
#: these keys are the values :class:`backend.app.core.authorization.
#: Role` defines.
ROLE_EMAILS = {
    "guest": "guest@example.com",
    "registered": "registered@example.com",
    "premium": "premium@example.com",
    "admin": "admin@example.com",
}

#: Address of the second row holding the ``registered`` role.
SECOND_REGISTERED_EMAIL = "second.registered@example.com"

#: Signing key a forged token is signed with in place of the configured
#: one. It is never the configured key.
FOREIGN_SIGNING_KEY = "pW3sJ8fH1nT6bC9mZ4vG7kR0dY2xQ5aL"

#: Audience a forged token carries in place of the configured one.
FOREIGN_AUDIENCE = "apartment-finder-other-audience"

#: Issuer a forged token carries in place of the configured one.
FOREIGN_ISSUER = "apartment-finder-other-issuer"

#: Base URL every client is opened on. It names a host present in
#: ``TEST_SETTINGS["ALLOWED_HOSTS"]``.
CLIENT_BASE_URL = "http://localhost"


def apply_test_settings() -> Dict[str, str]:
    """Place every entry of :data:`TEST_SETTINGS` in the environment.

    Each name is assigned, and any variable already carrying that name
    in any letter case is removed first, so a value exported by a shell
    or held in a deployment environment file reaches neither the settings
    the suite resolves nor any record the suite renders. Returns the
    mapping that was applied.

    Call this before the first ``backend.app.*`` import, which is when
    :class:`backend.app.core.config.Settings` is constructed.
    """
    for name, value in TEST_SETTINGS.items():
        for present in [
            key for key in os.environ if key.lower() == name.lower()
        ]:
            del os.environ[present]
        os.environ[name] = value
    return dict(TEST_SETTINGS)


def bearer_header(token: str) -> Dict[str, str]:
    """Return the ``Authorization`` header mapping carrying ``token``."""
    return {"Authorization": "Bearer {0}".format(token)}


def enforce_sqlite_foreign_keys(engine: Any) -> Any:
    """Enforce foreign keys on every connection ``engine`` opens.

    SQLite accepts a foreign key in a table definition but does not
    enforce it until ``PRAGMA foreign_keys`` is set, and the setting is
    per connection. Registering it on connect leaves every foreign key
    the models and the revisions declare enforced for the whole test, so
    a row naming a parent that is not stored is refused. Returns
    ``engine`` itself, unchanged apart from the registration.
    """

    @event.listens_for(engine, "connect")
    def _set_pragma(dbapi_connection: Any, connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    return engine
