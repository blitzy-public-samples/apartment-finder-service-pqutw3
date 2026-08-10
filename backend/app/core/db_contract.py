"""The database configuration contract, shared and side-effect free.

Three callers reach the database, and each reads its configuration from a
different place:

* :mod:`backend.app.core.config` builds ``Settings`` from the process
  environment and the environment file, and refuses a value that fails a
  check at import.
* :mod:`backend.app.db.database` builds the application's engine from
  those settings.
* :mod:`backend.migrations.env` and
  :mod:`backend.app.core.admin_provisioning` run as one-shot commands
  that are given the database credential and nothing else, so they read
  the few settings they need themselves rather than importing
  ``Settings``.

The rules those callers hold a value to live here, once. This module
imports no setting, opens no connection, reads no file at import and
publishes no mutable state, so a command may import it with only
``DATABASE_URL`` in its environment.

Every function raises ``ValueError`` for a value it refuses, and the
message names the rule rather than the value, so a caller may render it
without disclosing a credential.
"""

import os
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from dotenv import dotenv_values

__all__ = [
    "BCRYPT_ROUNDS_CEILING",
    "BCRYPT_ROUNDS_FLOOR",
    "DATABASE_SCHEMES",
    "DATABASE_URL_SETTING",
    "DB_MIGRATION_TIMEOUT_CEILING_SECONDS",
    "DB_TIMEOUT_CEILING_SECONDS",
    "DB_TIMEOUT_FLOOR_SECONDS",
    "DEFAULT_BCRYPT_ROUNDS",
    "DEFAULT_DB_CONNECT_TIMEOUT_SECONDS",
    "DEFAULT_DB_MIGRATION_STATEMENT_TIMEOUT_SECONDS",
    "DEFAULT_DB_STATEMENT_TIMEOUT_SECONDS",
    "DEFAULT_DB_TCP_USER_TIMEOUT_SECONDS",
    "DEFAULT_ENVIRONMENT",
    "ENVIRONMENT_NAMES",
    "ENVIRONMENT_SETTING",
    "ENV_FILE_VARIABLE",
    "LOCAL_DATABASE_SCHEMES",
    "LOCAL_ENVIRONMENT",
    "MILLISECONDS_PER_SECOND",
    "POSTGRESQL_SCHEMES",
    "POSTGRESQL_SESSION_OPTIONS_TEMPLATE",
    "SQLITE_CONNECT_ARGS",
    "SQLITE_SCHEMES",
    "WITHDRAWN_DATABASE_SCHEME",
    "connect_args",
    "default_env_file",
    "environment_name",
    "read_bound",
    "resolve_setting",
    "session_options",
    "split_url",
    "validate_bound",
    "validate_database_url",
]

#: URL schemes accepted in the database URL.
DATABASE_SCHEMES = frozenset({"postgresql", "postgresql+psycopg2"})

#: URL schemes accepted in the database URL under
#: :data:`LOCAL_ENVIRONMENT` only.
LOCAL_DATABASE_SCHEMES = frozenset({"sqlite", "sqlite+pysqlite"})

#: Scheme whose SQLAlchemy support was withdrawn.
WITHDRAWN_DATABASE_SCHEME = "postgres"

#: Environment name under which a local database scheme is accepted.
LOCAL_ENVIRONMENT = "local"

#: Deployment environment names accepted. ``Settings.ENVIRONMENT`` holds
#: its value to this set, and every caller that resolves the environment
#: itself holds it to the same set, so an unrecognised name refuses the
#: run rather than selecting a posture by falling through a comparison.
ENVIRONMENT_NAMES = frozenset(
    {"local", "development", "staging", "production"}
)

#: Environment name assumed when nothing names one. It is the value
#: ``Settings.ENVIRONMENT`` declares as its own default, so a command and
#: the application resolve the same environment from the same inputs.
DEFAULT_ENVIRONMENT = "development"

#: Name of the setting carrying the database URL.
DATABASE_URL_SETTING = "DATABASE_URL"

#: Name of the setting carrying the deployment environment.
ENVIRONMENT_SETTING = "ENVIRONMENT"

#: Environment variable naming the file a setting is read from when the
#: process environment does not carry it. An empty value reads no file.
ENV_FILE_VARIABLE = "ENV_FILE"

#: Lowest value any database timeout may take, in seconds.
DB_TIMEOUT_FLOOR_SECONDS = 1

#: Highest value the three request-path database timeouts may take, in
#: seconds.
DB_TIMEOUT_CEILING_SECONDS = 300

#: Highest value the migration statement timeout may take, in seconds. It
#: is above :data:`DB_TIMEOUT_CEILING_SECONDS` because the statements a
#: revision issues are schema changes rather than request-path reads.
DB_MIGRATION_TIMEOUT_CEILING_SECONDS = 3600

#: Seconds a connection attempt may take when nothing names a value.
DEFAULT_DB_CONNECT_TIMEOUT_SECONDS = 3

#: Seconds one request-path statement may run when nothing names a value.
DEFAULT_DB_STATEMENT_TIMEOUT_SECONDS = 3

#: Seconds an established socket may hold unacknowledged data when
#: nothing names a value.
DEFAULT_DB_TCP_USER_TIMEOUT_SECONDS = 4

#: Seconds one migration statement may run when nothing names a value. It
#: is below the wall-clock deadline the deployment paths place on the
#: migration job, so a statement is cancelled by the server before the
#: job is abandoned.
DEFAULT_DB_MIGRATION_STATEMENT_TIMEOUT_SECONDS = 600

#: Lowest bcrypt cost factor accepted.
BCRYPT_ROUNDS_FLOOR = 10

#: Highest bcrypt cost factor accepted.
BCRYPT_ROUNDS_CEILING = 15

#: Bcrypt cost factor used when nothing names one.
DEFAULT_BCRYPT_ROUNDS = 12

#: URL scheme prefixes served by the PostgreSQL driver.
POSTGRESQL_SCHEMES = ("postgresql://", "postgresql+")

#: URL scheme prefixes served by the SQLite driver.
SQLITE_SCHEMES = ("sqlite://", "sqlite+")

#: Driver arguments applied to every SQLite connection. The pool hands a
#: connection to one thread at a time, while a session is opened and
#: closed on whichever worker thread serves each step, so the driver's own
#: single-thread check is lifted.
SQLITE_CONNECT_ARGS: Dict[str, Any] = {"check_same_thread": False}

#: Template of the libpq runtime parameters applied to every PostgreSQL
#: connection. ``timezone`` pins the session to UTC and
#: ``statement_timeout`` bounds how long one statement may run on the
#: server, expressed in milliseconds.
POSTGRESQL_SESSION_OPTIONS_TEMPLATE = (
    "-c timezone=utc -c statement_timeout={statement_timeout_ms}"
)

#: Number of milliseconds in one second.
MILLISECONDS_PER_SECOND = 1000

#: Repository root, resolved from this file's own path rather than from
#: the working directory.
_REPOSITORY_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(
        __file__
    ))))
)


def split_url(value: str) -> Any:
    """Return the split URL, refusing a value that cannot be parsed."""
    try:
        parts = urlsplit(value)
        # Reading the port raises for a non-integer port.
        _ = parts.port
    except ValueError:
        raise ValueError("must be a well-formed URL")
    return parts


def validate_database_url(value: str, environment: Optional[str]) -> str:
    """Return the database URL, refusing an unsupported target.

    The URL must name a scheme in :data:`DATABASE_SCHEMES` and must carry
    both a host and a database name. A scheme in
    :data:`LOCAL_DATABASE_SCHEMES` is accepted only while ``environment``
    names :data:`LOCAL_ENVIRONMENT`.
    """
    candidate = value.strip()
    parts = split_url(candidate)
    scheme = parts.scheme.lower()
    accepted = sorted(DATABASE_SCHEMES)
    if scheme in LOCAL_DATABASE_SCHEMES:
        if environment != LOCAL_ENVIRONMENT:
            raise ValueError(
                f"must use one of {accepted} unless ENVIRONMENT is "
                f"{LOCAL_ENVIRONMENT}"
            )
        return candidate
    if scheme == WITHDRAWN_DATABASE_SCHEME:
        raise ValueError(
            f"must use one of {accepted} rather than "
            f"{WITHDRAWN_DATABASE_SCHEME}"
        )
    if scheme not in DATABASE_SCHEMES:
        raise ValueError(f"must use one of {accepted}")
    if not parts.hostname:
        raise ValueError("must carry a host")
    database = parts.path.lstrip("/")
    if not database or "/" in database:
        raise ValueError("must carry a database name")
    return candidate


def validate_bound(
    name: str, value: Any, floor: int, ceiling: int
) -> int:
    """Return one bound as a whole number of seconds, or refuse it.

    A value that is blank, is not a whole number, or lies outside
    ``floor`` to ``ceiling`` inclusive is refused. The message names the
    setting and the accepted range.
    """
    text = "" if value is None else str(value).strip()
    if not text:
        raise ValueError(
            f"{name} carries no value; it accepts a whole number of "
            f"seconds from {floor} to {ceiling}"
        )
    try:
        seconds = int(text)
    except ValueError:
        raise ValueError(
            f"{name} must be a whole number of seconds from {floor} to "
            f"{ceiling}"
        )
    if seconds < floor or seconds > ceiling:
        raise ValueError(
            f"{name} must be from {floor} to {ceiling} seconds"
        )
    return seconds


def default_env_file() -> str:
    """Return the environment file read when none is named."""
    return os.path.join(_REPOSITORY_ROOT, ".env")


def _env_file_path() -> Optional[str]:
    """Return the environment file to read, or ``None`` to read none.

    An ``ENV_FILE`` value is used exactly as given, and an empty one
    selects no file at all. Absent, :func:`default_env_file` is named.
    """
    named = os.environ.get(ENV_FILE_VARIABLE)
    if named is None:
        return default_env_file()
    if not named.strip():
        return None
    return named


def resolve_setting(name: str) -> Optional[str]:
    """Return one setting's value, or ``None`` when nothing names it.

    The process environment is read first and then the environment file
    :func:`_env_file_path` names, which are the two sources ``Settings``
    reads, so a command and the application resolve the same value. A
    name the process environment carries is answered from there even when
    its value is blank, which is the precedence ``Settings`` applies, and
    the blank value is returned for the caller's own check rather than
    read as absent.
    """
    supplied = os.environ.get(name)
    if supplied is not None:
        return supplied.strip()

    path = _env_file_path()
    if path and os.path.isfile(path):
        from_file = dotenv_values(path).get(name)
        if from_file is not None:
            return from_file.strip()
    return None


def environment_name() -> str:
    """Return the deployment environment a command runs under.

    :data:`DEFAULT_ENVIRONMENT` is returned when nothing names one, which
    is the default ``Settings.ENVIRONMENT`` declares, and a value either
    source names is folded to lower case as ``Settings`` folds it and held
    to :data:`ENVIRONMENT_NAMES`. Raises ``ValueError`` for a name outside
    that set, including a blank one.
    """
    named = resolve_setting(ENVIRONMENT_SETTING)
    if named is None:
        return DEFAULT_ENVIRONMENT
    resolved = named.lower()
    if resolved not in ENVIRONMENT_NAMES:
        raise ValueError(
            "{0} must be one of {1}".format(
                ENVIRONMENT_SETTING, sorted(ENVIRONMENT_NAMES)
            )
        )
    return resolved


def read_bound(
    name: str,
    default: int,
    floor: int = DB_TIMEOUT_FLOOR_SECONDS,
    ceiling: int = DB_TIMEOUT_CEILING_SECONDS,
) -> int:
    """Return one bound resolved from the environment, or refuse it.

    ``default`` is returned when neither source names the setting. A
    value either source does name is held to :func:`validate_bound`, so a
    command refuses a value the application would refuse rather than
    running under a different one.
    """
    supplied = resolve_setting(name)
    if supplied is None:
        return default
    return validate_bound(name, supplied, floor, ceiling)


def session_options(statement_timeout_seconds: int) -> str:
    """Return the libpq ``options`` string a connection is opened with.

    The statement timeout is rendered in milliseconds.
    """
    return POSTGRESQL_SESSION_OPTIONS_TEMPLATE.format(
        statement_timeout_ms=(
            int(statement_timeout_seconds) * MILLISECONDS_PER_SECOND
        )
    )


def connect_args(
    url: str,
    connect_timeout_seconds: int,
    statement_timeout_seconds: int,
    tcp_user_timeout_seconds: int,
) -> Dict[str, Any]:
    """Return the driver arguments the named backend accepts.

    A PostgreSQL URL receives three bounds beside the UTC session:

    * ``options`` carries the session time zone and the server-side
      ``statement_timeout``, which cancels a statement running past it.
    * ``connect_timeout`` bounds one connection attempt. libpq waits
      indefinitely when the parameter is omitted or zero.
    * ``tcp_user_timeout``, in milliseconds, bounds how long an
      established socket may hold unacknowledged data before it is
      aborted.

    A SQLite URL receives :data:`SQLITE_CONNECT_ARGS`. Every other
    backend receives no argument.
    """
    if url.startswith(POSTGRESQL_SCHEMES):
        return {
            "options": session_options(statement_timeout_seconds),
            "connect_timeout": int(connect_timeout_seconds),
            "tcp_user_timeout": (
                int(tcp_user_timeout_seconds) * MILLISECONDS_PER_SECOND
            ),
        }
    if url.startswith(SQLITE_SCHEMES):
        return dict(SQLITE_CONNECT_ARGS)
    return {}
