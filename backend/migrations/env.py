"""Alembic migration environment for the apartment-finder-service.

The repository root reaches ``sys.path`` through ``prepend_sys_path`` in
``backend/alembic.ini``, which Alembic applies before this module is
imported. The ``backend.app.*`` imports below resolve from there.

**This environment reads no setting that has no default beside the
database URL.** It resolves ``DATABASE_URL`` itself -- from the process
environment, then from the environment file :data:`ENV_FILE_VARIABLE`
names, then from ``.env`` at the repository root -- and builds its own
engine from it. It does not import :mod:`backend.app.core.config`, so
applying a revision needs neither the token-signing key nor any provider
credential, and a process that runs migrations may be given the database
credential alone. The mapped metadata comes from
:mod:`backend.app.db.models`, which reads no setting.

The three connection bounds :func:`connect_args` applies are read from
the same two sources, each with the default the application declares, so
this environment reaches the database on the terms the application does
without importing the application's settings to get there. None of the
three names a credential and none is required, so reading them adds
nothing a migration process must be given.

Logging is installed by
:func:`backend.app.core.logging.configure_migration_logging`, so every
record a revision writes is rendered as redacted JSON by the same handler
the application uses and reaches no handler installed elsewhere.
``backend/alembic.ini`` declares no logging sections and installs no
handler of its own.

Both of Alembic's modes are served. Online, a revision runs against a
connection and may inspect the schema it is altering. Offline --
``--sql`` -- a statement stream is produced with no database attached:
``op.get_bind()`` yields a stand-in that cannot be inspected and no
statement returns a result, so each revision emits its statements
unconditionally and checks no state. ``literal_binds`` is set below,
which is what carries a revision's bound values into the emitted
statements.

A statement stream therefore carries every value its statements match on
or write, inline. :data:`OFFLINE_BANNER` is emitted ahead of it saying
so, and setting :data:`SQL_OUTPUT_VARIABLE` writes the stream to the
named file, created with owner-only permissions, instead of to standard
output. While the stream itself is on standard output the log records are
moved to standard error, so the two are never interleaved and the stream
can be redirected into a file on its own.

Two entries of ``config.attributes`` are read, and both are absent when
Alembic is driven from its command line:

* :data:`CONNECTION_ATTRIBUTE` -- an open connection the migrations run
  on. Absent, a connection is opened from an engine built here and closed
  afterwards. Present, the connection is used as given and is left open,
  so its owner keeps control of the transaction it belongs to.
* :data:`CONFIGURE_LOGGER_ATTRIBUTE` -- whether the governed logging
  configuration is installed. Absent, it is installed.

"""

import os
import sys

from alembic import context
from dotenv import dotenv_values
from sqlalchemy import create_engine

from backend.app.core.logging import (
    configure_migration_logging,
    redirect_log_stream,
)
from backend.app.db.models import Base

#: ``config.attributes`` key naming a connection to run the migrations on.
CONNECTION_ATTRIBUTE = "connection"

#: ``config.attributes`` key selecting whether the governed logging
#: configuration is installed.
CONFIGURE_LOGGER_ATTRIBUTE = "configure_logger"

#: Setting this environment reads. It is the only one.
DATABASE_URL_SETTING = "DATABASE_URL"

#: Environment variable naming the file the setting is read from when the
#: process environment does not carry it. An empty value reads no file.
ENV_FILE_VARIABLE = "ENV_FILE"

#: Environment file read when :data:`ENV_FILE_VARIABLE` is absent,
#: resolved from this file's own path rather than from the working
#: directory.
DEFAULT_ENV_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)
    ))),
    ".env",
)

#: Environment variable naming the file an offline statement stream is
#: written to. Absent, the stream is written to standard output.
SQL_OUTPUT_VARIABLE = "ALEMBIC_SQL_OUTPUT"

#: Permission bits an offline statement stream file is created with.
SQL_OUTPUT_MODE = 0o600

#: Comment emitted ahead of an offline statement stream.
OFFLINE_BANNER = (
    "-- Generated statement stream. Every bound value is rendered inline,\n"
    "-- so this stream carries the values its statements match on and\n"
    "-- write. Handle it as sensitive material: restrict its permissions,\n"
    "-- do not commit it, and delete it once it has been applied.\n"
)

#: Message of the failure raised when the setting is absent or blank.
MISSING_URL_MESSAGE = (
    "DATABASE_URL is not set. The migration environment reads it from the "
    "process environment, from the file named by ENV_FILE, or from .env "
    "at the repository root."
)

#: URL scheme prefixes served by the PostgreSQL driver.
POSTGRESQL_SCHEMES = ("postgresql://", "postgresql+")

#: Template of the libpq runtime parameters applied to every PostgreSQL
#: connection. ``timezone`` pins the session to UTC and
#: ``statement_timeout`` bounds how long one statement may run on the
#: server, expressed in milliseconds.
POSTGRESQL_SESSION_OPTIONS_TEMPLATE = (
    "-c timezone=utc -c statement_timeout={statement_timeout_ms}"
)

#: Number of milliseconds in one second.
MILLISECONDS_PER_SECOND = 1000

#: The connection bounds this environment reads, each with the default
#: the application declares for it. Every one has a default, so none of
#: them has to be supplied to a migration process.
BOUND_SETTINGS = {
    "DB_CONNECT_TIMEOUT_SECONDS": 3,
    "DB_STATEMENT_TIMEOUT_SECONDS": 3,
    "DB_TCP_USER_TIMEOUT_SECONDS": 4,
}

#: URL scheme prefixes served by the SQLite driver.
SQLITE_SCHEMES = ("sqlite://", "sqlite+")

#: Driver arguments applied to every SQLite connection.
SQLITE_CONNECT_ARGS = {"check_same_thread": False}

config = context.config

if config.attributes.get(CONFIGURE_LOGGER_ATTRIBUTE, True):
    configure_migration_logging()

target_metadata = Base.metadata


def _env_file_path():
    """Return the environment file to read, or ``None`` to read none.

    An ``ENV_FILE`` value is used exactly as given, and an empty one
    selects no file at all. Absent, :data:`DEFAULT_ENV_FILE` is named.
    """
    named = os.environ.get(ENV_FILE_VARIABLE)
    if named is None:
        return DEFAULT_ENV_FILE
    if not named.strip():
        return None
    return named


def database_url() -> str:
    """Return the database URL this environment runs against.

    The process environment is read first, then the environment file
    :func:`_env_file_path` names, and only the one setting
    :data:`DATABASE_URL_SETTING` is taken from either. Raises
    ``RuntimeError`` carrying :data:`MISSING_URL_MESSAGE` when neither
    source supplies a non-blank value; the message names no value.
    """
    supplied = os.environ.get(DATABASE_URL_SETTING)
    if supplied and supplied.strip():
        return supplied.strip()

    path = _env_file_path()
    if path and os.path.isfile(path):
        values = dotenv_values(path)
        from_file = values.get(DATABASE_URL_SETTING)
        if from_file and from_file.strip():
            return from_file.strip()

    raise RuntimeError(MISSING_URL_MESSAGE)


def _bound(name: str) -> int:
    """Return one connection bound, in whole seconds.

    :data:`BOUND_SETTINGS` names the bound and carries the default the
    application declares for it. The process environment is read first
    and then the environment file :func:`_env_file_path` names, which are
    the two sources the application's settings read, so both sides reach
    the same value. A value that is absent, blank or not a whole number
    leaves the default in place; the application refuses such a value at
    startup, so no run that could compare the two mappings reaches this
    fallback.
    """
    default = BOUND_SETTINGS[name]
    supplied = os.environ.get(name)
    if supplied is None:
        path = _env_file_path()
        if path and os.path.isfile(path):
            supplied = dotenv_values(path).get(name)
    if supplied is None or not str(supplied).strip():
        return default
    try:
        return int(str(supplied).strip())
    except ValueError:
        return default


def session_options() -> str:
    """Return the libpq ``options`` string a connection is opened with.

    The statement timeout is rendered in milliseconds, matching
    :func:`backend.app.db.database.postgresql_session_options`.
    """
    return POSTGRESQL_SESSION_OPTIONS_TEMPLATE.format(
        statement_timeout_ms=(
            _bound("DB_STATEMENT_TIMEOUT_SECONDS") * MILLISECONDS_PER_SECOND
        )
    )


def connect_args(url: str):
    """Return the driver arguments the configured backend accepts.

    The mapping is the one
    :func:`backend.app.db.database._connect_args` builds for the same
    URL; ``backend/tests/security/test_migration_revisions.py`` asserts
    the two agree, so this environment reaches the database on the same
    terms the application does without importing the application's
    settings to get there. A PostgreSQL URL therefore carries the UTC
    session and the server-side statement timeout, a bound on one
    connection attempt, and a bound on how long an established socket may
    hold unacknowledged data.
    """
    if url.startswith(POSTGRESQL_SCHEMES):
        return {
            "options": session_options(),
            "connect_timeout": _bound("DB_CONNECT_TIMEOUT_SECONDS"),
            "tcp_user_timeout": (
                _bound("DB_TCP_USER_TIMEOUT_SECONDS")
                * MILLISECONDS_PER_SECOND
            ),
        }
    if url.startswith(SQLITE_SCHEMES):
        return dict(SQLITE_CONNECT_ARGS)
    return {}


def _migration_engine(url: str):
    """Return an engine on ``url`` that hides bound values from errors."""
    return create_engine(
        url, hide_parameters=True, connect_args=connect_args(url)
    )


def _offline_output_buffer():
    """Return the stream an offline run writes to, or ``None``.

    ``None`` leaves Alembic writing to standard output. A path in
    :data:`SQL_OUTPUT_VARIABLE` is opened for writing with
    :data:`SQL_OUTPUT_MODE`, so the file is readable by its owner alone.
    """
    named = os.environ.get(SQL_OUTPUT_VARIABLE)
    if not named or not named.strip():
        return None
    path = named.strip()
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SQL_OUTPUT_MODE
    )
    return os.fdopen(descriptor, "w", encoding="utf-8")


def run_migrations_offline() -> None:
    """Emit the migration statements as SQL without connecting.

    The resolved URL selects the dialect the statements are written for;
    no connection is opened to it. ``literal_binds`` renders each bound
    value into the statement text, so the stream is complete on its own,
    and :data:`OFFLINE_BANNER` precedes it saying what that means.
    """
    buffer = _offline_output_buffer()
    if buffer is None:
        redirect_log_stream(sys.stderr)
    try:
        context.configure(
            url=database_url(),
            target_metadata=target_metadata,
            literal_binds=True,
            dialect_opts={"paramstyle": "named"},
            compare_type=True,
            output_buffer=buffer,
        )
        context.get_context().impl.static_output(OFFLINE_BANNER)

        with context.begin_transaction():
            context.run_migrations()
    finally:
        if buffer is not None:
            buffer.close()


def _run_migrations(connection) -> None:
    """Run the migrations on ``connection`` inside one transaction."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run the migrations on the supplied or a locally built connection.

    The connection under :data:`CONNECTION_ATTRIBUTE` is used when one is
    supplied and is left open. Otherwise an engine is built from
    :func:`database_url` and its connection is closed once the migrations
    have run. A revision reached either way may inspect the schema it is
    altering and may read the result of a statement it runs.
    """
    supplied = config.attributes.get(CONNECTION_ATTRIBUTE)
    if supplied is not None:
        _run_migrations(supplied)
        return

    engine = _migration_engine(database_url())
    try:
        with engine.connect() as connection:
            _run_migrations(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
