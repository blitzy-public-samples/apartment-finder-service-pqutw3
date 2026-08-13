"""Alembic environment with bounded database connections and
redacted logging.
"""

import os
import sys

from alembic import context
from sqlalchemy import create_engine

from backend.app.core import db_contract
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

#: Setting this environment reads that has no default. It is the only
#: one.
DATABASE_URL_SETTING = db_contract.DATABASE_URL_SETTING

#: Setting naming the deployment environment, which decides whether a
#: local database scheme is accepted.
ENVIRONMENT_SETTING = db_contract.ENVIRONMENT_SETTING

#: Environment variable naming the file every setting is read from when
#: the process environment does not carry it. An empty value reads no
#: file.
ENV_FILE_VARIABLE = db_contract.ENV_FILE_VARIABLE

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

#: Message prefix of the failure raised when a resolved value is refused.
#: The reason follows it and names the rule rather than the value.
REFUSED_VALUE_PREFIX = "The migration environment refuses a value: "

#: URL scheme prefixes served by the PostgreSQL driver.
POSTGRESQL_SCHEMES = db_contract.POSTGRESQL_SCHEMES

#: Template of the libpq runtime parameters applied to every PostgreSQL
#: connection. ``timezone`` pins the session to UTC and
#: ``statement_timeout`` bounds how long one statement may run on the
#: server, expressed in milliseconds.
POSTGRESQL_SESSION_OPTIONS_TEMPLATE = (
    db_contract.POSTGRESQL_SESSION_OPTIONS_TEMPLATE
)

#: Number of milliseconds in one second.
MILLISECONDS_PER_SECOND = db_contract.MILLISECONDS_PER_SECOND

#: The connection bounds this environment reads, each with the default
#: the application declares for it. Every one has a default, so none of
#: them has to be supplied to a migration process. The statement bound is
#: the migration one: a revision's statements are schema changes, and the
#: request-path bound does not apply to them.
BOUND_SETTINGS = {
    "DB_CONNECT_TIMEOUT_SECONDS": (
        db_contract.DEFAULT_DB_CONNECT_TIMEOUT_SECONDS,
        db_contract.DB_TIMEOUT_CEILING_SECONDS,
    ),
    "DB_MIGRATION_STATEMENT_TIMEOUT_SECONDS": (
        db_contract.DEFAULT_DB_MIGRATION_STATEMENT_TIMEOUT_SECONDS,
        db_contract.DB_MIGRATION_TIMEOUT_CEILING_SECONDS,
    ),
    "DB_TCP_USER_TIMEOUT_SECONDS": (
        db_contract.DEFAULT_DB_TCP_USER_TIMEOUT_SECONDS,
        db_contract.DB_TIMEOUT_CEILING_SECONDS,
    ),
}

#: Setting carrying the bound on one migration statement.
STATEMENT_TIMEOUT_SETTING = "DB_MIGRATION_STATEMENT_TIMEOUT_SECONDS"

#: URL scheme prefixes served by the SQLite driver.
SQLITE_SCHEMES = db_contract.SQLITE_SCHEMES

#: Driver arguments applied to every SQLite connection.
SQLITE_CONNECT_ARGS = dict(db_contract.SQLITE_CONNECT_ARGS)

config = context.config

if config.attributes.get(CONFIGURE_LOGGER_ATTRIBUTE, True):
    configure_migration_logging()

target_metadata = Base.metadata


def _refuse(reason: str) -> "RuntimeError":
    """Return the failure raised for a value this environment refuses.

    The message carries :data:`REFUSED_VALUE_PREFIX` and the reason,
    which names the setting and the rule and never the value, so it can
    be rendered where a credential must not appear.
    """
    return RuntimeError(REFUSED_VALUE_PREFIX + reason)


def environment_name() -> str:
    """Return the deployment environment this run belongs to.

    The value is resolved from the same two sources as every other
    setting, and defaults to the one ``Settings.ENVIRONMENT`` declares. A
    name outside
    :data:`backend.app.core.db_contract.ENVIRONMENT_NAMES` raises
    ``RuntimeError``.
    """
    try:
        return db_contract.environment_name()
    except ValueError as refused:
        raise _refuse(str(refused)) from None


def database_url() -> str:
    """Return the database URL this environment runs against.

    The process environment is read first, then the environment file
    :data:`ENV_FILE_VARIABLE` names, and only the one setting
    :data:`DATABASE_URL_SETTING` is taken from either. Raises
    ``RuntimeError`` carrying :data:`MISSING_URL_MESSAGE` when neither
    source supplies a non-blank value.

    The resolved value is held to
    :func:`backend.app.core.db_contract.validate_database_url` under the
    environment :func:`environment_name` reports, so a target the
    application would refuse is refused here too. A refusal raises
    ``RuntimeError``, and neither message names a value.
    """
    supplied = db_contract.resolve_setting(DATABASE_URL_SETTING)
    if supplied is None:
        raise RuntimeError(MISSING_URL_MESSAGE)
    try:
        return db_contract.validate_database_url(
            supplied, environment_name()
        )
    except ValueError as refused:
        raise _refuse(
            "{0} {1}".format(DATABASE_URL_SETTING, refused)
        ) from None


def _bound(name: str) -> int:
    """Return one connection bound, in whole seconds.

    :data:`BOUND_SETTINGS` names the bound and carries the default the
    application declares for it together with its ceiling. The process
    environment is read first and then the environment file
    :data:`ENV_FILE_VARIABLE` names, which are the two sources the
    application's settings read, so both sides reach the same value. A
    value either source names is held to
    :func:`backend.app.core.db_contract.validate_bound`, so one the
    application would refuse raises ``RuntimeError`` here rather than
    being replaced by the default.
    """
    default, ceiling = BOUND_SETTINGS[name]
    try:
        return db_contract.read_bound(
            name,
            default,
            db_contract.DB_TIMEOUT_FLOOR_SECONDS,
            ceiling,
        )
    except ValueError as refused:
        raise _refuse(str(refused)) from None


def session_options() -> str:
    """Return the libpq ``options`` string a connection is opened with.

    The statement timeout is
    :data:`STATEMENT_TIMEOUT_SETTING`, rendered in milliseconds. It bounds
    one schema statement, so it is read from that setting rather than from
    the request-path bound
    :func:`backend.app.db.database.postgresql_session_options` renders.
    """
    return db_contract.session_options(_bound(STATEMENT_TIMEOUT_SETTING))


def connect_args(url: str):
    """Return driver arguments matching the application's database
    connection bounds.
    """
    return db_contract.connect_args(
        url,
        _bound("DB_CONNECT_TIMEOUT_SECONDS"),
        _bound(STATEMENT_TIMEOUT_SETTING),
        _bound("DB_TCP_USER_TIMEOUT_SECONDS"),
    )


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
