"""Alembic migration environment for the apartment-finder-service.

The repository root reaches ``sys.path`` through ``prepend_sys_path`` in
``backend/alembic.ini``, which Alembic applies before this module is
imported. The ``backend.app.*`` imports below resolve from there.

Both of Alembic's modes are served. Online, a revision runs against a
connection and may inspect the schema it is altering. Offline --
``--sql`` -- a statement stream is produced with no database attached:
``op.get_bind()`` yields a stand-in that cannot be inspected and no
statement returns a result, so each revision emits its statements
unconditionally and checks no state. ``literal_binds`` is set below,
which is what carries a revision's bound values into the emitted
statements.

Two entries of ``config.attributes`` are read, and both are absent when
Alembic is driven from its command line:

* :data:`CONNECTION_ATTRIBUTE` -- an open connection the migrations run
  on. Absent, a connection is opened from the application engine and
  closed afterwards. Present, the connection is used as given and is left
  open, so its owner keeps control of the transaction it belongs to.
* :data:`CONFIGURE_LOGGER_ATTRIBUTE` -- whether the logging configuration
  in ``backend/alembic.ini`` is applied. Absent, it is applied.

"""

from logging.config import fileConfig

from alembic import context

from backend.app.core.config import settings
from backend.app.db.database import engine
from backend.app.db.models import Base

#: ``config.attributes`` key naming a connection to run the migrations on.
CONNECTION_ATTRIBUTE = "connection"

#: ``config.attributes`` key selecting whether the configuration file's
#: logging section is applied.
CONFIGURE_LOGGER_ATTRIBUTE = "configure_logger"

config = context.config

if (
    config.attributes.get(CONFIGURE_LOGGER_ATTRIBUTE, True)
    and config.config_file_name is not None
):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit the migration statements as SQL without connecting.

    The configured URL selects the dialect the statements are written
    for; no connection is opened to it. ``literal_binds`` renders each
    bound value into the statement text, so the stream is complete on
    its own.
    """
    context.configure(
        url=settings.DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


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
    """Run the migrations on the supplied or the application connection.

    The connection under :data:`CONNECTION_ATTRIBUTE` is used when one is
    supplied and is left open. Otherwise a connection is opened from the
    application engine and closed once the migrations have run. A
    revision reached either way may inspect the schema it is altering and
    may read the result of a statement it runs.
    """
    supplied = config.attributes.get(CONNECTION_ATTRIBUTE)
    if supplied is not None:
        _run_migrations(supplied)
        return

    with engine.connect() as connection:
        _run_migrations(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
