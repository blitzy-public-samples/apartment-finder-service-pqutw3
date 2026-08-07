"""Alembic migration environment for the apartment-finder-service.

The repository root reaches ``sys.path`` through ``prepend_sys_path`` in
``backend/alembic.ini``, which Alembic applies before this module is
imported. The ``backend.app.*`` imports below resolve from there.
"""

from logging.config import fileConfig

from alembic import context

from backend.app.core.config import settings
from backend.app.db.database import engine
from backend.app.db.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit the migration statements as SQL without connecting."""
    context.configure(
        url=settings.DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run the migrations on a connection from the application engine."""
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
