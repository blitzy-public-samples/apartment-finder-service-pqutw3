"""Database engine, session factory and the request-scoped session.

The engine opens every PostgreSQL connection with its session time zone
set to UTC, so a naive ``TIMESTAMP`` value written by the application is
read back as the same instant regardless of the zone the server is
configured with. The application writes timezone-aware UTC values, and
this setting is what makes the naive columns unambiguous on the way
back out.

``Base`` is re-exported from :mod:`backend.app.db.models` so that one
metadata registry serves the models, the Alembic environment and the
application.
"""

from typing import Any, Dict

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.config import settings
from backend.app.db.models import Base

__all__ = ["Base", "SessionLocal", "engine", "get_db"]

#: URL scheme prefixes served by the PostgreSQL driver.
POSTGRESQL_SCHEMES = ("postgresql://", "postgresql+")

#: libpq runtime parameters applied to every PostgreSQL connection.
POSTGRESQL_SESSION_OPTIONS = "-c timezone=utc"

#: URL scheme prefixes served by the SQLite driver.
SQLITE_SCHEMES = ("sqlite://", "sqlite+")

#: Driver arguments applied to every SQLite connection. The pool hands a
#: connection to one thread at a time, while a request-scoped session is
#: opened and closed on whichever worker thread serves each step, so the
#: driver's own single-thread check is lifted.
SQLITE_CONNECT_ARGS: Dict[str, Any] = {"check_same_thread": False}


def _connect_args(url: str) -> Dict[str, Any]:
    """Returns the driver arguments the configured backend accepts.

    A PostgreSQL URL receives :data:`POSTGRESQL_SESSION_OPTIONS` as its
    libpq ``options`` parameter, and a SQLite URL receives
    :data:`SQLITE_CONNECT_ARGS`. Every other backend receives no
    argument.
    """
    if url.startswith(POSTGRESQL_SCHEMES):
        return {"options": POSTGRESQL_SESSION_OPTIONS}
    if url.startswith(SQLITE_SCHEMES):
        return dict(SQLITE_CONNECT_ARGS)
    return {}


# hide_parameters omits the values bound into a statement from the text
# of any error the driver raises. The connect arguments pin a PostgreSQL
# session to UTC, so a naive timestamp read back is unambiguous.
engine = create_engine(
    settings.DATABASE_URL,
    hide_parameters=True,
    connect_args=_connect_args(settings.DATABASE_URL),
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """Yields one session for the duration of a request.

    The session is closed in every case, including when the handler
    raises.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
