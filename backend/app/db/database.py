"""Database engine, session factory, and request-scoped session
dependency.
"""

from typing import Any, Dict

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core import db_contract
from backend.app.core.config import settings
from backend.app.db.models import Base

# POSTGRESQL_SESSION_OPTIONS is served by the module __getattr__ at the
# foot of this file and is not bound at import, so it appears here without
# a definition above.
__all__ = [  # noqa: F822
    "Base",
    "POSTGRESQL_SESSION_OPTIONS",
    "SessionLocal",
    "engine",
    "get_db",
    "postgresql_session_options",
]

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

#: URL scheme prefixes served by the SQLite driver.
SQLITE_SCHEMES = db_contract.SQLITE_SCHEMES

#: Driver arguments applied to every SQLite connection. The pool hands a
#: connection to one thread at a time, while a request-scoped session is
#: opened and closed on whichever worker thread serves each step, so the
#: driver's own single-thread check is lifted.
SQLITE_CONNECT_ARGS: Dict[str, Any] = dict(
    db_contract.SQLITE_CONNECT_ARGS
)


def postgresql_session_options() -> str:
    """Returns the libpq ``options`` string a connection is opened with.

    The statement timeout is rendered in milliseconds from
    ``settings.DB_STATEMENT_TIMEOUT_SECONDS``.
    """
    return db_contract.session_options(
        settings.DB_STATEMENT_TIMEOUT_SECONDS
    )


def __getattr__(name: str) -> Any:
    """Resolve POSTGRESQL_SESSION_OPTIONS dynamically from the current
    settings.
    """
    if name == "POSTGRESQL_SESSION_OPTIONS":
        return postgresql_session_options()
    raise AttributeError(
        "module %r has no attribute %r" % (__name__, name)
    )


def _connect_args(url: str) -> Dict[str, Any]:
    """Returns the driver arguments the configured backend accepts.

    A PostgreSQL URL receives three bounds beside the UTC session:

    * ``options`` carries the session time zone and the server-side
      ``statement_timeout``, which cancels a statement running past it.
    * ``connect_timeout`` bounds one connection attempt. libpq waits
      indefinitely when the parameter is omitted or zero.
    * ``tcp_user_timeout``, in milliseconds, bounds how long an
      established socket may hold unacknowledged data before it is
      aborted, so a caller holding a pooled connection to a server that
      has stopped answering does not wait on the socket indefinitely.

    A SQLite URL receives :data:`SQLITE_CONNECT_ARGS`. Every other
    backend receives no argument. The mapping is built by
    :func:`backend.app.core.db_contract.connect_args`, which the
    migration environment and the administrative command build theirs
    with.
    """
    return db_contract.connect_args(
        url,
        settings.DB_CONNECT_TIMEOUT_SECONDS,
        settings.DB_STATEMENT_TIMEOUT_SECONDS,
        settings.DB_TCP_USER_TIMEOUT_SECONDS,
    )


def _pool_args(url: str) -> Dict[str, Any]:
    """Returns the pool bounds the configured backend accepts.

    A PostgreSQL URL receives a checkout timeout, a recycle age and
    ``pool_pre_ping``. Every other backend receives no argument: the pool a
    SQLite URL resolves to refuses ``pool_timeout`` and acts on neither of
    the other two.

    ``pool_timeout`` bounds how long a request waits for a free
    connection, ``pool_recycle`` discards a connection older than the
    configured age, and ``pool_pre_ping`` issues a liveness check on
    checkout, so a connection an idle timeout or a failover closed
    underneath the pool is replaced.
    """
    if url.startswith(POSTGRESQL_SCHEMES):
        return {
            "pool_timeout": settings.DB_POOL_TIMEOUT_SECONDS,
            "pool_recycle": settings.DB_POOL_RECYCLE_SECONDS,
            "pool_pre_ping": True,
        }
    return {}


# hide_parameters omits the values bound into a statement from the text
# of any error the driver raises. The connect arguments pin a PostgreSQL
# session to UTC, under which a naive timestamp read back is unambiguous,
# and bound both the connection attempt and any single statement.
engine = create_engine(
    settings.DATABASE_URL,
    hide_parameters=True,
    connect_args=_connect_args(settings.DATABASE_URL),
    **_pool_args(settings.DATABASE_URL)
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
