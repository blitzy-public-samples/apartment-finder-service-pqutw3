"""The database boundary is bounded in time and checked for liveness.

The database is an external system, and every wait on it is bounded:

* the libpq handshake, by the ``connect_timeout`` driver parameter
* the wait for a free pooled connection, by ``pool_timeout``
* the age of a pooled connection, by ``pool_recycle``

and a connection closed underneath the pool is replaced on checkout
rather than handed to a request handler, by ``pool_pre_ping``.

The cases below cover three things. First, that
:func:`backend.app.db.database._connect_args` and
:func:`backend.app.db.database._pool_args` return those bounds for a
PostgreSQL URL and return them from the settings rather than from a
literal. Second, that the engine the module builds carries them. Third,
that the two pool bounds behave as claimed, which is asserted against a
pool built from the same keywords rather than against a live server, so
the cases are deterministic and need no network.

The SQLite exclusion is asserted too, and asserted as a necessity: the
pool a SQLite URL resolves to rejects those keywords outright, so
returning them for every backend would stop the suite and the local
stack.
"""

import time

import pytest
import sqlalchemy
from sqlalchemy import create_engine, text
from sqlalchemy.exc import TimeoutError as PoolCheckoutTimeout
from sqlalchemy.pool import QueuePool

from backend.app.core.config import settings
from backend.app.db import database
from backend.app.db.database import _connect_args, _pool_args, engine

#: PostgreSQL URLs in both spellings the module accepts.
POSTGRESQL_URLS = (
    "postgresql://user:pw@db.internal:5432/apartment_finder",
    "postgresql+psycopg2://user:pw@db.internal:5432/apartment_finder",
)

#: URLs that must receive no pool keyword.
NON_POOLED_URLS = (
    "sqlite://",
    "sqlite:///./local.db",
    "sqlite+pysqlite:///./local.db",
    "mysql://user:pw@db.internal:3306/apartment_finder",
)

#: Pool keywords a PostgreSQL URL must carry.
POOL_KEYWORDS = ("pool_timeout", "pool_recycle", "pool_pre_ping")

#: Of those, the ones the pool a SQLite URL resolves to refuses outright.
#: The rest it accepts and acts on neither, so the exclusion covers both
#: a refusal and a no-op.
REFUSED_BY_THE_SQLITE_POOL = ("pool_timeout",)

#: Seconds a bounded checkout is given in the behavioural case. Small so
#: the case is quick, and measured against rather than assumed.
CHECKOUT_BOUND_SECONDS = 0.5

#: Seconds of slack allowed over the bound before the case fails.
CHECKOUT_SLACK_SECONDS = 5.0


def _bounded_pool_engine(**overrides):
    """Returns a single-connection engine carrying the pool bounds.

    The keywords are the ones :func:`_pool_args` produces, applied to an
    in-memory SQLite database through the same queueing pool a PostgreSQL
    URL resolves to, so the behaviour asserted is the pool's own.
    """
    keywords = dict(
        pool_timeout=CHECKOUT_BOUND_SECONDS,
        pool_recycle=settings.DB_POOL_RECYCLE_SECONDS,
        pool_pre_ping=True,
    )
    keywords.update(overrides)
    return create_engine(
        "sqlite://",
        poolclass=QueuePool,
        pool_size=1,
        max_overflow=0,
        **keywords
    )


def _dbapi_connection(connection):
    """Returns the driver connection behind a SQLAlchemy connection."""
    handle = connection.connection
    return getattr(handle, "dbapi_connection", None) or handle.connection


class TestTheHandshakeIsBounded:
    """A PostgreSQL connection attempt cannot wait without bound."""

    @pytest.mark.parametrize("url", POSTGRESQL_URLS)
    def test_a_postgresql_url_carries_a_connect_timeout(self, url):
        assert _connect_args(url)["connect_timeout"] == (
            settings.DB_CONNECT_TIMEOUT_SECONDS
        )

    @pytest.mark.parametrize("url", POSTGRESQL_URLS)
    def test_the_timezone_option_is_kept_alongside_it(self, url):
        """The bound is added to the session options, not instead of them."""
        assert _connect_args(url)["options"] == (
            database.POSTGRESQL_SESSION_OPTIONS
        )

    def test_the_bound_is_read_from_the_settings(self, monkeypatch):
        """The value is not a literal in the module."""
        monkeypatch.setattr(settings, "DB_CONNECT_TIMEOUT_SECONDS", 7)

        assert _connect_args(POSTGRESQL_URLS[0])["connect_timeout"] == 7

    def test_the_bound_is_a_positive_number_of_seconds(self):
        assert settings.DB_CONNECT_TIMEOUT_SECONDS >= 1

    @pytest.mark.parametrize("url", NON_POOLED_URLS[:3])
    def test_a_sqlite_url_carries_no_handshake_bound(self, url):
        """Opening a local file takes no handshake to bound."""
        assert "connect_timeout" not in _connect_args(url)

    def test_an_engine_accepts_the_postgresql_connect_arguments(self):
        """The arguments are ones the driver dialect accepts.

        Building the engine is the assertion: a keyword the driver does
        not accept is refused here rather than at first connect.
        """
        url = POSTGRESQL_URLS[0]

        built = create_engine(url, connect_args=_connect_args(url))

        assert built.dialect.name == "postgresql"


class TestThePoolIsBounded:
    """Waiting for a connection, and holding a stale one, are bounded."""

    @pytest.mark.parametrize("url", POSTGRESQL_URLS)
    @pytest.mark.parametrize("keyword", POOL_KEYWORDS)
    def test_a_postgresql_url_carries_every_pool_bound(self, url, keyword):
        assert keyword in _pool_args(url)

    @pytest.mark.parametrize("url", POSTGRESQL_URLS)
    def test_the_pool_bounds_are_read_from_the_settings(self, url):
        arguments = _pool_args(url)

        assert arguments["pool_timeout"] == (
            settings.DB_POOL_TIMEOUT_SECONDS
        )
        assert arguments["pool_recycle"] == (
            settings.DB_POOL_RECYCLE_SECONDS
        )
        assert arguments["pool_pre_ping"] is True

    @pytest.mark.parametrize("url", NON_POOLED_URLS)
    def test_every_other_backend_carries_no_pool_bound(self, url):
        assert _pool_args(url) == {}

    @pytest.mark.parametrize("keyword", REFUSED_BY_THE_SQLITE_POOL)
    def test_the_sqlite_exclusion_is_a_necessity(self, keyword):
        """A SQLite URL resolves to a pool that refuses this keyword.

        The exclusion is therefore load-bearing rather than tidiness:
        returning this bound for every backend would stop the local stack
        and this suite, both of which run on SQLite.
        """
        with pytest.raises(TypeError) as excinfo:
            create_engine("sqlite://", **{keyword: 5})

        assert keyword in str(excinfo.value)

    @pytest.mark.parametrize(
        "keyword", sorted(set(POOL_KEYWORDS) - set(REFUSED_BY_THE_SQLITE_POOL))
    )
    def test_the_remaining_bounds_are_accepted_but_inapplicable(
        self, keyword
    ):
        """The pool a SQLite URL resolves to holds one connection per thread.

        It takes these two keywords without complaint and acts on neither,
        so they are excluded for having no effect rather than for being
        refused. The case records which of the two reasons applies to
        which keyword, so a future change to the exclusion is made against
        the real constraint.
        """
        built = create_engine("sqlite://", **{keyword: 60})

        assert not isinstance(built.pool, QueuePool)


class TestTheEngineTheModuleBuilds:
    """The bounds reach the engine the application actually uses.

    The suite runs on ``sqlite://``, so the engine built here is the
    SQLite one and carries no pool bound. Each case therefore asserts
    against what the configured URL calls for rather than against
    PostgreSQL unconditionally, which keeps the case meaningful under a
    PostgreSQL configuration and honest under this one.
    """

    def test_the_engine_matches_what_the_configured_url_calls_for(self):
        expected = _pool_args(settings.DATABASE_URL)

        if "pool_pre_ping" in expected:
            assert engine.pool._pre_ping is True
            assert engine.pool._recycle == (
                settings.DB_POOL_RECYCLE_SECONDS
            )
            assert engine.pool._timeout == settings.DB_POOL_TIMEOUT_SECONDS
        else:
            assert not isinstance(engine.pool, QueuePool)

    def test_a_postgresql_configuration_produces_a_bounded_engine(self):
        """The bounds are asserted on an engine built the module's way.

        The module hands ``_connect_args`` and ``_pool_args`` to
        ``create_engine`` for whichever URL is configured. This builds one
        the same way for a PostgreSQL URL, so the bounds are asserted on
        the engine a deployed configuration produces rather than on the
        SQLite engine this suite runs against.
        """
        url = POSTGRESQL_URLS[0]

        built = create_engine(
            url,
            hide_parameters=True,
            connect_args=_connect_args(url),
            **_pool_args(url)
        )

        assert built.pool._pre_ping is True
        assert built.pool._recycle == settings.DB_POOL_RECYCLE_SECONDS
        assert built.pool._timeout == settings.DB_POOL_TIMEOUT_SECONDS
        assert built.hide_parameters is True

    def test_the_engine_hides_bound_parameters_from_errors(self):
        """The bounds are added without dropping the existing setting."""
        assert engine.hide_parameters is True

    def test_the_session_factory_is_bound_to_that_engine(self):
        assert database.SessionLocal.kw["bind"] is engine

    def test_the_module_publishes_the_same_declarative_base(self):
        from backend.app.db.models import Base

        assert database.Base is Base


class TestTheBoundsBehaveAsClaimed:
    """The two pool bounds are measured, not assumed."""

    def test_a_saturated_pool_refuses_rather_than_queueing(self):
        """A checkout with no connection free is refused after the wait."""
        bounded = _bounded_pool_engine()
        held = bounded.connect()
        started = time.monotonic()
        try:
            with pytest.raises(PoolCheckoutTimeout):
                bounded.connect()
        finally:
            elapsed = time.monotonic() - started
            held.close()
            bounded.dispose()

        assert elapsed >= CHECKOUT_BOUND_SECONDS
        assert elapsed < CHECKOUT_BOUND_SECONDS + CHECKOUT_SLACK_SECONDS

    def test_a_connection_closed_underneath_the_pool_is_replaced(self):
        """A dead pooled connection is replaced instead of being served.

        The driver connection is closed while the pool believes it is
        usable, which is what an idle timeout or a failover does. The
        liveness check on checkout must notice and hand back a working
        connection.
        """
        bounded = _bounded_pool_engine()
        try:
            first = bounded.connect()
            driver_connection = _dbapi_connection(first)
            first.close()
            driver_connection.close()

            second = bounded.connect()
            try:
                assert second.execute(text("select 1")).scalar() == 1
            finally:
                second.close()
        finally:
            bounded.dispose()

    def test_the_liveness_check_is_what_makes_that_work(self):
        """Without the check the dead connection is served and fails.

        This is the negative half of the case above: it establishes that
        the recovery is produced by ``pool_pre_ping`` rather than by the
        pool discarding the connection for some other reason.
        """
        unchecked = _bounded_pool_engine(pool_pre_ping=False)
        try:
            first = unchecked.connect()
            driver_connection = _dbapi_connection(first)
            first.close()
            driver_connection.close()

            with pytest.raises(sqlalchemy.exc.SQLAlchemyError):
                second = unchecked.connect()
                second.execute(text("select 1"))
        finally:
            unchecked.dispose()
