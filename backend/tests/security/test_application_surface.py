"""Regression tests for the application surface and its error records.

The cases here cover three things the assembled application previously
gave away or spent without limit: an interactive schema published to
anyone in every environment, a chunked body replayed in a way whose cost
grew with the square of the number of chunks and with no bound on that
number, and an error record carrying a traceback whose database frames
hold the values bound into the statement being run.
"""

import inspect
import logging
import os
import re
import subprocess
import sys
import threading
import time
import uuid

import anyio
import pytest
from conftest import CLIENT_BASE_URL, REPO_ROOT
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import TimeoutError as PoolTimeout
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app import main as main_module
from backend.app.core import authorization
from backend.app.core.authorization import (
    audit_failure_count,
    reset_audit_failure_count,
)
from backend.app.core.config import LOCAL_ENVIRONMENT, settings
from backend.app.core.rate_limit import (
    RATE_LIMIT_HEADERS,
    RETRY_AFTER_HEADER,
)
from backend.app.schema.user import UserCreate, UserLogin
from backend.app.db import database as database_module
from backend.app.core.logging import (
    BASE_LOGGER_NAME,
    SIGNAL_FIELD,
    SPAN_ID_FIELD,
    TRACE_ID_FIELD,
    configure_logging,
    current_trace_context,
    parse_traceparent,
    reset_logging_failure_count,
)
from backend.app.db.database import engine, get_db

# Imported here rather than inside the test that uses it: the first
# ``get_logger`` call a module makes settles handler governance, which
# removes every handler on the governed logger that is not the redacting
# one -- the collecting fixture below included.
from backend.app.tasks import listing_updater  # noqa: E402

# Addresses that would appear in a traceback of a failing statement.
PII_ADDRESS = "resident@example.com"

PII_STREET = "42 Sensitive Street, Apartment 9"

#: Both of the above, as the set every record is asserted not to carry.
PII_VALUES = (PII_ADDRESS, PII_STREET)

#: Seconds the driver of the unreachable engine waits for a connection.
#: The address is a port nothing listens on, so the refusal is immediate
#: on a loopback interface; the bound is what stops a filtered network
#: from turning the refusal into a stall.
UNREACHABLE_CONNECT_TIMEOUT_SECONDS = 2

#: Attribute of ``Base.metadata`` that would create the schema at import.
SCHEMA_CREATION_ATTRIBUTE = "create_all"

#: Name of the installed cross-origin middleware.
CORS_MIDDLEWARE_NAME = "CORSMiddleware"

#: URL whose pool carries the two size bounds, so the admitted count is
#: read from it. It names a host nothing resolves: no case here opens a
#: connection, only builds the figures the bounds produce.
POOLED_URL = "postgresql://user:pw@db.internal:5432/apartment_finder"

#: Seconds a holding caller waits before releasing itself, so a case that
#: fails before releasing it still ends.
HELD_THREAD_TIMEOUT_SECONDS = 30.0

#: Seconds the liveness route is allowed while the gate is saturated. A
#: route the gate held would instead wait the allowance below.
LIVENESS_BUDGET_SECONDS = 10.0

#: Route of the admission probe that stays inside the router until it is
#: released, so a caller can saturate the gate on demand.
GATED_HOLD_PATH = "/hold"

#: Route of the admission probe that answers at once.
GATED_QUICK_PATH = "/quick"

#: Route of the admission probe that raises, so the slot it took is
#: observed being given back.
GATED_FAILING_PATH = "/fails"

#: Route of the admission probe that reports which bound object served
#: it, so two event loops are seen holding two.
GATED_LIMITER_PATH = "/limiter"

#: Seconds a gated request may wait for a slot in the cases that expect
#: every caller to be admitted. It is far longer than any route here
#: holds one, so a refusal in those cases is a real failure.
GATE_WAIT_SECONDS = 5.0

#: Seconds a gated request may wait for a slot in the cases that expect a
#: refusal, kept short so the refusal is prompt.
GATE_REFUSAL_WAIT_SECONDS = 0.2

#: Seconds between readings while waiting for the router to fill.
POLL_INTERVAL_SECONDS = 0.01

#: Seconds an extra caller is watched for while the gate is already full,
#: which is how long the crowd inside is asserted not to grow.
CROWD_OBSERVATION_SECONDS = 0.5

#: The value that must never appear in any cross-origin allowlist or in
#: any cross-origin response header, because it is what a credentialed
#: response may not be shared under.
CORS_WILDCARD = "*"

#: An origin outside ``settings.ALLOWED_ORIGINS``.
DISALLOWED_ORIGIN = "http://evil.example.com"

#: A method outside :data:`main_module.CORS_ALLOW_METHODS`.
DISALLOWED_METHOD = "DELETE"

#: A request header outside :data:`main_module.CORS_ALLOW_HEADERS`.
DISALLOWED_HEADER = "X-Sneaky-Header"

#: A method inside the allowed set, used as the preflight subject.
PREFLIGHT_METHOD = "POST"

#: Route the preflight cases negotiate against.
PREFLIGHT_PATH = "/listings/"

#: Request headers a browser sends on a preflight.
PREFLIGHT_METHOD_HEADER = "Access-Control-Request-Method"

PREFLIGHT_HEADERS_HEADER = "Access-Control-Request-Headers"

#: Response header naming the methods a preflight approves.
CORS_ALLOW_METHODS_HEADER = "Access-Control-Allow-Methods"

#: Response header naming the request headers a preflight approves.
CORS_ALLOW_HEADERS_HEADER = "Access-Control-Allow-Headers"

#: Response header naming the response headers a caller's code may read.
CORS_EXPOSE_HEADERS_HEADER = "Access-Control-Expose-Headers"

#: Status a request refused by its rate limit is answered with.
TOO_MANY_REQUESTS = 429

#: Address the throttle case registers with. The body it is sent in is
#: refused by the request contract, so no account is ever created.
REFUSED_ADDRESS = "throttle-surface@example.com"

#: Module whose import must not create the schema.
APPLICATION_MODULE = "backend.app.main"

#: Message the stand-in raises when the schema creation is reached.
SCHEMA_CREATION_MESSAGE = (
    "the application created the schema at import time"
)

#: Printed by the child interpreter once it has imported the application
#: and served one request without the creation having been reached.
NO_DDL_CONFIRMATION = "no schema was created"

#: Seconds the child interpreter is allowed.
NO_DDL_TIMEOUT_SECONDS = 180.0

#: Program the child interpreter runs. It replaces the schema creation
#: with a stand-in that raises, then imports the application, enters its
#: lifespan through a client and serves one liveness request.
NO_DDL_PROGRAM = """
import sys

from backend.app.db.models import Base


def refuse(*arguments, **keywords):
    raise AssertionError({message!r})


Base.metadata.create_all = refuse

from backend.app.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

with TestClient(app, base_url={base_url!r}) as client:
    answered = client.get("/health")

if answered.status_code != 200:
    sys.stderr.write(
        "the liveness route answered %s\\n" % answered.status_code
    )
    raise SystemExit(1)

print({confirmation!r})
""".format(
    message=SCHEMA_CREATION_MESSAGE,
    confirmation=NO_DDL_CONFIRMATION,
    base_url=CLIENT_BASE_URL,
)


def _values_in_records(collected, values):
    """Returns each of ``values`` a record carries anywhere.

    Every attribute of every record is rendered, together with the
    formatted message, so a value reaching a structured field is found as
    well as one reaching the message text.
    """
    found = []
    for value in values:
        for record in collected:
            rendered = repr(vars(record))
            try:
                message = record.getMessage()
            except Exception:  # pragma: no cover - defensive
                message = ""
            if value in rendered or value in message:
                found.append(value)
                break
    return found


@pytest.fixture
def records():
    """Collects every record the application logger emits.

    Handler governance is settled first, because it removes every handler
    on the governed logger that is not the redacting one -- this collector
    included -- and it runs on the first :func:`get_logger` call any
    module under test makes.
    """
    configure_logging()
    collected = []

    class Collector(logging.Handler):
        def emit(self, record):
            collected.append(record)

    handler = Collector(level=logging.DEBUG)
    logger = logging.getLogger(BASE_LOGGER_NAME)
    logger.addHandler(handler)
    try:
        yield collected
    finally:
        logger.removeHandler(handler)


class TestDocumentationSurface:
    """The schema and its viewers are published only in local runs."""

    DOC_PATHS = (
        "/docs",
        "/redoc",
        "/openapi.json",
        "/docs/oauth2-redirect",
    )

    def test_publication_follows_the_environment(self):
        assert main_module.DOCUMENTATION_ENABLED == (
            settings.ENVIRONMENT == LOCAL_ENVIRONMENT
        )

    def test_the_application_is_wired_to_that_decision(self):
        if main_module.DOCUMENTATION_ENABLED:
            assert main_module.app.docs_url == main_module.DOCS_PATH
            assert main_module.app.redoc_url == main_module.REDOC_PATH
            assert (
                main_module.app.openapi_url == main_module.OPENAPI_PATH
            )
        else:
            assert main_module.app.docs_url is None
            assert main_module.app.redoc_url is None
            assert main_module.app.openapi_url is None

    def test_a_deployed_application_publishes_none_of_them(self):
        """The arguments used when publication is off hide all four.

        ``/docs/oauth2-redirect`` is registered by the documentation
        viewer rather than declared, so it is asserted here too.
        """
        deployed = FastAPI(
            docs_url=None, redoc_url=None, openapi_url=None
        )
        with TestClient(deployed) as client:
            for path in self.DOC_PATHS:
                assert client.get(path).status_code == 404

    def test_the_anonymous_surface_is_the_authorized_one(self):
        """Only the routes the plan admits anonymously are reachable.

        Liveness, readiness, registration, login, the public listings
        read and the signature-checked webhook are the admitted set;
        when publication is off the documentation routes are not part of
        it.
        """
        declared = set()
        for route in main_module.app.routes:
            path = getattr(route, "path", None)
            if path:
                declared.add(path)
        if not main_module.DOCUMENTATION_ENABLED:
            for path in self.DOC_PATHS:
                assert path not in declared
        assert "/health" in declared
        assert main_module.READINESS_PATH in declared
        assert "/auth/login" in declared


@pytest.fixture
def unreachable_client():
    """Yields a client whose readiness session reaches no database.

    The engine addresses a port nothing listens on, so the probe
    statement raises the same class of error a stopped database raises.
    No credential is written into the URL, and the driver is given a
    connect timeout of :data:`UNREACHABLE_CONNECT_TIMEOUT_SECONDS` so the
    refusal is bounded rather than left to the platform's own default,
    which on a filtered network is tens of seconds.
    """
    down = create_engine(
        "postgresql://127.0.0.1:1/unreachable",
        connect_args={
            "connect_timeout": UNREACHABLE_CONNECT_TIMEOUT_SECONDS
        },
    )

    def override_get_db():
        session = Session(bind=down)
        try:
            yield session
        finally:
            session.close()

    main_module.app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(
            main_module.app,
            base_url=CLIENT_BASE_URL,
            raise_server_exceptions=False,
        ) as opened:
            yield opened
    finally:
        main_module.app.dependency_overrides.clear()
        down.dispose()


class TestReadinessProbe:
    """The readiness route reports whether the database can be read.

    The liveness route answers unconditionally, so on its own it cannot
    distinguish a process that is serving from one whose database is
    unusable. These cases cover that distinction in both directions and
    assert the refusal gives nothing away.
    """

    def test_a_reachable_database_answers_ready(self, client):
        response = client.get(main_module.READINESS_PATH)

        assert response.status_code == 200
        assert response.json() == {
            "status": main_module.READINESS_STATUS
        }

    def test_an_unreachable_database_is_answered_unavailable(
        self, unreachable_client
    ):
        response = unreachable_client.get(main_module.READINESS_PATH)

        assert response.status_code == 503
        assert response.json() == {
            "status": main_module.NOT_READY_STATUS
        }

    def test_liveness_still_answers_while_readiness_refuses(
        self, unreachable_client
    ):
        """One process, two probes, two different reports."""
        liveness = unreachable_client.get("/health")
        readiness = unreachable_client.get(main_module.READINESS_PATH)

        assert liveness.status_code == 200
        assert liveness.json() == {"status": main_module.HEALTH_STATUS}
        assert readiness.status_code == 503

    def test_the_refusal_names_no_internal_detail(
        self, unreachable_client
    ):
        """The body carries the outcome and nothing about the cause."""
        response = unreachable_client.get(main_module.READINESS_PATH)

        assert set(response.json()) == {"status"}

        body = response.text.lower()
        for leaked in (
            "select",
            "psycopg2",
            "sqlalchemy",
            "traceback",
            "operationalerror",
            "127.0.0.1",
            "unreachable",
            "backend",
        ):
            assert leaked not in body, leaked

    def test_the_refusal_carries_the_protective_headers(
        self, unreachable_client
    ):
        """A refused probe is still a governed response."""
        response = unreachable_client.get(main_module.READINESS_PATH)

        for header, value in main_module.SECURITY_HEADERS.items():
            assert response.headers.get(header) == value

    def test_the_refusal_is_recorded_through_the_logger(
        self, unreachable_client, records
    ):
        """The cause is recorded rather than returned."""
        response = unreachable_client.get(main_module.READINESS_PATH)
        assert response.status_code == 503

        matching = [
            record
            for record in records
            if record.getMessage()
            == main_module.READINESS_FAILURE_MESSAGE
        ]

        assert matching, [record.getMessage() for record in records]
        recorded = matching[0]
        assert recorded.levelno == logging.ERROR
        assert getattr(recorded, "exception_type", "")
        assert not recorded.exc_info


class TestTheReadinessProbeIsBounded:
    """The probe reads the database, so its cost is capped four ways.

    The route is reachable without a credential, so an unbounded read
    behind it is work any caller can spend on the service's behalf --
    and it is spent hardest during the very outage the probe exists to
    report. These cases assert each cap independently: one outcome is
    reused, one caller at a time reads, the read carries a transaction
    bound where the dialect supports one, and the route counts its
    requests.
    """

    def test_one_outcome_serves_every_probe_in_its_window(
        self, client, monkeypatch
    ):
        """A burst costs one read, not one read each."""
        reads = []
        original = main_module._read_database
        monkeypatch.setattr(
            main_module,
            "_read_database",
            lambda db: (reads.append(db), original(db))[1],
        )

        answers = [
            client.get(main_module.READINESS_PATH) for _ in range(5)
        ]

        assert [answer.status_code for answer in answers] == [200] * 5
        assert len(reads) == 1

    def test_a_lapsed_window_reads_the_database_again(
        self, client, monkeypatch
    ):
        """The report is current: a stale outcome is not reused."""
        reads = []
        original = main_module._read_database
        monkeypatch.setattr(
            main_module,
            "_read_database",
            lambda db: (reads.append(db), original(db))[1],
        )
        monkeypatch.setattr(
            main_module.settings, "READINESS_CACHE_SECONDS", 0.01
        )

        assert client.get(main_module.READINESS_PATH).status_code == 200
        time.sleep(0.05)
        assert client.get(main_module.READINESS_PATH).status_code == 200

        assert len(reads) == 2

    def test_only_one_caller_at_a_time_reads_the_database(
        self, client, monkeypatch
    ):
        """A probe arriving mid-read answers without a second read.

        The guard is held for the length of the read, so the number of
        connections this route holds never grows with the number of
        callers. Holding it here stands in for that in-flight read.
        """
        reads = []
        original = main_module._read_database
        monkeypatch.setattr(
            main_module,
            "_read_database",
            lambda db: (reads.append(db), original(db))[1],
        )

        monkeypatch.setattr(
            main_module.settings, "READINESS_CACHE_SECONDS", 0.01
        )

        assert client.get(main_module.READINESS_PATH).status_code == 200
        assert len(reads) == 1
        time.sleep(0.05)

        acquired = main_module._readiness_probe_lock.acquire(
            blocking=False
        )
        assert acquired
        try:
            answer = client.get(main_module.READINESS_PATH)
        finally:
            main_module._readiness_probe_lock.release()

        assert answer.status_code == 200
        assert answer.json() == {"status": main_module.READINESS_STATUS}
        assert len(reads) == 1

    def test_no_recorded_outcome_refuses_rather_than_waiting(
        self, client
    ):
        """With nothing recorded, a probe mid-read refuses at once."""
        main_module.reset_readiness_cache()

        acquired = main_module._readiness_probe_lock.acquire(
            blocking=False
        )
        assert acquired
        try:
            answer = client.get(main_module.READINESS_PATH)
        finally:
            main_module._readiness_probe_lock.release()

        assert answer.status_code == 503
        assert answer.json() == {"status": main_module.NOT_READY_STATUS}

    def test_the_read_is_bounded_where_the_dialect_supports_it(self):
        """PostgreSQL receives a transaction-local timeout, SQLite none.

        Each bound is transaction-local, so nothing else that uses the
        shared engine -- the Alembic revisions included -- inherits it.
        """
        issued = []

        class RecordingSession:
            def __init__(self, dialect_name):
                self._dialect_name = dialect_name

            def get_bind(self):
                dialect = type("Dialect", (), {})()
                dialect.name = self._dialect_name
                bind = type("Bind", (), {})()
                bind.dialect = dialect
                return bind

            def execute(self, statement, params=None):
                issued.append((str(statement), params))

        main_module._bound_readiness_transaction(
            RecordingSession("postgresql")
        )

        assert len(issued) == len(
            main_module.READINESS_BOUND_STATEMENTS
        )
        expected = str(
            int(settings.READINESS_TIMEOUT_SECONDS * 1000)
        )
        for statement, params in issued:
            assert "set_config" in statement
            assert params == {"milliseconds": expected}
        assert "statement_timeout" in issued[0][0]
        assert "lock_timeout" in issued[1][0]

        issued.clear()
        main_module._bound_readiness_transaction(
            RecordingSession("sqlite")
        )

        assert issued == []

    def test_the_route_counts_its_requests_against_a_limit(self, client):
        """A burst past the configured limit is refused."""
        permitted = int(settings.RATE_LIMIT_READINESS.split("/")[0])

        answers = [
            client.get(main_module.READINESS_PATH)
            for _ in range(permitted + 1)
        ]

        assert [
            answer.status_code for answer in answers[:permitted]
        ] == [200] * permitted
        assert answers[-1].status_code == 429


class TestShutdownDrainReporting:
    """A log queue that will not empty is reported as the process stops.

    The lifespan previously discarded the drain result, so records left
    queued at shutdown were lost without a trace of their loss.
    """

    def _run_lifespan(self):
        """Enters and leaves the application's lifespan once."""
        with TestClient(main_module.app):
            pass

    def test_an_incomplete_drain_reaches_standard_error(
        self, monkeypatch, capsys
    ):
        monkeypatch.setattr(
            main_module, "flush_log_queue", lambda: False
        )
        self._run_lifespan()

        reported = capsys.readouterr().err
        assert main_module.LOG_DRAIN_INCOMPLETE_MESSAGE in reported
        assert str(main_module.QUEUE_DRAIN_TIMEOUT_SECONDS) in reported

    def test_a_complete_drain_reports_nothing(self, monkeypatch, capsys):
        monkeypatch.setattr(main_module, "flush_log_queue", lambda: True)
        self._run_lifespan()

        reported = capsys.readouterr().err
        assert main_module.LOG_DRAIN_INCOMPLETE_MESSAGE not in reported

    def test_the_drain_runs_after_the_outbound_client_is_closed(
        self, monkeypatch
    ):
        order = []
        closer = main_module.close_http_client

        async def recording_close():
            order.append("close")
            await closer()

        def recording_drain():
            order.append("drain")
            return True

        monkeypatch.setattr(
            main_module, "close_http_client", recording_close
        )
        monkeypatch.setattr(
            main_module, "flush_log_queue", recording_drain
        )
        self._run_lifespan()

        assert order == ["close", "drain"]


class TestRequestBodyCaps:
    """Both the size and the chunk count of a body are bounded."""

    def build(self, max_body_bytes, max_messages):
        """Returns a client over one route behind the body cap."""
        probe = FastAPI()

        @probe.post("/echo")
        async def echo(payload: dict):
            return {"keys": sorted(payload)}

        probe.add_middleware(
            main_module.BodySizeLimitMiddleware,
            max_body_bytes=max_body_bytes,
            max_messages=max_messages,
        )
        return TestClient(probe, raise_server_exceptions=False)

    def test_a_declared_oversized_body_is_refused(self):
        client = self.build(64, 16)
        response = client.post(
            "/echo",
            content=b'{"a":"' + b"x" * 512 + b'"}',
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert response.json()["detail"] == (
            main_module.BODY_TOO_LARGE_DETAIL
        )

    def test_a_body_within_the_cap_reaches_the_handler(self):
        client = self.build(1024, 16)
        response = client.post("/echo", json={"a": 1, "b": 2})
        assert response.status_code == 200
        assert response.json()["keys"] == ["a", "b"]

    def test_a_chunked_body_within_the_caps_reaches_the_handler(self):
        client = self.build(1024, 64)

        def chunks():
            for piece in (b'{"a":', b"1,", b'"b":', b"2}"):
                yield piece

        response = client.post(
            "/echo",
            content=chunks(),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 200
        assert response.json()["keys"] == ["a", "b"]

    def test_a_chunked_body_over_the_size_cap_is_refused(self):
        client = self.build(64, 4096)

        def chunks():
            yield b'{"a":"'
            for _ in range(64):
                yield b"x" * 16
            yield b'"}'

        response = client.post(
            "/echo",
            content=chunks(),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413

    def test_a_body_of_too_many_chunks_is_refused(self):
        """Many tiny chunks stay inside the size cap but are bounded.

        The middleware is driven directly here: an HTTP client is free to
        coalesce the chunks it is handed, and this asserts the behaviour
        for the message stream the middleware actually sees.
        """
        import asyncio

        chunks = [
            {"type": "http.request", "body": b"x", "more_body": True}
            for _ in range(64)
        ]
        chunks.append(
            {"type": "http.request", "body": b"x", "more_body": False}
        )
        sent = []

        async def receive():
            if chunks:
                return chunks.pop(0)
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        read = []

        async def downstream(scope, receive_, send_):
            # The cap is applied as the body streams, so the wrapped
            # receive is what refuses rather than the layer above it.
            while True:
                read.append(await receive_())

        middleware = main_module.BodySizeLimitMiddleware(
            downstream, max_body_bytes=1048576, max_messages=8
        )
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/echo",
            "headers": [(b"content-type", b"application/json")],
        }
        with pytest.raises(StarletteHTTPException) as refused:
            asyncio.get_event_loop().run_until_complete(
                middleware(scope, receive, send)
            )
        assert refused.value.status_code == 413
        assert refused.value.detail == main_module.BODY_TOO_LARGE_DETAIL
        # The refusal arrives on the message that passes the bound, so no
        # more of the body than that is ever read.
        assert len(read) == 8
        assert sent == []

    def test_the_configured_chunk_cap_is_applied(self):
        assert settings.MAX_REQUEST_BODY_CHUNKS >= 1
        for middleware in main_module.app.user_middleware:
            if middleware.cls is main_module.BodySizeLimitMiddleware:
                options = getattr(middleware, "kwargs", None) or {}
                assert options.get("max_messages") == (
                    settings.MAX_REQUEST_BODY_CHUNKS
                )
                assert options.get("max_body_bytes") == (
                    settings.MAX_REQUEST_BODY_BYTES
                )
                return
        raise AssertionError("the body cap middleware is not installed")


class TestBodyIsReadBeforeAdmission:
    """A body that never finishes arriving costs no serving capacity.

    The admission gate holds its slot for the whole of the routed
    request, and a route reads its body inside that request. A client
    that declared a body, sent one byte of it and then held the socket
    open therefore held a slot for as long as it liked: measured, ten
    such connections took every slot, and the public listings read waited
    the whole admission allowance and was then refused 503 while both
    probes stayed green because their paths are ungated.

    The prefetch layer reads the body outside the gate, under a
    whole-body deadline and a per-chunk deadline, so a stalled body is
    answered 408 and occupies no slot at all.
    """

    SCOPE = {
        "type": "http",
        "method": "POST",
        "path": "/filters/",
        "headers": [(b"content-type", b"application/json")],
    }

    def _stalling_receive(self, opening=None):
        """Returns a channel that answers once and then never again."""
        answered = []

        async def receive():
            if opening is not None and not answered:
                answered.append(opening)
                return opening
            await anyio.sleep_forever()

        return receive

    def _collecting_send(self, sent):
        async def send(message):
            sent.append(message)

        return send

    def _recording_downstream(self, entered, read=None):
        async def downstream(scope, receive, send):
            entered.append(scope["path"])
            if read is not None:
                while True:
                    message = await receive()
                    read.append(message)
                    if message["type"] != "http.request":
                        return
                    if not message.get("more_body", False):
                        return

        return downstream

    def _layer(self):
        """Returns the one prefetch layer the application installs."""
        installed = [
            layer
            for layer in main_module.app.user_middleware
            if layer.cls is main_module.BodyPrefetchMiddleware
        ]
        assert len(installed) == 1
        return installed[0]

    def test_the_layer_sits_between_the_body_cap_and_the_gate(self):
        """So the cap still applies and the gate is still innermost."""
        installed = [
            layer.cls for layer in main_module.app.user_middleware
        ]

        assert installed[-1] is main_module.RequestAdmissionMiddleware
        assert installed[-2] is main_module.BodyPrefetchMiddleware
        assert installed[-3] is main_module.BodySizeLimitMiddleware

    def test_both_deadlines_come_from_the_configuration(self):
        """Neither figure is a literal at the registration."""
        registered = self._layer().kwargs

        assert registered["total_seconds"] == (
            settings.REQUEST_BODY_TIMEOUT_SECONDS
        )
        assert registered["chunk_seconds"] == (
            settings.REQUEST_BODY_CHUNK_TIMEOUT_SECONDS
        )

    @pytest.mark.asyncio
    async def test_a_body_that_never_arrives_is_refused_408(self):
        sent = []
        entered = []
        middleware = main_module.BodyPrefetchMiddleware(
            self._recording_downstream(entered),
            total_seconds=0.2,
            chunk_seconds=0.1,
        )

        await middleware(
            dict(self.SCOPE),
            self._stalling_receive(),
            self._collecting_send(sent),
        )

        assert entered == []
        assert sent[0]["status"] == 408
        assert main_module.BODY_NOT_RECEIVED_DETAIL.encode() in sent[1][
            "body"
        ]

    @pytest.mark.asyncio
    async def test_a_body_that_stops_part_way_is_refused_408(self):
        sent = []
        entered = []
        middleware = main_module.BodyPrefetchMiddleware(
            self._recording_downstream(entered),
            total_seconds=0.4,
            chunk_seconds=0.1,
        )

        await middleware(
            dict(self.SCOPE),
            self._stalling_receive(
                {"type": "http.request", "body": b"{", "more_body": True}
            ),
            self._collecting_send(sent),
        )

        assert entered == []
        assert sent[0]["status"] == 408

    @pytest.mark.asyncio
    async def test_a_complete_body_is_replayed_in_order(self):
        prepared = [
            {"type": "http.request", "body": b'{"a"', "more_body": True},
            {"type": "http.request", "body": b":1}", "more_body": False},
        ]
        pending = list(prepared)

        async def receive():
            if pending:
                return pending.pop(0)
            return {"type": "http.disconnect"}

        read = []
        entered = []
        middleware = main_module.BodyPrefetchMiddleware(
            self._recording_downstream(entered, read),
            total_seconds=5.0,
            chunk_seconds=5.0,
        )

        await middleware(dict(self.SCOPE), receive, self._collecting_send([]))

        assert entered == ["/filters/"]
        assert read == prepared

    @pytest.mark.asyncio
    async def test_a_read_past_the_body_is_answered_by_the_request(self):
        """A disconnect is delivered by the server, not manufactured."""
        pending = [
            {"type": "http.request", "body": b"{}", "more_body": False},
            {"type": "http.disconnect"},
        ]

        async def receive():
            if pending:
                return pending.pop(0)
            raise AssertionError("the channel was read past its end")

        read = []

        async def downstream(scope, receive_, send_):
            read.append(await receive_())
            read.append(await receive_())

        middleware = main_module.BodyPrefetchMiddleware(
            downstream, total_seconds=5.0, chunk_seconds=5.0
        )

        await middleware(dict(self.SCOPE), receive, self._collecting_send([]))

        assert [message["type"] for message in read] == [
            "http.request",
            "http.disconnect",
        ]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method", main_module.BODYLESS_METHODS)
    async def test_a_bodyless_method_is_passed_straight_through(
        self, method
    ):
        entered = []
        middleware = main_module.BodyPrefetchMiddleware(
            self._recording_downstream(entered),
            total_seconds=0.05,
            chunk_seconds=0.05,
        )
        scope = dict(self.SCOPE, method=method)

        await middleware(
            scope, self._stalling_receive(), self._collecting_send([])
        )

        assert entered == ["/filters/"]

    def test_a_body_over_the_cap_is_answered_rather_than_raised(self):
        """The cap's refusal is rendered, not left to the server.

        The counting channel refuses by raising, and this layer sits
        outside the handler that turns such a refusal into a response, so
        the response is produced here instead of reaching the server as an
        unhandled error.
        """
        probe = FastAPI()

        @probe.post("/echo")
        async def echo(payload: dict):
            return {"keys": sorted(payload)}

        probe.add_middleware(
            main_module.BodyPrefetchMiddleware,
            total_seconds=5.0,
            chunk_seconds=5.0,
        )
        probe.add_middleware(
            main_module.BodySizeLimitMiddleware,
            max_body_bytes=64,
            max_messages=16,
        )
        client = TestClient(probe, raise_server_exceptions=False)

        response = client.post(
            "/echo",
            content=b'{"a":"' + b"x" * 512 + b'"}',
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 413
        assert response.json() == {
            "detail": main_module.BODY_TOO_LARGE_DETAIL
        }

    def test_a_stalled_body_leaves_the_public_read_served(self, client):
        """The assembled application answers while a body is stalled.

        The bound the gate applies is per event loop and the client here
        drives one loop per request, so this case asserts the property the
        measurement showed rather than reproducing the ten-connection
        exhaustion: the prefetch layer refuses the stalled body itself,
        and the read that shares the process is answered.
        """
        prefetch = main_module.BodyPrefetchMiddleware(
            None, total_seconds=0.2, chunk_seconds=0.1
        )
        sent = []

        async def drive():
            await prefetch(dict(self.SCOPE), self._stalling_receive(), (
                self._collecting_send(sent)
            ))

        anyio.run(drive)

        assert sent[0]["status"] == 408
        assert client.get("/listings/").status_code == 200


class TestBodyReadingCost:
    """The body is counted as it streams, never held or replayed.

    The cap this layer applies costs one integer per bound rather than a
    copy of the body, so its memory does not follow the body's size and
    no message is ever read twice.
    """

    SCOPE = {
        "type": "http",
        "method": "POST",
        "path": "/echo",
        "headers": [(b"content-type", b"application/json")],
    }

    def _messages(self, count):
        from collections import deque

        return deque(
            {
                "type": "http.request",
                "body": b"x",
                "more_body": index < count - 1,
            }
            for index in range(count)
        )

    def _wrapped(self, prepared, max_body_bytes, max_messages):
        """Returns the counting receive the middleware installs."""
        async def receive():
            if prepared:
                return prepared.popleft()
            return {"type": "http.disconnect"}

        middleware = main_module.BodySizeLimitMiddleware(
            None,
            max_body_bytes=max_body_bytes,
            max_messages=max_messages,
        )
        return middleware._counting_receive(self.SCOPE, receive)

    def test_every_message_is_passed_through_in_order(self):
        import asyncio

        prepared = self._messages(5)
        receive = self._wrapped(prepared, 1048576, 1000)

        async def drain():
            seen = []
            for _ in range(6):
                seen.append(await receive())
            return seen

        seen = asyncio.get_event_loop().run_until_complete(drain())
        assert len(seen) == 6
        assert [
            message["more_body"] for message in seen[:5]
        ] == [True, True, True, True, False]
        assert seen[5]["type"] == "http.disconnect"

    def test_no_message_is_retained_after_it_is_passed_on(self):
        import asyncio

        prepared = self._messages(4)
        receive = self._wrapped(prepared, 1048576, 1000)

        async def drain():
            for _ in range(4):
                await receive()

        asyncio.get_event_loop().run_until_complete(drain())
        # The queue is drained rather than copied, so nothing is held for
        # a second pass over the body.
        assert len(prepared) == 0

    def test_reading_stops_at_the_message_cap(self):
        import asyncio

        prepared = self._messages(50)
        receive = self._wrapped(prepared, 1048576, 5)

        async def drain():
            for _ in range(50):
                await receive()

        with pytest.raises(StarletteHTTPException) as refused:
            asyncio.get_event_loop().run_until_complete(drain())
        assert refused.value.status_code == 413
        assert len(prepared) == 50 - 6

    def test_reading_stops_at_the_size_cap(self):
        import asyncio

        prepared = self._messages(50)
        receive = self._wrapped(prepared, 3, 1000)

        async def drain():
            for _ in range(50):
                await receive()

        with pytest.raises(StarletteHTTPException) as refused:
            asyncio.get_event_loop().run_until_complete(drain())
        assert refused.value.status_code == 413
        assert len(prepared) == 50 - 4


class TestErrorRecordsCarryNoUserData:
    """A failure is recorded by class and correlation, not by content."""

    def build(self):
        """Returns a client over a route that raises with user data."""
        probe = FastAPI()

        @probe.get("/boom")
        async def boom():
            raise RuntimeError(
                "INSERT INTO users (email, street_address) VALUES "
                "('%s', '%s')" % (PII_ADDRESS, PII_STREET)
            )

        probe.add_exception_handler(
            Exception, main_module.unhandled_exception_handler
        )
        return TestClient(probe, raise_server_exceptions=False)

    def test_the_response_carries_no_internal_detail(self, records):
        response = self.build().get("/boom")
        assert response.status_code == 500
        body = response.json()
        assert body["detail"] == main_module.SERVER_ERROR_DETAIL
        # The body names the request so an operator can find the record,
        # and carries nothing else.
        assert set(body) == {"detail", main_module.REQUEST_ID_FIELD}
        assert PII_ADDRESS not in response.text
        assert PII_STREET not in response.text

    def test_the_record_carries_no_frame_or_bound_value(self, records):
        """The finding was a traceback holding bound statement values.

        The record names the failure by class and module alone: no
        traceback, no frame, no source path and no local value, so
        nothing a statement bound can travel with it.
        """
        self.build().get("/boom")
        assert records
        for record in records:
            rendered = repr(vars(record))
            assert "Traceback" not in rendered
            assert __file__ not in rendered

    def test_no_record_carries_the_injected_user_data(self, records):
        """Neither sentinel reaches a record, in any field or message.

        The route raises with both sentinels embedded in its text, so a
        record that carried the exception message would carry them. Every
        attribute of every record is rendered and the message is
        formatted, so a sentinel reaching a structured field is caught as
        well as one reaching the message text.
        """
        self.build().get("/boom")
        assert records
        assert _values_in_records(records, PII_VALUES) == []
        for record in records:
            for field, value in vars(record).items():
                for sentinel in PII_VALUES:
                    assert sentinel not in str(value), field

    def test_the_record_carries_no_traceback(self, records):
        self.build().get("/boom")
        errors = [
            record
            for record in records
            if record.levelno >= logging.ERROR
        ]
        assert errors
        for record in errors:
            assert record.exc_info is None
            assert record.exc_text is None

    def test_the_record_names_the_class_and_the_request(self, records):
        self.build().get("/boom")
        errors = [
            record
            for record in records
            if record.levelno >= logging.ERROR
        ]
        assert errors
        fields = errors[-1].__dict__
        assert fields["exception_type"] == "RuntimeError"
        assert fields["exception_module"] == "builtins"
        assert main_module.REQUEST_ID_FIELD in fields

    def test_each_failure_gets_its_own_correlation(self, records):
        """The request identifier is what ties a 500 to its record.

        It is generated per request, returned on the response and bound
        for the record, so two failures never share one.
        """
        probe = FastAPI()

        @probe.get("/boom")
        async def boom():
            raise RuntimeError("failed")

        probe.add_middleware(main_module.RequestIdMiddleware)
        probe.add_exception_handler(
            Exception, main_module.unhandled_exception_handler
        )
        client = TestClient(probe, raise_server_exceptions=False)
        first = client.get("/boom")
        second = client.get("/boom")
        identifiers = [
            record.__dict__[main_module.REQUEST_ID_FIELD]
            for record in records
            if record.levelno >= logging.ERROR
        ]
        assert len(identifiers) == 2
        assert all(identifiers)
        assert identifiers[0] != identifiers[1]
        assert uuid.UUID(identifiers[0]).hex == identifiers[0]
        assert first.headers[main_module.REQUEST_ID_HEADER] == (
            identifiers[0]
        )
        assert second.headers[main_module.REQUEST_ID_HEADER] == (
            identifiers[1]
        )

    def test_the_security_headers_are_still_set(self, records):
        response = self.build().get("/boom")
        for name, value in main_module.SECURITY_HEADERS.items():
            assert response.headers[name] == value


class TestCrossOriginPolicy:
    """The cross-origin allowlist is explicit and preflight enforces it.

    Two layers are covered. The first reads the configuration the
    middleware was installed with, so a wildcard or an added method or
    header fails here even when no request would reveal it. The second
    negotiates real preflights through the assembled application, so a
    change that keeps the configuration intact but stops enforcing it
    fails too.
    """

    def installed(self):
        """Returns the keywords the cross-origin middleware carries."""
        found = [
            entry
            for entry in main_module.app.user_middleware
            if entry.cls.__name__ == CORS_MIDDLEWARE_NAME
        ]
        assert len(found) == 1
        return found[0].kwargs

    def client(self):
        """Returns a client whose host the trusted-host gate admits."""
        return TestClient(main_module.app, base_url=CLIENT_BASE_URL)

    def preflight(self, origin, method=PREFLIGHT_METHOD, header=None):
        """Negotiates one preflight and returns the response."""
        headers = {
            "Origin": origin,
            PREFLIGHT_METHOD_HEADER: method,
        }
        if header is not None:
            headers[PREFLIGHT_HEADERS_HEADER] = header
        return self.client().options(PREFLIGHT_PATH, headers=headers)

    def test_the_middleware_is_installed_once(self):
        assert self.installed() is not None

    def test_the_installed_methods_are_the_explicit_list(self):
        assert self.installed()["allow_methods"] == list(
            main_module.CORS_ALLOW_METHODS
        )

    def test_the_installed_headers_are_the_explicit_list(self):
        assert self.installed()["allow_headers"] == list(
            main_module.CORS_ALLOW_HEADERS
        )

    def test_the_installed_origins_are_the_configured_list(self):
        assert self.installed()["allow_origins"] == list(
            settings.ALLOWED_ORIGINS
        )

    def test_the_installed_configuration_is_credentialed(self):
        assert self.installed()["allow_credentials"] is True

    def test_no_installed_value_is_a_wildcard(self):
        """A wildcard alongside credentials is what M-3 removed."""
        keywords = self.installed()
        for name in (
            "allow_origins",
            "allow_methods",
            "allow_headers",
            "expose_headers",
        ):
            entries = keywords[name]
            assert entries
            assert CORS_WILDCARD not in entries, name
            for entry in entries:
                assert CORS_WILDCARD not in entry, (name, entry)

    def test_the_installed_exposed_headers_are_the_throttle_policy(self):
        assert self.installed()["expose_headers"] == list(
            main_module.CORS_EXPOSE_HEADERS
        )

    def test_the_exposed_set_is_the_headers_a_refusal_carries(self):
        """Every header the limiter writes is readable by its caller."""
        assert set(main_module.CORS_EXPOSE_HEADERS) == set(
            RATE_LIMIT_HEADERS
        ) | {RETRY_AFTER_HEADER}

    def test_a_shared_response_exposes_the_throttle_policy(self):
        origin = list(settings.ALLOWED_ORIGINS)[0]
        response = self.client().get(
            "/health", headers={"Origin": origin}
        )
        assert response.status_code == 200
        exposed = response.headers[CORS_EXPOSE_HEADERS_HEADER]
        for header in main_module.CORS_EXPOSE_HEADERS:
            assert header in exposed

    def test_a_throttled_response_is_read_back_by_its_caller(self):
        """A refused caller can read every header it must back off on.

        The refusal is produced by driving the limiter rather than by
        constructing a response, so the case fails if the exposed set
        and the set the limiter writes ever drift apart.
        """
        origin = list(settings.ALLOWED_ORIGINS)[0]
        client = self.client()
        allowed = int(settings.RATE_LIMIT_REGISTER.split("/", 1)[0])
        refused = None
        for _ in range(allowed + 1):
            response = client.post(
                "/auth/register",
                json={"email": REFUSED_ADDRESS, "password": ""},
                headers={"Origin": origin},
            )
            if response.status_code == TOO_MANY_REQUESTS:
                refused = response
                break
        assert refused is not None
        exposed = {
            name.strip()
            for name in refused.headers[
                CORS_EXPOSE_HEADERS_HEADER
            ].split(",")
        }
        for header in RATE_LIMIT_HEADERS + (RETRY_AFTER_HEADER,):
            assert header in refused.headers, header
            assert header in exposed, header

    def test_a_refused_preflight_shares_no_credentialed_response(self):
        """The credentials header never travels without its origin."""
        response = self.preflight(DISALLOWED_ORIGIN)
        assert response.status_code == 400
        assert (
            main_module.CORS_ALLOW_ORIGIN_HEADER not in response.headers
        )
        assert (
            main_module.CORS_ALLOW_CREDENTIALS_HEADER
            not in response.headers
        )

    def test_an_unlisted_origin_gets_no_credentialed_response(self):
        response = self.client().get(
            "/health", headers={"Origin": DISALLOWED_ORIGIN}
        )
        assert (
            main_module.CORS_ALLOW_ORIGIN_HEADER not in response.headers
        )
        assert (
            main_module.CORS_ALLOW_CREDENTIALS_HEADER
            not in response.headers
        )

    def test_an_allowed_preflight_is_approved(self):
        origin = list(settings.ALLOWED_ORIGINS)[0]
        response = self.preflight(
            origin, header=main_module.CORS_ALLOW_HEADERS[0]
        )
        assert response.status_code == 200
        assert response.headers[
            main_module.CORS_ALLOW_ORIGIN_HEADER
        ] == origin
        assert response.headers[
            main_module.CORS_ALLOW_CREDENTIALS_HEADER
        ] == "true"
        approved = response.headers[CORS_ALLOW_METHODS_HEADER]
        for method in main_module.CORS_ALLOW_METHODS:
            assert method in approved
        assert DISALLOWED_METHOD not in approved
        granted = response.headers[CORS_ALLOW_HEADERS_HEADER]
        for header in main_module.CORS_ALLOW_HEADERS:
            assert header in granted
        assert DISALLOWED_HEADER not in granted

    def test_a_preflight_from_an_unlisted_origin_is_refused(self):
        response = self.preflight(DISALLOWED_ORIGIN)
        assert response.status_code == 400
        assert (
            main_module.CORS_ALLOW_ORIGIN_HEADER not in response.headers
        )

    def test_a_preflight_for_an_unlisted_method_is_refused(self):
        origin = list(settings.ALLOWED_ORIGINS)[0]
        response = self.preflight(origin, method=DISALLOWED_METHOD)
        assert response.status_code == 400

    def test_a_preflight_for_an_unlisted_header_is_refused(self):
        origin = list(settings.ALLOWED_ORIGINS)[0]
        response = self.preflight(origin, header=DISALLOWED_HEADER)
        assert response.status_code == 400

    def test_a_credentialed_response_names_one_origin(self):
        """The shared origin is echoed exactly, never as a wildcard."""
        origin = list(settings.ALLOWED_ORIGINS)[0]
        response = self.client().get("/health", headers={"Origin": origin})
        assert response.status_code == 200
        shared = response.headers[main_module.CORS_ALLOW_ORIGIN_HEADER]
        assert shared == origin
        assert shared != CORS_WILDCARD
        assert response.headers[
            main_module.CORS_ALLOW_CREDENTIALS_HEADER
        ] == "true"

    def test_an_unlisted_origin_is_shared_with_nothing(self):
        response = self.client().get(
            "/health", headers={"Origin": DISALLOWED_ORIGIN}
        )
        assert (
            main_module.CORS_ALLOW_ORIGIN_HEADER not in response.headers
        )


class TestBoundParametersAreHidden:
    """A failing statement's values do not reach its error text."""

    def test_the_application_engine_hides_parameters(self):
        assert engine.hide_parameters is True

    def test_hiding_keeps_a_bound_address_out_of_the_error(self):
        hidden = create_engine("sqlite://", hide_parameters=True)
        shown = create_engine("sqlite://")
        statement = text("SELECT 1 FROM absent WHERE email = :email")
        outcomes = {}
        for label, candidate in (("hidden", hidden), ("shown", shown)):
            with candidate.connect() as connection:
                try:
                    connection.execute(
                        statement, {"email": PII_ADDRESS}
                    )
                except Exception as failure:
                    outcomes[label] = PII_ADDRESS in str(failure)
        hidden.dispose()
        shown.dispose()
        assert outcomes["hidden"] is False
        assert outcomes["shown"] is True


class TestEveryDatabaseWaitIsBounded:
    """A PostgreSQL connection carries three finite bounds.

    libpq waits indefinitely for a connection whose ``connect_timeout``
    is omitted or zero, and a statement the client has stopped waiting
    for keeps running on the server unless ``statement_timeout`` bounds
    it. A cancellation cannot reach a client whose packets are no longer
    acknowledged either, so ``tcp_user_timeout`` bounds the socket as
    well. The readiness handler reads through this same engine, so its
    worker inherits all three.
    """

    POSTGRES_URLS = (
        "postgresql://user:pw@db.internal:5432/apartment_finder",
        "postgresql+psycopg2://user:pw@db.internal:5432/apartment_finder",
    )

    @pytest.mark.parametrize("url", POSTGRES_URLS)
    def test_a_connection_attempt_is_bounded(self, url):
        arguments = database_module._connect_args(url)
        assert arguments["connect_timeout"] == (
            settings.DB_CONNECT_TIMEOUT_SECONDS
        )
        assert arguments["connect_timeout"] >= 1

    @pytest.mark.parametrize("url", POSTGRES_URLS)
    def test_one_statement_is_bounded_on_the_server(self, url):
        arguments = database_module._connect_args(url)
        expected = settings.DB_STATEMENT_TIMEOUT_SECONDS * 1000
        assert "-c statement_timeout=%d" % expected in arguments["options"]

    @pytest.mark.parametrize("url", POSTGRES_URLS)
    def test_an_established_socket_is_bounded(self, url):
        arguments = database_module._connect_args(url)
        assert arguments["tcp_user_timeout"] == (
            settings.DB_TCP_USER_TIMEOUT_SECONDS * 1000
        )

    @pytest.mark.parametrize("url", POSTGRES_URLS)
    def test_the_session_is_still_pinned_to_utc(self, url):
        arguments = database_module._connect_args(url)
        assert "-c timezone=utc" in arguments["options"]

    def test_the_options_string_is_built_from_the_configured_value(self):
        rendered = database_module.postgresql_session_options()
        assert rendered == (
            "-c timezone=utc -c statement_timeout=%d"
            % (settings.DB_STATEMENT_TIMEOUT_SECONDS * 1000)
        )

    def test_a_sqlite_url_carries_no_postgresql_parameter(self):
        arguments = database_module._connect_args("sqlite://")
        assert arguments == {"check_same_thread": False}

    def test_every_bound_is_below_the_container_probe_timeout(self):
        """Each bound sits under the health check's own client timeout."""
        probe_timeout_seconds = 5
        assert settings.DB_CONNECT_TIMEOUT_SECONDS < probe_timeout_seconds
        assert (
            settings.DB_STATEMENT_TIMEOUT_SECONDS < probe_timeout_seconds
        )
        assert (
            settings.DB_TCP_USER_TIMEOUT_SECONDS < probe_timeout_seconds
        )

    def test_a_timeout_above_the_ceiling_is_refused(self):
        from pydantic import ValidationError

        from backend.app.core.config import (
            DB_TIMEOUT_CEILING_SECONDS,
            Settings,
        )

        for name in (
            "DB_CONNECT_TIMEOUT_SECONDS",
            "DB_STATEMENT_TIMEOUT_SECONDS",
            "DB_TCP_USER_TIMEOUT_SECONDS",
        ):
            for rejected in (0, -1, DB_TIMEOUT_CEILING_SECONDS + 1):
                overrides = dict(settings.dict())
                overrides[name] = rejected
                with pytest.raises(ValidationError):
                    Settings(**overrides)

    def test_the_readiness_handler_runs_off_the_event_loop(self):
        """A synchronous handler is offloaded to a worker thread."""
        import inspect

        assert not inspect.iscoroutinefunction(
            main_module.readiness_check
        )


class TestCapacityRefusal:
    """Pool exhaustion is answered as a retryable capacity limit.

    It used to reach the catch-all handler, which answers 500 and lets
    the failure carry on to the server as an unhandled error: a client
    cannot retry a 500, a load balancer cannot read a backoff from one,
    and the raw traceback the server then wrote bypassed the redacting
    logger entirely. A handler registered for the pool's own class
    answers 503 with ``Retry-After`` and nothing propagates.
    """

    def build(self):
        """Returns a client over a route the pool refuses a connection."""
        probe = FastAPI()

        @probe.get("/exhausted")
        async def exhausted():
            raise PoolTimeout(
                "QueuePool limit of size 5 overflow 10 reached, "
                "connection timed out, timeout 10.00"
            )

        probe.add_exception_handler(
            PoolTimeout, main_module.pool_timeout_handler
        )
        probe.add_exception_handler(
            Exception, main_module.unhandled_exception_handler
        )
        return TestClient(probe, raise_server_exceptions=False)

    def test_the_pool_class_is_not_the_interpreter_timeout(self):
        """The registration is narrow enough not to catch other waits.

        The outbound provider and listing calls raise the interpreter's
        own timeout and the transport library's. Registering the pool's
        class must not answer either of those as a capacity refusal.
        """
        assert not issubclass(PoolTimeout, TimeoutError)
        assert PoolTimeout is not TimeoutError

    def test_the_application_registers_the_handler_for_that_class(self):
        registered = main_module.app.exception_handlers

        assert registered[PoolTimeout] is main_module.pool_timeout_handler

    def test_the_refusal_is_retryable_rather_than_a_fault(self):
        answered = self.build().get("/exhausted")

        assert answered.status_code == 503
        assert answered.headers["Retry-After"] == str(
            main_module.capacity_retry_after_seconds()
        )

    def test_the_body_names_the_request_and_nothing_else(self):
        """No pool figure, no exception text and no traceback."""
        answered = self.build().get("/exhausted")
        body = answered.json()

        assert body["detail"] == main_module.CAPACITY_DETAIL
        assert set(body) == {"detail", main_module.REQUEST_ID_FIELD}
        for absent in ("QueuePool", "overflow", "sqlalchemy", "Traceback"):
            assert absent not in answered.text, absent

    def test_the_retry_hint_is_the_configured_wait(self, monkeypatch):
        """Rounded up to whole seconds, with a floor of one."""
        monkeypatch.setattr(settings, "DB_POOL_TIMEOUT_SECONDS", 2.5)
        assert main_module.capacity_retry_after_seconds() == 3

        monkeypatch.setattr(settings, "DB_POOL_TIMEOUT_SECONDS", 0.25)
        assert main_module.capacity_retry_after_seconds() == 1

    def test_the_refusal_is_recorded_without_the_pool_message(
        self, records
    ):
        """The record names the class, the route and the correlation.

        The pool's own message names its size and overflow, so it is
        suppressed the way every other exception message is, and the
        wait and the hint travel as discrete fields instead.
        """
        self.build().get("/exhausted")
        recorded = [
            record
            for record in records
            if record.getMessage() == main_module.POOL_EXHAUSTED_MESSAGE
        ]

        assert recorded
        rendered = repr(vars(recorded[0]))
        assert "QueuePool" not in rendered
        assert "Traceback" not in rendered
        assert getattr(recorded[0], "exception_type", None) == (
            PoolTimeout.__name__
        )
        assert getattr(recorded[0], "retry_after_seconds", None) == (
            main_module.capacity_retry_after_seconds()
        )

    def test_the_refusal_carries_the_protective_headers(
        self, client, monkeypatch
    ):
        """Reached inside the middleware stack, so the layers apply.

        The readiness route is driven because it is the one route whose
        database work this case can make fail on demand. Its own 503
        reports a status rather than a detail, so the body distinguishes
        the two answers.
        """

        def refuse_connection(*arguments, **keywords):
            raise PoolTimeout("connection timed out")

        monkeypatch.setattr(
            main_module, "readiness_outcome", refuse_connection
        )

        answered = client.get(main_module.READINESS_PATH)

        assert answered.status_code == 503
        assert answered.json()["detail"] == main_module.CAPACITY_DETAIL
        assert answered.headers["Retry-After"]
        assert answered.headers[main_module.REQUEST_ID_HEADER]
        for name, value in main_module.SECURITY_HEADERS.items():
            assert answered.headers[name] == value, name

    def test_nothing_propagates_past_the_handler(self, client, monkeypatch):
        """The client raises server exceptions, so a leak would fail here.

        The fixture's client is built without the escape hatch that
        converts a propagating exception into a 500, which is what the
        earlier behaviour relied on.
        """

        def refuse_connection(*arguments, **keywords):
            raise PoolTimeout("connection timed out")

        monkeypatch.setattr(
            main_module, "readiness_outcome", refuse_connection
        )

        assert client.get(main_module.READINESS_PATH).status_code == 503


def _settles(predicate, timeout=HELD_THREAD_TIMEOUT_SECONDS):
    """Returns whether ``predicate`` became true before ``timeout``."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(POLL_INTERVAL_SECONDS)
    return predicate()


class _AdmissionProbe:
    """A one-route application whose callers report the crowd inside it.

    ``GATED_HOLD_PATH`` stays inside the router until :meth:`release` is
    called and records how many callers were within it at once, so the
    number the gate allowed is read from the router rather than inferred
    from timings. The liveness route is published unchanged, so the path
    the gate does not hold is driven against the same saturated process.
    """

    def __init__(self, bound, wait_seconds=GATE_WAIT_SECONDS):
        self._lock = threading.Lock()
        self._released = threading.Event()
        self.inside = 0
        self.peak = 0
        self.app = FastAPI()

        @self.app.get(GATED_HOLD_PATH)
        def hold():
            self._enter()
            try:
                self._released.wait(HELD_THREAD_TIMEOUT_SECONDS)
            finally:
                self._leave()
            return {"held": True}

        @self.app.get(GATED_QUICK_PATH)
        def quick():
            self._enter()
            self._leave()
            return {"quick": True}

        @self.app.get(GATED_FAILING_PATH)
        def failing():
            raise RuntimeError("the probe route failed")

        @self.app.get(GATED_LIMITER_PATH)
        async def limiter_identity():
            return {"limiter": id(main_module._ADMISSION_LIMITER.get())}

        self.app.get(main_module.HEALTH_PATH)(main_module.health_check)
        self.app.add_middleware(
            main_module.RequestAdmissionMiddleware,
            bound=bound,
            wait_seconds=wait_seconds,
        )

    def _enter(self):
        with self._lock:
            self.inside += 1
            self.peak = max(self.peak, self.inside)

    def _leave(self):
        with self._lock:
            self.inside -= 1

    def release(self):
        self._released.set()

    def client(self, raise_server_exceptions=True):
        return TestClient(
            self.app, raise_server_exceptions=raise_server_exceptions
        )

    def hold_from(self, client, callers):
        """Starts ``callers`` threads holding the gated route."""
        threads = [
            threading.Thread(
                target=client.get, args=(GATED_HOLD_PATH,), daemon=True
            )
            for _ in range(callers)
        ]
        for thread in threads:
            thread.start()
        return threads


class TestAdmissionIsBoundedByThePool:
    """The router is never entered by more requests than the pool serves.

    Every route that reads the database holds one pooled connection for
    as long as its session is open, and the session is closed inside the
    routed request. The number of connections wanted at once is therefore
    the number of requests inside this layer, and holding that below the
    pool's ceiling is what stops a request waiting the whole checkout
    timeout for a connection that was never going to be free.

    Capping the worker threads instead was measured not to do this: the
    session's close is a separate unit of work from the handler, so a
    finished request's connection is still held while its close waits
    behind the handlers that are blocked on checkout.
    """

    def _layer(self):
        """Returns the one admission layer the application installs."""
        installed = [
            layer
            for layer in main_module.app.user_middleware
            if layer.cls is main_module.RequestAdmissionMiddleware
        ]

        assert len(installed) == 1
        return installed[0]

    def test_the_gate_is_the_innermost_layer(self):
        """So a refused or oversized request never takes a slot.

        The layer added first is the last to run on an inbound request,
        so the gate encloses the router and nothing else: the rate
        limiter and the body cap both sit outside it and refuse before a
        slot is spent, and the 503 the gate returns still travels back
        out through every layer above it.
        """
        assert (
            main_module.app.user_middleware[-1].cls
            is main_module.RequestAdmissionMiddleware
        )

    def test_the_bound_and_the_wait_come_from_the_configuration(self):
        """Neither figure is a literal at the registration."""
        registered = self._layer().kwargs

        assert registered["bound"] == database_module.admitted_concurrency(
            settings.DATABASE_URL
        )
        assert registered["wait_seconds"] == (
            settings.DB_POOL_TIMEOUT_SECONDS
        )

    def test_the_paths_the_gate_does_not_hold_are_the_two_probes(self):
        """An orchestrator acts on a probe that does not answer."""
        assert main_module.UNGATED_PATHS == (
            main_module.HEALTH_PATH,
            main_module.READINESS_PATH,
        )

    def test_no_more_than_the_bound_are_inside_the_router(self):
        """Two callers fill a bound of two and a third waits outside.

        The crowd inside is read from the route itself and watched for
        long enough that a third admission would have shown up in it.
        """
        probe = _AdmissionProbe(bound=2)
        with probe.client() as client:
            holders = probe.hold_from(client, 3)
            try:
                assert _settles(lambda: probe.inside == 2)
                time.sleep(CROWD_OBSERVATION_SECONDS)

                assert probe.inside == 2
                assert probe.peak == 2
            finally:
                probe.release()
                for holder in holders:
                    holder.join(HELD_THREAD_TIMEOUT_SECONDS)

            assert probe.peak == 2
            assert client.get(GATED_QUICK_PATH).status_code == 200

    def test_a_backend_with_no_pool_ceiling_is_a_pass_through(self):
        """The suite's own configuration is one of these.

        With no bound the three callers are all inside at once, which is
        what distinguishes a pass-through from a bound of one.
        """
        probe = _AdmissionProbe(bound=None)
        with probe.client() as client:
            holders = probe.hold_from(client, 3)
            try:
                assert _settles(lambda: probe.inside == 3)
            finally:
                probe.release()
                for holder in holders:
                    holder.join(HELD_THREAD_TIMEOUT_SECONDS)

            assert probe.peak == 3

    def test_a_caller_that_waits_its_whole_allowance_is_refused(self):
        """And is refused as a retryable capacity limit, not a fault."""
        probe = _AdmissionProbe(
            bound=1, wait_seconds=GATE_REFUSAL_WAIT_SECONDS
        )
        with probe.client() as client:
            holders = probe.hold_from(client, 1)
            try:
                assert _settles(lambda: probe.inside == 1)
                refused = client.get(GATED_QUICK_PATH)
            finally:
                probe.release()
                for holder in holders:
                    holder.join(HELD_THREAD_TIMEOUT_SECONDS)

        assert refused.status_code == 503
        assert refused.headers["Retry-After"] == str(
            main_module.capacity_retry_after_seconds()
        )

    def test_the_refusal_is_the_answer_the_pool_refusal_gives(self):
        """One answer, whichever of the two refused the request.

        A caller cannot tell the gate's refusal from the pool's, and
        neither carries the bound, a pool figure or a traceback.
        """
        probe = _AdmissionProbe(
            bound=1, wait_seconds=GATE_REFUSAL_WAIT_SECONDS
        )
        with probe.client() as client:
            holders = probe.hold_from(client, 1)
            try:
                assert _settles(lambda: probe.inside == 1)
                refused = client.get(GATED_QUICK_PATH)
            finally:
                probe.release()
                for holder in holders:
                    holder.join(HELD_THREAD_TIMEOUT_SECONDS)

        body = refused.json()

        assert body["detail"] == main_module.CAPACITY_DETAIL
        assert set(body) == {"detail", main_module.REQUEST_ID_FIELD}
        for absent in ("QueuePool", "overflow", "bound", "Traceback"):
            assert absent not in refused.text, absent

    def test_the_refusal_is_recorded_with_what_it_applied(self, records):
        """The record names the route, the bound and the allowance."""
        probe = _AdmissionProbe(
            bound=1, wait_seconds=GATE_REFUSAL_WAIT_SECONDS
        )
        with probe.client() as client:
            holders = probe.hold_from(client, 1)
            try:
                assert _settles(lambda: probe.inside == 1)
                client.get(GATED_QUICK_PATH)
            finally:
                probe.release()
                for holder in holders:
                    holder.join(HELD_THREAD_TIMEOUT_SECONDS)

        recorded = [
            record
            for record in records
            if record.getMessage() == main_module.ADMISSION_REFUSED_MESSAGE
        ]

        assert recorded
        assert getattr(recorded[0], "path", None) == GATED_QUICK_PATH
        assert getattr(recorded[0], "admitted_concurrency", None) == 1
        assert getattr(recorded[0], "admission_wait_seconds", None) == (
            GATE_REFUSAL_WAIT_SECONDS
        )
        assert "Traceback" not in repr(vars(recorded[0]))

    def test_the_liveness_route_is_never_held_by_the_gate(self):
        """Driven with the gate saturated by a caller that stays inside.

        An orchestrator restarts a pod whose liveness route times out, so
        a saturated gate must not be able to cause that.
        """
        probe = _AdmissionProbe(
            bound=1, wait_seconds=GATE_REFUSAL_WAIT_SECONDS
        )
        with probe.client() as client:
            holders = probe.hold_from(client, 1)
            try:
                assert _settles(lambda: probe.inside == 1)
                started = time.monotonic()
                answered = client.get(main_module.HEALTH_PATH)
                elapsed = time.monotonic() - started
            finally:
                probe.release()
                for holder in holders:
                    holder.join(HELD_THREAD_TIMEOUT_SECONDS)

        assert answered.status_code == 200
        assert answered.json() == {"status": main_module.HEALTH_STATUS}
        assert elapsed < LIVENESS_BUDGET_SECONDS, elapsed

    def test_a_failing_route_gives_its_slot_back(self):
        """A leaked slot would refuse every later caller for good."""
        probe = _AdmissionProbe(
            bound=1, wait_seconds=GATE_REFUSAL_WAIT_SECONDS
        )
        with probe.client(raise_server_exceptions=False) as client:
            failed = client.get(GATED_FAILING_PATH)
            after = client.get(GATED_QUICK_PATH)

        assert failed.status_code == 500
        assert after.status_code == 200

    def test_each_event_loop_holds_its_own_bound(self):
        """Every test client here builds a loop of its own.

        A bound created on one loop and awaited on another would be a
        bound shared between processes that do not share a scheduler, so
        the layer resolves it per loop and each client sees its own.
        """
        probe = _AdmissionProbe(bound=1)
        with probe.client() as first:
            one = first.get(GATED_LIMITER_PATH).json()["limiter"]
        with probe.client() as second:
            two = second.get(GATED_LIMITER_PATH).json()["limiter"]

        assert one != two

    def test_the_liveness_route_is_answered_off_the_worker_threads(self):
        """It reads nothing, so it must not need a worker thread.

        Its path is named in :data:`main_module.UNGATED_PATHS`, so the
        gate never holds it; answering on the event loop is what keeps it
        independent of the worker threads the gated routes occupy too.
        """
        assert inspect.iscoroutinefunction(main_module.health_check)


class TestIngestionFailureRecord:
    """The ingestion pass records a failure without its content."""

    def test_the_record_carries_no_user_data_or_traceback(
        self, records
    ):
        import asyncio
        from unittest.mock import MagicMock, patch

        session = MagicMock()
        with patch.object(
            listing_updater, "SessionLocal", return_value=session
        ), patch.object(
            listing_updater, "tracked_zip_codes", return_value=["10001"]
        ), patch.object(
            listing_updater,
            "fetch_listings",
            side_effect=RuntimeError(
                "provider rejected %s at %s"
                % (PII_ADDRESS, PII_STREET)
            ),
        ):
            # The pass re-raises after rolling back, so the failure is
            # awaited here rather than being absorbed by the task.
            with pytest.raises(RuntimeError):
                asyncio.get_event_loop().run_until_complete(
                    listing_updater.update_listings()
                )

        errors = [
            record
            for record in records
            if record.levelno >= logging.ERROR
        ]
        assert errors
        for record in errors:
            rendered = repr(vars(record))
            assert "Traceback" not in rendered
            assert record.exc_info is None
        fields = errors[-1].__dict__
        assert fields["exception_type"] == "RuntimeError"
        # Only how far the pass got travels with the failure, never a
        # listing it had already mapped.
        assert fields["processed_listings"] == 0
        assert session.rollback.call_count == 1
        assert session.close.call_count == 1
        # Neither sentinel reaches a record, in any field or message.
        assert _values_in_records(records, PII_VALUES) == []
        for record in records:
            for field, value in vars(record).items():
                for sentinel in PII_VALUES:
                    assert sentinel not in str(value), field


class TestTheSchemaIsNotCreatedByTheApplication:
    """The revisions own the schema, so importing creates nothing.

    ``Base.metadata.create_all`` was called at import time before this
    remediation, which meant the running code built its own schema and the
    revisions were not the authority for it. Its absence was previously
    asserted by nobody, so a reintroduction would have gone unreported.
    """

    def test_the_application_source_calls_no_schema_creation(self):
        """Asserts the assembled application names no DDL call."""
        source = (
            REPO_ROOT / "backend" / "app" / "main.py"
        ).read_text(encoding="utf-8")

        assert SCHEMA_CREATION_ATTRIBUTE not in source

    def test_a_fresh_interpreter_creates_no_schema_on_import(self):
        """Asserts a fresh import and startup issue no DDL.

        The stand-in raises when the creation is reached, so a call from
        the module body, from a startup handler or from anything either of
        them imports ends the child interpreter. The child also serves one
        liveness request, so the lifespan of the application is entered
        rather than only its module body being executed.
        """
        completed = subprocess.run(
            [sys.executable, "-c", NO_DDL_PROGRAM],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env=dict(os.environ),
            timeout=NO_DDL_TIMEOUT_SECONDS,
        )

        assert completed.returncode == 0, (
            completed.stdout + completed.stderr
        )
        assert NO_DDL_CONFIRMATION in completed.stdout, (
            completed.stdout + completed.stderr
        )


class TestRouteMatchingFailsClosed:
    """A route that cannot answer a match call is not silently skipped.

    The rate-limit gate resolves a request's endpoint from the scope so it
    can evaluate the limit that endpoint declares before any body is read.
    A candidate swallowed silently there would leave the request running
    without the governance its route carries, so the two outcomes are
    separated: a failure a route genuinely raises for a scope it cannot
    read is recorded and skipped, and anything else propagates.
    """

    class _Raising:
        """A route candidate whose match call raises ``error``."""

        name = "raising-candidate"

        def __init__(self, error):
            self.error = error
            self.endpoint = None

        def matches(self, scope):
            raise self.error

    @staticmethod
    def _scope(routes):
        """Returns a scope whose application publishes ``routes``."""
        from unittest.mock import MagicMock

        application = MagicMock()
        application.routes = routes
        return {
            "type": "http",
            "method": "POST",
            "path": "/auth/login",
            "app": application,
        }

    @pytest.mark.parametrize(
        "error_type", list(main_module.UNMATCHABLE_ROUTE_ERRORS)
    )
    def test_an_unreadable_scope_skips_the_candidate(
        self, error_type, records
    ):
        """Each declared failure is recorded and the candidate skipped."""
        candidate = self._Raising(error_type("unreadable scope"))

        matched = main_module._matched_endpoint(self._scope([candidate]))

        assert matched is None
        warnings = [
            record
            for record in records
            if record.levelno >= logging.WARNING
            and getattr(record, "candidate", None) == candidate.name
        ]
        assert len(warnings) == 1
        assert warnings[0].error == error_type.__name__
        assert warnings[0].path == "/auth/login"
        assert warnings[0].method == "POST"

    def test_a_skipped_candidate_does_not_stop_the_search(self):
        """A later route still resolves after an earlier one is skipped."""

        def endpoint():
            return None

        class _Matching:
            name = "matching-candidate"

            def __init__(self):
                self.endpoint = endpoint

            def matches(self, scope):
                return main_module.Match.FULL, {}

        routes = [self._Raising(KeyError("method")), _Matching()]

        assert main_module._matched_endpoint(self._scope(routes)) is (
            endpoint
        )

    def test_an_unexpected_failure_propagates(self):
        """Anything outside the declared set is not swallowed.

        The caller depends on the match to decide which limit applies, so
        an unexpected failure must surface rather than resolve to "no
        endpoint" and let the request through ungoverned.
        """
        candidate = self._Raising(RuntimeError("router is inconsistent"))

        with pytest.raises(RuntimeError):
            main_module._matched_endpoint(self._scope([candidate]))

    def test_the_declared_set_excludes_the_base_exception(self):
        """The set names specific failures rather than everything."""
        assert Exception not in main_module.UNMATCHABLE_ROUTE_ERRORS
        assert BaseException not in main_module.UNMATCHABLE_ROUTE_ERRORS
        for error_type in main_module.UNMATCHABLE_ROUTE_ERRORS:
            assert issubclass(error_type, Exception)

    def test_a_scope_without_an_application_resolves_nothing(self):
        """No application means no routes to consider."""
        assert main_module._matched_endpoint({"type": "http"}) is None

    def test_every_real_route_answers_the_match_call(self, records):
        """The live router skips nothing, so nothing is recorded.

        The recording exists for a candidate that cannot answer. The
        application's own routes all can, so a normal lookup must produce
        no warning at all.
        """
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/auth/login",
            "app": main_module.app,
        }

        matched = main_module._matched_endpoint(scope)

        assert matched is not None
        assert [
            record
            for record in records
            if getattr(record, "candidate", None) is not None
        ] == []


class TestRequestCorrelation:
    """Every response carries the identifiers its records were written with.

    Without them a record cannot be tied to the request that produced it,
    which is what makes a security record actionable: a caller reporting
    a refusal can name the trace, and the operator can find every record
    of that request without searching by content. The trace identifier is
    adopted from the caller when the caller supplies valid W3C trace
    context, so one identifier spans the caller and this process, and a
    fresh span is always minted for this process's own work.
    """

    #: Trace context a caller supplies. Fixed local test values.
    CALLER_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
    CALLER_SPAN = "00f067aa0ba902b7"

    def caller_header(self, trace=None, span=None):
        return "00-{0}-{1}-01".format(
            trace or self.CALLER_TRACE, span or self.CALLER_SPAN
        )

    def test_a_response_carries_a_traceparent(self, client):
        response = client.get("/health")

        returned = response.headers.get(main_module.TRACEPARENT_HEADER)
        assert returned
        assert parse_traceparent(returned) is not None

    def test_the_caller_trace_is_adopted(self, client):
        response = client.get(
            "/health",
            headers={
                main_module.TRACEPARENT_HEADER: self.caller_header()
            },
        )

        parsed = parse_traceparent(
            response.headers[main_module.TRACEPARENT_HEADER]
        )
        assert parsed is not None
        assert parsed[0] == self.CALLER_TRACE

    def test_the_caller_span_is_not_reused(self, client):
        """This process reports its own span beneath the caller's trace."""
        response = client.get(
            "/health",
            headers={
                main_module.TRACEPARENT_HEADER: self.caller_header()
            },
        )

        parsed = parse_traceparent(
            response.headers[main_module.TRACEPARENT_HEADER]
        )
        assert parsed is not None
        assert parsed[1] != self.CALLER_SPAN

    @pytest.mark.parametrize(
        "supplied",
        [
            "",
            "nonsense",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4bf92f3577b34da6a3ce929d0e0e473Z-00f067aa0ba902b7-01",
        ],
    )
    def test_an_unusable_caller_value_starts_a_fresh_trace(
        self, client, supplied
    ):
        """A malformed header is replaced, never propagated."""
        response = client.get(
            "/health",
            headers={main_module.TRACEPARENT_HEADER: supplied},
        )

        returned = response.headers[main_module.TRACEPARENT_HEADER]
        assert parse_traceparent(returned) is not None
        assert returned != supplied

    def test_two_requests_carry_two_traces(self, client):
        first = client.get("/health").headers[
            main_module.TRACEPARENT_HEADER
        ]
        second = client.get("/health").headers[
            main_module.TRACEPARENT_HEADER
        ]

        assert first != second

    def test_a_refusal_carries_the_identifiers_too(self, client):
        """A response the request never reached a handler for still
        correlates."""
        response = client.get("/health", headers={"host": "elsewhere"})

        assert response.status_code == 400
        assert response.headers.get(main_module.REQUEST_ID_HEADER)
        assert response.headers.get(main_module.TRACEPARENT_HEADER)

    def test_the_record_carries_what_the_response_returned(
        self, unreachable_client, records
    ):
        """The identifiers on the record are the ones the caller was
        given, so the two can be joined.

        The unreadable database is what makes the request record
        anything: it drives one record out of a handler, inside the
        request, which is where the identifiers are bound.
        """
        response = unreachable_client.get(
            main_module.READINESS_PATH,
            headers={
                main_module.TRACEPARENT_HEADER: self.caller_header()
            },
        )
        assert response.status_code == 503

        returned = parse_traceparent(
            response.headers[main_module.TRACEPARENT_HEADER]
        )
        assert returned is not None
        emitted = [
            record
            for record in records
            if record.getMessage()
            == main_module.READINESS_FAILURE_MESSAGE
        ]
        assert emitted
        for record in emitted:
            assert getattr(record, TRACE_ID_FIELD) == self.CALLER_TRACE
            assert getattr(record, TRACE_ID_FIELD) == returned[0]
            assert getattr(record, SPAN_ID_FIELD) == returned[1]
            assert getattr(record, main_module.REQUEST_ID_FIELD)

    def test_the_context_is_unbound_once_the_request_ends(self, client):
        """No identifier leaks into work outside a request."""
        client.get("/health")

        assert current_trace_context() is None


class TestDegradedSinkReporting:
    """A record the process could not write is reported on the probe.

    Both counters name records this process produced and failed to write
    through its primary sink, so a non-zero value means the evidence
    trail is incomplete while the process still serves. The probe is
    where a deployment already looks, and the counts are reported as a
    record rather than in the body, because the body is a probe contract
    and a probe is not an authenticated reader.
    """

    @pytest.fixture(autouse=True)
    def _cleared_counters(self):
        reset_audit_failure_count()
        reset_logging_failure_count()
        yield
        reset_audit_failure_count()
        reset_logging_failure_count()

    def degradation_records(self, records):
        return [
            record
            for record in records
            if record.getMessage() == main_module.SINK_DEGRADED_MESSAGE
        ]

    def test_nothing_is_recorded_while_every_sink_writes(
        self, client, records
    ):
        response = client.get(main_module.READINESS_PATH)

        assert response.status_code == 200
        assert self.degradation_records(records) == []

    def test_a_rejected_audit_record_is_reported(
        self, client, records, monkeypatch
    ):
        monkeypatch.setattr(
            main_module, "audit_failure_count", lambda: 3
        )
        response = client.get(main_module.READINESS_PATH)

        assert response.status_code == 200
        reported = self.degradation_records(records)
        assert reported
        fields = reported[-1].__dict__
        assert reported[-1].levelno == logging.WARNING
        assert fields[SIGNAL_FIELD] == main_module.SINK_DEGRADED_SIGNAL
        assert fields["audit_failures"] == 3
        assert fields["log_emit_failures"] == 0

    def test_an_unemitted_record_is_reported(
        self, client, records, monkeypatch
    ):
        monkeypatch.setattr(
            main_module, "logging_failure_count", lambda: 2
        )
        client.get(main_module.READINESS_PATH)

        reported = self.degradation_records(records)
        assert reported
        assert reported[-1].__dict__["log_emit_failures"] == 2

    def test_the_body_gains_no_field(self, client, monkeypatch):
        """The probe contract is unchanged by the signal."""
        monkeypatch.setattr(
            main_module, "audit_failure_count", lambda: 1
        )
        monkeypatch.setattr(
            main_module, "logging_failure_count", lambda: 1
        )
        response = client.get(main_module.READINESS_PATH)

        assert set(response.json()) == {"status"}
        assert response.json() == {
            "status": main_module.READINESS_STATUS
        }

    def test_an_unreadable_database_is_still_reported_degraded(
        self, unreachable_client, records, monkeypatch
    ):
        """The two conditions are independent and both are recorded."""
        monkeypatch.setattr(
            main_module, "audit_failure_count", lambda: 1
        )
        response = unreachable_client.get(main_module.READINESS_PATH)

        assert response.status_code == 503
        assert self.degradation_records(records)
        assert [
            record
            for record in records
            if record.getMessage()
            == main_module.READINESS_FAILURE_MESSAGE
        ]

    def test_the_counter_the_probe_reads_is_the_exported_one(self):
        """The probe reads the authorization module's own counter."""
        assert (
            main_module.audit_failure_count is audit_failure_count
        )
        assert "audit_failure_count" in authorization.__all__


class TestThePublishedSchemaReadsAsDocumentation:
    """Every published description is prose a consumer can read.

    The viewers render a description verbatim and resolve no markup, so a
    documentation-generator cross-reference reaches the reader with its
    own punctuation intact and reads as broken documentation. A dotted
    package name additionally hands this application's internal layout to
    anyone who fetches the schema.
    """

    #: A documentation-generator cross-reference, in each of the forms the
    #: descriptions once carried.
    ROLE = re.compile(
        r":(?:class|mod|func|data|meth|attr|exc|obj|ref):`"
    )

    #: A dotted path into this application's own package.
    MODULE_PATH = re.compile(r"\bbackend\.app[\w.]*")

    #: A configuration value named by its internal attribute.
    SETTING_NAME = re.compile(r"\bsettings\.[A-Z_]+")

    @staticmethod
    def described():
        """Yields every ``(location, text)`` pair the schema publishes."""
        schema = main_module.app.openapi()
        for path, operations in (schema.get("paths") or {}).items():
            for method, operation in operations.items():
                if not isinstance(operation, dict):
                    continue
                for key in ("summary", "description"):
                    yield (
                        "paths.%s.%s.%s" % (path, method, key),
                        operation.get(key),
                    )
                parameters = operation.get("parameters") or []
                for index, parameter in enumerate(parameters):
                    yield (
                        "paths.%s.%s.parameters[%d]"
                        % (path, method, index),
                        parameter.get("description"),
                    )
        components = schema.get("components") or {}
        for name, model in (components.get("schemas") or {}).items():
            yield (
                "components.schemas.%s" % name,
                model.get("description"),
            )
            for field, published in (
                model.get("properties") or {}
            ).items():
                yield (
                    "components.schemas.%s.%s" % (name, field),
                    published.get("description"),
                )
        yield (
            "info.description",
            (schema.get("info") or {}).get("description"),
        )

    def offenders(self, pattern):
        """Returns every published location ``pattern`` matches."""
        return [
            (where, pattern.search(text).group(0))
            for where, text in self.described()
            if isinstance(text, str) and pattern.search(text)
        ]

    def test_the_scan_reads_a_populated_schema(self):
        """A silent scan over an empty schema would prove nothing."""
        described = [
            text
            for _, text in self.described()
            if isinstance(text, str) and text.strip()
        ]
        assert len(described) >= 10

    def test_no_description_carries_a_generator_role(self):
        assert self.offenders(self.ROLE) == []

    def test_no_description_names_an_internal_module(self):
        assert self.offenders(self.MODULE_PATH) == []

    def test_no_description_names_a_configuration_attribute(self):
        assert self.offenders(self.SETTING_NAME) == []

    def test_the_scan_matches_what_was_removed(self):
        """Each pattern is shown to match the construct it guards."""
        assert self.ROLE.search(
            "no field outside :class:`ListingCreate` reaches it"
        )
        assert self.MODULE_PATH.search(
            "bounded by :mod:`backend.app.schema.filter`"
        )
        assert self.SETTING_NAME.search(
            "``limit`` by ``settings.MAX_PAGE_SIZE``"
        )


class TestTheCredentialExampleIsUsable:
    """A viewer pre-fills a credential body the contract accepts.

    With no example published, the viewer synthesises one from each
    field's own constraints. That produced an address of random
    punctuation and the literal name of the password's type -- valid
    JSON, so nothing warned the reader, and refused the moment it was
    sent.
    """

    def published(self, name):
        """Returns the example the schema publishes for ``name``."""
        schema = main_module.app.openapi()
        return schema["components"]["schemas"][name].get("example")

    @pytest.mark.parametrize("name", ["UserCreate", "UserLogin"])
    def test_the_schema_publishes_an_example(self, name):
        example = self.published(name)
        assert isinstance(example, dict)
        assert set(example) == {"email", "password"}

    @pytest.mark.parametrize(
        "name,model",
        [("UserCreate", UserCreate), ("UserLogin", UserLogin)],
    )
    def test_the_example_satisfies_the_contract_that_publishes_it(
        self, name, model
    ):
        """The model accepts its own published example unedited."""
        example = self.published(name)
        parsed = model(**example)
        assert parsed.email == example["email"]
        assert parsed.password == example["password"]

    def test_both_routes_publish_one_example(self):
        """One body serves both, so a reader retypes nothing."""
        assert self.published("UserCreate") == self.published(
            "UserLogin"
        )

    def test_the_example_meets_the_registration_password_policy(self):
        """The stricter of the two contracts is the one to satisfy."""
        password = self.published("UserCreate")["password"]
        assert len(password) >= 12
        assert len(password.encode("utf-8")) <= 72
        assert any(character.isupper() for character in password)
        assert any(character.islower() for character in password)
        assert any(character.isdigit() for character in password)

    @pytest.mark.usefixtures("reset_rate_limits")
    def test_the_example_registers_when_sent_unedited(self, client):
        """Sent exactly as published, the body is not refused."""
        response = client.post(
            "/auth/register", json=self.published("UserCreate")
        )
        assert response.status_code == 200


class TestThePermissionsPolicyNamesOnlyRealFeatures:
    """The policy carries no directive a browser does not recognise.

    An unrecognised directive is inert, so it buys no restriction, and
    every browser that parses the header reports it once per document
    load.
    """

    #: Directive shape the header carries: a feature name disallowed for
    #: every origin.
    DIRECTIVE = re.compile(r"^[a-z0-9-]+=\(\)$")

    #: Feature the header once named, which no browser implements.
    WITHDRAWN = "ambient-light-sensor"

    def directives(self):
        """Returns each directive the published policy carries."""
        policy = main_module.SECURITY_HEADERS["Permissions-Policy"]
        return [part.strip() for part in policy.split(",")]

    def test_the_policy_is_published(self):
        assert "Permissions-Policy" in main_module.SECURITY_HEADERS
        assert len(self.directives()) >= 10

    def test_every_directive_is_well_formed(self):
        malformed = [
            directive
            for directive in self.directives()
            if not self.DIRECTIVE.match(directive)
        ]
        assert malformed == []

    def test_the_withdrawn_feature_is_not_named(self):
        names = [
            directive.split("=", 1)[0]
            for directive in self.directives()
        ]
        assert self.WITHDRAWN not in names

    def test_a_served_response_carries_the_same_policy(self, client):
        """The header a response carries is the published one."""
        response = client.get(main_module.HEALTH_PATH)
        assert (
            response.headers["Permissions-Policy"]
            == main_module.SECURITY_HEADERS["Permissions-Policy"]
        )
        assert self.WITHDRAWN not in response.headers[
            "Permissions-Policy"
        ]
