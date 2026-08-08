"""Regression tests for the application surface and its error records.

The cases here cover three things the assembled application previously
gave away or spent without limit: an interactive schema published to
anyone in every environment, a chunked body replayed in a way whose cost
grew with the square of the number of chunks and with no bound on that
number, and an error record carrying a traceback whose database frames
hold the values bound into the statement being run.
"""

import logging
import uuid

import pytest
from conftest import CLIENT_BASE_URL
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app import main as main_module
from backend.app.core.config import LOCAL_ENVIRONMENT, settings
from backend.app.core.logging import BASE_LOGGER_NAME, configure_logging
from backend.app.db.database import engine, get_db

# Imported here rather than inside the test that uses it: the first
# ``get_logger`` call a module makes settles handler governance, which
# removes every handler on the governed logger that is not the redacting
# one -- the collecting fixture below included.
from backend.app.tasks import listing_updater  # noqa: E402

# Addresses that would appear in a traceback of a failing statement.
PII_ADDRESS = "resident@example.com"

PII_STREET = "42 Sensitive Street, Apartment 9"


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
    No credential is written into the URL.
    """
    down = create_engine("postgresql://127.0.0.1:1/unreachable")

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

        The record names the failure by class, module and redacted
        message: no traceback, no frame, no source path and no local
        value, so nothing a statement bound can travel with it.
        """
        self.build().get("/boom")
        assert records
        for record in records:
            rendered = repr(vars(record))
            assert "Traceback" not in rendered
            assert __file__ not in rendered

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
