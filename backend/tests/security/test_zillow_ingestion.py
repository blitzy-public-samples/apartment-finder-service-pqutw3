"""Regression cases for the Zillow ingestion pipeline.

Two defects are pinned here. The provider-to-model transform produced
obsolete field names and omitted the columns the listings table declares
NOT NULL, so no fetched record could be persisted. The scheduled updater
called the fetch without its required arguments, awaited two synchronous
functions, and matched on a column the model does not declare, so a run
ended in one rollback and zero commits. The outbound provider request also
carried no timeout, so a stalled upstream could hold the ingestion worker
open without bound.

The cases below drive a mocked provider through fetch, transform, database
write and read back, and drive a real slow and a real never-answering
server through the bounded outbound wait.

Rationale is indexed in ``documentation/security/decision-log.md`` at
DL-436 through DL-438.
"""
import asyncio
import socket
import threading
import time
from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from conftest import TestingSessionLocal

from backend.app.db.models import Criteria, Filter, Listing, User, ZipCode
from backend.app.schema.listing import ListingCreate
from backend.app.services import zillow_service
from backend.app.tasks import listing_updater


# One provider record in the canonical spelling, carrying every writable
# column the listings table declares
CANONICAL_RECORD = {
    "rent": 2750.0,
    "broker_fee": 1200.0,
    "square_footage": 720.0,
    "bedrooms": 2,
    "bathrooms": 1,
    "available_date": "2026-09-01T00:00:00",
    "street_address": "18 Fulton Street",
    "zillow_url": "https://www.zillow.com/homedetails/18-fulton-street/1",
}

# The same record in the spellings the provider is also observed to use,
# with the numerics quoted and formatted the way a feed presents them
ALTERNATE_RECORD = {
    "price": "$2,750",
    "brokerFee": "1200",
    "livingArea": "720",
    "beds": "2",
    "baths": "1.0",
    "availableDate": "2026-09-01T00:00:00",
    "address": "  18 Fulton Street  ",
    "detailUrl": "https://www.zillow.com/homedetails/18-fulton-street/1",
}

# Columns the server owns; a provider record may not set any of them
SERVER_OWNED_COLUMNS = ("id", "created_at", "updated_at")

# The zip code the seeded filter watches
TRACKED_ZIP_CODE = "10038"

# The one-hour cadence AAP 0.1.4 freezes
EXPECTED_UPDATE_INTERVAL = timedelta(hours=1)


def _seed_tracked_zip_code(session, code=TRACKED_ZIP_CODE):
    """Store one filter watching one zip code, and return that code."""
    stamped_at = datetime(2026, 1, 1)
    user = User(
        email="ingestion-{0}@example.com".format(code),
        hashed_password="unused-in-this-module",  # blitzy-scan-allow: fixture
        created_at=stamped_at,
    )
    session.add(user)
    session.flush()
    watched = Filter(
        user_id=user.id, name="watched-{0}".format(code),
        created_at=stamped_at,
    )
    session.add(watched)
    session.flush()
    session.add(ZipCode(filter_id=watched.id, code=code))
    session.commit()
    return code


def _run_updater(monkeypatch, records, capture=None):
    """Run one updater pass against the harness database and a stub feed.

    ``capture`` receives the arguments the updater passes to the provider.
    """
    def _stub_fetch(zip_codes, filters):
        if capture is not None:
            capture.append((list(zip_codes), dict(filters)))
        return list(records)

    monkeypatch.setattr(listing_updater, "SessionLocal", TestingSessionLocal)
    monkeypatch.setattr(listing_updater, "fetch_listings", _stub_fetch)
    asyncio.get_event_loop().run_until_complete(
        listing_updater.update_listings()
    )


def _stored_listings(session):
    """Return every stored listing, oldest identifier first."""
    return session.query(Listing).order_by(Listing.id).all()


# The transform maps a provider record onto the writable columns
def test_the_transform_maps_a_provider_record_onto_the_writable_columns():
    """Every writable column receives the value the provider supplies."""
    mapped = zillow_service.process_listing(CANONICAL_RECORD)

    assert isinstance(mapped, ListingCreate)
    assert mapped.rent == 2750.0
    assert mapped.broker_fee == 1200.0
    assert mapped.square_footage == 720.0
    assert mapped.bedrooms == 2
    assert mapped.bathrooms == 1
    assert mapped.available_date == datetime(2026, 9, 1)
    assert mapped.street_address == "18 Fulton Street"
    assert mapped.zillow_url == CANONICAL_RECORD["zillow_url"]


# The transform reads the alternate provider key spellings
def test_the_transform_reads_the_alternate_provider_key_spellings():
    """The quoted, formatted, alternately named record maps identically."""
    canonical = zillow_service.process_listing(CANONICAL_RECORD)
    alternate = zillow_service.process_listing(ALTERNATE_RECORD)

    assert alternate.dict() == canonical.dict()


# The transform supplies no server-owned column
def test_the_transform_supplies_no_server_owned_column():
    """The mapped record names none of the columns the server sets."""
    mapped = zillow_service.process_listing(CANONICAL_RECORD).dict()

    for column in SERVER_OWNED_COLUMNS:
        assert column not in mapped, column


# SEC-05: a provider key outside the allow-list is not absorbed
@pytest.mark.parametrize(
    "hostile_key", ["id", "created_at", "updated_at", "owner_id"]
)
def test_a_provider_key_outside_the_allow_list_is_not_absorbed(hostile_key):
    """A server-owned or unknown provider key reaches no column."""
    record = dict(CANONICAL_RECORD)
    record[hostile_key] = 99999

    mapped = zillow_service.process_listing(record).dict()

    assert hostile_key not in mapped


# A record with no rent cannot be mapped, because the column is NOT NULL
def test_a_record_without_a_rent_value_is_refused():
    """The transform refuses a record missing the one required column."""
    record = dict(CANONICAL_RECORD)
    del record["rent"]

    with pytest.raises(ValueError) as refused:
        zillow_service.process_listing(record)

    assert "rent" in str(refused.value)


# An unusable value in a required column is refused rather than coerced
@pytest.mark.parametrize("rent", ["", "not-a-number", None, True])
def test_an_unusable_rent_value_is_refused(rent):
    """A blank, non-numeric, null or boolean rent is refused."""
    record = dict(CANONICAL_RECORD)
    record["rent"] = rent

    with pytest.raises((ValueError, ValidationError)):
        zillow_service.process_listing(record)


# The transform omits an optional column the provider does not supply
def test_an_omitted_optional_column_is_left_unset():
    """A column the provider omits is absent from the mapped field set."""
    record = {"rent": 1900, "detailUrl": "https://example.com/listing/2"}

    mapped = zillow_service.process_listing(record)

    # the updater writes exclude_unset, so an omitted column reaches no row
    assert mapped.dict(exclude_unset=True) == {
        "rent": 1900,
        "zillow_url": "https://example.com/listing/2",
    }
    assert mapped.broker_fee is None
    assert mapped.street_address is None


# The updater fetches, transforms, writes and the row reads back
def test_the_updater_commits_a_fetched_record(monkeypatch, db_session):
    """One fetched provider record becomes one stored listing."""
    _seed_tracked_zip_code(db_session)

    _run_updater(monkeypatch, [CANONICAL_RECORD])

    stored = _stored_listings(db_session)
    assert len(stored) == 1
    row = stored[0]
    assert row.rent == 2750.0
    assert row.broker_fee == 1200.0
    assert row.square_footage == 720.0
    assert row.bedrooms == 2
    assert row.bathrooms == 1
    assert row.available_date == datetime(2026, 9, 1)
    assert row.street_address == "18 Fulton Street"
    assert row.zillow_url == CANONICAL_RECORD["zillow_url"]
    # the server owns both timestamps, and both are populated
    assert row.created_at is not None
    assert row.updated_at is not None


# The updater passes the tracked zip codes the fetch requires
def test_the_updater_passes_the_tracked_zip_codes(monkeypatch, db_session):
    """The provider receives the zip codes the stored filters name."""
    _seed_tracked_zip_code(db_session, "10038")
    _seed_tracked_zip_code(db_session, "11201")
    capture = []

    _run_updater(monkeypatch, [], capture=capture)

    assert len(capture) == 1
    zip_codes, filters = capture[0]
    assert sorted(zip_codes) == ["10038", "11201"]
    assert filters == {}


# With no zip code stored there is nothing to fetch
def test_the_updater_fetches_nothing_when_no_zip_code_is_tracked(
    monkeypatch, db_session
):
    """No stored zip code means no provider call and no stored listing."""
    capture = []

    _run_updater(monkeypatch, [CANONICAL_RECORD], capture=capture)

    assert capture == []
    assert _stored_listings(db_session) == []


# The updater matches an existing row on the provider reference
def test_the_updater_updates_the_row_the_provider_reference_names(
    monkeypatch, db_session
):
    """A second pass updates the same row rather than inserting a second."""
    _seed_tracked_zip_code(db_session)

    _run_updater(monkeypatch, [CANONICAL_RECORD])
    first = _stored_listings(db_session)
    assert len(first) == 1
    identifier = first[0].id
    created_at = first[0].created_at

    repriced = dict(CANONICAL_RECORD, rent=2900.0)
    _run_updater(monkeypatch, [repriced])

    db_session.expire_all()
    second = _stored_listings(db_session)
    assert len(second) == 1
    assert second[0].id == identifier
    assert second[0].rent == 2900.0
    # the insertion stamp is not rewritten by an update
    assert second[0].created_at == created_at


# A column the second payload omits keeps its stored value
def test_an_omitted_column_keeps_its_stored_value(monkeypatch, db_session):
    """An update writes only the columns the provider supplied."""
    _seed_tracked_zip_code(db_session)
    _run_updater(monkeypatch, [CANONICAL_RECORD])

    partial = {
        "rent": 2900.0,
        "zillow_url": CANONICAL_RECORD["zillow_url"],
    }
    _run_updater(monkeypatch, [partial])

    db_session.expire_all()
    stored = _stored_listings(db_session)
    assert len(stored) == 1
    assert stored[0].rent == 2900.0
    assert stored[0].broker_fee == 1200.0
    assert stored[0].street_address == "18 Fulton Street"


# One unusable record does not cost the rest of the batch
def test_an_unusable_record_is_skipped_and_the_batch_commits(
    monkeypatch, db_session
):
    """A record the transform refuses is skipped, not fatal."""
    _seed_tracked_zip_code(db_session)
    unusable = {"street_address": "no rent supplied"}
    second = dict(
        CANONICAL_RECORD,
        rent=1500.0,
        zillow_url="https://www.zillow.com/homedetails/second/2",
    )

    _run_updater(monkeypatch, [unusable, CANONICAL_RECORD, second])

    stored = _stored_listings(db_session)
    assert len(stored) == 2
    assert sorted(row.rent for row in stored) == [1500.0, 2750.0]


# A record carrying no provider reference is still stored
def test_a_record_without_a_provider_reference_is_stored(
    monkeypatch, db_session
):
    """A feed record with no reference inserts rather than raising."""
    _seed_tracked_zip_code(db_session)

    _run_updater(monkeypatch, [{"rent": 2100.0}])

    stored = _stored_listings(db_session)
    assert len(stored) == 1
    assert stored[0].rent == 2100.0
    assert stored[0].zillow_url is None


# Ingestion leaves the stored filters it read untouched
def test_ingestion_writes_nothing_to_the_filters_it_read(
    monkeypatch, db_session
):
    """Reading the watched zip codes mutates no filter state."""
    _seed_tracked_zip_code(db_session)
    before = (
        db_session.query(Filter).count(),
        db_session.query(ZipCode).count(),
        db_session.query(Criteria).count(),
    )

    _run_updater(monkeypatch, [CANONICAL_RECORD])

    db_session.expire_all()
    assert (
        db_session.query(Filter).count(),
        db_session.query(ZipCode).count(),
        db_session.query(Criteria).count(),
    ) == before


# The frozen one-hour cadence is unchanged
def test_the_one_hour_cadence_is_preserved():
    """AAP 0.1.4 freezes the ingestion schedule."""
    assert listing_updater.UPDATE_INTERVAL == EXPECTED_UPDATE_INTERVAL


# The outbound request carries a bounded connect and read timeout
def test_the_outbound_request_carries_a_bounded_timeout(monkeypatch):
    """Every provider call passes the bounded (connect, read) pair."""
    captured = {}

    class _Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"listings": []}

    def _stub_get(url, **kwargs):
        captured.update(kwargs)
        return _Response()

    monkeypatch.setattr(zillow_service.requests, "get", _stub_get)

    zillow_service.fetch_listings(["10038"], {})

    assert captured["timeout"] == zillow_service.REQUEST_TIMEOUT
    connect, read = zillow_service.REQUEST_TIMEOUT
    assert 0 < connect <= 30
    assert 0 < read <= 30


def _serve_one_slow_response(delay, ready, stop):
    """Accept one connection, wait ``delay``, then answer."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    ready.append(listener.getsockname()[1])
    listener.settimeout(15)
    try:
        connection, _peer = listener.accept()
    except socket.timeout:
        listener.close()
        return
    try:
        connection.recv(4096)
        waited = 0.0
        while waited < delay and not stop.is_set():
            time.sleep(0.05)
            waited += 0.05
        if not stop.is_set():
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: 15\r\n\r\n{\"listings\": []}"
            )
    except OSError:
        pass
    finally:
        connection.close()
        listener.close()


def _measure_against_a_stalled_provider(monkeypatch, delay, read_timeout):
    """Return (elapsed, result) for one fetch against a stalled server."""
    ready = []
    stop = threading.Event()
    server = threading.Thread(
        target=_serve_one_slow_response, args=(delay, ready, stop),
        daemon=True,
    )
    server.start()
    for _attempt in range(200):
        if ready:
            break
        time.sleep(0.01)
    assert ready, "the stalled provider never bound a port"

    monkeypatch.setattr(
        zillow_service,
        "ZILLOW_API_URL",
        "http://127.0.0.1:{0}/listings".format(ready[0]),
    )
    monkeypatch.setattr(
        zillow_service, "REQUEST_TIMEOUT", (2, read_timeout)
    )
    started = time.monotonic()
    try:
        result = zillow_service.fetch_listings(["10038"], {})
    finally:
        elapsed = time.monotonic() - started
        stop.set()
        server.join(5)
    return elapsed, result


# A slow provider cannot hold the worker past the read timeout
def test_a_slow_provider_is_abandoned_at_the_read_timeout(monkeypatch):
    """A provider slower than the read timeout fails closed and returns."""
    elapsed, result = _measure_against_a_stalled_provider(
        monkeypatch, delay=8.0, read_timeout=1
    )

    assert result == []
    assert elapsed < 5.0, elapsed


# A provider that accepts and never answers is abandoned too
def test_a_never_answering_provider_is_abandoned(monkeypatch):
    """An upstream that never answers cannot hold the worker open."""
    elapsed, result = _measure_against_a_stalled_provider(
        monkeypatch, delay=30.0, read_timeout=1
    )

    assert result == []
    assert elapsed < 5.0, elapsed


# A provider failure returns the empty batch rather than raising
def test_a_provider_failure_returns_an_empty_batch(monkeypatch):
    """A refused connection is answered with no listings."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    monkeypatch.setattr(
        zillow_service,
        "ZILLOW_API_URL",
        "http://127.0.0.1:{0}/listings".format(port),
    )

    assert zillow_service.fetch_listings(["10038"], {}) == []
