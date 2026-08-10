"""Scheduled ingestion of provider listings into the ``listings`` table.

One pass reads the postal codes stored on saved filters, asks the
provider for the listings covering them, maps each returned record onto
the listing creation contract, and reconciles it against the stored
corpus on :data:`IDENTITY_COLUMN`: a record whose value already names a
stored row updates that row rather than adding another.

Two bounds keep the work one pass does independent of how large the
corpus of saved filters grows. :func:`tracked_zip_codes` reads at most
``settings.INGESTION_MAX_ZIP_CODES`` postal codes, recording once when it
reaches that number, and :func:`zip_code_chunks` splits what it read into
requests of at most ``settings.INGESTION_ZIP_CODE_CHUNK`` postal codes
each, so no single provider request carries an unbounded list. Each
chunk's provider response is bounded in turn by the provider client.

Within one chunk the stored rows every record in it might reconcile
against are read by :func:`_existing_by_identity` in one statement, so
the number of read statements a pass issues follows the number of chunks
rather than the number of records the provider returned.

That reconciliation is a read followed by a write, and the column it
matches on carries no uniqueness in the mapped table or in revision
``0001``, so the database refuses nothing on the strength of it. Two
passes running at once may therefore each read no row and each insert
one, leaving two rows carrying one value. The read is ordered by primary
key and takes the first row, so once that has happened every later pass
reconciles the same one of them and the corpus does not keep growing.

Every write goes through a mapped ORM instance and names its columns
explicitly: a record is either constructed as a new
:class:`backend.app.db.models.Listing` or assigned onto the declared
mutable columns of the row it matches. No attribute is copied
dynamically from a provider object, and the identity column and the
server-assigned ``id`` and ``created_at`` are never reassigned.

A record carrying no identity is discarded rather than recorded, so it is
never inserted and never reconciled. A record that fails the contract is
discarded the same way, and names the contract fields it failed. A record
the database refuses for a reason that describes that record -- one
:func:`_is_record_failure` attributes to it, drawn from
:data:`RECORD_FAILURES` -- is discarded too: each record is written inside
its own savepoint, so one unwritable record is counted and dropped while
every other record in the same payload is still recorded. All three are
counted and reported once per pass. A failure that describes the session,
the database or this module ends the pass instead, and is never counted as
a record the database refused.

The pass owns one session and commits once. Any failure rolls the session
back and is reported rather than propagated, and the schedule continues.
A failure is reported by exception class -- and by the driver's error
class where the database raised it -- carrying no message text, and no
provider value travels with it.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from sqlalchemy.exc import (
    DataError,
    DBAPIError,
    IntegrityError,
    StatementError,
)
from sqlalchemy.orm import Session
from backend.app.db.database import SessionLocal
from backend.app.services.zillow_service import (
    ListingMappingError,
    fetch_listings,
    process_listing,
)
from backend.app.db.models import Listing, ZipCode
from backend.app.schema.listing import ListingCreate
from backend.app.core.config import settings
from backend.app.core.logging import (
    bind_request_id,
    bind_trace_context,
    get_logger,
    log_exception,
    new_span_id,
    reset_request_id,
    reset_trace_context,
)

UPDATE_INTERVAL = timedelta(hours=1)

#: Prefix identifying a correlation identifier minted for one ingestion
#: pass rather than for a request. Every record one pass emits carries the
#: same identifier, so the records of one pass can be read together and
#: two passes cannot be confused with one another.
RUN_ID_PREFIX = "ingest-"

#: Column a provider record is reconciled against. It is the only
#: declared column carrying a value the provider assigns per listing. A
#: record whose value already names a row updates that row, so one pass
#: writes one value to one row.
#:
#: The column carries no uniqueness, in the mapped table and in revision
#: ``0001`` alike, so two rows may carry one value. The read is ordered
#: by primary key and takes the first row, which is the earliest row
#: carrying the value: two rows carrying one value resolve to the same
#: one on every pass, rather than to whichever row the database returns
#: first.
IDENTITY_COLUMN = "zillow_url"

#: Provider query filters sent with every scheduled pass. The pass
#: narrows by postal code alone.
PROVIDER_FILTERS: Dict[str, str] = {}

#: Message recorded when one ingestion pass does not complete.
INGESTION_FAILED_MESSAGE = "An error occurred while updating listings"

#: Message recorded when the database refuses one provider record.
RECORD_REFUSED_MESSAGE = "Discarded a provider listing the database refused"

#: Message recorded when one pass reads as many postal codes as
#: ``settings.INGESTION_MAX_ZIP_CODES`` admits, so saved filters may name
#: more than the pass covered.
ZIP_CODE_CAP_REACHED_MESSAGE = (
    "Read the configured maximum number of postal codes, so a pass may "
    "not cover every postal code saved filters name"
)

#: Failures :func:`_is_record_failure` examines. Every one of them is
#: raised for one statement, so the record that statement writes is named
#: by the exception itself. A failure outside this set -- a lost
#: connection, a missing privilege, a schema mismatch, or a defect in
#: this module raising ``ValueError`` or ``TypeError`` on its own --
#: describes the session, the database or the code rather than the record,
#: applies to every record equally, and ends the pass.
RECORD_FAILURES = (IntegrityError, DataError, StatementError)

#: Causes a bind-processing failure carries. A statement whose parameters
#: could not be prepared raises before the database is reached, and the
#: value that could not be prepared belongs to the one record being
#: written.
BIND_FAILURE_CAUSES = (TypeError, ValueError)

logger = get_logger(__name__)


def _is_record_failure(error: BaseException) -> bool:
    """Reports whether ``error`` describes the record being written.

    A constraint violation and a value the column cannot hold both name
    that record. So does a statement whose parameters could not be
    prepared, which the database never received: it carries one of
    :data:`BIND_FAILURE_CAUSES` and is not a driver error. Every other
    driver error describes the session or the database.
    """
    if isinstance(error, (IntegrityError, DataError)):
        return True
    if isinstance(error, DBAPIError):
        return False
    return isinstance(
        getattr(error, "orig", None), BIND_FAILURE_CAUSES
    )


def _failure_fields(error: BaseException) -> Dict[str, Optional[str]]:
    """Returns the class-level description of ``error``.

    The exception's class and defining module are reported, together with
    the driver error class when the exception wraps one. No message text
    is included: a driver message carries the server's own detail line,
    which repeats the value it refused.
    """
    origin = getattr(error, "orig", None)
    return {
        "exception_type": type(error).__name__,
        "exception_module": getattr(type(error), "__module__", None),
        "database_error": (
            type(origin).__name__ if origin is not None else None
        ),
    }


def tracked_zip_codes(db: Session) -> List[str]:
    """Returns the distinct postal codes saved filters name.

    Blank and non-string values are dropped, and the result is sorted so
    one pass sends the provider a stable list.

    The statement reads at most ``settings.INGESTION_MAX_ZIP_CODES``
    rows, and the returned list carries at most that many entries, so the
    memory one pass holds for this list and the work it hands the
    provider do not follow the number of saved filters. Reaching the cap
    is recorded once, naming the cap.
    """
    ceiling = int(settings.INGESTION_MAX_ZIP_CODES)
    rows = (
        db.query(ZipCode.code)
        .distinct()
        .order_by(ZipCode.code)
        .limit(ceiling)
        .all()
    )
    codes = sorted(
        set(
            code
            for (code,) in rows
            if isinstance(code, str) and code
        )
    )
    if len(rows) >= ceiling:
        logger.warning(
            ZIP_CODE_CAP_REACHED_MESSAGE,
            extra={
                "setting": "INGESTION_MAX_ZIP_CODES",
                "max_zip_codes": ceiling,
                "zip_codes": len(codes),
            },
        )
    return codes


def zip_code_chunks(zip_codes: List[str]) -> List[List[str]]:
    """Returns ``zip_codes`` split into provider-request sized chunks.

    Each chunk carries at most ``settings.INGESTION_ZIP_CODE_CHUNK``
    entries, so the number of postal codes one provider request names is
    bounded whatever the corpus of saved filters holds. An empty input
    yields no chunk.
    """
    size = int(settings.INGESTION_ZIP_CODE_CHUNK)
    return [
        zip_codes[start:start + size]
        for start in range(0, len(zip_codes), size)
    ]


def _existing_by_identity(
    db: Session, identities: List[str]
) -> Dict[str, Listing]:
    """Returns the earliest stored row for each of ``identities``.

    One statement reads every row whose identity column matches any of
    ``identities``, so the number of statements does not follow the
    number of records in a payload. The rows are read in primary-key
    order and the first row carrying a value is the one kept, which is
    the same row the per-record read resolved to, so a value carried by
    two rows reconciles to the earliest of them here as well.

    An empty input reads nothing and returns an empty mapping.
    """
    if not identities:
        return {}
    column = getattr(Listing, IDENTITY_COLUMN)
    found: Dict[str, Listing] = {}
    for row in (
        db.query(Listing)
        .filter(column.in_(identities))
        .order_by(Listing.id)
        .all()
    ):
        value = getattr(row, IDENTITY_COLUMN)
        if value not in found:
            found[value] = row
    return found


def _new_listing(
    processed: ListingCreate,
    moment: datetime,
) -> Listing:
    """Returns a mapped row carrying ``processed``.

    Every column is named explicitly. ``created_at`` and ``updated_at``
    are taken from ``moment`` and ``id`` is left to the database.
    """
    return Listing(
        created_at=moment,
        updated_at=moment,
        rent=processed.rent,
        broker_fee=processed.broker_fee,
        square_footage=processed.square_footage,
        bedrooms=processed.bedrooms,
        bathrooms=processed.bathrooms,
        available_date=processed.available_date,
        street_address=processed.street_address,
        zillow_url=processed.zillow_url,
    )


def _refresh_listing(
    row: Listing,
    processed: ListingCreate,
    moment: datetime,
) -> None:
    """Assigns ``processed`` onto the declared mutable columns of ``row``.

    ``id``, ``created_at`` and the identity column are not assigned. Every
    other declared column is, so a column the provider no longer supplies
    is set to ``None``: the stored row states what the provider currently
    reports rather than accumulating values from earlier passes.
    """
    row.rent = processed.rent
    row.broker_fee = processed.broker_fee
    row.square_footage = processed.square_footage
    row.bedrooms = processed.bedrooms
    row.bathrooms = processed.bathrooms
    row.available_date = processed.available_date
    row.street_address = processed.street_address
    row.updated_at = moment


def _mapped(raw_listing: Dict) -> Optional[ListingCreate]:
    """Returns ``raw_listing`` mapped, or ``None`` when it is unusable.

    A record that fails the contract and a record carrying no identity
    both return ``None``. A contract failure names the contract fields it
    failed, so a systematic discard can be attributed to a field. Neither
    the record nor any provider value reaches the log line.
    """
    try:
        processed = process_listing(raw_listing)
    except ListingMappingError as error:
        logger.warning(
            "Discarded a provider listing that failed the contract",
            extra={"contract_fields": list(error.fields)},
        )
        return None
    if not getattr(processed, IDENTITY_COLUMN):
        logger.warning(
            "Discarded a provider listing that carried no identity",
            extra={"identity_column": IDENTITY_COLUMN},
        )
        return None
    return processed


def _write(
    db: Session,
    existing_listing: Optional[Listing],
    mapped: ListingCreate,
    moment: datetime,
) -> Optional[Listing]:
    """Writes one record inside its own savepoint. Returns the row.

    The row is constructed or refreshed and flushed within a nested
    transaction, and the row that was written is returned, so a later
    record in the same payload carrying the same identity reconciles
    against it rather than adding a second row. A record the database
    refuses is rolled back to the savepoint on its own, and the records
    already written in this pass stay pending. A failure
    :func:`_is_record_failure` attributes to the record is recorded by
    exception class, naming no provider value, and ``None`` is returned.
    Every other failure describes the session, the database or this
    module rather than the record and is raised, ending the pass.
    """
    try:
        with db.begin_nested():
            if existing_listing is None:
                written = _new_listing(mapped, moment)
                db.add(written)
            else:
                written = existing_listing
                _refresh_listing(written, mapped, moment)
            db.flush()
    except RECORD_FAILURES as error:
        if not _is_record_failure(error):
            raise
        fields = _failure_fields(error)
        fields["identity_column"] = IDENTITY_COLUMN
        logger.warning(RECORD_REFUSED_MESSAGE, extra=fields)
        return None
    return written


@asyncio.coroutine
async def update_listings():
    """Run one ingestion cycle over the listings the provider returns.

    Opens its own session, upserts each fetched listing by its Zillow
    identifier -- copying the processed attributes onto an existing row
    or adding a new one -- and commits once at the end of the cycle.

    The postal codes the cycle covers are read under
    ``settings.INGESTION_MAX_ZIP_CODES`` and issued as one provider
    request per chunk of at most ``settings.INGESTION_ZIP_CODE_CHUNK``
    codes. Each chunk's records are reconciled against one read of the
    stored rows for that chunk, and the number of provider requests the
    cycle made is reported alongside the record counts.

    Every provider call is synchronous and is run on a worker thread, so
    awaiting it yields the event loop for the duration of that request
    rather than holding it until the request's timeout elapses.

    Any exception rolls the session back and is recorded through the
    redacting logger rather than propagated, so a failed cycle leaves no
    partial write behind and does not stop the caller. The session is
    closed on every path.

    One correlation identifier and one trace are bound for the whole
    cycle, so every record the cycle emits -- its own, the provider
    client's and the statement logger's -- carries them, and the outbound
    provider call carries the trace onward. Both are unbound on every
    path, so nothing leaks into the next cycle.
    """
    run_id = RUN_ID_PREFIX + new_span_id()
    run_token = bind_request_id(run_id)
    trace_token = bind_trace_context()
    db: Session = SessionLocal()
    processed = 0
    try:
        zip_codes = tracked_zip_codes(db)
        if not zip_codes:
            logger.info(
                "Skipped an ingestion pass because no saved filter "
                "names a postal code"
            )
            return
        chunks = zip_code_chunks(zip_codes)
        moment = datetime.now(timezone.utc)
        received = 0
        recorded = 0
        refreshed = 0
        discarded = 0
        refused = 0
        for chunk in chunks:
            raw_listings = await asyncio.to_thread(
                fetch_listings, chunk, PROVIDER_FILTERS
            )
            received += len(raw_listings)
            mapped_records = []
            for raw_listing in raw_listings:
                # Only the counts are carried outside this loop, so a
                # failure record names how far the pass got and never a
                # listing.
                mapped = _mapped(raw_listing)
                if mapped is None:
                    discarded += 1
                    continue
                mapped_records.append(mapped)
            processed += len(mapped_records)
            # One statement reads the stored rows for the whole chunk, so
            # the number of reads follows the number of chunks rather
            # than the number of records. Every record written in this
            # chunk is flushed as it is written, so a value first seen
            # earlier in the same chunk is reconciled against the row
            # that write produced rather than against a second insert.
            existing = _existing_by_identity(
                db,
                [
                    getattr(mapped, IDENTITY_COLUMN)
                    for mapped in mapped_records
                ],
            )
            for mapped in mapped_records:
                identity = getattr(mapped, IDENTITY_COLUMN)
                existing_listing = existing.get(identity)
                written = _write(db, existing_listing, mapped, moment)
                if written is None:
                    refused += 1
                elif existing_listing is None:
                    recorded += 1
                    existing[identity] = written
                else:
                    refreshed += 1
        db.commit()
        logger.info(
            "Completed an ingestion pass",
            extra={
                "zip_codes": len(zip_codes),
                "provider_requests": len(chunks),
                "received": received,
                "recorded": recorded,
                "refreshed": refreshed,
                "discarded": discarded,
                "refused": refused,
            },
        )
    except Exception as e:
        db.rollback()
        # Records the failure as the exception's class, the module that
        # defines it and the driver's error class, together with the pass
        # metadata. No message text is carried.
        log_exception(
            logger,
            INGESTION_FAILED_MESSAGE,
            e,
            processed_listings=processed,
            exception_message=None,
            database_error=_failure_fields(e)["database_error"],
        )
    finally:
        db.close()
        reset_trace_context(trace_token)
        reset_request_id(run_token)


async def run_listing_updater():
    """Run :func:`update_listings` forever, once per interval.

    Each cycle is awaited and then followed by a sleep of
    :data:`UPDATE_INTERVAL`, so cycles never overlap and the interval is
    measured between the end of one cycle and the start of the next.

    This coroutine does not return: it is scheduled as a background task
    and cancelled to stop it. A failed cycle is followed by the next one
    after the same interval; :func:`update_listings` reports every
    failure rather than propagating it.
    """
    while True:
        await update_listings()
        await asyncio.sleep(UPDATE_INTERVAL.total_seconds())
