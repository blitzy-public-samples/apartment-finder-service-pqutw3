"""Bounded scheduled ingestion and reconciliation of provider
listings.
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

#: Message recorded when the in-process schedule absorbs a failed pass and
#: continues to the next one. A caller running a single pass per process
#: receives the failure instead of this record.
SCHEDULE_CONTINUED_MESSAGE = (
    "Continuing the ingestion schedule after a failed pass"
)

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
    the driver error class when the exception wraps one and the provider's
    stable refusal reason when the error carries one. No message text is
    included: a driver message carries the server's own detail line,
    which repeats the value it refused.
    """
    origin = getattr(error, "orig", None)
    reason = getattr(error, "reason", None)
    return {
        "exception_type": type(error).__name__,
        "exception_module": getattr(type(error), "__module__", None),
        "database_error": (
            type(origin).__name__ if origin is not None else None
        ),
        "provider_reason": reason if isinstance(reason, str) else None,
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
    """Run one bounded ingestion cycle, reconcile each chunk, commit
    once, and log and roll back any cycle failure.
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
        # defines it, the driver's error class and the provider's refusal
        # reason where it carries one, together with the pass metadata. No
        # message text is carried.
        log_exception(
            logger,
            INGESTION_FAILED_MESSAGE,
            e,
            processed_listings=processed,
            exception_message=None,
            database_error=_failure_fields(e)["database_error"],
            provider_reason=_failure_fields(e)["provider_reason"],
        )
        raise
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
    and cancelled to stop it. :func:`update_listings` re-raises a failed
    pass, so a failure is caught here, recorded once as the exception's
    class with no message text, and followed by the next cycle after the
    same interval. Cancellation is not a failure and is allowed through,
    so the task still stops when it is cancelled.
    """
    while True:
        try:
            await update_listings()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log_exception(
                logger,
                SCHEDULE_CONTINUED_MESSAGE,
                e,
                exception_message=None,
                provider_reason=_failure_fields(e)["provider_reason"],
            )
        await asyncio.sleep(UPDATE_INTERVAL.total_seconds())
