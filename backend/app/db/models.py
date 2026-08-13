from sqlalchemy import (
    Column, Index, Integer, String, Float, DateTime, ForeignKey, Numeric,
    UniqueConstraint, event, func, text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

#: Non-unique index names supporting application query predicates.
WORKLOAD_INDEX_NAMES = (
    "ix_filters_user_id_id",
    "ix_zip_codes_filter_id",
    "ix_criteria_filter_id",
    "ix_subscriptions_user_id_status_end_date",
    "ix_subscriptions_user_id_plan_id_status",
    "ix_listings_zillow_url",
)

#: Statuses marking a subscription row as an open payment intent: a
#: charge its owner may still complete. These mirror ``STATUS_PENDING``
#: and ``STATUS_FAILED`` in ``backend.app.core.plans``, which this module
#: does not import so that it keeps importing nothing from the
#: application. A contract test pins the two sets to each other.
OPEN_INTENT_STATUSES = ("pending", "failed")

#: Name of the partial unique index holding an owner to at most one open
#: payment intent per plan. Revision ``0004_add_open_intent_uniqueness``
#: creates the same index under the same name over the same predicate, so
#: the mapped table and the migrated table carry the same uniqueness.
OPEN_INTENT_UNIQUE_INDEX_NAME = "uq_subscriptions_open_intent_per_plan"

#: The ``WHERE`` clause restricting ``OPEN_INTENT_UNIQUE_INDEX_NAME`` to
#: rows in the open window. A row whose status records a settlement or a
#: reversal, and a row whose entitlement window has been closed, falls
#: outside the predicate and carries no uniqueness from it.
OPEN_INTENT_INDEX_PREDICATE = "status IN ({0}) AND end_date IS NULL".format(
    ", ".join("'{0}'".format(status) for status in OPEN_INTENT_STATUSES)
)

#: Number of rows :class:`LoginAttemptSlot` holds. The table is this size
#: and no other: revision ``0005_add_login_attempt_slots`` seeds one row
#: per bucket in ``range(LOGIN_ATTEMPT_SLOT_COUNT)``, and every login
#: refusal updates one of those rows. The migration and
#: :func:`backend.app.core.security.login_attempt_slot` read this same
#: value, so a bucket the application computes always names a row that
#: exists.
LOGIN_ATTEMPT_SLOT_COUNT = 1024


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False)
    last_login = Column(DateTime)
    role = Column(String, nullable=False, server_default="registered")
    failed_login_attempts = Column(Integer, nullable=False, server_default="0")
    # Instant the account's lock expires, held with its offset. It is
    # compared against the server clock without a zone assumption.
    locked_until = Column(
        DateTime(timezone=True), nullable=True, server_default=text("NULL")
    )

    filters = relationship("Filter", back_populates="user")
    subscriptions = relationship("Subscription", back_populates="user")


class Listing(Base):
    __tablename__ = 'listings'
    # The index over the provider address is non-unique, so it supports
    # the reconciliation lookup without refusing a repeated address.
    __table_args__ = (
        Index("ix_listings_zillow_url", "zillow_url"),
    )

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    rent = Column(Float, nullable=False)
    broker_fee = Column(Float)
    square_footage = Column(Float)
    bedrooms = Column(Integer)
    bathrooms = Column(Integer)
    available_date = Column(DateTime)
    street_address = Column(String)
    # Provider address used by scheduled reconciliation; duplicates are
    # allowed.
    zillow_url = Column(String)


class Filter(Base):
    __tablename__ = 'filters'
    # Supports the owner-scoped page the filters endpoint reads, whose
    # predicate is user_id and whose order and offset follow id.
    __table_args__ = (
        Index("ix_filters_user_id_id", "user_id", "id"),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False)
    last_used = Column(DateTime)

    user = relationship("User", back_populates="filters")
    zip_codes = relationship("ZipCode", back_populates="filter")
    criteria = relationship("Criteria", back_populates="filter")


class ZipCode(Base):
    __tablename__ = 'zip_codes'
    # Supports the page-wide load of the postal codes belonging to a
    # page of filters, whose predicate is filter_id.
    __table_args__ = (
        Index("ix_zip_codes_filter_id", "filter_id"),
    )

    id = Column(Integer, primary_key=True)
    filter_id = Column(Integer, ForeignKey('filters.id'), nullable=False)
    code = Column(String, nullable=False)

    filter = relationship("Filter", back_populates="zip_codes")


class Criteria(Base):
    __tablename__ = 'criteria'
    # Supports the page-wide load of the predicates belonging to a page
    # of filters, whose predicate is filter_id.
    __table_args__ = (
        Index("ix_criteria_filter_id", "filter_id"),
    )

    id = Column(Integer, primary_key=True)
    filter_id = Column(Integer, ForeignKey('filters.id'), nullable=False)
    field = Column(String, nullable=False)
    operator = Column(String, nullable=False)
    value = Column(String, nullable=False)

    filter = relationship("Filter", back_populates="criteria")


class Subscription(Base):
    __tablename__ = 'subscriptions'
    # The two indexes support the predicates the entitlement decision
    # and the subscription routes issue: the owner with the status and
    # the entitlement window, and the owner with the plan and the status.
    __table_args__ = (
        UniqueConstraint(
            'paypal_order_id', name='uq_subscriptions_paypal_order_id'
        ),
        Index(
            "ix_subscriptions_user_id_status_end_date",
            "user_id",
            "status",
            "end_date",
        ),
        Index(
            "ix_subscriptions_user_id_plan_id_status",
            "user_id",
            "plan_id",
            "status",
        ),
        Index(
            OPEN_INTENT_UNIQUE_INDEX_NAME,
            "user_id",
            "plan_id",
            unique=True,
            postgresql_where=text(OPEN_INTENT_INDEX_PREDICATE),
            sqlite_where=text(OPEN_INTENT_INDEX_PREDICATE),
        ),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime)
    status = Column(String, nullable=False)
    plan_id = Column(String, nullable=True, server_default=text("NULL"))
    amount = Column(
        Numeric(10, 2), nullable=True, server_default=text("NULL")
    )
    currency = Column(String, nullable=False, server_default="USD")
    paypal_order_id = Column(
        String, nullable=True, server_default=text("NULL")
    )

    user = relationship("User", back_populates="subscriptions")


class LoginAttemptSlot(Base):
    __tablename__ = 'login_attempt_slots'
    # A fixed set of LOGIN_ATTEMPT_SLOT_COUNT rows, seeded by revision
    # 0005 and never added to or removed from at runtime. A refused login
    # takes a write lock on the one row its bucket names, updates it and
    # commits, so the refusal branches that hold no account row still
    # perform one locking read, one write and one commit.
    #
    # The bucket is a keyed digest of the submitted address, computed by
    # backend.app.core.security.login_attempt_slot. No address, no
    # credential and no account identifier is stored here: a row records
    # only how many refusals landed on its bucket and when the last one
    # did, and several addresses may share a bucket.

    bucket = Column(Integer, primary_key=True, autoincrement=False)
    attempts = Column(Integer, nullable=False, server_default="0")
    # Instant the most recent refusal landed on this bucket, held with its
    # offset. Null until one has.
    observed_at = Column(
        DateTime(timezone=True), nullable=True, server_default=text("NULL")
    )


@event.listens_for(LoginAttemptSlot.__table__, "after_create")
def _seed_login_attempt_slots(target, connection, **kwargs) -> None:
    """Seed one row per bucket as part of creating the table.

    The full set of ``LOGIN_ATTEMPT_SLOT_COUNT`` rows is part of the
    table's definition: the application updates one of them on a refused
    login and never inserts one, so a bucket it computes has to name a row
    that exists.

    Revision ``0005_add_login_attempt_slots`` seeds this same set for a
    schema built by migration. This listener seeds it for a schema built
    by ``Base.metadata.create_all``, so both ways of building the schema
    leave the same rows in place.
    """
    connection.execute(
        target.insert(),
        [
            {"bucket": bucket, "attempts": 0}
            for bucket in range(LOGIN_ATTEMPT_SLOT_COUNT)
        ],
    )


class WebhookEvent(Base):
    __tablename__ = 'webhook_events'
    __table_args__ = (
        UniqueConstraint(
            'transmission_id', name='uq_webhook_events_transmission_id'
        ),
    )

    id = Column(Integer, primary_key=True)
    transmission_id = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    # Instant the delivery was recorded, held with its offset.
    received_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
