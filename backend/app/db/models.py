from sqlalchemy import (
    Column, Integer, String, Float, DateTime, ForeignKey, Numeric,
    UniqueConstraint, func, text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


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
    # Provider address a scheduled ingestion pass reconciles a record
    # against.
    zillow_url = Column(String)


class Filter(Base):
    __tablename__ = 'filters'

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

    id = Column(Integer, primary_key=True)
    filter_id = Column(Integer, ForeignKey('filters.id'), nullable=False)
    code = Column(String, nullable=False)

    filter = relationship("Filter", back_populates="zip_codes")


class Criteria(Base):
    __tablename__ = 'criteria'

    id = Column(Integer, primary_key=True)
    filter_id = Column(Integer, ForeignKey('filters.id'), nullable=False)
    field = Column(String, nullable=False)
    operator = Column(String, nullable=False)
    value = Column(String, nullable=False)

    filter = relationship("Filter", back_populates="criteria")


class Subscription(Base):
    __tablename__ = 'subscriptions'
    # The uniqueness over the provider order identifier is declared
    # under the name revision 0001 gives it, so the mapped table and the
    # migrated table carry the same constraint under the same name.
    __table_args__ = (
        UniqueConstraint(
            'paypal_order_id', name='uq_subscriptions_paypal_order_id'
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


class WebhookEvent(Base):
    __tablename__ = 'webhook_events'
    # The uniqueness over the delivery identifier is declared under the
    # name revision 0001 gives it, so the mapped table and the migrated
    # table carry the same constraint under the same name.
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
