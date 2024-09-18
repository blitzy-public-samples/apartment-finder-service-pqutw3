from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
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

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime)
    status = Column(String, nullable=False)

    user = relationship("User", back_populates="subscriptions")

# HUMAN ASSISTANCE NEEDED
# Please review the following:
# 1. Ensure that all necessary indexes are added for optimal query performance.
# 2. Consider adding any additional constraints or validations that may be required.
# 3. Verify if any additional relationships or cascade behaviors need to be defined.
# 4. Check if any fields should have default values or additional constraints.