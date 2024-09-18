from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from backend.app.api.router import api_router
from backend.app.core.config import settings
from backend.app.db.database import engine, SessionLocal, Base

app = FastAPI()

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    Base.metadata.create_all(bind=engine)

# HUMAN ASSISTANCE NEEDED
# The following setup section has a confidence level below 0.8 and may need review
# Application setup and configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

create_tables()

# TODO: Add exception handlers