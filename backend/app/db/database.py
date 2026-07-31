from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app.core.config import settings

# SEC-10: applies the configured SSL mode to PostgreSQL connections.
# SEC-08: hide_parameters keeps bound values, which include credentials,
# out of SQLAlchemy exception text and log records (CWE-532)
engine = create_engine(
    settings.DATABASE_URL,
    hide_parameters=True,
    **(
        {"connect_args": {"sslmode": settings.DB_SSLMODE}}
        if settings.DATABASE_URL.startswith("postgres")
        else {}
    ),
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()