from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app.core.config import settings

# SEC-10: explicit transport encryption; replaces the inherited 'prefer'
# negotiation
# SEC-08: bound parameter values are withheld from every statement error
# this engine raises, including background consumers (CWE-532)
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