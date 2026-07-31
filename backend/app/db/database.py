from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app.core.config import settings

# SEC-10: explicit transport encryption; replaces the inherited
# 'prefer' negotiation
engine = create_engine(
    settings.DATABASE_URL,
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