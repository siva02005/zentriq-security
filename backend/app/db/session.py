from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from backend.app.core.config import settings
from backend.app.db.base import Base
import os

# Ensure data directory exists for file-backed SQLite
if settings.DATABASE_URL.startswith("sqlite") and ":memory:" not in settings.DATABASE_URL:
    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)

# For in-memory SQLite, use StaticPool so all connections share the same DB
_engine_kwargs = {}
if ":memory:" in settings.DATABASE_URL:
    _engine_kwargs["poolclass"] = StaticPool

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
    echo=settings.DEBUG,
    **_engine_kwargs,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    # Import all models so they register with Base
    import backend.app.models.policy  # noqa
    import backend.app.models.audit  # noqa
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
