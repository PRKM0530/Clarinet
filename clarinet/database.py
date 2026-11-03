"""
clarinet/database.py
SQLAlchemy sync engine with SQLite WAL mode + a writer-queue comment.

WAL mode lets multiple readers run while one writer holds the lock,
so the APScheduler thread writing traffic counters never blocks the
web worker responding to the dashboard.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from clarinet.config import settings

# Engine
# check_same_thread=False is required for SQLite when the engine is shared
# across threads (FastAPI + APScheduler both hit it).
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
    # Pool size 1 = one writer at a time, matches SQLite's single-writer model
    pool_size=1,
    max_overflow=4,
    echo=settings.APP_ENV == "development",
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _record):
    """
    Run once per new connection.
    WAL  → readers don't block writers and vice-versa.
    NORMAL → flush at checkpoints, not every commit (safe enough for LAN tool).
    FK ON  → enforce foreign-key constraints.
    """
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA cache_size=-8000")   # 8 MB page cache
    cursor.close()


# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Base class for all ORM models
class Base(DeclarativeBase):
    pass


# Dependency injected into FastAPI route functions
def get_db():
    """Yields a DB session and always closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
