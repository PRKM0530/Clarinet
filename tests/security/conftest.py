"""
Test setup for the security tests.

Points the app at a throw-away SQLite file before clarinet is imported, so the
real clarinet.db is never touched.
"""

import os
import sys
import tempfile
from pathlib import Path

_db_file = Path(tempfile.mkdtemp(prefix="clarinet_test_")) / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_db_file.as_posix()}"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["APP_ENV"] = "test"

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest  # noqa: E402

from clarinet.database import Base, SessionLocal, engine  # noqa: E402
import clarinet.models  # noqa: E402,F401  (registers every table)


@pytest.fixture()
def db():
    """A clean database for each test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
