"""
Test setup for the security tests.

tests/conftest.py points the session at a throw-away database; this file only
double-checks that before it drops and recreates tables.
"""

import pytest

from clarinet.database import Base, SessionLocal, engine
import clarinet.models  # noqa: F401  (registers every table)


@pytest.fixture()
def db():
    """A clean database for each test."""
    assert "clarinet_test_" in str(engine.url), (
        f"refusing to reset tables on {engine.url}: not the throw-away test database"
    )
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
