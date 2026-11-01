"""
tests/m3_performance/conftest.py
Shared fixtures for M3 performance / slowdown tests.
Uses an in-memory SQLite DB so no real pinger / nft required.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from clarinet.database import Base


# ── engine & session ───────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def db(engine):
    """Provide a fresh, auto-rolling-back DB session per test."""
    connection = engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


# ── helpers ────────────────────────────────────────────────────────────────────

def utc(*args) -> datetime:
    """Shorthand UTC datetime: utc(2024,1,1,12,0)."""
    return datetime(*args, tzinfo=timezone.utc)

