"""
tests/member/conftest.py
Shared fixtures for member-role audit tests.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from clarinet.database import Base
from clarinet.models import Member, Device


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
    connection = engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture()
def alice(db):
    """Member Alice (regular member, not admin)."""
    m = Member(username="alice", password_hash="hashed", role="MEMBER")
    db.add(m)
    db.flush()
    return m


@pytest.fixture()
def bob(db):
    """Member Bob (regular member, not admin)."""
    m = Member(username="bob", password_hash="hashed", role="MEMBER")
    db.add(m)
    db.flush()
    return m


@pytest.fixture()
def alice_device(db, alice):
    """A device owned by Alice."""
    d = Device(
        mac_address="AA:BB:CC:DD:EE:01",
        ip_address="192.168.1.10",
        hostname="alice-laptop",
        state="APPROVED",
        owner_member_id=alice.member_id,
    )
    db.add(d)
    db.flush()
    return d


@pytest.fixture()
def bob_device(db, bob):
    """A device owned by Bob."""
    d = Device(
        mac_address="AA:BB:CC:DD:EE:02",
        ip_address="192.168.1.11",
        hostname="bob-phone",
        state="APPROVED",
        owner_member_id=bob.member_id,
    )
    db.add(d)
    db.flush()
    return d
