"""
tests/m1_core/conftest.py
Test fixtures for M1 core tests.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from clarinet.database import Base, get_db


def _make_engine():
    return create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})


@pytest.fixture(scope="function")
def engine():
    e = _make_engine()
    # Import all models so tables are created
    from clarinet.models import core  # noqa: F401
    from clarinet.models import reports, traffic, devices_ext  # noqa: F401
    Base.metadata.create_all(bind=e)
    yield e
    Base.metadata.drop_all(bind=e)


@pytest.fixture(scope="function")
def db(engine):
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture(scope="function")
def app(engine):
    """FastAPI test app with in-memory DB."""
    from clarinet.main import app as _app

    Session = sessionmaker(bind=engine)

    def override_get_db():
        session = Session()
        try:
            yield session
        finally:
            session.close()

    _app.dependency_overrides[get_db] = override_get_db
    yield _app
    _app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def anon_client(app):
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(scope="function")
def _make_admin(db):
    """Create the default admin account + mark setup done."""
    from clarinet.auth import hash_password
    from clarinet.models import Member, Settings

    admin = Member(
        username="admin",
        password_hash=hash_password("Admin@secure1"),
        role="ADMIN",
        is_active=True,
    )
    db.add(admin)
    db.add(Settings(key="setup_complete", value="true"))
    db.commit()
    db.refresh(admin)
    return admin


@pytest.fixture(scope="function")
def admin_client(app, engine, _make_admin):
    """TestClient logged in as admin."""
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.post("/login", data={"username": "admin", "password": "Admin@secure1"})
    assert resp.status_code in (200, 302), f"Admin login failed: {resp.status_code}"
    return client


@pytest.fixture(scope="function")
def _make_member(db):
    from clarinet.auth import hash_password
    from clarinet.models import Member

    member = Member(
        username="alice",
        password_hash=hash_password("Alice@secure1"),
        role="MEMBER",
        is_active=True,
    )
    db.add(member)
    db.commit()
    db.refresh(member)
    return member


@pytest.fixture(scope="function")
def member_client(app, engine, _make_admin, _make_member):
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.post("/login", data={"username": "alice", "password": "Alice@secure1"})
    assert resp.status_code in (200, 302), f"Member login failed: {resp.status_code}"
    return client

