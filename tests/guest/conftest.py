"""
tests/guest/conftest.py
Fixtures for the guest-role audit (M2 audit duties).
"""
import os
import pytest


def pytest_configure(config):
    os.environ.setdefault("APP_ENV", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-guest-audit-xyz")


@pytest.fixture(scope="session")
def app():
    import tempfile, os
    db_path = tempfile.mktemp(suffix=".db")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["APP_ENV"] = "test"
    os.environ["SECRET_KEY"] = "test-secret-key-guest-audit-xyz"

    from clarinet import app as _app
    from clarinet.database import Base, engine
    from clarinet.models import Member
    from clarinet.auth import hash_password

    Base.metadata.create_all(bind=engine)
    from clarinet.database import SessionLocal
    with SessionLocal() as db:
        db.add(Member(username="admin_ga", password_hash=hash_password("adminpass999"), role="ADMIN", is_active=True))
        db.add(Member(username="member_ga", password_hash=hash_password("memberpass999"), role="MEMBER", is_active=True))
        db.commit()
    return _app


@pytest.fixture(scope="session")
def admin_client(app):
    from fastapi.testclient import TestClient
    c = TestClient(app, raise_server_exceptions=True)
    c.post("/login", data={"username": "admin_ga", "password": "adminpass999"}, follow_redirects=True)
    return c


@pytest.fixture(scope="session")
def guest_client(app):
    """An unauthenticated client — simulates a guest (voucher holder)."""
    from fastapi.testclient import TestClient
    return TestClient(app, raise_server_exceptions=True)


def pytest_collection_modifyitems(items):
    import os
    skip_lab = pytest.mark.skip(reason="linux_lab: set CLARINET_LAB=1 to run")
    for item in items:
        if item.get_closest_marker("linux_lab") and not os.environ.get("CLARINET_LAB"):
            item.add_marker(skip_lab)
