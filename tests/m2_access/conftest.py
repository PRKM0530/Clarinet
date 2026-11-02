"""
tests/m2_access/conftest.py
Test fixtures for M2 (guest, speed, rules, priority).
"""
import os
import tempfile
import pytest

# ── set env vars BEFORE importing clarinet ──────────────────────────────────
def pytest_configure(config):
    os.environ.setdefault("APP_ENV", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-m2-access-1234567890")


@pytest.fixture(scope="session")
def tmp_db_path(tmp_path_factory):
    return str(tmp_path_factory.mktemp("db") / "test_m2.db")


@pytest.fixture(scope="session")
def app(tmp_db_path):
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp_db_path}"
    os.environ["APP_ENV"] = "test"
    os.environ["SECRET_KEY"] = "test-secret-key-m2-access-1234567890"

    from clarinet import app as _app
    from clarinet.database import Base, engine
    from clarinet.models import Member
    from clarinet.auth import hash_password

    Base.metadata.create_all(bind=engine)

    # Seed admin + member
    from clarinet.database import SessionLocal
    with SessionLocal() as db:
        if not db.query(Member).filter(Member.username == "admin").first():
            db.add(Member(
                username="admin",
                password_hash=hash_password("adminpassword123"),
                role="ADMIN",
                is_active=True,
            ))
        if not db.query(Member).filter(Member.username == "member1").first():
            db.add(Member(
                username="member1",
                password_hash=hash_password("memberpassword123"),
                role="MEMBER",
                is_active=True,
            ))
        db.commit()

    return _app


@pytest.fixture(scope="session")
def client(app):
    from httpx import Client
    from fastapi.testclient import TestClient
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(scope="session")
def admin_client(app):
    from fastapi.testclient import TestClient
    c = TestClient(app, raise_server_exceptions=True)
    resp = c.post("/login", data={"username": "admin", "password": "adminpassword123"}, follow_redirects=True)
    assert resp.status_code == 200
    return c


@pytest.fixture(scope="session")
def member_client(app):
    from fastapi.testclient import TestClient
    c = TestClient(app, raise_server_exceptions=True)
    resp = c.post("/login", data={"username": "member1", "password": "memberpassword123"}, follow_redirects=True)
    assert resp.status_code == 200
    return c


@pytest.fixture(scope="session")
def anon_client(app):
    from fastapi.testclient import TestClient
    return TestClient(app, raise_server_exceptions=True)


# ── FakeRunner for enforcer tests ────────────────────────────────────────────

class FakeRunner:
    """Records commands; returns scripted responses."""
    def __init__(self, responses: dict | None = None):
        self.calls: list[list[str]] = []
        self._responses = responses or {}

    def run(self, argv, input=None, timeout=5):
        self.calls.append(argv)
        from clarinet.enforcer.runner import CommandResult
        key = " ".join(argv[:3])
        resp = self._responses.get(key, self._responses.get("default"))
        if resp:
            return CommandResult(**resp)
        return CommandResult(returncode=0, stdout="", stderr="")


@pytest.fixture()
def fake_runner(monkeypatch):
    runner = FakeRunner()
    import clarinet.enforcer.runner as rmod
    monkeypatch.setattr(rmod, "_runner", runner)
    return runner


# ── Linux-lab skip ────────────────────────────────────────────────────────────

def pytest_collection_modifyitems(items):
    skip_lab = pytest.mark.skip(reason="linux_lab: set CLARINET_LAB=1 to run")
    for item in items:
        if item.get_closest_marker("linux_lab") and not os.environ.get("CLARINET_LAB"):
            item.add_marker(skip_lab)
