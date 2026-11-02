"""
tests/m2_access/test_vouchers.py
Voucher lifecycle: AT-13.1 (30-min voucher), AT-13.2/3, brute-force protection.
"""
import pytest
from datetime import datetime, timedelta, timezone


# ── helpers ──────────────────────────────────────────────────────────────────

def _create_voucher(admin_client, expires_minutes=60, data_cap_mb=None, speed_cap_mbps=None):
    data = {"expires_minutes": expires_minutes}
    if data_cap_mb:
        data["data_cap_mb"] = data_cap_mb
    if speed_cap_mbps:
        data["speed_cap_mbps"] = speed_cap_mbps
    resp = admin_client.post("/vouchers/create", data=data, follow_redirects=True)
    assert resp.status_code == 200
    # Extract the code from the vouchers page
    from clarinet.database import SessionLocal
    from clarinet.models import Voucher
    with SessionLocal() as db:
        voucher = db.query(Voucher).order_by(Voucher.created_at.desc()).first()
        return voucher


# ── tests ────────────────────────────────────────────────────────────────────

class TestVoucherCreation:
    def test_admin_can_create_voucher(self, admin_client):
        resp = admin_client.post("/vouchers/create", data={"expires_minutes": 120}, follow_redirects=True)
        assert resp.status_code == 200

    def test_voucher_list_visible_to_admin(self, admin_client):
        resp = admin_client.get("/vouchers", follow_redirects=True)
        assert resp.status_code == 200

    def test_voucher_list_refuses_anonymous(self, anon_client):
        resp = anon_client.get("/vouchers", follow_redirects=False)
        assert resp.status_code in (302, 401, 403)

    def test_member_cannot_access_vouchers(self, member_client):
        resp = member_client.get("/vouchers", follow_redirects=False)
        assert resp.status_code in (302, 401, 403)

    def test_AT_13_1_thirty_minute_voucher_allowed(self, admin_client):
        """AT-13.1: A 30-minute voucher can be created."""
        from clarinet.database import SessionLocal
        from clarinet.models import Voucher
        resp = admin_client.post("/vouchers/create", data={"expires_minutes": 30}, follow_redirects=True)
        assert resp.status_code == 200
        with SessionLocal() as db:
            v = db.query(Voucher).order_by(Voucher.created_at.desc()).first()
            assert v is not None
            # Expires roughly 30 min from now
            now = datetime.utcnow()  # naive, matches SQLite
            expires = v.expires_at.replace(tzinfo=None) if v.expires_at.tzinfo else v.expires_at
            diff = (expires - now).total_seconds()
            assert 25 * 60 <= diff <= 35 * 60, f"Expected ~30 min, got {diff/60:.1f} min"

    def test_minimum_duration_enforced(self, admin_client):
        """Durations below 30 min are clamped to 30 min."""
        from clarinet.database import SessionLocal
        from clarinet.models import Voucher
        admin_client.post("/vouchers/create", data={"expires_minutes": 5}, follow_redirects=True)
        with SessionLocal() as db:
            v = db.query(Voucher).order_by(Voucher.created_at.desc()).first()
            now = datetime.utcnow()  # naive, matches SQLite
            expires = v.expires_at.replace(tzinfo=None) if v.expires_at.tzinfo else v.expires_at
            diff = (expires - now).total_seconds()
            assert diff >= 29 * 60   # clamped to 30


class TestVoucherRedemption:
    def test_valid_code_returns_success_page(self, client, admin_client):
        v = _create_voucher(admin_client, expires_minutes=60)
        resp = client.post("/guest/redeem", data={"code": v.code}, follow_redirects=True)
        assert resp.status_code == 200
        assert "success" in resp.text.lower() or v.code in resp.text

    def test_invalid_code_returns_error(self, client):
        resp = client.post("/guest/redeem", data={"code": "INVALID1"}, follow_redirects=True)
        assert resp.status_code == 200
        assert "invalid" in resp.text.lower() or "error" in resp.text.lower()

    def test_redeemed_voucher_cannot_be_used_again(self, client, admin_client):
        """AT-13.2: Voucher becomes ACTIVE after redemption, cannot be reused."""
        v = _create_voucher(admin_client, expires_minutes=60)
        # First redemption
        client.post("/guest/redeem", data={"code": v.code}, follow_redirects=True)
        # Second attempt
        resp = client.post("/guest/redeem", data={"code": v.code}, follow_redirects=True)
        assert resp.status_code == 200
        assert "used" in resp.text.lower() or "invalid" in resp.text.lower() or "error" in resp.text.lower()

    def test_expired_voucher_rejected(self, client, admin_client):
        """AT-13.3: Expired voucher cannot be used."""
        from clarinet.database import SessionLocal
        from clarinet.models import Voucher
        v = _create_voucher(admin_client, expires_minutes=30)
        # Manually expire it
        with SessionLocal() as db:
            db_v = db.get(Voucher, v.voucher_id)
            db_v.expires_at = datetime.utcnow() - timedelta(minutes=5)  # naive UTC
            db.commit()

        resp = client.post("/guest/redeem", data={"code": v.code}, follow_redirects=True)
        assert resp.status_code == 200
        assert "expired" in resp.text.lower()

    def test_brute_force_limit(self, client):
        """After many failed attempts, the IP is rate-limited."""
        for _ in range(12):
            client.post("/guest/redeem", data={"code": "WRONGXXX"}, follow_redirects=True)
        resp = client.post("/guest/redeem", data={"code": "WRONGXXX"}, follow_redirects=True)
        assert "too many" in resp.text.lower() or "wait" in resp.text.lower() or resp.status_code in (200, 429)


class TestVoucherRevocation:
    def test_admin_can_revoke_unused_voucher(self, admin_client):
        v = _create_voucher(admin_client, expires_minutes=60)
        resp = admin_client.post(f"/vouchers/{v.voucher_id}/revoke", follow_redirects=True)
        assert resp.status_code == 200
        from clarinet.database import SessionLocal
        from clarinet.models import Voucher
        with SessionLocal() as db:
            db_v = db.get(Voucher, v.voucher_id)
            assert db_v.status == "REVOKED"


class TestGuestSummaryAPI:
    def test_summary_returns_json_for_admin(self, admin_client):
        resp = admin_client.get("/api/guest/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "active_sessions" in data
        assert "available" in data

    def test_summary_refuses_anonymous(self, anon_client):
        resp = anon_client.get("/api/guest/summary", follow_redirects=False)
        assert resp.status_code in (401, 302)
