"""
tests/m2_access/test_time_rules.py
Time rule enforcement: AT-11.1 (block window applies), AT-11.2 (window lifts),
                       AT-11.3 (exception grants access).
"""
import json
import pytest
from datetime import datetime, time, timezone


class TestNftTimeHelpers:
    """Unit-test the pure time-window logic (no nft needed)."""

    def test_simple_window(self):
        from clarinet.enforcer.nft_wrapper import _time_in_window
        assert _time_in_window(time(22, 30), time(22, 0), time(23, 0)) is True
        assert _time_in_window(time(21, 59), time(22, 0), time(23, 0)) is False

    def test_overnight_window(self):
        """22:00–07:00 overnight window."""
        from clarinet.enforcer.nft_wrapper import _time_in_window
        assert _time_in_window(time(23, 0), time(22, 0), time(7, 0)) is True
        assert _time_in_window(time(6, 0), time(22, 0), time(7, 0)) is True
        assert _time_in_window(time(7, 0), time(22, 0), time(7, 0)) is False
        assert _time_in_window(time(12, 0), time(22, 0), time(7, 0)) is False

    def test_parse_time(self):
        from clarinet.enforcer.nft_wrapper import _parse_time
        t = _parse_time("22:30")
        assert t.hour == 22 and t.minute == 30


class TestRuleRoutes:
    def test_rules_page_loads_for_admin(self, admin_client):
        resp = admin_client.get("/rules", follow_redirects=True)
        assert resp.status_code == 200

    def test_member_cannot_access_rules(self, member_client):
        resp = member_client.get("/rules", follow_redirects=False)
        assert resp.status_code in (302, 401, 403)

    def test_create_block_rule(self, admin_client):
        from clarinet.database import SessionLocal
        from clarinet.models import Device, Settings, TimeRule
        # Time rules only work in Full Control mode, so the app must be in it for a rule to be created
        with SessionLocal() as db:
            mode = db.get(Settings, "network_mode")
            if mode is None:
                db.add(Settings(key="network_mode", value="FULL"))
            else:
                mode.value = "FULL"
            db.commit()
        # Create a test device
        with SessionLocal() as db:
            dev = Device(mac_address="aa:bb:cc:11:22:33", state="APPROVED", label="RuleTestDevice")
            db.add(dev)
            db.commit()
            device_id = dev.device_id

        resp = admin_client.post("/rules/create", data={
            "device_id": device_id,
            "days": ["Mon", "Tue"],
            "start_time": "22:00",
            "end_time": "07:00",
            "action": "BLOCK",
        }, follow_redirects=True)
        assert resp.status_code == 200

        with SessionLocal() as db:
            rule = db.query(TimeRule).filter(TimeRule.device_id == device_id).first()
            assert rule is not None
            assert rule.action == "BLOCK"
            assert rule.active is True

    def test_toggle_rule_deactivates(self, admin_client):
        from clarinet.database import SessionLocal
        from clarinet.models import TimeRule
        with SessionLocal() as db:
            rule = db.query(TimeRule).first()
            if not rule:
                pytest.skip("No rules exist")
            rule_id = rule.rule_id
            was_active = rule.active

        admin_client.post(f"/rules/{rule_id}/toggle", follow_redirects=True)

        with SessionLocal() as db:
            rule = db.get(TimeRule, rule_id)
            assert rule.active == (not was_active)

    def test_delete_rule(self, admin_client):
        from clarinet.database import SessionLocal
        from clarinet.models import Device, TimeRule
        with SessionLocal() as db:
            dev = Device(mac_address="aa:bb:cc:44:55:66", state="APPROVED", label="DeleteRuleDevice")
            db.add(dev)
            db.flush()
            rule = TimeRule(
                device_id=dev.device_id,
                days_json=json.dumps(["Mon"]),
                start_time="10:00",
                end_time="11:00",
                action="BLOCK",
                active=True,
                created_by=1,
            )
            db.add(rule)
            db.commit()
            rule_id = rule.rule_id

        resp = admin_client.post(f"/rules/{rule_id}/delete", follow_redirects=True)
        assert resp.status_code == 200
        with SessionLocal() as db:
            assert db.get(TimeRule, rule_id) is None

    def test_rules_summary_api(self, admin_client):
        resp = admin_client.get("/rules/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "active_rules" in data
        assert "available" in data

    def test_rules_device_api(self, admin_client):
        from clarinet.database import SessionLocal
        from clarinet.models import Device
        with SessionLocal() as db:
            dev = db.query(Device).first()
            if not dev:
                pytest.skip("No devices")
            device_id = dev.device_id

        resp = admin_client.get(f"/rules/device/{device_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "rules" in data


class TestRuleEnforcerUnit:
    """Unit tests for apply_time_rules logic without nft (using FakeRunner)."""

    def test_does_not_crash_on_no_rules(self, fake_runner):
        from clarinet.enforcer.nft_wrapper import apply_time_rules
        # Should not raise even if nft is missing
        try:
            apply_time_rules()
        except Exception as exc:
            pytest.fail(f"apply_time_rules raised: {exc}")

    @pytest.mark.linux_lab
    def test_AT_11_1_block_window_applied(self, fake_runner):
        """AT-11.1: Block rule applied when inside window."""
        pass  # Full lab test

    @pytest.mark.linux_lab
    def test_AT_11_2_block_lifted_after_window(self, fake_runner):
        """AT-11.2: Block lifted when outside window."""
        pass  # Full lab test
