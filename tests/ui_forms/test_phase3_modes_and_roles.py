"""
Phase 3: each person sees only what their role and the network mode allow, and the pages tell the truth
about whether Clarinet can really change the network.
"""
from __future__ import annotations

import json

import pytest

from tests._support import ADMIN, ALICE, new_client, seed_world


@pytest.fixture(autouse=True)
def network_ready(monkeypatch):
    """Pretend Clarinet may change the network (nftables and root), unless a test says otherwise."""
    monkeypatch.setattr("clarinet.core_svc.enforcement_status.problem", lambda: None)


FULL_ONLY = [("/rules", "Time rules"), ("/vouchers", "Guest vouchers"), ("/priority", "Priority")]


@pytest.mark.parametrize("mode", ["MONITOR", "PUBLIC"])
def test_features_that_need_full_control_are_hidden_outside_it(mode):
    seed_world(mode)
    for who in (ADMIN, ALICE):
        c = new_client(who)
        page = c.get("/dashboard").text
        for path, _ in FULL_ONLY:
            assert f'href="{path}"' not in page, f"{who[0]} in {mode} is offered {path}"
        for path, name in FULL_ONLY:
            if who == ALICE and path != "/priority":
                continue                                          # members cannot open the others at all
            body = c.get(path).text
            assert "needs Full Control mode" in body, f"{who[0]} on {path} in {mode}"


def test_in_full_control_everything_is_offered():
    seed_world("FULL")
    admin = new_client(ADMIN).get("/dashboard").text
    for path, _ in FULL_ONLY:
        assert f'href="{path}"' in admin
    assert 'href="/priority"' in new_client(ALICE).get("/dashboard").text
    assert "needs Full Control" not in new_client(ADMIN).get("/rules").text


@pytest.mark.parametrize("path", ["/rules", "/vouchers", "/priority"])
def test_the_page_outside_full_control_explains_instead_of_showing_dead_buttons(path):
    seed_world("MONITOR")
    body = new_client(ADMIN).get(path).text
    assert "needs Full Control mode" in body
    for dead in ("New Rule", "Create Voucher", "Request Priority"):
        assert dead not in body


def test_device_buttons_follow_the_mode():
    world = seed_world("MONITOR")
    page = new_client(ADMIN).get(f"/devices/{world['d_new']}").text
    for gone in ("Block Device", "Mark as guest", "Add Time Rule"):
        assert gone not in page
    assert "Approve Device" in page
    listing = new_client(ADMIN).get("/devices").text
    assert 'title="Block"' not in listing
    full = seed_world("FULL")
    page = new_client(ADMIN).get(f"/devices/{full['d_new']}").text
    assert "Block Device" in page and "Mark as guest" in page and "Add Time Rule" in page


def test_a_blocked_device_can_always_be_released_even_in_monitor_mode():
    from clarinet.database import SessionLocal
    from clarinet.models import Device
    world = seed_world("MONITOR")
    with SessionLocal() as db:
        db.get(Device, world["d_bob"]).state = "BLOCKED"
        db.commit()
    assert "/unblock" in new_client(ADMIN).get(f"/devices/{world['d_bob']}").text


# Full Control that cannot change the network says so
def test_full_control_without_permission_shows_a_warning_to_admins_only(monkeypatch):
    seed_world("FULL")
    monkeypatch.setattr("clarinet.core_svc.enforcement_status.problem", lambda: "Clarinet is not running as root, so it is not allowed to change the firewall")
    admin = new_client(ADMIN).get("/dashboard").text
    assert "Full Control cannot change the network right now" in admin and "not running as root" in admin
    assert "cannot change the network right now" not in new_client(ALICE).get("/dashboard").text


def test_blocking_without_permission_does_not_claim_success(monkeypatch):
    world = seed_world("FULL")
    monkeypatch.setattr("clarinet.core_svc.enforcement_status.problem", lambda: "no permission")
    r = new_client(ADMIN).post(f"/devices/{world['d_free']}/block")
    assert "info=blocked_pending" in r.headers["location"]
    page = new_client(ADMIN).get(r.headers["location"]).text
    assert "cannot change the network right now" in page and "Device blocked." not in page


def test_blocking_with_permission_says_blocked():
    world = seed_world("FULL")
    r = new_client(ADMIN).post(f"/devices/{world['d_free']}/block")
    assert r.headers["location"].endswith("info=blocked")


def test_priority_without_permission_does_not_claim_success(monkeypatch):
    world = seed_world("FULL")
    monkeypatch.setattr("clarinet.core_svc.enforcement_status.problem", lambda: "no permission")
    r = new_client(ALICE).post("/priority/request", data={"device_id": str(world["d_alice"]), "duration_min": "30"})
    assert "saved" in r.headers["location"].lower() and "granted+automatically" not in r.headers["location"]


# Speed and slowdowns for members
def test_members_can_read_speed_results_but_not_run_or_export():
    seed_world("FULL")
    page = new_client(ALICE).get("/speed").text
    assert "Run speed test" not in page and "Export CSV" not in page and "Report for your provider" not in page
    assert "Run speed test" in new_client(ADMIN).get("/speed").text


def test_speed_test_button_is_hidden_in_public_mode():
    seed_world("PUBLIC")
    assert "Run speed test" not in new_client(ADMIN).get("/speed").text


def test_member_cannot_use_the_speed_actions():
    seed_world("FULL")
    c = new_client(ALICE)
    assert c.post("/speed/run").headers["location"].startswith("/dashboard?error=forbidden")
    assert c.get("/speed/export.csv").headers["location"].startswith("/dashboard?error=forbidden")


def _slowdown(world, mac):
    from datetime import datetime, timezone
    from clarinet.database import SessionLocal
    from clarinet.models import SlowdownEvent
    with SessionLocal() as db:
        db.add(SlowdownEvent(started_at=datetime.now(timezone.utc), causes_json=json.dumps([{
            "cause": "ONE_DEVICE_HEAVY", "confidence": "likely", "device_mac": mac,
            "evidence": "SECRETNAME is using 80% of your network.", "suggestion": "Pause downloads on SECRETNAME."}]),
            raw_metrics_json=json.dumps({"internet_ms": 321.0})))
        db.commit()


def test_slowdown_page_shows_the_evidence_and_what_to_do_to_admins():
    world = seed_world("FULL")
    _slowdown(world, "AA:00:00:00:00:02")
    page = new_client(ADMIN).get("/slowdowns").text
    assert "SECRETNAME is using 80%" in page and "What to do: Pause downloads on SECRETNAME" in page
    assert "Likely" in page and "internet ms" in page


def test_a_member_is_not_told_whose_device_slowed_the_network():
    world = seed_world("FULL")
    _slowdown(world, "AA:00:00:00:00:02")                          # bob's phone
    page = new_client(ALICE).get("/slowdowns").text
    assert "SECRETNAME" not in page and "using most of the bandwidth" in page
    assert "internet ms" not in page                               # technical measurements stay with administrators


def test_a_member_is_told_when_their_own_device_is_the_cause():
    world = seed_world("FULL")
    _slowdown(world, "AA:00:00:00:00:01")                          # alice's laptop
    assert "SECRETNAME is using 80%" in new_client(ALICE).get("/slowdowns").text
