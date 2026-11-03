"""
Phase 4 (lab): do the enforcement and counting features have a REAL effect on traffic?
Every claim is measured with ping / iperf3 and the nft or tc state in clb-router.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from tests._support import ADMIN, new_client
from tests.lab.conftest import (A_IP, B_IP, IFACE, INTERNET_IP, can_reach, iperf_mbps, mac_of, nft_ruleset, ns, sh)

pytestmark = pytest.mark.linux_lab


def test_lab_baseline_clients_reach_the_fake_internet(world):
    assert can_reach("a", INTERNET_IP) and can_reach("b", INTERNET_IP)
    assert "clarinet" not in nft_ruleset()


# DEV-04: blocking
def test_dev04_enforcer_layer_blocks_and_unblocks_real_traffic(world):
    from clarinet.enforcer.nft_wrapper import block_device, unblock_device
    assert block_device(world["mac_a"])
    assert f"block_{world['mac_a']}" in nft_ruleset()
    assert not can_reach("a", INTERNET_IP), "blocked device still reaches the internet"
    assert can_reach("b", INTERNET_IP), "an unrelated device was affected"
    assert unblock_device(world["mac_a"])
    assert can_reach("a", INTERNET_IP), "device did not recover after unblock"


def test_s02_block_button_stops_real_traffic(world):
    r = new_client(ADMIN).post(f"/devices/{world['d_alice']}/block")
    assert "info=blocked" in r.headers["location"]
    time.sleep(1)
    assert not can_reach("a", INTERNET_IP)


def test_s02_reconcile_applies_blocked_devices_from_the_database(world):
    from clarinet.database import SessionLocal
    from clarinet.enforcer.reconcile import reconcile_now
    from clarinet.models import Device
    with SessionLocal() as db:
        db.get(Device, world["d_alice"]).state = "BLOCKED"
        db.commit()
    reconcile_now()
    assert not can_reach("a", INTERNET_IP)


def test_s02_reconcile_removes_a_block_after_unblock(world):
    from clarinet.database import SessionLocal
    from clarinet.enforcer.nft_wrapper import block_device
    from clarinet.enforcer.reconcile import reconcile_now
    from clarinet.models import Device
    block_device(world["mac_a"])
    with SessionLocal() as db:
        db.get(Device, world["d_alice"]).state = "APPROVED"
        db.commit()
    reconcile_now()
    assert can_reach("a", INTERNET_IP)


# USG-01: counting
def _wire_accounting(world):
    from clarinet.collector.traffic_counter import NftAccountingSource, set_source
    from clarinet.enforcer.accounting import sync_accounting
    from clarinet.enforcer.nft_wrapper import ensure_table_exists
    ensure_table_exists()
    assert sync_accounting([(world["mac_a"], A_IP), (world["mac_b"], B_IP)])     # counts uploads by MAC, downloads by IP
    set_source(NftAccountingSource())


def _unwire():
    from clarinet.collector import traffic_counter
    traffic_counter.set_source(traffic_counter.NullSource())
    traffic_counter._prev_counters.clear()


def _usage_bytes(device_id):
    from clarinet.database import SessionLocal
    from clarinet.models import UsageRecord
    with SessionLocal() as db:
        rows = db.query(UsageRecord).filter(UsageRecord.device_id == device_id).all()
        return sum(r.bytes_in for r in rows), sum(r.bytes_out for r in rows)


def test_usg01_with_explicit_wiring_real_upload_is_counted_as_bytes_out(world):
    from clarinet.collector.traffic_counter import poll_and_record
    _wire_accounting(world)
    try:
        poll_and_record()                       # baseline reading
        base_in, base_out = _usage_bytes(world["d_alice"])
        bob_before = _usage_bytes(world["d_bob"])
        iperf_mbps("a", reverse=False, seconds=2)       # a UPLOADS
        poll_and_record()
        up_in, up_out = _usage_bytes(world["d_alice"])
        assert up_out - base_out > 1_000_000, "upload traffic was not counted as bytes_out"
        assert up_in - base_in < (up_out - base_out) / 20, "upload was counted as download (ACKs only should come back)"
        assert _usage_bytes(world["d_bob"]) == bob_before, "an idle device got usage"
    finally:
        _unwire()


def test_n10_real_download_is_counted_as_bytes_in(world):
    from clarinet.collector.traffic_counter import poll_and_record
    _wire_accounting(world)
    try:
        poll_and_record()
        base_in, _ = _usage_bytes(world["d_alice"])
        iperf_mbps("a", reverse=True, seconds=2)        # a DOWNLOADS
        poll_and_record()
        dn_in, _ = _usage_bytes(world["d_alice"])
        assert dn_in - base_in > 1_000_000, f"download of several MB counted as {dn_in - base_in} bytes"
    finally:
        _unwire()


def test_s01_app_default_wiring_records_usage_for_real_traffic(world):
    """No test wiring: only the app's own startup/job functions are used."""
    from clarinet.collector.traffic_counter import poll_and_record
    from clarinet.enforcer.reconcile import reconcile_now
    from clarinet.jobs import core

    class Scheduler:                                           # registering the jobs is what the app does at start-up
        def add_job(self, *a, **k):
            pass
    core.register(Scheduler())
    reconcile_now()                                            # the reconcile job installs the counting rules
    try:
        poll_and_record()
        before = sum(_usage_bytes(world["d_alice"]))
        iperf_mbps("a", seconds=2)
        poll_and_record()
        assert sum(_usage_bytes(world["d_alice"])) - before > 1_000_000
    finally:
        _unwire()


# Shaping
def test_tc_rate_limit_really_slows_one_device(world):
    from clarinet.enforcer.tc_wrapper import set_rate_limit, setup_htb
    free_up, free_down = iperf_mbps("a"), iperf_mbps("a", reverse=True)
    assert setup_htb(IFACE, 100)
    assert set_rate_limit(IFACE, world["mac_a"], 1000)        # 1 Mbit/s
    up, down = iperf_mbps("a"), iperf_mbps("a", reverse=True)
    b_down = iperf_mbps("b", reverse=True)
    print(f"a before: up {free_up:.1f} down {free_down:.1f} | a limited: up {up:.1f} down {down:.1f} | b: down {b_down:.1f}")
    assert b_down > 20, "the other device must stay fast"
    assert down < 3 and up < 3, f"1 Mbit limit not applied: up {up:.1f} down {down:.1f} Mbit/s"


def test_tc_priority_filter_is_removed_when_priority_ends(world):
    from clarinet.enforcer.tc_wrapper import remove_priority, set_priority, setup_htb
    setup_htb(IFACE, 100)
    set_priority(IFACE, world["mac_a"])
    before = sh("tc", "filter", "show", "dev", IFACE).stdout
    remove_priority(IFACE, world["mac_a"])
    after = sh("tc", "filter", "show", "dev", IFACE).stdout
    assert after.count("flowid 1:10") < before.count("flowid 1:10"), "remove_priority leaves the filter in place"


# Guest access
def test_s06_guest_without_voucher_is_stopped(world):
    from clarinet.enforcer.reconcile import reconcile_now
    reconcile_now()
    assert not can_reach("guest", INTERNET_IP)


def test_gst02_guest_with_open_access_reaches_the_internet(world):
    from clarinet.enforcer.nft_wrapper import open_guest_access
    assert open_guest_access(world["mac_guest"])
    assert can_reach("guest", INTERNET_IP)


def test_s06_voucher_guest_cannot_reach_the_lan(world):
    from clarinet.enforcer.nft_wrapper import open_guest_access
    open_guest_access(world["mac_guest"], interface=IFACE)
    assert not can_reach("guest", A_IP)


def test_gst02_closing_guest_access_removes_the_rules(world):
    from clarinet.enforcer.nft_wrapper import close_guest_access, open_guest_access
    open_guest_access(world["mac_guest"])
    assert close_guest_access(world["mac_guest"])
    assert f"guest_{world['mac_guest']}" not in nft_ruleset()


# "Keep new devices offline": a device nobody has approved is held back like a guest
def _public_mode_with_guest_as_new():
    from clarinet.database import SessionLocal
    from clarinet.models import Device, Settings
    with SessionLocal() as db:
        db.get(Settings, "network_mode").value = "FULL"
        db.merge(Settings(key="hold_new_devices", value="true"))
        for d in db.query(Device).filter(Device.state == "GUEST"):
            d.state = "NEW"
        db.commit()


def test_h6_hold_mode_holds_back_a_new_device_but_not_an_approved_one(world):
    from clarinet.enforcer.reconcile import reconcile_now
    _public_mode_with_guest_as_new()
    reconcile_now()
    assert not can_reach("guest", INTERNET_IP), "a new device reached the internet while new devices are held"
    assert can_reach("a", INTERNET_IP), "an approved device was held back"


def test_h6_hold_mode_a_voucher_opens_the_way_and_approval_lifts_the_hold(world):
    from clarinet.database import SessionLocal
    from clarinet.enforcer.reconcile import reconcile_now
    from clarinet.models import Device
    _public_mode_with_guest_as_new()
    reconcile_now()
    assert not can_reach("guest", INTERNET_IP)
    with SessionLocal() as db:
        db.query(Device).filter(Device.mac_address == world["mac_guest"].upper()).one().state = "APPROVED"
        db.commit()
    reconcile_now()
    assert can_reach("guest", INTERNET_IP), "approving a device did not lift the hold"


# GST-06: time rules
def _rule(world, action="BLOCK", rate=None):
    from clarinet.database import SessionLocal
    from clarinet.models import Settings, TimeRule
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.add(Settings(key="timezone", value="UTC"))
        db.add(TimeRule(device_id=world["d_alice"], days_json=f'["{now.strftime("%a")}"]', start_time="00:00",
                        end_time="23:59", action=action, rate_kbps=rate, created_by=world["boss"], active=True))
        db.commit()


def test_gst06_block_rule_really_blocks_inside_its_window(world):
    from clarinet.enforcer.nft_wrapper import apply_time_rules, ensure_table_exists
    ensure_table_exists()
    _rule(world)
    apply_time_rules()
    assert not can_reach("a", INTERNET_IP)
    assert can_reach("b", INTERNET_IP)


def test_gst06_block_rule_is_lifted_when_the_rule_is_deactivated(world):
    from clarinet.database import SessionLocal
    from clarinet.enforcer.nft_wrapper import apply_time_rules, ensure_table_exists
    from clarinet.models import TimeRule
    ensure_table_exists()
    _rule(world)
    apply_time_rules()
    with SessionLocal() as db:
        db.query(TimeRule).update({"active": False})
        db.commit()
    apply_time_rules()
    assert can_reach("a", INTERNET_IP)


def test_s08_repeated_cycles_do_not_pile_up_rules(world):
    from clarinet.enforcer.nft_wrapper import apply_time_rules, ensure_table_exists
    ensure_table_exists()
    _rule(world)
    for _ in range(10):
        apply_time_rules()
    assert nft_ruleset().count(world["mac_a"]) <= 4


# E3: the active ARP scan finds hosts the router has never talked to
def test_e3_active_scan_finds_devices_the_neighbour_table_does_not_know(world):
    from clarinet.app_settings import set_setting
    from clarinet.collector import arp_scanner
    from clarinet.database import SessionLocal
    from clarinet.models import Device
    sh("ip", "neigh", "flush", "all")                         # the router knows nobody now
    arp_scanner.set_source(arp_scanner._default_source)      # the plain neighbour table, as in the running app
    attacker = mac_of("attacker").upper()
    with SessionLocal() as db:
        set_setting(db, "active_discovery", "off")
        arp_scanner.scan_once(db, IFACE)
        assert db.query(Device).filter(Device.mac_address == attacker).first() is None, "passive scan should not know it yet"
        sh("ip", "neigh", "flush", "all")
        set_setting(db, "active_discovery", "on")
        arp_scanner.scan_once(db, IFACE)
        found = db.query(Device).filter(Device.mac_address == attacker).first()
        assert found is not None and found.ip_address == "10.77.0.66", "the active scan did not find a silent device"
