"""
Phase 4 (lab): real pings through tc/netem impairment drive the slowdown detector end to end.
The pinger's real public targets 8.8.8.8 and 1.1.1.1 are added to the fake internet namespace, so the
production code (icmplib pings -> PingRecord -> baseline -> detector -> diagnosis -> alert) runs unmodified.
The "router" ping target is pointed at clb-b, a stand-in for a router hop whose delay we can control.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from tests.lab.conftest import A_IP, B_IP, IFACE, can_reach, iperf_mbps, ns, sh

pytestmark = pytest.mark.linux_lab

WAN_DEV = "clbw-i"          # clb-internet's side of the upstream link (netem on its egress delays every reply)
B_DEV = "clbl-b"            # clb-router's port towards clb-b


@pytest.fixture(autouse=True)
def lab_targets_and_cleanup(world):
    """Public ping targets live in the fake internet; netem and test rules are removed afterwards."""
    for ip in ("8.8.8.8", "1.1.1.1"):
        ns("internet", "ip", "addr", "add", f"{ip}/32", "dev", "lo")
    from clarinet.analytics import diagnosis
    diagnosis._consecutive_bad = 0
    yield
    ns("internet", "tc", "qdisc", "del", "dev", WAN_DEV, "root")
    sh("tc", "qdisc", "del", "dev", B_DEV, "root")
    sh("nft", "delete", "table", "inet", "labtest")
    for ip in ("8.8.8.8", "1.1.1.1"):
        ns("internet", "ip", "addr", "del", f"{ip}/32", "dev", "lo")
    diagnosis._consecutive_bad = 0


def netem(where, *args):
    dev, run = (WAN_DEV, lambda *a: ns("internet", *a)) if where == "wan" else (B_DEV, sh)
    run("tc", "qdisc", "del", "dev", dev, "root")
    out = run("tc", "qdisc", "replace", "dev", dev, "root", "netem", *args)
    assert out.returncode == 0, f"netem failed: {out.stderr}"


def set_setting(key, value):
    from clarinet.database import SessionLocal
    from clarinet.models import Settings
    with SessionLocal() as db:
        row = db.get(Settings, key)
        if row:
            row.value = value
        else:
            db.add(Settings(key=key, value=value))
        db.commit()


def seed_baseline(ms=5.0):
    from clarinet.analytics.baseline import rebuild_all
    from clarinet.database import SessionLocal
    from clarinet.models import PingRecord
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        for i in range(60):
            db.add(PingRecord(measured_at=now - timedelta(minutes=i * 10), target="google_dns", host="8.8.8.8",
                              avg_ms=ms + (i % 3) * 0.2, min_ms=ms, max_ms=ms + 1, packet_loss=0.0, reachable=True))
        db.commit()
    rebuild_all()


def cycle(times=2):
    from clarinet.collector.pinger import measure_and_store
    for _ in range(times):
        last = measure_and_store()
    return last


def events():
    from clarinet.database import SessionLocal
    from clarinet.models import Alert, SlowdownEvent
    with SessionLocal() as db:
        evs = db.query(SlowdownEvent).all()
        return [(json.loads(e.causes_json), e.ended_at) for e in evs], [(a.type, a.level) for a in db.query(Alert)]


# Real pings under impairment
def test_prf01_clean_lab_pings_are_fast_and_reachable():
    from clarinet.collector.pinger import ping_host
    r = ping_host("8.8.8.8", "google_dns")
    assert r.reachable and r.packet_loss == 0 and r.avg_ms < 20, r


def test_prf01_netem_delay_shows_up_in_the_measured_latency():
    from clarinet.collector.pinger import ping_host
    netem("wan", "delay", "120ms")
    r = ping_host("8.8.8.8", "google_dns")
    assert r.reachable and 100 < r.avg_ms < 200, r


def test_prf01_netem_loss_shows_up_in_the_measured_packet_loss():
    from clarinet.collector.pinger import ping_host
    netem("wan", "loss", "50%")
    losses = [ping_host("8.8.8.8", "google_dns").packet_loss for _ in range(6)]
    assert max(losses) > 0, f"50% loss never showed up in 6 runs of 4 pings: {losses}"


def test_prf01_records_are_stored_for_every_target_including_the_router_once_set():
    from clarinet.collector.pinger import measure_and_store
    from clarinet.database import SessionLocal
    from clarinet.models import PingRecord
    set_setting("router_ip", B_IP)
    measure_and_store()
    with SessionLocal() as db:
        assert {r.target for r in db.query(PingRecord)} == {"google_dns", "cloudflare", "router"}


# Diagnosis, one scenario per cause
def test_prf04_real_outage_is_critical_opens_one_event_and_closes_on_recovery():
    seed_baseline()
    netem("wan", "loss", "100%")
    cycle(2)
    evs, alerts = events()
    assert len(evs) == 1 and evs[0][0][0]["cause"] == "INTERNET_OUTAGE" and evs[0][1] is None
    assert ("OUTAGE", "CRITICAL") in alerts
    ns("internet", "tc", "qdisc", "del", "dev", WAN_DEV, "root")
    # After 100% loss the router's ARP entry for the next hop has to be re-learned, which takes a few
    # seconds, so the first pings after recovery can still fail. The app measures once a minute; allow 5 cycles.
    history = []
    for _ in range(5):
        last = cycle(1)
        history.append({k: (v.reachable, v.avg_ms) for k, v in last.items()})
        evs, _ = events()
        if evs[0][1] is not None:
            break
        time.sleep(2)
    assert len(evs) == 1 and evs[0][1] is not None, (
        f"the outage event stayed open after the link recovered; pings per cycle: {history}; "
        f"neighbours: {sh('ip', 'neigh', 'show').stdout!r}")


def test_prf04_provider_issue_when_only_the_internet_side_is_slow():
    seed_baseline()
    set_setting("router_ip", B_IP)             # the "router" hop stays fast
    netem("wan", "delay", "300ms")
    cycle(2)
    causes = events()[0][0][0][0]
    assert causes["cause"] == "PROVIDER_ISSUE" and causes["confidence"] == "likely"
    assert "internet provider" in causes["suggestion"].lower() or "provider" in causes["suggestion"].lower()


def test_prf04_local_congestion_when_the_router_hop_is_slow_too():
    seed_baseline()
    set_setting("router_ip", B_IP)
    netem("wan", "delay", "300ms")
    netem("b", "delay", "300ms")
    cycle(2)
    causes = [c["cause"] for c in events()[0][0][0]]
    assert causes[0] == "LOCAL_CONGESTION", causes
    assert events()[0][0][0][0]["confidence"] == "possible"


def test_prf04_slow_dns_is_reported_as_possible_next_to_a_mildly_slow_line():
    from clarinet.collector import dns_timer
    seed_baseline()
    netem("wan", "delay", "40ms")
    # the DNS timer's own result store, as filled by measure_dns(); the lab has no resolver to query
    dns_timer._last_results = [dns_timer.DnsResult("example.com", "lab", 900.0, True),
                               dns_timer.DnsResult("example.org", "lab", 850.0, True)]
    try:
        cycle(2)
    finally:
        dns_timer._last_results = []
    causes = {c["cause"]: c for c in events()[0][0][0]}
    assert "SLOW_DNS" in causes and causes["SLOW_DNS"]["confidence"] == "possible", list(causes)


def test_prf04_no_clear_cause_when_only_the_speed_test_is_low():
    from clarinet.database import SessionLocal
    from clarinet.models import SpeedTestResult
    seed_baseline()
    set_setting("plan_download_mbps", "100")
    with SessionLocal() as db:
        db.add(SpeedTestResult(tested_at=datetime.now(timezone.utc), download_mbps=10, upload_mbps=5, latency_ms=10,
                               busy=False, below_plan=True, server_host="lab"))
        db.commit()
    cycle(2)
    assert events()[0][0][0][0]["cause"] == "NO_CLEAR_CAUSE"


def _wire(world, macs):
    from clarinet.collector.traffic_counter import NftAccountingSource, set_source
    from clarinet.enforcer.accounting import ensure_accounting_rules
    from clarinet.enforcer.nft_wrapper import ensure_table_exists
    ensure_table_exists()
    assert ensure_accounting_rules(macs, IFACE)
    set_source(NftAccountingSource())


def _unwire():
    from clarinet.collector import traffic_counter
    traffic_counter.set_source(traffic_counter.NullSource())
    traffic_counter._prev_counters.clear()


def _send(client, megabytes):
    out = ns(client, "iperf3", "-c", "203.0.113.10", "-n", f"{megabytes}M", "-J", timeout=60)
    assert json.loads(out.stdout)["end"]["sum_sent"]["bytes"] > megabytes * 900_000


def test_prf04_one_heavy_device_is_named_when_it_dominates_real_traffic(world):
    from clarinet.collector.traffic_counter import poll_and_record
    seed_baseline()
    _wire(world, [world["mac_a"], world["mac_b"]])
    try:
        poll_and_record()
        _send("a", 60)
        poll_and_record()
        netem("wan", "delay", "300ms")
        cycle(2)
    finally:
        _unwire()
    top = events()[0][0][0][0]
    assert top["cause"] == "ONE_DEVICE_HEAVY" and top["device_mac"].lower() == world["mac_a"], top


def test_prf04_collective_congestion_when_three_devices_each_use_a_third(world):
    from clarinet.collector.traffic_counter import poll_and_record
    seed_baseline()
    macs = [world["mac_a"], world["mac_b"], world["mac_guest"]]
    _wire(world, macs)
    try:
        poll_and_record()
        for client in ("a", "b", "guest"):
            _send(client, 40)
        poll_and_record()
        netem("wan", "delay", "300ms")
        cycle(2)
    finally:
        _unwire()
    assert events()[0][0][0][0]["cause"] == "COLLECTIVE_CONGESTION"


@pytest.mark.xfail(strict=True, reason="S-16: losing only 8.8.8.8 is reported as a full outage although 1.1.1.1 still works")
def test_s16_one_dead_public_target_is_not_an_outage_in_the_lab():
    from clarinet.collector.pinger import ping_host
    seed_baseline()
    sh("nft", "add", "table", "inet", "labtest")
    sh("nft", "add", "chain", "inet", "labtest", "out", "{ type filter hook output priority 0 ; }")
    sh("nft", "add", "rule", "inet", "labtest", "out", "ip", "daddr", "8.8.8.8", "drop")
    assert ping_host("1.1.1.1").reachable and not ping_host("8.8.8.8").reachable
    cycle(2)
    assert "OUTAGE" not in [t for t, _ in events()[1]]
