"""
Network-lab fixtures. These tests need root inside the clb-router namespace, so run them with:
    sudo bash tests/lab/lab_run_tests.sh
They are skipped otherwise. They create real nftables / tc state, but only inside clb-router.
"""
from __future__ import annotations

import json
import os
import subprocess
import time

import pytest

IFACE = "br-lan"
A_IP, B_IP, ATTACKER_IP, GUEST_IP, ROUTER_IP, INTERNET_IP = (
    "10.77.0.11", "10.77.0.12", "10.77.0.66", "10.77.0.30", "10.77.0.1", "203.0.113.10")


def pytest_collection_modifyitems(config, items):
    if os.environ.get("CLARINET_LAB") == "1":
        return
    skip = pytest.mark.skip(reason="lab test: run with sudo bash tests/lab/lab_run_tests.sh")
    for item in items:
        if "tests/lab" in str(item.fspath).replace("\\", "/"):
            item.add_marker(skip)


def sh(*cmd, timeout=30, input=None):
    return subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout, input=input)


def ns(name, *cmd, timeout=30):
    """Run a command inside lab namespace clb-<name>."""
    return sh("ip", "netns", "exec", f"clb-{name}", *cmd, timeout=timeout)


def mac_of(name):
    data = json.loads(ns(name, "ip", "-j", "link", "show", "eth0").stdout)
    return data[0]["address"].lower()


def can_reach(src, dst, count=2, wait=1):
    return ns(src, "ping", "-c", str(count), "-W", str(wait), "-i", "0.2", dst).returncode == 0


def iperf_mbps(client, reverse=False, seconds=3):
    """Throughput in Mbit/s from a lab client to the fake internet server (reverse = download)."""
    cmd = ["iperf3", "-c", INTERNET_IP, "-t", str(seconds), "-J"] + (["-R"] if reverse else [])
    out = ns(client, *cmd, timeout=seconds + 25)
    try:
        j = json.loads(out.stdout)
        key = "sum_received" if reverse else "sum_sent"
        return j["end"][key]["bits_per_second"] / 1e6
    except Exception:
        raise AssertionError(f"iperf3 failed: {out.stdout[:200]} {out.stderr[:200]}")


def nft_ruleset():
    return sh("nft", "list", "ruleset").stdout


@pytest.fixture(scope="session", autouse=True)
def lab_exists():
    names = sh("ip", "netns", "list").stdout
    for n in ("router", "a", "b", "attacker", "guest", "internet"):
        assert f"clb-{n}" in names, f"lab namespace clb-{n} missing: run tests/lab/lab_setup.sh first"
    assert sh("ip", "link", "show", IFACE).returncode == 0, "run these tests inside clb-router (lab_run_tests.sh does this)"


@pytest.fixture(scope="session", autouse=True)
def iperf_server(lab_exists):
    p = subprocess.Popen(["ip", "netns", "exec", "clb-internet", "iperf3", "-s"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.8)
    yield
    p.terminate()


@pytest.fixture(autouse=True)
def clean_router_state():
    """Every test starts and ends with no Clarinet nft table and no tc shaping on br-lan."""
    def wipe():
        sh("nft", "delete", "table", "inet", "clarinet")
        sh("tc", "qdisc", "del", "dev", IFACE, "root")
    wipe()
    yield
    wipe()


@pytest.fixture(autouse=True)
def real_runner():
    """The app's own command runner (real subprocess) - the network guard from tests/_support is NOT used here."""
    from clarinet.enforcer import runner
    runner.set_runner(runner.RealRunner())
    yield


@pytest.fixture()
def world():
    """Seeded database whose devices carry the real MACs and IPs of clb-a / clb-b / clb-guest."""
    from tests._support import seed_world
    from clarinet.database import SessionLocal
    from clarinet.models import Alert, Device, Settings
    ids = seed_world("FULL")
    with SessionLocal() as db:
        db.query(Alert).delete()            # the shared world has fake open alerts; they would hide or fake lab results
        db.add(Settings(key="network_interface", value=IFACE))
        a, b, free = db.get(Device, ids["d_alice"]), db.get(Device, ids["d_bob"]), db.get(Device, ids["d_new"])
        a.mac_address, a.ip_address = mac_of("a").upper(), A_IP
        b.mac_address, b.ip_address = mac_of("b").upper(), B_IP
        free.mac_address, free.ip_address, free.state = mac_of("guest").upper(), GUEST_IP, "GUEST"
        db.commit()
    ids.update(mac_a=mac_of("a"), mac_b=mac_of("b"), mac_guest=mac_of("guest"), mac_attacker=mac_of("attacker"))
    return ids
