"""
Phase 4/5 (lab): the REAL app (uvicorn + APScheduler + threads) running inside clb-router, driven over HTTP.
Nothing is wired by the tests: whatever the app does on its own is what is measured.
"""
from __future__ import annotations

import json
import os
import signal
import sqlite3
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pytest

from tests.lab.conftest import A_IP, B_IP, GUEST_IP, IFACE, ROUTER_IP, can_reach, iperf_mbps, nft_ruleset, ns, sh

pytestmark = pytest.mark.linux_lab

PORT = 8765
EXPIRY_DELAY: dict = {}
BASE = f"http://127.0.0.1:{PORT}"
ADMIN = {"username": "owner", "password": "lab-owner-pw-1"}
REPO = Path(__file__).resolve().parents[2]
FAKE_SPEEDTEST = ('#!/bin/sh\necho \'{"download":{"bandwidth":12500000},"upload":{"bandwidth":2500000},'
                  '"ping":{"latency":12.5},"server":{"host":"fake-lab"}}\'\n')


@pytest.fixture(autouse=True)
def clean_router_state():
    """Override the shared per-test wipe: the tests in this module build on each other's nft state on purpose."""
    yield


class RunningApp:
    def __init__(self, workdir: Path):
        self.dir = workdir
        self.db = workdir / "app.db"
        self.log = workdir / "app.log"
        self.proc = None
        (workdir / "bin").mkdir(exist_ok=True)
        f = workdir / "bin" / "speedtest"
        f.write_text(FAKE_SPEEDTEST)
        f.chmod(0o755)
        (workdir / "home").mkdir(exist_ok=True)
        self.client = httpx.Client(base_url=BASE, follow_redirects=False, timeout=15)

    def start(self):
        env = {"PATH": f"{self.dir/'bin'}:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(self.dir / "home"),
               "PYTHONDONTWRITEBYTECODE": "1", "SECRET_KEY": "lab-fixed-secret-for-restart-test",
               "DATABASE_URL": f"sqlite:///{self.db}", "APP_ENV": "production", "APP_PORT": str(PORT),
               "NETWORK_INTERFACE": IFACE, "NETWORK_MODE": "FULL"}
        self.logfile = open(self.log, "ab")
        self.proc = subprocess.Popen([sys.executable, str(REPO / "tests/lab/app_main.py")], cwd=REPO, env=env,
                                     stdout=self.logfile, stderr=self.logfile)
        for _ in range(60):
            try:
                if httpx.get(f"{BASE}/api/status/health", timeout=2).status_code == 200:
                    return
            except Exception:
                time.sleep(0.5)
        raise AssertionError("app did not come up:\n" + self.log.read_text()[-3000:])

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.logfile.close()

    def restart(self):
        self.stop()
        self.start()

    def query(self, sql, *args):
        con = sqlite3.connect(self.db, timeout=10)
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()

    def log_text(self):
        return self.log.read_text(errors="replace")

    def wait_for(self, fn, timeout=90, every=3):
        end = time.time() + timeout
        last = None
        while time.time() < end:
            last = fn()
            if last:
                return last
            time.sleep(every)
        return last


@pytest.fixture(scope="module")
def app():
    for ip in ("8.8.8.8", "1.1.1.1"):
        ns("internet", "ip", "addr", "add", f"{ip}/32", "dev", "lo")
    for client in ("a", "b", "guest"):                       # make the clients visible to the router's ARP table
        ns(client, "ping", "-c", "1", "-W", "1", ROUTER_IP)
    sh("nft", "delete", "table", "inet", "clarinet")
    workdir = Path(tempfile.mkdtemp(prefix="clarinet-liveapp-"))      # not pytest's shared tmp root, which is per-uid
    a = RunningApp(workdir)
    a.start()
    r = a.client.post("/setup/admin", data={"username": ADMIN["username"], "password": ADMIN["password"],
                                            "password_confirm": ADMIN["password"], "network_mode": "FULL",
                                            "plan_download": "100", "plan_upload": "20", "billing_day": "1",
                                            "consent": "yes"})
    assert r.status_code in (200, 302), r.text[:300]
    r = a.client.post("/login", data=ADMIN)
    assert r.status_code == 302, r.text[:300]
    yield a
    a.stop()
    shutil.rmtree(workdir, ignore_errors=True)
    sh("nft", "delete", "table", "inet", "clarinet")
    for ip in ("8.8.8.8", "1.1.1.1"):
        ns("internet", "ip", "addr", "del", f"{ip}/32", "dev", "lo")


def device_rows(app):
    return {m.lower(): (i, s, ip) for i, m, s, ip in app.query("select device_id, mac_address, state, ip_address from device")}


# Start-up
def test_app_serves_pages_and_the_scheduler_started_its_jobs(app):
    assert app.client.get("/dashboard").status_code == 200
    started = [l for l in app.log_text().splitlines() if "APScheduler started with" in l]
    assert started, app.log_text()[-1500:]
    jobs = int(started[0].split("with")[1].split()[0])
    assert jobs >= 20, f"only {jobs} jobs registered"


def test_startup_speed_test_ran_through_the_fake_tool_and_was_stored(app):
    rows = app.wait_for(lambda: app.query("select download_mbps, upload_mbps, server_host from speed_test_result"), 40)
    assert rows and rows[0] == (100.0, 20.0, "fake-lab"), rows


def test_pinger_job_stores_real_pings_for_both_public_targets(app):
    rows = app.wait_for(lambda: app.query("select target, reachable from ping_record"), 40)
    assert {t for t, ok in rows if ok} >= {"google_dns", "cloudflare"}, rows


def test_scan_job_finds_the_real_clients_with_their_real_macs(app):
    from tests.lab.conftest import mac_of
    macs = {mac_of(n) for n in ("a", "b", "guest")}
    found = app.wait_for(lambda: macs <= set(device_rows(app)), 60)
    assert found, f"expected {macs}, scheduler found {set(device_rows(app))}"
    assert all(device_rows(app)[m][1] == "NEW" for m in macs)
    alerts = app.query("select count(*) from alert where type = 'NEW_DEVICE'")[0][0]
    assert alerts >= 3


def test_startup_warnings_in_the_log(app):
    """Raised log level: list every ERROR / Traceback the app wrote after a quiet minute."""
    time.sleep(30)
    bad = [l for l in app.log_text().splitlines() if l.startswith(("ERROR", "CRITICAL")) or "Traceback" in l]
    assert bad == [], "\n".join(bad[:15])


# Live alerts from a real scheduler job
def test_s03_new_device_alert_reaches_a_connected_websocket(app):
    from websockets.sync.client import connect
    cookie = "; ".join(f"{k}={v}" for k, v in app.client.cookies.items())
    with connect(f"ws://127.0.0.1:{PORT}/ws/alerts", additional_headers={"Cookie": cookie}, open_timeout=5) as ws:
        ns("attacker", "ping", "-c", "1", "-W", "1", ROUTER_IP)          # a brand-new device appears
        ws.send("ping")
        messages = []
        deadline = time.time() + 45                                      # the scan runs every 15 s
        while time.time() < deadline and not any("NEW_DEVICE" in m for m in messages):
            try:
                messages.append(ws.recv(timeout=3))
            except TimeoutError:
                pass
        assert any("NEW_DEVICE" in m for m in messages), f"only got {messages}"


# Heartbeat and traffic accounting with the app's own wiring
def test_s18_collectors_write_heartbeats(app):
    assert app.query("select count(*) from collector_heartbeat")[0][0] > 0


def test_s01_real_traffic_creates_usage_rows_in_the_running_app(app):
    from tests.lab.conftest import mac_of
    a_id = device_rows(app)[mac_of("a")][0]
    assert app.client.post(f"/devices/{a_id}/approve", data={"label": "lab-a"}).status_code == 302
    iperf_mbps("a", seconds=3)
    rows = app.wait_for(lambda: app.query("select sum(bytes_in + bytes_out) from usage_record where device_id = ?", a_id)[0][0], 130)
    assert rows and rows > 1_000_000, (
        f"no usage for device {a_id} after 130 s.\nrules:\n{sh('nft', 'list', 'chain', 'inet', 'clarinet', 'accounting').stdout[:1200]}\n"
        f"usage rows: {app.query('select * from usage_record')}\n"
        f"log: {[l for l in app.log_text().splitlines() if 'traffic' in l.lower() or 'reconcile' in l.lower()][-8:]}")


# Real guest voucher over the real network
def _make_voucher(app, minutes="60"):
    assert app.client.post("/vouchers/create", data={"expires_minutes": minutes}).status_code == 302
    return app.query("select voucher_id, code from voucher order by voucher_id desc limit 1")[0]


def test_guest_redeems_a_voucher_over_the_network_and_access_rules_appear(app):
    from tests.lab.conftest import mac_of
    vid, code = _make_voucher(app)
    out = ns("guest", "curl", "-s", "-X", "POST", f"http://{ROUTER_IP}:{PORT}/guest/redeem", "-d", f"code={code}", timeout=30)
    assert out.returncode == 0 and out.stdout, out.stderr
    status = app.query("select status from voucher where voucher_id = ?", vid)[0][0]
    assert status == "ACTIVE", (status, out.stdout[:300])
    assert f"guest_{mac_of('guest')}" in nft_ruleset()


def test_guest_access_survives_an_app_restart_and_the_session_cookie_still_works(app):
    from tests.lab.conftest import mac_of
    app.restart()
    assert app.client.get("/dashboard").status_code == 200, "the old session cookie stopped working after restart"
    assert app.query("select status from voucher order by voucher_id desc limit 1")[0][0] == "ACTIVE"
    assert f"guest_{mac_of('guest')}" in nft_ruleset()
    assert len(device_rows(app)) >= 3


def test_expired_voucher_loses_access_and_the_rules_go_eventually(app):
    from tests.lab.conftest import mac_of
    # Start clean: the earlier voucher is still ACTIVE on this device, and a second voucher redeemed on the same
    # device gets no enforcement record at all (observation N-16), so retire the first one before redeeming.
    con = sqlite3.connect(app.db, timeout=10)
    con.execute("delete from enforcement_status")
    con.execute("update voucher set status = 'REVOKED' where status = 'ACTIVE'")
    con.commit()
    con.close()
    sh("nft", "delete", "table", "inet", "clarinet")
    vid, code = _make_voucher(app)
    ns("guest", "curl", "-s", "-X", "POST", f"http://{ROUTER_IP}:{PORT}/guest/redeem", "-d", f"code={code}", timeout=30)
    assert app.query("select status from voucher where voucher_id = ?", vid)[0][0] == "ACTIVE"
    assert f"guest_{mac_of('guest')}" in nft_ruleset()
    con = sqlite3.connect(app.db, timeout=10)
    con.execute("update voucher set expires_at = datetime('now', '-5 minutes') where voucher_id = ?", (vid,))
    con.execute("update enforcement_status set expires_at = datetime('now', '-5 minutes') where voucher_id = ?", (vid,))
    con.commit()
    con.close()
    started = time.time()
    expired = app.wait_for(lambda: app.query("select status from voucher where voucher_id = ?", vid)[0][0] == "EXPIRED", 330, every=5)
    EXPIRY_DELAY["seconds"] = round(time.time() - started)
    assert expired, "the voucher was still ACTIVE 330 s after its expiry time"
    assert f"guest_{mac_of('guest')}" not in nft_ruleset(), "the guest's access rules stayed after expiry"


def test_n15_guest_access_ends_within_a_minute_of_expiry(app):
    assert EXPIRY_DELAY.get("seconds") is not None, "run after the expiry test"
    assert EXPIRY_DELAY["seconds"] <= 90, f"access lasted {EXPIRY_DELAY['seconds']} s past the expiry time"


def test_manual_speed_test_from_the_page_adds_a_second_result(app):
    before = app.query("select count(*) from speed_test_result")[0][0]
    assert app.client.post("/speed/run").status_code == 302
    after = app.wait_for(lambda: app.query("select count(*) from speed_test_result")[0][0] > before, 30)
    assert after
