"""
Phase 4 (lab): security features against real traffic from the attacker namespace and a fake router.
"""
from __future__ import annotations

import base64
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingTCPServer, BaseRequestHandler

import pytest

from tests.lab.conftest import A_IP, ATTACKER_IP, IFACE, ROUTER_IP, can_reach, mac_of, ns, sh

pytestmark = pytest.mark.linux_lab


# A fake router that listens on the router's LAN address
class FakeRouter:
    def __init__(self, telnet=False, ftp=False, web=False, web_password="admin"):
        self.servers = []
        if telnet:
            self._tcp(23)
        if ftp:
            self._tcp(21)
        if web:
            self._http(8080, web_password)

    def _tcp(self, port):
        class H(BaseRequestHandler):
            def handle(self):
                self.request.sendall(b"login: ")
        ThreadingTCPServer.allow_reuse_address = True
        srv = ThreadingTCPServer((ROUTER_IP, port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.servers.append(srv)

    def _http(self, port, password):
        expected = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get("Authorization") == expected:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"router admin")
                else:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="router"')
                    self.end_headers()

            def log_message(self, *a):
                pass
        HTTPServer.allow_reuse_address = True
        srv = HTTPServer((ROUTER_IP, port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.servers.append(srv)

    def close(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()


@pytest.fixture()
def fake_router():
    made = []

    def make(**kw):
        r = FakeRouter(**kw)
        made.append(r)
        return r
    yield make
    for r in made:
        r.close()


def _alerts(kind):
    from clarinet.database import SessionLocal
    from clarinet.models import Alert
    with SessionLocal() as db:
        return [(a.level, a.title, a.device_id) for a in db.query(Alert).filter(Alert.type == kind)]


def test_sec01_router_audit_finds_open_telnet_ftp_and_default_login(world, fake_router):
    from clarinet.collector.router_audit import run_audit, run_checks
    fake_router(telnet=True, ftp=True, web=True)
    found = {f.check: f.severity for f in run_checks(ROUTER_IP)}
    assert found.get("port_23") == "HIGH", found
    assert found.get("port_21") == "MEDIUM", found
    assert found.get("default_credentials") == "HIGH", found
    from clarinet.database import SessionLocal
    with SessionLocal() as db:
        out = run_audit(db, gateway_ip=ROUTER_IP)
    assert out["ok"] and out["high"] >= 2
    assert any(level == "CRITICAL" for level, *_ in _alerts("ROUTER_AUDIT"))


def test_sec01_router_audit_does_not_flag_a_strong_password(world, fake_router):
    from clarinet.collector.router_audit import run_checks
    fake_router(web=True, web_password="long-unique-passphrase-9317")
    found = {f.check for f in run_checks(ROUTER_IP)}
    assert "default_credentials" not in found


def test_sec01_clean_router_gets_an_ok_result_and_no_alert(world):
    from clarinet.collector.router_audit import run_audit, run_checks
    assert [f.severity for f in run_checks(ROUTER_IP)] == ["OK"]
    from clarinet.database import SessionLocal
    with SessionLocal() as db:
        assert run_audit(db, gateway_ip=ROUTER_IP)["high"] == 0
    assert _alerts("ROUTER_AUDIT") == []


# SEC-02: ARP spoofing from clb-attacker
SPOOF = (
    "from scapy.all import ARP, Ether, sendp\n"
    "sendp(Ether(dst='{router_mac}', src='{att}')/ARP(op=1, psrc='{victim_ip}', hwsrc='{att}', "
    "pdst='{router_ip}', hwdst='{router_mac}'), iface='eth0', count=3, verbose=0)\n"
)


def test_sec02_real_arp_spoof_from_the_attacker_raises_a_critical_alert(world):
    from clarinet.collector import arp_scanner
    from clarinet.database import SessionLocal
    assert can_reach("a", ROUTER_IP)
    arp_scanner.set_source(arp_scanner.NeighbourTableSource())
    with SessionLocal() as db:
        arp_scanner.scan_once(db, IFACE)                   # learns A_IP -> mac of clb-a
    assert _alerts("ARP_SPOOF") == []
    router_mac = sh("cat", f"/sys/class/net/{IFACE}/address").stdout.strip()
    code = SPOOF.format(router_mac=router_mac, att=world["mac_attacker"], victim_ip=A_IP, router_ip=ROUTER_IP)
    out = ns("attacker", sys.executable, "-c", code)
    assert out.returncode == 0, out.stderr
    time.sleep(1)
    neigh = sh("ip", "neigh", "show", A_IP).stdout
    assert world["mac_attacker"] in neigh.lower(), f"the spoof did not change the router's table: {neigh}"
    with SessionLocal() as db:
        arp_scanner.scan_once(db, IFACE)
    alerts = _alerts("ARP_SPOOF")
    assert alerts and alerts[0][0] == "CRITICAL", alerts


# SEC-03: port scan with real nmap
def _attacker_device(world):
    from clarinet.database import SessionLocal
    from clarinet.models import Device
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.add(Device(mac_address=world["mac_attacker"].upper(), ip_address=ATTACKER_IP, state="NEW",
                      label="evil-laptop", first_seen=now, last_seen=now))
        db.commit()


def _scan_and_wait():
    out = ns("attacker", "nmap", "-sS", "-Pn", "-n", "-T4", "-p", "1-80", ROUTER_IP, timeout=60)
    assert out.returncode == 0, out.stderr
    for _ in range(10):
        if _alerts("PORT_SCAN"):
            break
        time.sleep(0.5)
    return _alerts("PORT_SCAN")


# This test must run BEFORE the next one: it relies on Scapy's layers not having been imported yet,
# which is exactly the state the app is in when its start-up job begins sniffing.
@pytest.mark.xfail(strict=True, reason="N-13: the sniffer imports only scapy.sendrecv, packets decode as Raw and no scan is ever seen")
def test_sec03_app_started_sniffer_sees_a_real_nmap_scan(world):
    from clarinet.collector import port_scan
    _attacker_device(world)
    assert port_scan.start_sniffer(IFACE), "sniffer did not start (scapy missing?)"
    time.sleep(1.5)
    assert _scan_and_wait(), "an 80-port SYN scan produced no alert"


def test_sec03_with_scapy_layers_loaded_a_real_scan_raises_an_alert_naming_the_device(world):
    import scapy.layers.inet, scapy.layers.l2   # noqa: F401  (what the app should do before sniffing)
    from clarinet.collector import port_scan
    _attacker_device(world)
    port_scan._sniffer_started = False
    port_scan.detector = port_scan.PortScanDetector()
    assert port_scan.start_sniffer(IFACE)
    time.sleep(1.5)
    alerts = _scan_and_wait()
    assert alerts, "an 80-port SYN scan produced no alert"
    assert "evil-laptop" in alerts[0][1], alerts
