"""
clarinet/collector/router_audit.py
Security audit of the router (default gateway) of the network Clarinet runs on.

Checks, all against your own gateway:
  - risky services listening (Telnet, FTP, SMB, TR-069, admin panel over plain HTTP)
  - UPnP answering on the LAN
  - admin login still using a factory default password (HTTP Basic only)

The probes are passed in as functions so the logic can be tested without a router.
"""

import base64
import logging
import socket
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

log = logging.getLogger("clarinet.collector.router_audit")

# port -> (severity if open, title, advice)
RISKY_PORTS = {
    21:   ("MEDIUM", "FTP is open on the router", "FTP sends passwords in clear text. Turn it off unless you need it."),
    23:   ("HIGH",   "Telnet is open on the router", "Telnet is unencrypted and a favourite target of botnets. Disable it and use SSH if you need remote access."),
    445:  ("HIGH",   "SMB file sharing is open on the router", "Router file sharing should not be reachable. Disable it."),
    7547: ("MEDIUM", "TR-069 remote management port is open", "This is the ISP management port. Make sure only your ISP can reach it."),
    8080: ("LOW",    "Alternate web admin port (8080) is open", "Check that this is intended and protected by a strong password."),
}

DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"), ("admin", ""),
    ("root", "admin"), ("user", "user"),
]

PROBE_PORTS = sorted(set(RISKY_PORTS) | {22, 80, 443})


@dataclass
class Finding:
    check: str
    severity: str      # HIGH | MEDIUM | LOW | OK
    title: str
    detail: str = ""


# Real probes

def probe_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_upnp(ip: str, timeout: float = 2.0) -> bool:
    """Send an SSDP M-SEARCH straight to the router and see if it answers."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n'
    ).encode()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(msg, (ip, 1900))
            data, _ = s.recvfrom(2048)
            return data.upper().startswith(b"HTTP/1.1 200")
    except OSError:
        return False


def http_basic_status(ip: str, port: int, user: str | None, password: str = "") -> tuple[int, bool]:
    """
    GET / with optional Basic auth.
    Returns (status_code, offers_basic_auth). Status 0 means no HTTP answer.
    """
    req = urllib.request.Request(f"http://{ip}:{port}/")
    if user is not None:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, False
    except urllib.error.HTTPError as e:
        return e.code, "basic" in (e.headers.get("WWW-Authenticate", "") or "").lower()
    except (urllib.error.URLError, OSError):
        return 0, False


# Audit logic

def run_checks(
    gateway_ip: str,
    port_probe=None,
    upnp_probe=None,
    http_status=None,
) -> list[Finding]:
    port_probe = port_probe or probe_port
    upnp_probe = upnp_probe or probe_upnp
    http_status = http_status or http_basic_status
    findings: list[Finding] = []

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = dict(zip(PROBE_PORTS, pool.map(lambda p: port_probe(gateway_ip, p), PROBE_PORTS)))
    open_ports = {p for p, is_open in results.items() if is_open}

    for port, (severity, title, advice) in RISKY_PORTS.items():
        if port in open_ports:
            findings.append(Finding(f"port_{port}", severity, title, advice))

    if 80 in open_ports and 443 not in open_ports:
        findings.append(Finding(
            "admin_plain_http", "MEDIUM", "Router admin page has no HTTPS",
            "Port 80 answers but 443 does not, so admin passwords travel unencrypted over the LAN.",
        ))
    if 22 in open_ports:
        findings.append(Finding("port_22", "LOW", "SSH is open on the router",
                                "Fine if you use it. Make sure it needs a strong password or a key."))

    if upnp_probe(gateway_ip):
        findings.append(Finding(
            "upnp", "MEDIUM", "UPnP is enabled on the router",
            "Any device on the network can open ports on the router. Turn UPnP off unless a game or app needs it.",
        ))

    # Default credentials (only where the router uses HTTP Basic auth)
    for port in (80, 8080):
        if port not in open_ports:
            continue
        status, wants_basic = http_status(gateway_ip, port, None)
        if status != 401 or not wants_basic:
            continue
        for user, password in DEFAULT_CREDENTIALS:
            code, _ = http_status(gateway_ip, port, user, password)
            if code == 200:
                findings.append(Finding(
                    "default_credentials", "HIGH", "Router uses a default admin login",
                    f"The admin page accepted '{user}' / '{password or '(blank)'}'. Change the password now.",
                ))
                break
        break

    if not any(f.severity in ("HIGH", "MEDIUM") for f in findings):
        findings.append(Finding("summary", "OK", "No serious problems found on the router",
                                f"Checked {len(PROBE_PORTS)} ports, UPnP and default logins."))
    return findings


def run_audit(db, gateway_ip: str | None = None) -> dict:
    """Run the audit, store the findings, and raise one alert if something serious was found."""
    from clarinet.collector.network_check import get_gateway_ip
    from clarinet.collector.security_alerts import raise_alert
    from clarinet.models.security import RouterAuditFinding

    gateway_ip = gateway_ip or get_gateway_ip()
    if not gateway_ip:
        return {"ok": False, "error": "No default gateway found", "findings": 0}

    findings = run_checks(gateway_ip)
    run_id = uuid.uuid4().hex[:12]
    for f in findings:
        db.add(RouterAuditFinding(
            run_id=run_id, gateway_ip=gateway_ip, check=f.check,
            severity=f.severity, title=f.title, detail=f.detail,
        ))
    db.commit()

    high = [f for f in findings if f.severity == "HIGH"]
    if high:
        raise_alert(
            "ROUTER_AUDIT", "CRITICAL",
            f"Router audit found {len(high)} serious problem(s) on {gateway_ip}",
            "; ".join(f.title for f in high),
            db=db,
        )
    return {"ok": True, "run_id": run_id, "gateway_ip": gateway_ip, "findings": len(findings), "high": len(high)}
