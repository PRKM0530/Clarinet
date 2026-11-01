"""
clarinet/collector/wifi_scan.py
Fake access point ("evil twin") detection.

Scans nearby Wi-Fi with the OS tools (netsh on Windows, nmcli on Linux) and
compares what it sees with the access points the admin trusts. An access point
is suspicious when it:
  - uses the same name as a trusted network but a BSSID nobody has approved, or
  - uses a name that looks almost the same (e.g. "HomeWiFi" vs "H0meWiFi").

The first time it runs with no trusted access points, the one this machine is
connected to is trusted automatically, so there is nothing to configure.
"""

import logging
import platform
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger("clarinet.collector.wifi_scan")

_LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "!": "i", "|": "l", "_": "", "-": "", " ": ""})


@dataclass
class Sighting:
    ssid: str
    bssid: str
    signal: int | None = None   # percent
    security: str | None = None


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return out.stdout or ""
    except (OSError, subprocess.SubprocessError) as e:
        log.debug("Wi-Fi tool %s unavailable: %s", cmd[0], e)
        return ""


# Parsers (pure functions, easy to test)

def parse_netsh_networks(text: str) -> list[Sighting]:
    """Parse `netsh wlan show networks mode=bssid`."""
    results: list[Sighting] = []
    ssid, security = "", None
    current: Sighting | None = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            ssid, security, current = m.group(1).strip(), None, None
            continue
        m = re.match(r"^Authentication\s*:\s*(.*)$", line)
        if m:
            security = m.group(1).strip()
            continue
        m = re.match(r"^BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]{17})$", line)
        if m:
            current = Sighting(ssid=ssid, bssid=m.group(1).upper(), security=security)
            results.append(current)
            continue
        m = re.match(r"^Signal\s*:\s*(\d+)%", line)
        if m and current is not None:
            current.signal = int(m.group(1))
    return results


def _split_nmcli(line: str) -> list[str]:
    """Split an nmcli -t line on unescaped colons."""
    parts, buf, i = [], "", 0
    while i < len(line):
        if line[i] == "\\" and i + 1 < len(line):
            buf += line[i + 1]
            i += 2
        elif line[i] == ":":
            parts.append(buf)
            buf = ""
            i += 1
        else:
            buf += line[i]
            i += 1
    parts.append(buf)
    return parts


def parse_nmcli_networks(text: str) -> list[Sighting]:
    """Parse `nmcli -t -f SSID,BSSID,SIGNAL,SECURITY dev wifi list`."""
    results: list[Sighting] = []
    for line in text.splitlines():
        parts = _split_nmcli(line.strip())
        if len(parts) < 3 or not re.fullmatch(r"[0-9A-Fa-f:]{17}", parts[1]):
            continue
        signal = int(parts[2]) if parts[2].isdigit() else None
        security = parts[3] if len(parts) > 3 and parts[3] else "Open"
        results.append(Sighting(ssid=parts[0], bssid=parts[1].upper(), signal=signal, security=security))
    return results


def parse_netsh_connection(text: str) -> Sighting | None:
    """Parse `netsh wlan show interfaces` for the connected access point."""
    ssid = bssid = auth = None
    signal = None
    for raw in text.splitlines():
        line = raw.strip()
        if re.match(r"^SSID\s*:", line):
            ssid = line.split(":", 1)[1].strip()
        elif re.match(r"^(AP )?BSSID\s*:", line):
            bssid = line.split(":", 1)[1].strip().upper()
        elif re.match(r"^Authentication\s*:", line):
            auth = line.split(":", 1)[1].strip()
        elif re.match(r"^Signal\s*:", line):
            m = re.search(r"(\d+)", line)
            signal = int(m.group(1)) if m else None
    if ssid and bssid:
        return Sighting(ssid=ssid, bssid=bssid, signal=signal, security=auth)
    return None


def parse_nmcli_connection(text: str) -> Sighting | None:
    """Parse `nmcli -t -f ACTIVE,SSID,BSSID,SIGNAL,SECURITY dev wifi list`."""
    for line in text.splitlines():
        parts = _split_nmcli(line.strip())
        if len(parts) >= 3 and parts[0] == "yes" and re.fullmatch(r"[0-9A-Fa-f:]{17}", parts[2]):
            signal = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else None
            security = parts[4] if len(parts) > 4 and parts[4] else "Open"
            return Sighting(ssid=parts[1], bssid=parts[2].upper(), signal=signal, security=security)
    return None


# OS access

def scan() -> list[Sighting]:
    if platform.system() == "Windows":
        return parse_netsh_networks(_run(["netsh", "wlan", "show", "networks", "mode=bssid"]))
    return parse_nmcli_networks(_run(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "yes"]))


def current_connection() -> Sighting | None:
    if platform.system() == "Windows":
        return parse_netsh_connection(_run(["netsh", "wlan", "show", "interfaces"]))
    return parse_nmcli_connection(_run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list"]))


# Evaluation (pure)

def normalise(ssid: str) -> str:
    return ssid.lower().translate(_LOOKALIKE)


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _is_open(security: str | None) -> bool:
    return security is None or security.strip().lower() in ("", "open", "none", "--")


def judge(sighting: Sighting, trusted: list[tuple[str, str]]) -> tuple[str, str | None, str]:
    """
    Decide what an access point is.
    `trusted` is a list of (ssid, bssid) pairs.
    Returns (verdict, reason, level) where verdict is OK / UNKNOWN / SUSPECT.
    """
    if not sighting.ssid:
        return "UNKNOWN", None, "INFO"      # hidden network, nothing to compare

    trusted_bssids = {b.upper() for _, b in trusted}
    if sighting.bssid.upper() in trusted_bssids:
        return "OK", None, "INFO"

    own = {s.casefold() for s, _ in trusted}
    if sighting.ssid.casefold() in own:
        weaker = _is_open(sighting.security)
        reason = "Same name as your network but not a trusted access point"
        if weaker:
            reason += " and it has no password (open)"
        return "SUSPECT", reason, "CRITICAL" if weaker else "WARNING"

    wanted = normalise(sighting.ssid)
    for ssid, _ in trusted:
        target = normalise(ssid)
        if wanted and target and (wanted == target or edit_distance(wanted, target) <= 1) and sighting.ssid != ssid:
            return "SUSPECT", f"Looks like your network name '{ssid}'", "WARNING"

    return "UNKNOWN", None, "INFO"


# Orchestration

def learn_from_connection(db) -> bool:
    """Trust the access point we're connected to, if nothing is trusted yet."""
    from clarinet.models.security import TrustedAccessPoint

    if db.query(TrustedAccessPoint).count() > 0:
        return False
    current = current_connection()
    if current is None:
        return False
    db.add(TrustedAccessPoint(ssid=current.ssid, bssid=current.bssid, label="Learned on first scan"))
    db.commit()
    log.info("Trusted current access point %s (%s)", current.ssid, current.bssid)
    return True


def scan_and_evaluate(db) -> dict:
    """Scan, store what was seen, and raise an alert for each suspect access point."""
    from clarinet.collector.security_alerts import raise_alert
    from clarinet.models.security import SeenAccessPoint, TrustedAccessPoint

    learn_from_connection(db)
    sightings = scan()
    trusted = [(t.ssid, t.bssid) for t in db.query(TrustedAccessPoint).all()]
    now = datetime.now(timezone.utc)
    summary = {"seen": len(sightings), "suspect": 0, "trusted": len(trusted)}

    for s in sightings:
        verdict, reason, level = judge(s, trusted) if trusted else ("UNKNOWN", None, "INFO")
        row = db.get(SeenAccessPoint, s.bssid)
        if row is None:
            row = SeenAccessPoint(bssid=s.bssid, ssid=s.ssid, first_seen=now)
            db.add(row)
        row.ssid, row.signal, row.security = s.ssid, s.signal, s.security
        row.last_seen, row.verdict, row.reason = now, verdict, reason

        if verdict == "SUSPECT":
            summary["suspect"] += 1
            raise_alert(
                "FAKE_AP",
                level,
                f"Possible fake access point: {s.ssid or '(hidden)'} ({s.bssid})",
                f"{reason}. Signal {s.signal if s.signal is not None else '?'}%, security {s.security or 'unknown'}. "
                "If this is your own repeater or mesh node, mark it as trusted on the Security page.",
                extra={"ssid": s.ssid, "bssid": s.bssid},
                db=db,
            )
    db.commit()
    return summary
