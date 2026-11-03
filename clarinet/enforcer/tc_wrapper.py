"""
clarinet/enforcer/tc_wrapper.py
Linux tc (traffic control) wrappers for bandwidth priority and rate limiting.

Uses HTB (Hierarchical Token Bucket) as the root qdisc and
fq_codel / CAKE as leaf qdiscs for fairness and latency control.

Linux only — gracefully no-ops on other platforms.

Class hierarchy (example for eth0, 100 Mbps plan):
  root: htb default 999
    class 1:10  — priority (admin-granted)     → CAKE
    class 1:100 — normal (APPROVED devices)   → fq_codel
    class 1:200 — rate-limited (TimeRule)     → htb leaf
    class 1:999 — default / unmatched         → fq_codel

Filters map device MACs → class handles.
"""

import logging
import subprocess
from dataclasses import dataclass

log = logging.getLogger("clarinet.enforcer.tc")


def _tc(*args: str) -> bool:
    """Run a tc command. Returns True on success."""
    cmd = ["tc"] + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        if result.returncode != 0:
            log.debug("tc error: %s", result.stderr.decode().strip())
        return result.returncode == 0
    except FileNotFoundError:
        log.debug("tc not found — Linux only, skipping")
        return False
    except Exception as e:
        log.error("tc call failed: %s", e)
        return False


def setup_htb(interface: str, plan_mbps: float) -> bool:
    """
    Set up HTB root qdisc and class hierarchy on `interface`.
    Idempotent — replaces existing setup.
    """
    plan_kbit = int(plan_mbps * 1000)
    priority_kbit = plan_kbit           # priority class gets full plan speed
    normal_kbit = plan_kbit             # normal class shares full speed

    # Replace root qdisc
    _tc("qdisc", "del", "dev", interface, "root")   # ignore errors if not present
    if not _tc("qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "100"):
        return False

    # Root class
    _tc("class", "add", "dev", interface, "parent", "1:", "classid", "1:1",
        "htb", "rate", f"{plan_kbit}kbit", "burst", "32k")

    # Priority class (approved speed-priority grants)
    _tc("class", "add", "dev", interface, "parent", "1:1", "classid", "1:10",
        "htb", "rate", f"{priority_kbit}kbit", "prio", "1", "burst", "64k")
    _tc("qdisc", "add", "dev", interface, "parent", "1:10", "fq_codel")

    # Normal class
    _tc("class", "add", "dev", interface, "parent", "1:1", "classid", "1:100",
        "htb", "rate", f"{normal_kbit}kbit", "prio", "2", "burst", "32k")
    _tc("qdisc", "add", "dev", interface, "parent", "1:100", "fq_codel")

    log.info("HTB setup complete on %s (%.0f Mbps plan)", interface, plan_mbps)
    return True


def ensure_htb(interface: str, plan_mbps: float) -> bool:
    """Build the shaping tree only if the interface does not have one yet (setup_htb would wipe existing limits)."""
    try:
        shown = subprocess.run(["tc", "qdisc", "show", "dev", interface], capture_output=True, text=True, timeout=5)
        if shown.returncode == 0 and "htb 1:" in shown.stdout:
            return True
    except Exception:
        pass
    return setup_htb(interface, plan_mbps)


def _minor(mac: str) -> int:
    """Stable class number for a device, from the last two bytes of its MAC (kept above the reserved classes)."""
    parts = mac.split(":")
    return max(int(parts[-2], 16) * 256 + int(parts[-1], 16), 1000)


def set_rate_limit(interface: str, mac: str, rate_kbps: int) -> bool:
    """
    Limit one device in both directions. Replaces an earlier limit for the same device.

    Download (router -> device): an HTB class on the interface's egress, selected by the device's
    destination MAC, which is already set when a frame leaves the router.
    Upload (device -> router): a policer on the interface's ingress, selected by source MAC.
    Every filter uses the device's class number as its priority so remove_rate_limit can find it.
    """
    mac = mac.lower()
    minor = _minor(mac)
    classid = f"1:{minor:x}"                  # tc reads class numbers as hexadecimal
    remove_rate_limit(interface, mac)

    ok = _tc("class", "add", "dev", interface, "parent", "1:1", "classid", classid,
             "htb", "rate", f"{rate_kbps}kbit", "ceil", f"{rate_kbps}kbit", "burst", "8k")
    ok &= _tc("filter", "add", "dev", interface, "parent", "1:", "protocol", "all", "prio", str(minor),
              "u32", "match", "ether", "dst", mac, "flowid", classid)

    _tc("qdisc", "add", "dev", interface, "handle", "ffff:", "ingress")        # no-op if it exists
    ok &= _tc("filter", "add", "dev", interface, "parent", "ffff:", "protocol", "all", "prio", str(minor),
              "u32", "match", "ether", "src", mac,
              "police", "rate", f"{rate_kbps}kbit", "burst", "32k", "drop", "flowid", ":1")
    log.info("Rate limit %.0f kbps applied to %s (class %s)", rate_kbps, mac, classid)
    return bool(ok)


def remove_rate_limit(interface: str, mac: str) -> bool:
    """Remove a device's limit in both directions (silently succeeds if it had none)."""
    minor = _minor(mac.lower())
    _tc("filter", "del", "dev", interface, "parent", "1:", "prio", str(minor))
    _tc("filter", "del", "dev", interface, "parent", "ffff:", "prio", str(minor))
    _tc("class", "del", "dev", interface, "classid", f"1:{minor:x}")
    return True


def _priority_prio(mac: str) -> int:
    """Filter priority for a device's priority-class filter; mirrors the rate-limit one so the two never share a number."""
    return 65_536 - _minor(mac)


def set_priority(interface: str, mac: str) -> bool:
    """Send traffic addressed to a device through the high-priority class 1:10."""
    remove_priority(interface, mac)
    return _tc("filter", "add", "dev", interface, "parent", "1:", "protocol", "all",
               "prio", str(_priority_prio(mac.lower())), "u32", "match", "ether", "dst", mac.lower(),
               "flowid", "1:10")


def remove_priority(interface: str, mac: str) -> bool:
    """Take a device off the priority class (its filter is found by its own priority number)."""
    _tc("filter", "del", "dev", interface, "parent", "1:", "prio", str(_priority_prio(mac.lower())))
    return True
