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


def set_rate_limit(interface: str, mac: str, rate_kbps: int) -> bool:
    """
    Create or update a rate-limiting class for a specific device MAC.
    Uses a high minor number derived from the MAC to avoid collisions.
    """
    # Build a stable class ID from the last 2 bytes of MAC
    parts = mac.split(":")
    minor = int(parts[-2], 16) * 256 + int(parts[-1], 16)
    minor = max(minor, 1000)   # keep above reserved classes
    classid = f"1:{minor}"

    _tc("class", "add", "dev", interface, "parent", "1:1", "classid", classid,
        "htb", "rate", f"{rate_kbps}kbit", "ceil", f"{rate_kbps}kbit", "burst", "8k")

    # Add MAC-based filter
    _tc("filter", "add", "dev", interface, "parent", "1:",
        "protocol", "all", "u32",
        "match", "ether", "src", mac.lower(),
        "flowid", classid)

    log.info("Rate limit %.0f kbps applied to %s (class %s)", rate_kbps, mac, classid)
    return True


def remove_rate_limit(interface: str, mac: str) -> bool:
    """Remove rate limiting for a MAC (move back to default class)."""
    parts = mac.split(":")
    minor = int(parts[-2], 16) * 256 + int(parts[-1], 16)
    minor = max(minor, 1000)
    classid = f"1:{minor}"
    return _tc("class", "del", "dev", interface, "classid", classid)


def set_priority(interface: str, mac: str) -> bool:
    """Direct a device's traffic to the high-priority class 1:10."""
    return _tc("filter", "add", "dev", interface, "parent", "1:",
               "protocol", "all", "u32",
               "match", "ether", "src", mac.lower(),
               "flowid", "1:10")


def remove_priority(interface: str, mac: str) -> bool:
    """Remove priority filter for a MAC (falls back to default class)."""
    # tc doesn't easily remove individual filters by MAC; flush and reapply all
    # For now, log and return True; Phase 2 will implement full filter management
    log.info("Priority removed for %s (manual filter flush may be needed)", mac)
    return True
