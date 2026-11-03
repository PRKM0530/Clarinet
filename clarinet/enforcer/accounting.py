"""
clarinet/enforcer/accounting.py
Read per-device byte counters from nftables accounting sets.

Contract C-11: clarinet.enforcer.accounting.read_counters()
Called by M1's traffic_counter.py (NftAccountingSource) and M3's device_load.py.
"""
from __future__ import annotations

import json
import logging

from clarinet.enforcer.runner import run

log = logging.getLogger("clarinet.enforcer.accounting")

# nftables accounting set name used by Clarinet
_COUNTER_TABLE = "inet clarinet"
_COUNTER_CHAIN = "accounting"


def read_counters() -> dict[str, tuple[int, int]]:
    """
    Return {mac: (bytes_in, bytes_out)} from the nftables accounting rules.

    bytes_in  = traffic addressed to the device (download), counted by its IP address
    bytes_out = traffic sent by the device (upload), counted by its MAC address
    The rules carry the MAC in their comment ("acc_out_<mac>", "acc_in_<mac>_<ip>"), so a device
    whose IP changes is still the same device. Returns {} when nftables or the table is missing.
    """
    result = run(["nft", "-j", "list", "chain", _COUNTER_TABLE, _COUNTER_CHAIN])
    if not result.ok:
        return {}
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}

    counters: dict[str, tuple[int, int]] = {}
    for item in data.get("nftables", []):
        rule = item.get("rule", {})
        comment = str(rule.get("comment", ""))
        if comment.startswith("acc_out_"):
            direction, mac = "out", comment[len("acc_out_"):].split("_")[0]
        elif comment.startswith("acc_in_"):
            direction, mac = "in", comment[len("acc_in_"):].split("_")[0]
        else:
            continue
        byte_count = 0
        for expr in rule.get("expr", []):
            counter = expr.get("counter")
            if isinstance(counter, dict) and "bytes" in counter:
                byte_count = counter["bytes"]
        b_in, b_out = counters.get(mac, (0, 0))
        counters[mac] = (b_in + byte_count, b_out) if direction == "in" else (b_in, b_out + byte_count)
    return counters


def _existing_comments() -> dict[str, int]:
    """comment -> rule handle for every rule in the accounting chain."""
    result = run(["nft", "-j", "list", "chain", _COUNTER_TABLE, _COUNTER_CHAIN])
    if not result.ok:
        return {}
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}
    return {r["comment"]: r["handle"] for i in data.get("nftables", [])
            if (r := i.get("rule")) and r.get("comment") and r.get("handle") is not None}


def sync_accounting(devices: list[tuple[str, str | None]]) -> bool:
    """
    Make the accounting rules match `devices`, a list of (mac, ip). Idempotent: rules that already
    exist keep their counters; rules for devices that are gone (or whose IP changed) are replaced.
    """
    from clarinet.enforcer.nft_wrapper import ensure_table_exists
    ensure_table_exists()
    existing = _existing_comments()
    wanted: dict[str, str] = {}
    for mac, ip in devices:
        mac = mac.lower()
        wanted[f"acc_out_{mac}"] = f"ether saddr {mac} counter comment \"acc_out_{mac}\""
        if ip and ":" not in ip:                           # IPv4 only
            wanted[f"acc_in_{mac}_{ip}"] = f"ip daddr {ip} counter comment \"acc_in_{mac}_{ip}\""

    for comment, handle in existing.items():
        if comment.startswith(("acc_out_", "acc_in_")) and comment not in wanted:
            run(["nft", "delete", "rule", "inet", "clarinet", _COUNTER_CHAIN, "handle", str(handle)])
    missing = [rule for comment, rule in wanted.items() if comment not in existing]
    if not missing:
        return True
    ok = run(["nft", "-f", "-"], input="\n".join(f"add rule inet clarinet {_COUNTER_CHAIN} {r}" for r in missing)).ok
    if not ok:
        log.debug("accounting sync failed")
    return ok


def ensure_accounting_rules(macs: list[str], interface: str = "") -> bool:
    """Upload counting only, for callers that know MACs but not IPs. Prefer sync_accounting()."""
    if not macs:
        return True
    return sync_accounting([(m, None) for m in macs])
