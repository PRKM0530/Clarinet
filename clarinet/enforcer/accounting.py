"""
clarinet/enforcer/accounting.py
Read per-device byte counters from nftables accounting sets.

Contract C-11: clarinet.enforcer.accounting.read_counters()
Called by M1's traffic_counter.py (NftAccountingSource) and M3's device_load.py.
"""
from __future__ import annotations

import json
import logging
import re

from clarinet.enforcer.runner import run

log = logging.getLogger("clarinet.enforcer.accounting")

# nftables accounting set name used by Clarinet
_COUNTER_TABLE = "inet clarinet"
_COUNTER_CHAIN = "accounting"


def read_counters() -> dict[str, tuple[int, int]]:
    """
    Return {mac: (bytes_in, bytes_out)} from nftables accounting rules.

    Falls back to empty dict on non-Linux or if accounting not set up.
    bytes_in  = traffic arriving at this device (download)
    bytes_out = traffic sent by this device (upload)
    """
    result = run(["nft", "-j", "list", "table", "inet", "clarinet"])
    if not result.ok:
        return {}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}

    counters: dict[str, tuple[int, int]] = {}
    # Parse nft JSON output for counter rules with ether saddr/daddr + counter
    for item in data.get("nftables", []):
        rule = item.get("rule", {})
        expr_list = rule.get("expr", [])
        mac = None
        direction = None  # "src" or "dst"
        byte_count = 0

        for expr in expr_list:
            # Match ether src/dst MAC
            match = expr.get("match", {})
            if match.get("op") == "==":
                left = match.get("left", {})
                right = match.get("right", "")
                if isinstance(left, dict):
                    payload = left.get("payload", {})
                    if payload.get("protocol") == "ether":
                        field = payload.get("field", "")
                        if field == "saddr":
                            mac = right.lower()
                            direction = "out"
                        elif field == "daddr":
                            mac = right.lower()
                            direction = "in"
            # Counter bytes
            counter = expr.get("counter", {})
            if "bytes" in counter:
                byte_count = counter["bytes"]

        if mac and direction:
            b_in, b_out = counters.get(mac, (0, 0))
            if direction == "in":
                counters[mac] = (b_in + byte_count, b_out)
            else:
                counters[mac] = (b_in, b_out + byte_count)

    return counters


def ensure_accounting_rules(macs: list[str], interface: str) -> bool:
    """
    Ensure per-MAC accounting rules exist in nftables.
    Idempotent: re-adding an existing rule is a no-op via nft.
    """
    if not macs:
        return True

    rules = []
    for mac in macs:
        mac = mac.lower()
        rules.append(
            f'add rule inet clarinet accounting ether saddr {mac} counter comment "acc_out_{mac}"'
        )
        rules.append(
            f'add rule inet clarinet accounting ether daddr {mac} counter comment "acc_in_{mac}"'
        )

    nft_input = "\n".join(rules)
    result = run(["nft", "-f", "-"], input=nft_input)
    if not result.ok:
        log.debug("accounting rule setup failed: %s", result.stderr)
    return result.ok

