"""
clarinet/enforcer/nft_wrapper.py
Wrappers around nftables for device blocking, time rules, and guest vouchers.

Linux / Ubuntu 24.04 only.
On Windows / dev, all functions log a warning and return early.

nftables table layout created by Clarinet:
  table inet clarinet {
    chain forward {
      type filter hook forward priority 0; policy accept;
      # per-device BLOCK rules added dynamically here
    }
    chain guest_forward {
      type filter hook forward priority 1; policy accept;
      # guest voucher rules — allow only internet (not LAN)
    }
  }
"""

import json
import logging
import subprocess
from datetime import datetime, timezone

log = logging.getLogger("clarinet.enforcer.nft")

NFT_TABLE = "inet clarinet"
NFT_CHAIN_BLOCK = "forward"


def _nft(ruleset_json: dict) -> bool:
    """
    Apply a nftables ruleset via 'nft -j -f -'.
    Returns True on success.
    """
    try:
        proc = subprocess.run(
            ["nft", "-j", "-f", "-"],
            input=json.dumps(ruleset_json).encode(),
            capture_output=True,
            timeout=5,
        )
        if proc.returncode != 0:
            log.error("nft error: %s", proc.stderr.decode())
            return False
        return True
    except FileNotFoundError:
        log.debug("nft not found — running on non-Linux system, skipping enforcement")
        return False
    except Exception as e:
        log.error("nft call failed: %s", e)
        return False


def _mac_to_nft(mac: str) -> str:
    """Normalise MAC to lowercase colon format for nft."""
    return mac.lower().replace("-", ":")


def block_device(mac: str) -> bool:
    """Drop all traffic from a MAC address."""
    mac_nft = _mac_to_nft(mac)
    log.info("Blocking device %s", mac_nft)
    ruleset = {
        "nftables": [
            {"add": {"rule": {
                "family": "inet", "table": "clarinet", "chain": NFT_CHAIN_BLOCK,
                "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ether", "field": "saddr"}},
                               "right": mac_nft}},
                    {"drop": None}
                ],
                "comment": f"clarinet-block-{mac_nft}"
            }}}
        ]
    }
    return _nft(ruleset)


def unblock_device(mac: str) -> bool:
    """Remove the drop rule for a MAC (flush by comment is cleanest via nft delete)."""
    mac_nft = _mac_to_nft(mac)
    log.info("Unblocking device %s", mac_nft)
    try:
        # List current rules and find one with matching comment
        out = subprocess.check_output(["nft", "-j", "list", "table", "inet", "clarinet"],
                                      timeout=5, stderr=subprocess.DEVNULL)
        data = json.loads(out)
        for item in data.get("nftables", []):
            rule = item.get("rule", {})
            if rule.get("comment") == f"clarinet-block-{mac_nft}":
                handle = rule.get("handle")
                if handle is not None:
                    subprocess.run(
                        ["nft", "delete", "rule", "inet", "clarinet", NFT_CHAIN_BLOCK,
                         "handle", str(handle)],
                        timeout=5
                    )
                    return True
    except Exception as e:
        log.error("unblock_device failed: %s", e)
    return False


def ensure_table_exists() -> None:
    """Create the clarinet nftables table and chains if they don't exist."""
    script = """
add table inet clarinet
add chain inet clarinet forward { type filter hook forward priority 0; policy accept; }
add chain inet clarinet guest_forward { type filter hook forward priority 1; policy accept; }
"""
    try:
        subprocess.run(["nft", "-f", "-"], input=script.encode(), timeout=5,
                       capture_output=True)
    except Exception as e:
        log.debug("ensure_table_exists: %s (Linux only)", e)


def apply_time_rules() -> None:
    """
    Called every minute by APScheduler.
    Reads all active TimeRule rows and either blocks or unblocks devices
    based on whether the current time falls inside the rule window.
    Also honours RuleException rows (one-hour override).
    """
    from clarinet.database import SessionLocal
    from clarinet.models import Device, TimeRule, RuleException

    now = datetime.now(timezone.utc)
    day_abbr = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][now.weekday()]
    current_time = now.strftime("%H:%M")

    with SessionLocal() as db:
        rules = db.query(TimeRule).filter(TimeRule.active == True).all()

        for rule in rules:
            device = db.get(Device, rule.device_id)
            if device is None:
                continue

            # Check for active exception (ACC-3)
            exception_active = db.query(RuleException).filter(
                RuleException.rule_id == rule.rule_id,
                RuleException.expires_at > now,
            ).first()
            if exception_active:
                # Ensure device is not blocked during exception
                if device.state == "BLOCKED":
                    unblock_device(device.mac_address)
                continue

            # Is the current time inside this rule's window?
            in_window = (
                day_abbr in rule.days
                and rule.start_time <= current_time < rule.end_time
            )

            if in_window and rule.action == "BLOCK":
                if device.state != "BLOCKED":
                    device.state = "BLOCKED"
                    block_device(device.mac_address)
            elif not in_window and device.state == "BLOCKED":
                # Rule window ended — restore
                device.state = "APPROVED"
                unblock_device(device.mac_address)

        db.commit()
