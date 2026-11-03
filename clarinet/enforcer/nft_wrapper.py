"""
clarinet/enforcer/nft_wrapper.py  (M2 rewrite)
Wrappers around nftables for device blocking, time rules, and guest vouchers.

Linux / Ubuntu 24.04 only.
On Windows / dev, all functions log a debug message and return early.

Fixes applied (F-05, F-06):
  - ensure_table_exists() is now called on startup and before any rule add
  - apply_time_rules() uses local timezone (Asia/Kolkata default)
  - Time comparison uses proper time objects, not strings
  - RATE_LIMIT action is applied via tc_wrapper
  - Rule activation/deactivation does NOT overwrite admin block / GUEST state
  - Overnight windows (e.g. 22:00-07:00) handled correctly
  - Overlapping rules: stricter action wins (BLOCK > RATE_LIMIT)
  - Rule deletion lifts its block (separate tracker per rule)
  - Time-limited exceptions respected
"""
from __future__ import annotations

from clarinet.core_svc.localtime import configured_zone
import json
import logging
from datetime import datetime, time, timezone
from zoneinfo import ZoneInfo

log = logging.getLogger("clarinet.enforcer.nft")

NFT_TABLE = "inet clarinet"
NFT_CHAIN_BLOCK = "forward"
NFT_CHAIN_GUEST = "guest_forward"
NFT_CHAIN_ACCOUNTING = "accounting"


# ──────────────────────────────────────────────
# Low-level nft helper
# ──────────────────────────────────────────────

def _nft_run(args: list[str], input_text: str | None = None) -> bool:
    """Run an nft command. Returns True on success."""
    from clarinet.enforcer.runner import run
    result = run(args, input=input_text)
    if not result.ok:
        log.debug("nft error (%s): %s", " ".join(args[:3]), result.stderr.strip())
    return result.ok


def _nft_input(ruleset: str) -> bool:
    """Feed multi-line nft commands via stdin."""
    return _nft_run(["nft", "-f", "-"], input_text=ruleset)


# ──────────────────────────────────────────────
# Table / chain setup
# ──────────────────────────────────────────────

def ensure_table_exists() -> bool:
    """
    Idempotently create the Clarinet nftables table and chains.
    Safe to call multiple times.
    """
    ruleset = f"""
table {NFT_TABLE} {{
    chain {NFT_CHAIN_BLOCK} {{
        type filter hook forward priority 0; policy accept;
    }}
    chain {NFT_CHAIN_GUEST} {{
        type filter hook forward priority 1; policy accept;
    }}
    chain {NFT_CHAIN_ACCOUNTING} {{
        type filter hook forward priority 2; policy accept;
    }}
}}
"""
    # nft add table is idempotent; chains may already exist → use 'add' not 'create'
    _nft_run(["nft", "add", "table", NFT_TABLE])
    _nft_run(["nft", "add", "chain", NFT_TABLE, NFT_CHAIN_BLOCK,
              "{ type filter hook forward priority 0; policy accept; }"])
    _nft_run(["nft", "add", "chain", NFT_TABLE, NFT_CHAIN_GUEST,
              "{ type filter hook forward priority 1; policy accept; }"])
    _nft_run(["nft", "add", "chain", NFT_TABLE, NFT_CHAIN_ACCOUNTING,
              "{ type filter hook forward priority 2; policy accept; }"])
    return True


# ──────────────────────────────────────────────
# Helpers to read what is already installed
# ──────────────────────────────────────────────

def _chain_rules(chain: str) -> list[dict]:
    """Rules currently in one of our chains, as nft's JSON objects. Empty list if unreadable."""
    from clarinet.enforcer.runner import run as _run
    raw = _run(["nft", "-j", "list", "chain", NFT_TABLE, chain])
    if not raw.ok:
        return []
    try:
        data = json.loads(raw.stdout)
    except Exception:
        return []
    return [item["rule"] for item in data.get("nftables", []) if "rule" in item]


def macs_with_rules(chain: str, kind: str) -> set[str]:
    """MACs that have rules whose comment is '<kind>_<mac>' in `chain`."""
    prefix = f"{kind}_"
    return {r["comment"][len(prefix):] for r in _chain_rules(chain)
            if str(r.get("comment", "")).startswith(prefix) and ":" in str(r.get("comment", ""))}


def _delete_rules(chain: str, comment: str) -> int:
    deleted = 0
    for rule in _chain_rules(chain):
        if rule.get("comment") == comment and rule.get("handle") is not None:
            if _nft_run(["nft", "delete", "rule", NFT_TABLE, chain, "handle", str(rule["handle"])]):
                deleted += 1
    return deleted


def _has_rule(chain: str, comment: str) -> bool:
    return any(r.get("comment") == comment for r in _chain_rules(chain))


# ──────────────────────────────────────────────
# Device blocking
# ──────────────────────────────────────────────
# Rules in the forward hook see the Ethernet header of the frame that ARRIVED, so a device is matched by
# its source MAC when it sends, and by its IP address when traffic is addressed to it (a destination MAC
# match would never fire here: it holds the router's own MAC).
# kind "block"     = blocked by an administrator (managed by reconcile from the device state)
# kind "ruleblock" = blocked by a time rule (managed by apply_time_rules)

def block_device(mac: str, ip: str | None = None, kind: str = "block") -> bool:
    """Drop everything a device sends, and everything addressed to its IP. Safe to call repeatedly."""
    ensure_table_exists()
    mac = mac.lower()
    comment = f"{kind}_{mac}"
    if _has_rule(NFT_CHAIN_BLOCK, comment):
        return True
    rules = f'add rule {NFT_TABLE} {NFT_CHAIN_BLOCK} ether saddr {mac} drop comment "{comment}"'
    if ip and _is_ipv4(ip):
        rules += f'\nadd rule {NFT_TABLE} {NFT_CHAIN_BLOCK} ip daddr {ip} drop comment "{comment}"'
    ok = _nft_input(rules)
    if ok:
        log.info("Blocked device %s (%s)", mac, kind)
    return ok


def unblock_device(mac: str, kind: str = "block") -> bool:
    """Remove the drop rules for a MAC."""
    ensure_table_exists()
    deleted = _delete_rules(NFT_CHAIN_BLOCK, f"{kind}_{mac.lower()}")
    if deleted:
        log.info("Unblocked device %s (%d rule(s) removed)", mac.lower(), deleted)
    return True


def _is_ipv4(text: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(text).version == 4
    except ValueError:
        return False


# ──────────────────────────────────────────────
# Guest access
# ──────────────────────────────────────────────
# A device in state GUEST is denied by default ("guestdeny_<mac>" in the guest chain). A voucher opens it:
# the deny rule is removed and "guest_<mac>" marker rules are added. When the interface is a bridge, the
# guest's frames to other ports are also dropped in a bridge-family table, so it cannot reach the LAN
# (routed traffic to the router itself and the internet is unaffected).

NFT_BRIDGE_TABLE = "bridge clarinet"


def _is_bridge(interface: str) -> bool:
    """True if `interface` is a Linux bridge (asked of `ip`, which works inside network namespaces)."""
    if not interface:
        return False
    from clarinet.enforcer.runner import run as _run
    out = _run(["ip", "-j", "-d", "link", "show", interface])
    if not out.ok:
        return False
    try:
        return any(link.get("linkinfo", {}).get("info_kind") == "bridge" for link in json.loads(out.stdout))
    except Exception:
        return False


def _bridge_isolate(mac: str, on: bool) -> None:
    comment = f"guest_{mac}"
    from clarinet.enforcer.runner import run as _run
    if on:
        _nft_run(["nft", "add", "table", *NFT_BRIDGE_TABLE.split()])
        _nft_run(["nft", "add", "chain", *NFT_BRIDGE_TABLE.split(), "forward",
                  "{ type filter hook forward priority 0; policy accept; }"])
        raw = _run(["nft", "-j", "list", "chain", *NFT_BRIDGE_TABLE.split(), "forward"])
        if raw.ok and comment in raw.stdout:
            return
        _nft_run(["nft", "add", "rule", *NFT_BRIDGE_TABLE.split(), "forward",
                  "ether", "saddr", mac, "drop", "comment", f'"{comment}"'])     # nft re-parses its arguments: quote the colons
        return
    raw = _run(["nft", "-j", "list", "chain", *NFT_BRIDGE_TABLE.split(), "forward"])
    if not raw.ok:
        return
    try:
        rules = [i["rule"] for i in json.loads(raw.stdout).get("nftables", []) if "rule" in i]
    except Exception:
        return
    for rule in rules:
        if rule.get("comment") == comment and rule.get("handle") is not None:
            _nft_run(["nft", "delete", "rule", *NFT_BRIDGE_TABLE.split(), "forward", "handle", str(rule["handle"])])


def deny_guest(mac: str) -> bool:
    """Default for a guest without a valid voucher: nothing gets through."""
    ensure_table_exists()
    mac = mac.lower()
    if _has_rule(NFT_CHAIN_GUEST, f"guestdeny_{mac}"):
        return True
    return _nft_input(f'add rule {NFT_TABLE} {NFT_CHAIN_GUEST} ether saddr {mac} drop comment "guestdeny_{mac}"')


def allow_guest_again(mac: str) -> None:
    _delete_rules(NFT_CHAIN_GUEST, f"guestdeny_{mac.lower()}")


def open_guest_access(mac: str, internet_only: bool = True, interface: str = "") -> bool:
    """Let a voucher holder reach the internet (and, with internet_only, not the LAN). Idempotent."""
    ensure_table_exists()
    mac = mac.lower()
    allow_guest_again(mac)
    ok = True
    if not _has_rule(NFT_CHAIN_GUEST, f"guest_{mac}"):
        ok = _nft_input(
            f'add rule {NFT_TABLE} {NFT_CHAIN_GUEST} ether saddr {mac} accept comment "guest_{mac}"\n'
            f'add rule {NFT_TABLE} {NFT_CHAIN_GUEST} ether daddr {mac} accept comment "guest_{mac}"'
        )
    if ok and internet_only and _is_bridge(interface):
        _bridge_isolate(mac, True)
    if ok:
        log.info("Guest access opened for %s", mac)
    return ok


def close_guest_access(mac: str) -> bool:
    """Remove a guest's access rules (and its bridge isolation rule)."""
    ensure_table_exists()
    mac = mac.lower()
    _delete_rules(NFT_CHAIN_GUEST, f"guest_{mac}")
    _bridge_isolate(mac, False)
    log.info("Guest access closed for %s", mac)
    return True


# ──────────────────────────────────────────────
# Time rule enforcement  (F-06 rewrite)
# ──────────────────────────────────────────────

def _time_in_window(now_time: time, start: time, end: time) -> bool:
    """
    Return True if now_time is within [start, end).
    Handles overnight windows (start > end) like 22:00–07:00.
    """
    if start <= end:
        return start <= now_time < end
    else:
        # Overnight: e.g. 22:00 – 07:00
        return now_time >= start or now_time < end


def _parse_time(t: str) -> time:
    """Parse 'HH:MM' into a time object."""
    h, m = t.split(":")
    return time(int(h), int(m))


def apply_time_rules() -> None:
    """
    Evaluate all active TimeRules and apply blocking/rate-limiting.

    Fixes (F-06):
    1. Uses local timezone (Asia/Kolkata default) not UTC.
    2. Compares time objects, not strings.
    3. RATE_LIMIT is applied via tc_wrapper.
    4. Does NOT overwrite BLOCKED (admin) / GUEST / NEW state.
    5. Overnight windows handled.
    6. Overlapping rules: BLOCK wins over RATE_LIMIT.
    7. Active RuleException for a device skips all rules for that device.
    """
    from clarinet.database import SessionLocal
    from clarinet.models import Device, TimeRule, RuleException
    from clarinet.app_settings import get_setting

    with SessionLocal() as db:
        from clarinet.core_svc.mode import can_enforce, parse_mode
        if not can_enforce(parse_mode(get_setting(db, "network_mode"))):
            return                                   # time rules only act in Full Control mode
        tz_name = configured_zone(db)
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = ZoneInfo("UTC")

        now_local = datetime.now(tz)
        now_time = now_local.time()
        day_abbr = now_local.strftime("%a")   # 'Mon', 'Tue', …

        iface = get_setting(db, "network_interface", "")
        plan_dl = get_setting(db, "plan_download_mbps", "100")
        try:
            int(float(plan_dl) * 1000)
        except ValueError:
            pass

        # Build a map: device_id → list of active rules applying now
        rules = (
            db.query(TimeRule)
            .filter(TimeRule.active == True)
            .all()
        )

        # Group by device_id
        from collections import defaultdict
        device_rules: dict[int, list] = defaultdict(list)
        for rule in rules:
            try:
                days = json.loads(rule.days_json or "[]")
            except Exception:
                days = []
            if day_abbr not in days:
                continue
            try:
                r_start = _parse_time(rule.start_time)
                r_end = _parse_time(rule.end_time)
            except Exception:
                continue
            if _time_in_window(now_time, r_start, r_end):
                device_rules[rule.device_id].append(rule)

        devices = db.query(Device).all()
        now_utc = datetime.now(timezone.utc)

        for device in devices:
            # Skip states that rules must not touch
            if device.state in ("BLOCKED", "GUEST", "NEW"):
                continue

            # Check for active exception (overrides all rules for this device)
            exception = (
                db.query(RuleException)
                .filter(
                    RuleException.device_id == device.device_id,
                    RuleException.expires_at > now_utc,
                )
                .first()
            )
            if exception:
                # Exception is active: lift any rule-imposed block
                _lift_rule_block(device, iface)
                continue

            applying = device_rules.get(device.device_id, [])

            if not applying:
                # No rule applies now — lift any rule-imposed block
                _lift_rule_block(device, iface)
                continue

            # Overlapping rules: BLOCK wins over RATE_LIMIT
            actions = [r.action for r in applying]
            if "BLOCK" in actions:
                _apply_rule_block(device, iface)
            else:
                # Find the most restrictive rate limit
                rate_limits = [r.rate_kbps for r in applying if r.action == "RATE_LIMIT" and r.rate_kbps]
                if rate_limits:
                    _lift_rule_block(device, iface)  # ensure not blocked
                    if iface:
                        from clarinet.enforcer.tc_wrapper import set_rate_limit
                        set_rate_limit(iface, device.mac_address, min(rate_limits))

        db.commit()


def _apply_rule_block(device, iface: str) -> None:
    """Block a device via a time rule. Uses its own rule kind so reconcile never mistakes it for an admin block."""
    if not _has_rule(NFT_CHAIN_BLOCK, f"ruleblock_{device.mac_address.lower()}"):
        block_device(device.mac_address, device.ip_address, kind="ruleblock")
        log.info("Rule-blocked device %s (%s)", device.mac_address, device.label or "")


def _lift_rule_block(device, iface: str) -> None:
    """Lift a rule-imposed block (does not touch admin-blocked devices)."""
    if device.state == "APPROVED":
        unblock_device(device.mac_address, kind="ruleblock")
        if iface:
            try:
                from clarinet.enforcer.tc_wrapper import remove_rate_limit
                remove_rate_limit(iface, device.mac_address)
            except Exception:
                pass
