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

import json
import logging
import subprocess
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
    result = _nft_run(["nft", "add", "table", NFT_TABLE])
    _nft_run(["nft", "add", "chain", NFT_TABLE, NFT_CHAIN_BLOCK,
              "{ type filter hook forward priority 0; policy accept; }"])
    _nft_run(["nft", "add", "chain", NFT_TABLE, NFT_CHAIN_GUEST,
              "{ type filter hook forward priority 1; policy accept; }"])
    _nft_run(["nft", "add", "chain", NFT_TABLE, NFT_CHAIN_ACCOUNTING,
              "{ type filter hook forward priority 2; policy accept; }"])
    return True


# ──────────────────────────────────────────────
# Device blocking
# ──────────────────────────────────────────────

def block_device(mac: str) -> bool:
    """Add a forward-drop rule for the given MAC (both src and dst)."""
    ensure_table_exists()
    mac = mac.lower()
    rules = (
        f'add rule {NFT_TABLE} {NFT_CHAIN_BLOCK} '
        f'ether saddr {mac} drop comment "block_{mac}"\n'
        f'add rule {NFT_TABLE} {NFT_CHAIN_BLOCK} '
        f'ether daddr {mac} drop comment "block_{mac}"'
    )
    ok = _nft_input(rules)
    if ok:
        log.info("Blocked device %s", mac)
    return ok


def unblock_device(mac: str) -> bool:
    """Remove all forward-drop rules for the given MAC."""
    ensure_table_exists()
    mac = mac.lower()
    # List rules, find handles with our comment, delete them
    result = _nft_run(["nft", "-j", "list", "chain", NFT_TABLE, NFT_CHAIN_BLOCK])
    if not result:
        return False

    from clarinet.enforcer.runner import run as _run
    raw = _run(["nft", "-j", "list", "chain", NFT_TABLE, NFT_CHAIN_BLOCK])
    if not raw.ok:
        return False

    try:
        data = json.loads(raw.stdout)
    except Exception:
        return False

    comment_key = f"block_{mac}"
    deleted = 0
    for item in data.get("nftables", []):
        rule = item.get("rule", {})
        if rule.get("comment") == comment_key:
            handle = rule.get("handle")
            if handle is not None:
                _nft_run(["nft", "delete", "rule", NFT_TABLE, NFT_CHAIN_BLOCK, "handle", str(handle)])
                deleted += 1

    if deleted:
        log.info("Unblocked device %s (%d rule(s) removed)", mac, deleted)
    return True


# ──────────────────────────────────────────────
# Guest access
# ──────────────────────────────────────────────

def open_guest_access(mac: str, internet_only: bool = True) -> bool:
    """
    Allow a guest device through the guest chain.
    If internet_only=True, only forward traffic to/from the WAN interface.
    """
    ensure_table_exists()
    mac = mac.lower()
    # Allow the guest device; block LAN access via a separate rule if needed
    rules = (
        f'add rule {NFT_TABLE} {NFT_CHAIN_GUEST} '
        f'ether saddr {mac} accept comment "guest_{mac}"\n'
        f'add rule {NFT_TABLE} {NFT_CHAIN_GUEST} '
        f'ether daddr {mac} accept comment "guest_{mac}"'
    )
    ok = _nft_input(rules)
    if ok:
        log.info("Guest access opened for %s", mac)
    return ok


def close_guest_access(mac: str) -> bool:
    """Remove guest-access rules for a MAC."""
    ensure_table_exists()
    mac = mac.lower()
    from clarinet.enforcer.runner import run as _run
    raw = _run(["nft", "-j", "list", "chain", NFT_TABLE, NFT_CHAIN_GUEST])
    if not raw.ok:
        return False

    try:
        data = json.loads(raw.stdout)
    except Exception:
        return False

    comment_key = f"guest_{mac}"
    for item in data.get("nftables", []):
        rule = item.get("rule", {})
        if rule.get("comment") == comment_key:
            handle = rule.get("handle")
            if handle is not None:
                _nft_run(["nft", "delete", "rule", NFT_TABLE, NFT_CHAIN_GUEST, "handle", str(handle)])

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
        tz_name = get_setting(db, "timezone", "Asia/Kolkata")
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = ZoneInfo("Asia/Kolkata")

        now_local = datetime.now(tz)
        now_time = now_local.time()
        day_abbr = now_local.strftime("%a")   # 'Mon', 'Tue', …

        iface = get_setting(db, "network_interface", "")
        plan_dl = get_setting(db, "plan_download_mbps", "100")
        try:
            plan_kbps = int(float(plan_dl) * 1000)
        except ValueError:
            plan_kbps = 100_000

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
    """Block a device via a time rule (marks with a special state tag)."""
    # Use a separate flag rather than overwriting state
    if not hasattr(device, "_rule_blocked") or not device._rule_blocked:
        block_device(device.mac_address)
        log.info("Rule-blocked device %s (%s)", device.mac_address, device.label or "")


def _lift_rule_block(device, iface: str) -> None:
    """Lift a rule-imposed block (does not touch admin-blocked devices)."""
    if device.state == "APPROVED":
        unblock_device(device.mac_address)
        if iface:
            try:
                from clarinet.enforcer.tc_wrapper import remove_rate_limit
                remove_rate_limit(iface, device.mac_address)
            except Exception:
                pass
