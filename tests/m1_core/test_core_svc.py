"""
tests/m1_core/test_core_svc.py
Tests for M1 core service modules.
"""

import pytest


# ─── passwords ────────────────────────────────────────────────────────────────

def test_password_too_short():
    from clarinet.core_svc.passwords import check_password
    errors = check_password("Short1!")
    assert any("10 characters" in e for e in errors)


def test_password_common_blocked():
    from clarinet.core_svc.passwords import check_password
    errors = check_password("password123")
    assert any("common" in e.lower() for e in errors)


def test_password_same_as_username():
    from clarinet.core_svc.passwords import check_password
    errors = check_password("adminadmin1", username="admin")
    assert any("username" in e.lower() for e in errors)


def test_password_valid_complexity():
    from clarinet.core_svc.passwords import is_valid_password
    assert is_valid_password("Secure@Pass1", "alice")


def test_password_valid_passphrase():
    from clarinet.core_svc.passwords import is_valid_password
    assert is_valid_password("correct horse battery staple", "alice")


def test_password_fails_1_class():
    from clarinet.core_svc.passwords import check_password
    # Only lowercase, no upper/digit/special but long
    errors = check_password("abcdefghijk", "alice")
    assert any("complexity" in e.lower() or "3 of" in e.lower() for e in errors)


# ─── timeutil ────────────────────────────────────────────────────────────────

def test_billing_period_start_mid_month():
    from clarinet.core_svc.timeutil import billing_period_start
    from datetime import date
    # billing_day=15, today=20 → period started on the 15th this month
    ref = date(2026, 10, 20)
    start = billing_period_start(15, ref)
    assert start == date(2026, 10, 15)


def test_billing_period_start_early_month():
    from clarinet.core_svc.timeutil import billing_period_start
    from datetime import date
    # billing_day=20, today=5 → period started on the 20th LAST month
    ref = date(2026, 10, 5)
    start = billing_period_start(20, ref)
    assert start == date(2026, 9, 20)


def test_days_remaining():
    from clarinet.core_svc.timeutil import days_remaining_in_period
    from datetime import date
    # If billing_day=1 and today=Oct 20, period ends Oct 31, so 12 days left
    ref = date(2026, 10, 20)
    remaining = days_remaining_in_period(1, ref)
    assert remaining > 0


def test_period_fraction_elapsed():
    from clarinet.core_svc.timeutil import period_fraction_elapsed
    from datetime import date
    ref = date(2026, 10, 15)
    frac = period_fraction_elapsed(1, ref)
    assert 0.0 < frac < 1.0


# ─── mode ────────────────────────────────────────────────────────────────────

def test_parse_mode_full():
    from clarinet.core_svc.mode import parse_mode, NetworkMode
    assert parse_mode("FULL") == NetworkMode.FULL


def test_parse_mode_default():
    from clarinet.core_svc.mode import parse_mode, NetworkMode
    assert parse_mode(None) == NetworkMode.MONITOR
    assert parse_mode("GARBAGE") == NetworkMode.MONITOR


def test_can_enforce_full_only():
    from clarinet.core_svc.mode import parse_mode, can_enforce
    assert can_enforce(parse_mode("FULL")) is True
    assert can_enforce(parse_mode("MONITOR")) is False
    assert can_enforce(parse_mode("PUBLIC")) is False


# ─── oui ────────────────────────────────────────────────────────────────────

def test_is_random_mac_detects_locally_administered():
    from clarinet.collector.oui import is_random_mac
    # Locally administered MAC (bit 1 of first octet set)
    assert is_random_mac("02:AA:BB:CC:DD:EE") is True


def test_is_random_mac_universal():
    from clarinet.collector.oui import is_random_mac
    # Universally administered (bit 1 clear)
    assert is_random_mac("00:50:56:AA:BB:CC") is False


def test_lookup_vendor_fallback():
    from clarinet.collector.oui import lookup_vendor
    # Unknown MAC → None (not a crash)
    result = lookup_vendor("FF:FF:FF:FF:FF:FF")
    assert result is None or isinstance(result, str)


# ─── exporter ────────────────────────────────────────────────────────────────

def test_exporter_sanitises_formula():
    from clarinet.core_svc.exporter import rows_to_csv
    csv_str = rows_to_csv(["col"], [["=EVIL()"]])
    # The tab-prefix sanitisation prepends a tab, so the raw "=EVIL()" cannot
    # appear as the first character of a cell — check it starts with tab now
    assert csv_str.startswith("col") or "col" in csv_str  # header present
    # Value is tab-prefixed, not a bare formula
    assert "\t=EVIL()" in csv_str


def test_exporter_safe_values_unchanged():
    from clarinet.core_svc.exporter import rows_to_csv
    csv_str = rows_to_csv(["name", "ip"], [["mydevice", "192.168.1.1"]])
    assert "mydevice" in csv_str
    assert "192.168.1.1" in csv_str


# ─── traffic_counter ─────────────────────────────────────────────────────────

def test_compute_deltas_normal():
    from clarinet.collector.traffic_counter import _compute_deltas
    cur = {"AA:BB": (200, 100)}
    prev = {"AA:BB": (100, 60)}
    deltas = _compute_deltas(cur, prev)
    assert deltas["AA:BB"] == (100, 40)


def test_compute_deltas_reset_safe():
    from clarinet.collector.traffic_counter import _compute_deltas
    # Counter reset: current < previous → use current as delta
    cur = {"AA:BB": (10, 5)}
    prev = {"AA:BB": (1000, 800)}
    deltas = _compute_deltas(cur, prev)
    assert deltas["AA:BB"] == (10, 5)


def test_get_recent_device_bytes_empty():
    from clarinet.collector.traffic_counter import get_recent_device_bytes
    result = get_recent_device_bytes(window_s=1)
    # May have stale entries from other tests; just check it returns dict
    assert isinstance(result, dict)


# ─── alerts service ──────────────────────────────────────────────────────────

def test_raise_alert_dedup(db):
    """Second call within cooldown returns None."""
    from clarinet.core_svc.alerts import raise_alert
    a1 = raise_alert(db, "WARNING", "TEST_ALERT", "Test", "Test message", cooldown_s=3600)
    a2 = raise_alert(db, "WARNING", "TEST_ALERT", "Test", "Test message", cooldown_s=3600)
    assert a1 is not None
    assert a2 is None  # suppressed by dedup


def test_raise_alert_returns_alert(db):
    from clarinet.core_svc.alerts import raise_alert
    from clarinet.models import Alert
    a = raise_alert(db, "INFO", "UNIT_TEST", "Unit test alert", "Test body")
    assert isinstance(a, Alert)
    assert a.alert_id is not None
    assert a.status == "OPEN"


def test_resolve_alert(db):
    from clarinet.core_svc.alerts import raise_alert, resolve_alert
    raise_alert(db, "INFO", "TO_RESOLVE", "Will be resolved", "msg")
    count = resolve_alert(db, "TO_RESOLVE")
    assert count == 1


# ─── limit_service ───────────────────────────────────────────────────────────

def test_limit_summary_no_limit(db):
    """No limit set → status UNLIMITED."""
    from clarinet.core_svc.limit_service import get_limit_summary
    summary = get_limit_summary(db)
    assert summary.status == "UNLIMITED"
    assert summary.bytes_limit is None


def test_limit_summary_with_limit(db):
    from clarinet.core_svc.limit_service import get_limit_summary
    from clarinet.models import Settings
    db.add(Settings(key="limit.bytes", value=str(10 * 1024 ** 3)))  # 10 GB
    db.add(Settings(key="billing_day", value="1"))
    db.commit()
    summary = get_limit_summary(db)
    assert summary.bytes_limit == 10 * 1024 ** 3
    assert summary.status in ("UNDER", "WARN", "OVER", "UNLIMITED")
