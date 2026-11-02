"""
clarinet/core_svc/settings_m1.py
Typed getter helpers for all M1-owned setting keys.

Setting keys owned by M1:
  auth.*          — lockout/session thresholds
  scan.*          — ARP scanner config
  alerts.*        — alert thresholds and cooldowns
  summary.*       — summary job config
  limit.*         — data limit thresholds
  retention.*     — data retention periods
  timezone        — user-chosen display timezone
  router_ip       — detected/configured gateway IP
  setup_complete  — bool flag (string "true"/"false")
  setup_completed_at — ISO datetime string
  network_mode    — FULL | MONITOR | PUBLIC
  plan_download_mbps / plan_upload_mbps / billing_day — ISP plan

These are read-only getters; writes go through app_settings._set().
"""

from __future__ import annotations

from sqlalchemy.orm import Session


def _get(db: Session, key: str, default: str = "") -> str:
    """Read a setting value from the DB. Returns `default` if key is absent."""
    from clarinet.app_settings import get_setting
    val = get_setting(db, key)
    return val if val is not None else default


def _get_int(db: Session, key: str, default: int = 0) -> int:
    try:
        return int(_get(db, key, str(default)))
    except (ValueError, TypeError):
        return default


def _get_float(db: Session, key: str, default: float = 0.0) -> float:
    try:
        return float(_get(db, key, str(default)))
    except (ValueError, TypeError):
        return default


def _get_bool(db: Session, key: str, default: bool = False) -> bool:
    val = _get(db, key, "true" if default else "false")
    return val.lower() in ("true", "1", "yes")


# ─── Auth settings ─────────────────────────────────────────────────────────────

def auth_max_attempts(db: Session) -> int:
    return _get_int(db, "auth.max_attempts", 5)


def auth_lockout_minutes(db: Session) -> int:
    return _get_int(db, "auth.lockout_minutes", 5)


def auth_ip_window_seconds(db: Session) -> int:
    return _get_int(db, "auth.ip_window_seconds", 300)


# ─── Scanner settings ──────────────────────────────────────────────────────────

def scan_interval_seconds(db: Session) -> int:
    return _get_int(db, "scan.interval_seconds", 15)


def scan_interface(db: Session) -> str:
    return _get(db, "network_interface", "")


def scan_router_ip(db: Session) -> str:
    return _get(db, "router_ip", "")


def scan_subnet(db: Session) -> str:
    return _get(db, "scan.subnet", "")


# ─── Alert settings ────────────────────────────────────────────────────────────

def alerts_new_device_cooldown_s(db: Session) -> int:
    return _get_int(db, "alerts.new_device_cooldown_s", 3600)


def alerts_limit_warn_pct(db: Session) -> float:
    return _get_float(db, "alerts.limit_warn_pct", 0.70)


def alerts_limit_crit_pct(db: Session) -> float:
    return _get_float(db, "alerts.limit_crit_pct", 0.90)


# ─── Data limit settings ───────────────────────────────────────────────────────

def limit_bytes(db: Session) -> int | None:
    val = _get(db, "limit.bytes", "")
    if not val:
        return None
    try:
        return int(val)
    except ValueError:
        return None


def limit_warn_pct(db: Session) -> float:
    return alerts_limit_warn_pct(db)


def limit_crit_pct(db: Session) -> float:
    return alerts_limit_crit_pct(db)


def billing_day(db: Session) -> int:
    return _get_int(db, "billing_day", 1)


# ─── Retention settings ────────────────────────────────────────────────────────

def retention_traffic_days(db: Session) -> int:
    return _get_int(db, "retention.traffic_days", 90)


def retention_domain_days(db: Session) -> int:
    return _get_int(db, "retention.domain_days", 7)


def retention_samples_hours(db: Session) -> int:
    return _get_int(db, "retention.samples_hours", 24)


def retention_login_attempts_days(db: Session) -> int:
    return _get_int(db, "retention.login_attempts_days", 30)


# ─── Plan settings ─────────────────────────────────────────────────────────────

def plan_download_mbps(db: Session) -> float:
    return _get_float(db, "plan_download_mbps", 100.0)


def plan_upload_mbps(db: Session) -> float:
    return _get_float(db, "plan_upload_mbps", 20.0)


# ─── Network ──────────────────────────────────────────────────────────────────

def network_mode(db: Session) -> str:
    return _get(db, "network_mode", "MONITOR")


def timezone_setting(db: Session) -> str:
    return _get(db, "timezone", "Asia/Kolkata")


def setup_complete(db: Session) -> bool:
    return _get_bool(db, "setup_complete", False)

