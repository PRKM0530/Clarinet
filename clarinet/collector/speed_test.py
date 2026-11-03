"""
clarinet/collector/speed_test.py  (M2 rewrite)
Run a network speed test and store the result.

Fixes (F-08):
- Correct CLI flags for speedtest-cli and librespeed-cli
- `busy` flag based on active connections / traffic
- Failed tests are recorded in DB
- below_plan threshold: 80% (SRS default), not 70%
- Alert only when consistently below plan (≥ 3 in last 5 tests), not on one test
- Info alert "speed test finished" always raised
- Respects network_mode (skipped in PUBLIC, note in MONITOR)
"""
from __future__ import annotations

import json
import logging
import subprocess
import threading
from datetime import datetime, timezone

log = logging.getLogger("clarinet.collector.speed_test")

_running_lock = threading.Lock()
_is_running = False

# Plan threshold: below 80% of plan = below_plan
PLAN_THRESHOLD = 0.80
# Alert if ≥ this many of the last N tests are below plan
BELOW_PLAN_COUNT = 3
BELOW_PLAN_WINDOW = 5


def _is_busy(db) -> bool:
    """Return True if there is significant active traffic on the network."""
    try:
        from clarinet.enforcer.accounting import read_counters
        # If nft counters available, use them
        counters = read_counters()
        if counters:
            total = sum(i + o for i, o in counters.values())
            return total > 10_000_000  # 10 MB in sampling window = busy
    except Exception:
        pass
    return False


def _run_speedtest_cli() -> dict | None:
    """Run speedtest-cli (Ookla or open-source) and return parsed result."""
    # Try Ookla CLI first (uses --format=json)
    try:
        proc = subprocess.run(
            ["speedtest", "--format=json", "--accept-license", "--accept-gdpr"],
            capture_output=True, timeout=90,
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            return {
                "download_mbps": data["download"]["bandwidth"] * 8 / 1_000_000,
                "upload_mbps": data["upload"]["bandwidth"] * 8 / 1_000_000,
                "latency_ms": data["ping"]["latency"],
                "server_host": data.get("server", {}).get("host"),
                "tool": "ookla",
            }
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError, IndexError):
        pass

    # Try speedtest-cli (Python, older open-source)
    try:
        proc = subprocess.run(
            ["speedtest-cli", "--json", "--secure"],
            capture_output=True, timeout=90,
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            return {
                "download_mbps": data["download"] / 1_000_000,
                "upload_mbps": data["upload"] / 1_000_000,
                "latency_ms": data["ping"],
                "server_host": data.get("server", {}).get("host"),
                "tool": "speedtest-cli",
            }
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError, IndexError):
        pass

    # Try librespeed-cli (correct flags: no --no-download / --no-upload)
    try:
        proc = subprocess.run(
            ["librespeed-cli", "--json"],
            capture_output=True, timeout=90,
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            if isinstance(data, list):
                data = data[0]
            return {
                "download_mbps": float(data.get("download", 0)),
                "upload_mbps": float(data.get("upload", 0)),
                "latency_ms": float(data.get("ping", 0)),
                "server_host": data.get("server", {}).get("name") if isinstance(data.get("server"), dict) else None,
                "tool": "librespeed",
            }
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError, IndexError):
        pass

    return None


def _below_plan_consistently(db, plan_download_mbps: float, plan_upload_mbps: float) -> bool:
    """
    Return True if ≥ BELOW_PLAN_COUNT of the last BELOW_PLAN_WINDOW tests
    are below 80% of the plan speed.  Single failures are ignored (F-08f).
    """
    from clarinet.models import SpeedTestResult
    from clarinet.core_svc.speed_filters import valid_only
    recent = (
        valid_only(db.query(SpeedTestResult))
        .order_by(SpeedTestResult.tested_at.desc())
        .limit(BELOW_PLAN_WINDOW)
        .all()
    )
    if len(recent) < BELOW_PLAN_WINDOW:
        return False
    below = sum(
        1 for r in recent
        if not r.busy and (
            r.download_mbps < plan_download_mbps * PLAN_THRESHOLD
            or r.upload_mbps < plan_upload_mbps * PLAN_THRESHOLD
        )
    )
    return below >= BELOW_PLAN_COUNT


def run_speed_test() -> None:
    """
    Run a speed test, store the result, and raise alerts as needed.
    Called by jobs/access.py on a schedule.
    """
    global _is_running
    with _running_lock:
        if _is_running:
            log.info("Speed test already running, skipping")
            return
        _is_running = True

    try:
        _do_run()
    finally:
        with _running_lock:
            _is_running = False


def _do_run() -> None:
    from clarinet.database import SessionLocal
    from clarinet.models import SpeedTestResult
    from clarinet.app_settings import get_setting

    with SessionLocal() as db:
        mode = get_setting(db, "network_mode", "MONITOR").upper()
        if mode == "PUBLIC":
            log.info("Speed test skipped: PUBLIC mode")
            return

        plan_dl = float(get_setting(db, "plan_download_mbps", "0") or 0)
        plan_ul = float(get_setting(db, "plan_upload_mbps", "0") or 0)
        busy = _is_busy(db)

        log.info("Starting speed test (busy=%s)", busy)
        raw = _run_speedtest_cli()

        now = datetime.now(timezone.utc)

        if raw is None:
            # Record failed test
            record = SpeedTestResult(
                tested_at=now,
                download_mbps=0.0,
                upload_mbps=0.0,
                latency_ms=0.0,
                busy=busy,
                below_plan=False,
                server_host="failed",
            )
            db.add(record)
            db.commit()
            log.warning("Speed test failed: no tool available")
            return

        # Determine below_plan
        below = False
        if plan_dl > 0 and plan_ul > 0:
            below = (
                raw["download_mbps"] < plan_dl * PLAN_THRESHOLD
                or raw["upload_mbps"] < plan_ul * PLAN_THRESHOLD
            )

        record = SpeedTestResult(
            tested_at=now,
            download_mbps=round(raw["download_mbps"], 2),
            upload_mbps=round(raw["upload_mbps"], 2),
            latency_ms=round(raw["latency_ms"], 1),
            busy=busy,
            below_plan=below,
            server_host=raw.get("server_host"),
        )
        db.add(record)
        db.commit()
        log.info(
            "Speed test done: ↓%.1f Mbps ↑%.1f Mbps latency=%.0f ms below_plan=%s",
            record.download_mbps, record.upload_mbps, record.latency_ms, below,
        )

        # Info alert: test finished
        _raise_alert(db, "INFO", "SPEED_TEST_DONE",
                     "Speed test finished",
                     f"Download {record.download_mbps:.1f} Mbps, "
                     f"Upload {record.upload_mbps:.1f} Mbps, "
                     f"Latency {record.latency_ms:.0f} ms")

        # Warning alert: consistently below plan (not single test)
        if below and plan_dl > 0 and _below_plan_consistently(db, plan_dl, plan_ul):
            _raise_alert(db, "WARNING", "SPEED_BELOW_PLAN",
                         "Your internet speed is often below the plan",
                         f"Several recent tests show speeds below "
                         f"{PLAN_THRESHOLD*100:.0f}% of your plan "
                         f"({plan_dl:.0f} Mbps down, {plan_ul:.0f} Mbps up). "
                         f"This may indicate a provider issue.")


def _raise_alert(db, level: str, alert_type: str, title: str, message: str) -> None:
    """Create an alert, using M1's helper if available."""
    try:
        from clarinet.core_svc.alerts import raise_alert
        raise_alert(db, level, alert_type, title, message, cooldown_s=3600)
    except ImportError:
        # Fallback: create alert directly
        try:
            from clarinet.models import Alert
            existing = (
                db.query(Alert)
                .filter(Alert.type == alert_type, Alert.status == "OPEN")
                .first()
            )
            if not existing:
                db.add(Alert(level=level, type=alert_type, title=title, message=message))
                db.commit()
        except Exception as exc:
            log.error("Alert fallback failed: %s", exc)
    except Exception as exc:
        log.error("raise_alert failed: %s", exc)


def run_speed_test_async() -> None:
    """Trigger a speed test in a background thread (used by the manual-run route)."""
    t = threading.Thread(target=run_speed_test, daemon=True, name="speed_test")
    t.start()


def is_running() -> bool:
    return _is_running
