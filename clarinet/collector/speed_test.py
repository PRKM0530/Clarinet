"""
clarinet/collector/speed_test.py
Internet speed tests using the speedtest-cli tool or librespeed-cli.

The result is stored in SpeedTestResult and compared against the
configured ISP plan. If download falls below the threshold, a
BELOW_PLAN alert is raised.
"""

import json
import logging
import subprocess
import threading
from datetime import datetime, timezone

log = logging.getLogger("clarinet.collector.speed")

_lock = threading.Lock()   # Only one test at a time


def _run_speedtest_cli() -> dict | None:
    """
    Run 'speedtest --json' (Ookla CLI) and parse output.
    Falls back to librespeed-cli if Ookla isn't available.
    Returns a dict with download_mbps, upload_mbps, latency_ms, server_host.
    """
    # Try Ookla speedtest CLI
    try:
        out = subprocess.check_output(
            ["speedtest", "--json", "--secure"],
            timeout=90, stderr=subprocess.DEVNULL,
        )
        data = json.loads(out)
        return {
            "download_mbps": round(data["download"] / 1_000_000, 2),
            "upload_mbps": round(data["upload"] / 1_000_000, 2),
            "latency_ms": round(data["ping"], 1),
            "server_host": data.get("server", {}).get("host", "ookla"),
        }
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning("Ookla speedtest failed: %s", e)

    # Try librespeed-cli
    try:
        out = subprocess.check_output(
            ["librespeed-cli", "--json", "--no-download", "--no-upload"],
            timeout=90, stderr=subprocess.DEVNULL,
        )
        # librespeed returns a JSON array
        data = json.loads(out)
        if isinstance(data, list):
            data = data[0]
        return {
            "download_mbps": round(float(data.get("download", 0)), 2),
            "upload_mbps": round(float(data.get("upload", 0)), 2),
            "latency_ms": round(float(data.get("ping", 0)), 1),
            "server_host": data.get("server", {}).get("name", "librespeed"),
        }
    except FileNotFoundError:
        log.warning("No speed-test CLI found. Install 'speedtest' or 'librespeed-cli'.")
    except Exception as e:
        log.error("librespeed-cli failed: %s", e)

    return None


def run_speed_test() -> None:
    """
    Run a speed test and write the result to DB.
    Called by APScheduler (every N hours) or manually from /speed/run.
    Thread-safe: only one test runs at a time.
    """
    if not _lock.acquire(blocking=False):
        log.info("Speed test already running, skipping")
        return

    try:
        log.info("Speed test started")
        result = _run_speedtest_cli()
        if result is None:
            log.warning("Speed test produced no result")
            return

        from clarinet.database import SessionLocal
        from clarinet.models import SpeedTestResult, Alert, Settings as AppSettings

        with SessionLocal() as db:
            # Get plan thresholds
            dl_row = db.get(AppSettings, "plan_download_mbps")
            threshold_row = db.get(AppSettings, "slowdown_speed_threshold")
            plan_dl = float(dl_row.value) if dl_row else 100.0
            threshold = float(threshold_row.value) if threshold_row else 0.70

            below_plan = result["download_mbps"] < (plan_dl * threshold)

            record = SpeedTestResult(
                tested_at=datetime.now(timezone.utc),
                download_mbps=result["download_mbps"],
                upload_mbps=result["upload_mbps"],
                latency_ms=result["latency_ms"],
                below_plan=below_plan,
                server_host=result.get("server_host"),
            )
            db.add(record)

            if below_plan:
                alert = Alert(
                    level="WARNING",
                    type="BELOW_PLAN",
                    title="Internet speed below plan",
                    message=(
                        f"Speed test: {result['download_mbps']:.1f} Mbps download "
                        f"(plan: {plan_dl:.0f} Mbps, threshold: {threshold*100:.0f}%). "
                        f"Latency: {result['latency_ms']:.0f} ms."
                    ),
                )
                db.add(alert)

            db.commit()
            log.info(
                "Speed test done: %.1f↓ %.1f↑ Mbps, %.0f ms %s",
                result["download_mbps"], result["upload_mbps"],
                result["latency_ms"],
                "[BELOW PLAN]" if below_plan else ""
            )
    finally:
        _lock.release()


def run_speed_test_async() -> None:
    """Fire-and-forget in a daemon thread (for the manual /speed/run endpoint)."""
    t = threading.Thread(target=run_speed_test, daemon=True, name="speed-test")
    t.start()
