"""
clarinet/analytics/fairness.py
Bandwidth fairness policy checks.

Used to flag devices that are consistently hogging the link
and to suggest rate-limit rules to the administrator.
"""

import logging
from datetime import date, timedelta

log = logging.getLogger("clarinet.analytics.fairness")

# If a device uses more than this fraction of total daily traffic
# for 3+ consecutive days, recommend a rate-limit rule.
HOG_THRESHOLD = 0.40    # 40%
HOG_MIN_DAYS = 3


def find_hogs(db) -> list[dict]:
    """
    Analyse the last 7 days of UsageRecord data.
    Returns a list of {device, avg_share, days_over_threshold} dicts
    for devices consistently above HOG_THRESHOLD.
    """
    from clarinet.models import Device, UsageRecord
    from sqlalchemy import func

    results = []
    since = (date.today() - timedelta(days=7)).isoformat()

    # Daily totals per device
    per_device = (
        db.query(
            UsageRecord.device_id,
            UsageRecord.date,
            func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out).label("total"),
        )
        .filter(UsageRecord.date >= since)
        .group_by(UsageRecord.device_id, UsageRecord.date)
        .all()
    )

    # Daily network totals
    daily_totals: dict[str, int] = {}
    for r in per_device:
        daily_totals[r.date] = daily_totals.get(r.date, 0) + (r.total or 0)

    # Per-device daily share
    device_days: dict[int, list[float]] = {}
    for r in per_device:
        day_total = daily_totals.get(r.date, 0)
        if day_total > 0:
            share = (r.total or 0) / day_total
            device_days.setdefault(r.device_id, []).append(share)

    for device_id, shares in device_days.items():
        days_over = sum(1 for s in shares if s > HOG_THRESHOLD)
        if days_over >= HOG_MIN_DAYS:
            device = db.get(Device, device_id)
            results.append({
                "device": device,
                "avg_share": round(sum(shares) / len(shares), 3),
                "days_over_threshold": days_over,
            })

    return results


def suggest_rate_limits(db) -> list[dict]:
    """
    Higher-level API: return actionable suggestions for the admin.
    Each suggestion is a dict with device info and recommended rate_kbps.
    """
    from clarinet.models import Settings as AppSettings
    plan_row = db.get(AppSettings, "plan_download_mbps")
    plan_mbps = float(plan_row.value) if plan_row else 100.0
    # Recommend capping a hog at 40% of the plan
    cap_kbps = int(plan_mbps * 1000 * 0.40)

    suggestions = []
    for h in find_hogs(db):
        suggestions.append({
            "device": h["device"],
            "avg_share_pct": round(h["avg_share"] * 100, 1),
            "days_over": h["days_over_threshold"],
            "suggested_rate_kbps": cap_kbps,
        })
    return suggestions
