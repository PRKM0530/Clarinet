"""
clarinet/core_svc/speed_report.py
The evidence behind "is my internet as fast as I pay for?" (UC-08).

Compares speed tests with the subscribed plan over a period. Tests taken while
the network was busy are left out of the verdict, because a busy network makes
any connection look slow. The result can be printed and shown to the provider.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from clarinet.app_settings import get_setting
from clarinet.models import SpeedTestResult

DEFAULT_THRESHOLD_PCT = 80      # a test under this share of the plan counts as "below plan"
OFTEN_BELOW_SHARE = 0.25        # "often below" means more than a quarter of valid tests


@dataclass
class SpeedReport:
    days: int
    start: datetime
    end: datetime
    plan_download: float
    plan_upload: float
    threshold_pct: int
    tests: list[SpeedTestResult] = field(default_factory=list)   # valid tests, newest first
    busy_excluded: int = 0
    avg_download: float | None = None
    min_download: float | None = None
    max_download: float | None = None
    avg_upload: float | None = None
    below_count: int = 0
    below_share: float = 0.0
    often_below: bool = False

    @property
    def avg_download_pct(self) -> float | None:
        if self.avg_download is None or self.plan_download <= 0:
            return None
        return round(self.avg_download * 100 / self.plan_download, 1)

    def pct_of_plan(self, test: SpeedTestResult) -> float | None:
        return round(test.download_mbps * 100 / self.plan_download, 1) if self.plan_download > 0 else None

    def verdict(self) -> str:
        if not self.tests:
            return "There are no valid speed tests in this period, so no conclusion can be drawn."
        if self.plan_download <= 0:
            return "No plan speed is set, so the results cannot be compared with a plan."
        if self.often_below:
            return (
                f"The connection was often slower than the plan: {self.below_count} of {len(self.tests)} tests "
                f"({round(self.below_share * 100)}%) were below {self.threshold_pct}% of the {self.plan_download:g} Mbps plan."
            )
        return (
            f"The connection mostly delivered the plan: {len(self.tests) - self.below_count} of {len(self.tests)} tests "
            f"were at or above {self.threshold_pct}% of the {self.plan_download:g} Mbps plan."
        )


def build_speed_report(db: Session, days: int = 30, now: datetime | None = None) -> SpeedReport:
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    threshold = int(get_setting(db, "speed_report_threshold_pct", str(DEFAULT_THRESHOLD_PCT)) or DEFAULT_THRESHOLD_PCT)

    report = SpeedReport(
        days=days, start=start, end=now,
        plan_download=float(get_setting(db, "plan_download_mbps", "0") or 0),
        plan_upload=float(get_setting(db, "plan_upload_mbps", "0") or 0),
        threshold_pct=threshold,
    )

    rows = (
        db.query(SpeedTestResult)
        .filter(SpeedTestResult.tested_at >= start)
        .order_by(SpeedTestResult.tested_at.desc())
        .all()
    )
    report.busy_excluded = sum(1 for r in rows if r.busy)
    report.tests = [r for r in rows if not r.busy]
    if not report.tests:
        return report

    downloads = [r.download_mbps for r in report.tests]
    uploads = [r.upload_mbps for r in report.tests]
    report.avg_download = round(sum(downloads) / len(downloads), 1)
    report.min_download = round(min(downloads), 1)
    report.max_download = round(max(downloads), 1)
    report.avg_upload = round(sum(uploads) / len(uploads), 1)

    if report.plan_download > 0:
        floor = report.plan_download * threshold / 100
        report.below_count = sum(1 for d in downloads if d < floor)
        report.below_share = report.below_count / len(downloads)
        report.often_below = report.below_share > OFTEN_BELOW_SHARE
    return report
