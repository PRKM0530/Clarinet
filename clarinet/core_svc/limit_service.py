"""
clarinet/core_svc/limit_service.py
Data limit tracking and projection for M1. (C-07 backend)

Public API:
  get_limit_summary(db) -> LimitSummary
  check_and_alert(db)   — called by the limit_check job every 5 min
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date

from sqlalchemy import func
from sqlalchemy.orm import Session

log = logging.getLogger("clarinet.core_svc.limit")


@dataclass
class LimitSummary:
    """C-07 response payload (also used internally)."""
    bytes_used: int
    bytes_limit: int | None       # None = unlimited
    projected_bytes: int | None   # projected usage by end of billing period
    status: str                   # UNDER | WARN | OVER | UNLIMITED | UNKNOWN
    period_start: str             # "YYYY-MM-DD"
    period_end: str
    days_remaining: int
    warn_pct: float
    crit_pct: float

    @property
    def pct_used(self) -> float | None:
        if self.bytes_limit and self.bytes_limit > 0:
            return round(self.bytes_used / self.bytes_limit, 4)
        return None

    @property
    def mb_used(self) -> float:
        return round(self.bytes_used / 1_048_576, 2)

    @property
    def gb_used(self) -> float:
        return round(self.bytes_used / 1_073_741_824, 3)


def get_limit_summary(db: Session) -> LimitSummary:
    """
    Compute the current data limit summary for the active billing period.
    Reads settings for billing_day, limit.bytes, and alert thresholds.
    (C-07 contract backend)
    """
    from clarinet.core_svc.settings_m1 import (
        billing_day as get_billing_day,
        limit_bytes,
        limit_warn_pct,
        limit_crit_pct,
    )
    from clarinet.core_svc.timeutil import (
        billing_period_start,
        billing_period_end,
        days_remaining_in_period,
        period_fraction_elapsed,
    )
    from clarinet.models import UsageRecord

    bday = get_billing_day(db)
    today = date.today()
    period_start = billing_period_start(bday, today)
    period_end = billing_period_end(bday, today)
    days_left = days_remaining_in_period(bday, today)
    frac_elapsed = period_fraction_elapsed(bday, today)

    start_str = period_start.isoformat()
    end_str = period_end.isoformat()

    # Sum all usage in the current billing period
    bytes_used = (
        db.query(func.sum(UsageRecord.bytes_in + UsageRecord.bytes_out))
        .filter(
            UsageRecord.date >= start_str,
            UsageRecord.date <= today.isoformat(),
        )
        .scalar()
    ) or 0

    bytes_lim = limit_bytes(db)
    warn_pct = limit_warn_pct(db)
    crit_pct = limit_crit_pct(db)

    # Projection: linear extrapolation
    projected: int | None = None
    if frac_elapsed > 0:
        projected = int(bytes_used / frac_elapsed)

    # Status
    if bytes_lim is None:
        status = "UNLIMITED"
    elif bytes_used >= bytes_lim:
        status = "OVER"
    elif bytes_used >= bytes_lim * crit_pct:
        status = "WARN"  # approaching critical
    elif bytes_used >= bytes_lim * warn_pct:
        status = "WARN"
    else:
        status = "UNDER"

    return LimitSummary(
        bytes_used=bytes_used,
        bytes_limit=bytes_lim,
        projected_bytes=projected,
        status=status,
        period_start=start_str,
        period_end=end_str,
        days_remaining=days_left,
        warn_pct=warn_pct,
        crit_pct=crit_pct,
    )


def check_and_alert(db: Session) -> None:
    """
    Called by the limit_check job every 5 min.
    Raises alerts if usage is approaching or has exceeded the data limit.
    """
    summary = get_limit_summary(db)

    if summary.status == "UNLIMITED" or summary.bytes_limit is None:
        return

    from clarinet.core_svc.alerts import raise_alert

    pct = summary.pct_used or 0.0
    used_gb = summary.gb_used
    limit_gb = round(summary.bytes_limit / 1_073_741_824, 1)

    if pct >= summary.crit_pct:
        raise_alert(
            db,
            level="CRITICAL",
            type="DATA_LIMIT_CRITICAL",
            title="Data limit nearly exhausted",
            message=(
                f"Used {used_gb:.1f} GB of {limit_gb} GB "
                f"({pct*100:.0f}%). {summary.days_remaining} day(s) remaining."
            ),
            cooldown_s=3600,
        )
    elif pct >= summary.warn_pct:
        raise_alert(
            db,
            level="WARNING",
            type="DATA_LIMIT_WARN",
            title="Data limit warning",
            message=(
                f"Used {used_gb:.1f} GB of {limit_gb} GB "
                f"({pct*100:.0f}%). {summary.days_remaining} day(s) remaining."
            ),
            cooldown_s=7200,
        )
