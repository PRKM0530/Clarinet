"""
clarinet/models/reports.py
M1-owned report and audit tables.

Tables:
  LoginAttempt   — record of every login attempt (IP + user + success)
  SetupProgress  — resumable wizard state
  UsageSummary   — pre-aggregated daily/weekly summary snapshots
  LimitState     — current billing-period data limit state
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from clarinet.database import Base


class LoginAttempt(Base):
    """
    Record of every login attempt (success and failure).
    Used for lockout enforcement and audit trail.
    """
    __tablename__ = "login_attempt"

    attempt_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    member_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("member.member_id", ondelete="SET NULL"), nullable=True
    )
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)

    member: Mapped["Member | None"] = relationship("Member", foreign_keys=[member_id])  # type: ignore[name-defined]


class SetupProgress(Base):
    """
    Resumable wizard state — one row per setup session.
    step_number goes from 1 to 6 as each step is completed.
    """
    __tablename__ = "setup_progress"

    progress_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    step_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # JSON snapshot of partial form data so wizard can resume mid-way
    partial_data_json: Mapped[str] = mapped_column(Text, default="{}")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed: Mapped[bool] = mapped_column(Boolean, default=False)


class UsageSummary(Base):
    """
    Pre-aggregated traffic summary for quick dashboard/report rendering.
    Populated by the daily_summary job.
    """
    __tablename__ = "usage_summary"

    summary_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # "daily" or "weekly"
    period_type: Mapped[str] = mapped_column(String(8), nullable=False)
    period_date: Mapped[str] = mapped_column(String(10), nullable=False, index=True)  # "YYYY-MM-DD"
    device_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("device.device_id", ondelete="CASCADE"), nullable=True
    )
    bytes_in: Mapped[int] = mapped_column(Integer, default=0)
    bytes_out: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class LimitState(Base):
    """
    Current data-limit state for the billing period.
    One row; updated each time the limit_check job runs.
    """
    __tablename__ = "limit_state"

    state_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    billing_period_start: Mapped[str] = mapped_column(String(10), nullable=False)  # "YYYY-MM-DD"
    bytes_used: Mapped[int] = mapped_column(Integer, default=0)
    bytes_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)  # None = unlimited
    projected_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # UNDER | WARN | OVER | UNKNOWN
    status: Mapped[str] = mapped_column(String(8), default="UNKNOWN")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

