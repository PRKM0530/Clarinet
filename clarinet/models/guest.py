"""
clarinet/models/guest.py
M2-owned tables: voucher redemptions and enforcement status.
Table prefix: voucher_*, redeem_attempt, enforcement_status, priority_*,
              fairness_credit, speed_test_run
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from clarinet.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RedeemAttempt(Base):
    """Brute-force log for voucher redemptions (per IP)."""
    __tablename__ = "redeem_attempt"

    attempt_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    code_tried: Mapped[str] = mapped_column(String(32), nullable=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False)


class EnforcementStatus(Base):
    """
    Tracks which device currently has guest access (active voucher binding).
    One row per device MAC while access is active; deleted on expiry.
    """
    __tablename__ = "enforcement_status"

    mac: Mapped[str] = mapped_column(String(17), primary_key=True)
    voucher_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("voucher.voucher_id", ondelete="CASCADE"), nullable=False, index=True
    )
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    data_cap_mb: Mapped[float | None] = mapped_column(Float, nullable=True)
    speed_cap_mbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    bytes_used: Mapped[int] = mapped_column(Integer, default=0)


class FairnessCredit(Base):
    """
    FAIR-5: track cumulative priority minutes granted per member per day.
    Prevents one member from monopolising priority bandwidth.
    """
    __tablename__ = "fairness_credit"

    credit_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    member_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("member.member_id", ondelete="CASCADE"), nullable=False, index=True
    )
    day: Mapped[str] = mapped_column(String(10), nullable=False, index=True)   # YYYY-MM-DD local
    minutes_used: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

