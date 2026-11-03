"""
clarinet/models/devspeed.py
Speed results measured from a device itself, one row per test and per device.

These are not the internet speed (SpeedTestResult, measured at the gateway by the
Clarinet computer). They describe one device's own link to Clarinet.
"""

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column

from clarinet.database import Base
from clarinet.models.core import _now


class DeviceSpeedResult(Base):
    __tablename__ = "device_speed_result"

    result_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("device.device_id", ondelete="CASCADE"), nullable=False, index=True
    )
    tested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    download_mbps: Mapped[float] = mapped_column(Float, nullable=False)
    upload_mbps: Mapped[float] = mapped_column(Float, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    jitter_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    run_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("member.member_id", ondelete="SET NULL"), nullable=True
    )
