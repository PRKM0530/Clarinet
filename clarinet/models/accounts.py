"""
clarinet/models/accounts.py
Sign-up, admin-access requests and device claims.
"""
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from clarinet.database import Base
from clarinet.models.core import _now


class AdminRequest(Base):
    """A member who asked to become an administrator. An existing admin decides."""
    __tablename__ = "admin_request"

    member_id: Mapped[int] = mapped_column(Integer, ForeignKey("member.member_id", ondelete="CASCADE"), primary_key=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="PENDING")     # PENDING | APPROVED | DECLINED
    decided_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("member.member_id", ondelete="SET NULL"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DeviceClaim(Base):
    """A member saying "this device is mine". An admin confirms before the device becomes theirs."""
    __tablename__ = "device_claim"

    claim_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"), index=True, nullable=False)
    member_id: Mapped[int] = mapped_column(Integer, ForeignKey("member.member_id", ondelete="CASCADE"), index=True, nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="PENDING")     # PENDING | APPROVED | DECLINED


class SignupAttempt(Base):
    """Every sign-up submission, so one address cannot create accounts or probe usernames without limit."""
    __tablename__ = "signup_attempt"

    attempt_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
