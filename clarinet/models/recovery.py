"""
clarinet/models/recovery.py
Recovery codes: how a member who forgot their password gets back in without
anyone else, including an administrator, ever knowing or setting it.
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from clarinet.database import Base
from clarinet.models.core import _now


class RecoveryCode(Base):
    """One code per member. Only a hash is stored, so the code cannot be read back, only checked."""
    __tablename__ = "recovery_code"

    member_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("member.member_id", ondelete="CASCADE"), primary_key=True
    )
    code_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class RecoveryAttempt(Base):
    """Every try to reset a password with a code, so guessing can be slowed down."""
    __tablename__ = "recovery_attempt"

    attempt_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(64), index=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
