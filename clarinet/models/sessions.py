"""
clarinet/models/sessions.py
Server-side record of each live login. The browser cookie is signed but cannot be revoked on its own,
so a session only counts while its row exists here: logout, disabling a member and password resets delete it.
"""
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from clarinet.database import Base
from clarinet.models.core import _now


class ActiveSession(Base):
    __tablename__ = "active_session"

    sid: Mapped[str] = mapped_column(String(64), primary_key=True)
    member_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("member.member_id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
