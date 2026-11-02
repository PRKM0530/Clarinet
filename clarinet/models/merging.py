"""
clarinet/models/merging.py
Hardware addresses that belong to another device (DEV-5).

When an admin merges two entries that are really one device, for example a
phone that rotates its MAC address, the absorbed address is kept here. The
scanner then recognises it as the main device instead of announcing a new one.
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from clarinet.database import Base
from clarinet.models.core import _now


class MergedMac(Base):
    __tablename__ = "merged_mac"

    mac_address: Mapped[str] = mapped_column(String(17), primary_key=True)
    primary_device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("device.device_id", ondelete="CASCADE"), nullable=False, index=True
    )
    # what the absorbed entry was called, so the admin can recognise it in the list
    former_label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    merged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    merged_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("member.member_id", ondelete="SET NULL"), nullable=True
    )
