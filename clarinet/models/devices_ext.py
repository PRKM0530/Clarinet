"""
clarinet/models/devices_ext.py
M1-owned device extension tables.

Tables:
  DeviceAlias  — user-set friendly name history
  DeviceMerge  — admin-initiated MAC merge records
  DeviceEvent  — richer event log beyond DeviceHistory (IP changes, state changes)
  DeviceHint   — auto-detected metadata hints (hostname, vendor, OS guess)

NOTE: device_owner NOT created here — Device.owner_member_id already exists in core.py (A-M1-12)
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from clarinet.database import Base


class DeviceAlias(Base):
    """
    History of admin-set labels for a device.
    The current label lives on Device.label (core.py).
    This table keeps the audit trail of changes.
    """
    __tablename__ = "device_alias"

    alias_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("device.device_id", ondelete="CASCADE"), index=True
    )
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    set_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("member.member_id", ondelete="SET NULL"), nullable=True
    )
    set_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class DeviceMerge(Base):
    """
    Records when an admin merges two Device rows (e.g. MAC change on device re-join).
    After merge, secondary_device_id is deleted and its data remapped.
    """
    __tablename__ = "device_merge"

    merge_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    primary_device_id: Mapped[int] = mapped_column(Integer, nullable=False)   # kept
    secondary_device_id: Mapped[int] = mapped_column(Integer, nullable=False)  # deleted
    merged_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("member.member_id", ondelete="SET NULL"), nullable=True
    )
    merged_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class DeviceEvent(Base):
    """
    Richer event log than DeviceHistory.
    Captures IP changes, state transitions (APPROVED/BLOCKED/GUEST), and rename events.
    """
    __tablename__ = "device_event"

    event_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("device.device_id", ondelete="CASCADE"), index=True
    )
    # JOIN | LEAVE | IP_CHANGE | STATE_CHANGE | RENAME | MERGE | BLOCK | UNBLOCK
    event_type: Mapped[str] = mapped_column(String(16), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    old_value: Mapped[str | None] = mapped_column(String(256), nullable=True)
    new_value: Mapped[str | None] = mapped_column(String(256), nullable=True)
    actor_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("member.member_id", ondelete="SET NULL"), nullable=True
    )
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    device: Mapped["Device"] = relationship("Device")  # type: ignore[name-defined]


class DeviceHint(Base):
    """
    Auto-detected metadata hints for a device (from mDNS, DHCP, SSDP, etc.).
    These are suggestions only — admin's label (Device.label) takes precedence.
    """
    __tablename__ = "device_hint"

    hint_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("device.device_id", ondelete="CASCADE"), index=True
    )
    # Source of the hint: "mdns" | "dhcp" | "ssdp" | "oui" | "manual"
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    # Kind of hint: "hostname" | "vendor" | "os" | "model" | "type"
    hint_key: Mapped[str] = mapped_column(String(32), nullable=False)
    hint_value: Mapped[str] = mapped_column(String(256), nullable=False)
    confidence: Mapped[float] = mapped_column(Integer, default=100)  # 0-100
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

