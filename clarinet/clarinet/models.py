"""
clarinet/models.py
All SQLAlchemy ORM models.

Tables:
  Member          – users (admin or member role)
  Device          – network devices keyed by MAC
  DeviceHistory   – join/leave log (DEV-7)
  Alert           – security / performance alerts
  TimeRule        – schedule-based block or rate-limit rule
  RuleException   – one-hour override for a blocked device (ACC-3)
  UsageRecord     – per-device per-hour traffic buckets
  SlowdownEvent   – detected internet slowdown episodes
  Voucher         – guest one-time-use access code
  PriorityGrant   – member speed-priority request + decision
  SpeedTestResult – scheduled speed test snapshot
  Baseline        – per-hour traffic normal ranges (PERF-2)
  PingRecord      – ICMP latency time-series (latency charts)
  AuditLog        – immutable record of every admin action (ACC-9)
  Settings        – key/value store for mode, plan, thresholds
"""

import json
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, String, Text,
    UniqueConstraint, func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from clarinet.database import Base


def _now() -> datetime:
    """UTC timestamp helper."""
    return datetime.now(timezone.utc)


# Member (users of the Clarinet dashboard)

class Member(Base):
    __tablename__ = "member"

    member_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    # role: ADMIN has full access; MEMBER sees own devices + usage + priority
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="MEMBER")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # Login lockout (ACC-02: 5 failed attempts → locked 5 min)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Soft-disable a member without deleting them
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Relationships
    devices: Mapped[list["Device"]] = relationship(back_populates="owner", foreign_keys="Device.owner_member_id")
    vouchers_created: Mapped[list["Voucher"]] = relationship(back_populates="creator")
    rules_created: Mapped[list["TimeRule"]] = relationship(back_populates="creator")
    priority_grants: Mapped[list["PriorityGrant"]] = relationship(back_populates="member")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="actor")

    def __repr__(self) -> str:
        return f"<Member {self.username!r} role={self.role}>"

    @property
    def is_admin(self) -> bool:
        return self.role == "ADMIN"

    @property
    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        return _now() < self.locked_until


# Device

class Device(Base):
    __tablename__ = "device"

    device_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    mac_address: Mapped[str] = mapped_column(String(17), unique=True, nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)  # IPv4 or IPv6
    hostname: Mapped[str | None] = mapped_column(String(256), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Device lifecycle: NEW → APPROVED | BLOCKED | GUEST
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="NEW")
    owner_member_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("member.member_id", ondelete="SET NULL"), nullable=True
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    # True if MAC OUI doesn't match any known vendor (randomised MAC warning)
    is_random_mac: Mapped[bool] = mapped_column(Boolean, default=False)
    # Human-friendly label set by admin
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)

    owner: Mapped["Member | None"] = relationship(back_populates="devices", foreign_keys=[owner_member_id])
    usage_records: Mapped[list["UsageRecord"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    time_rules: Mapped[list["TimeRule"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="device")
    history: Mapped[list["DeviceHistory"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    priority_grants: Mapped[list["PriorityGrant"]] = relationship(back_populates="device")

    def __repr__(self) -> str:
        return f"<Device {self.mac_address} state={self.state}>"


# DeviceHistory (join/leave log, DEV-7)

class DeviceHistory(Base):
    __tablename__ = "device_history"

    history_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    # JOIN or LEAVE
    event: Mapped[str] = mapped_column(String(8), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    device: Mapped["Device"] = relationship(back_populates="history")


# Alert

class Alert(Base):
    __tablename__ = "alert"

    alert_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    # CRITICAL | WARNING | INFO
    level: Mapped[str] = mapped_column(String(16), nullable=False)
    # e.g. NEW_DEVICE | ARP_SPOOF | SLOWDOWN | BELOW_PLAN | VOUCHER_EXPIRED
    type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    raised_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    # OPEN | ACK | RESOLVED
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN")
    device_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("device.device_id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    device: Mapped["Device | None"] = relationship(back_populates="alerts")

    def __repr__(self) -> str:
        return f"<Alert {self.type} level={self.level} status={self.status}>"


# TimeRule

class TimeRule(Base):
    __tablename__ = "time_rule"

    rule_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    device_id: Mapped[int] = mapped_column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    # JSON array of day names e.g. '["Mon","Tue","Wed"]'
    days_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    start_time: Mapped[str] = mapped_column(String(5), nullable=False)   # "HH:MM"
    end_time: Mapped[str] = mapped_column(String(5), nullable=False)     # "HH:MM"
    # BLOCK | RATE_LIMIT
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    rate_kbps: Mapped[int | None] = mapped_column(Integer, nullable=True)   # only for RATE_LIMIT
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("member.member_id"))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    device: Mapped["Device"] = relationship(back_populates="time_rules")
    creator: Mapped["Member"] = relationship(back_populates="rules_created")
    exceptions: Mapped[list["RuleException"]] = relationship(back_populates="rule", cascade="all, delete-orphan")

    @property
    def days(self) -> list[str]:
        return json.loads(self.days_json)

    @days.setter
    def days(self, value: list[str]) -> None:
        self.days_json = json.dumps(value)


# RuleException (one-hour override, ACC-3)

class RuleException(Base):
    __tablename__ = "rule_exception"

    exception_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey("time_rule.rule_id", ondelete="CASCADE"))
    device_id: Mapped[int] = mapped_column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    granted_by: Mapped[int] = mapped_column(Integer, ForeignKey("member.member_id"))

    rule: Mapped["TimeRule"] = relationship(back_populates="exceptions")


# UsageRecord (per-device per-hour traffic buckets)

class UsageRecord(Base):
    __tablename__ = "usage_record"
    __table_args__ = (UniqueConstraint("device_id", "date", "hour"),)

    record_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"), index=True)
    date: Mapped[str] = mapped_column(String(10), nullable=False, index=True)   # "YYYY-MM-DD"
    hour: Mapped[int] = mapped_column(Integer, nullable=False)                  # 0-23
    # Coarse traffic category (STREAMING | GAMING | BROWSING | VOIP | DOWNLOAD | UPLOAD | OTHER)
    activity: Mapped[str] = mapped_column(String(16), nullable=False, default="OTHER")
    bytes_in: Mapped[int] = mapped_column(Integer, default=0)
    bytes_out: Mapped[int] = mapped_column(Integer, default=0)

    device: Mapped["Device"] = relationship(back_populates="usage_records")


# SlowdownEvent

class SlowdownEvent(Base):
    __tablename__ = "slowdown_event"

    event_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # JSON list of cause dicts: [{"cause": "ONE_DEVICE_HEAVY", "confidence": "HIGH", "detail": "..."}]
    causes_json: Mapped[str] = mapped_column(Text, default="[]")
    # JSON snapshot of raw metrics at detection time
    raw_metrics_json: Mapped[str] = mapped_column(Text, default="{}")

    @property
    def causes(self) -> list[dict]:
        return json.loads(self.causes_json)

    @causes.setter
    def causes(self, value: list[dict]) -> None:
        self.causes_json = json.dumps(value)

    @property
    def raw_metrics(self) -> dict:
        return json.loads(self.raw_metrics_json)

    @raw_metrics.setter
    def raw_metrics(self, value: dict) -> None:
        self.raw_metrics_json = json.dumps(value)


# Voucher (guest one-time-use access code)

class Voucher(Base):
    __tablename__ = "voucher"

    voucher_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("member.member_id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_by_mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # UNUSED | ACTIVE | EXPIRED | REVOKED
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="UNUSED")
    data_cap_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    speed_cap_mbps: Mapped[float | None] = mapped_column(Float, nullable=True)

    creator: Mapped["Member"] = relationship(back_populates="vouchers_created")


# PriorityGrant

class PriorityGrant(Base):
    __tablename__ = "priority_grant"

    grant_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    member_id: Mapped[int] = mapped_column(Integer, ForeignKey("member.member_id"))
    device_id: Mapped[int] = mapped_column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # PENDING | APPROVED | DENIED | EXPIRED
    decision: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    duration_min: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    grant_mbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    member: Mapped["Member"] = relationship(back_populates="priority_grants")
    device: Mapped["Device"] = relationship(back_populates="priority_grants")


# SpeedTestResult

class SpeedTestResult(Base):
    __tablename__ = "speed_test_result"

    test_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    download_mbps: Mapped[float] = mapped_column(Float, nullable=False)
    upload_mbps: Mapped[float] = mapped_column(Float, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    # Was network heavily loaded during test? (affects validity)
    busy: Mapped[bool] = mapped_column(Boolean, default=False)
    # Did result fall below the configured plan threshold?
    below_plan: Mapped[bool] = mapped_column(Boolean, default=False)
    server_host: Mapped[str | None] = mapped_column(String(128), nullable=True)


# Baseline (per-hour normal ranges, PERF-2)

class Baseline(Base):
    __tablename__ = "baseline"
    __table_args__ = (UniqueConstraint("hour", "day_of_week"),)

    baseline_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hour: Mapped[int] = mapped_column(Integer, nullable=False)           # 0-23
    day_of_week: Mapped[int] = mapped_column(Integer, nullable=False)    # 0=Mon … 6=Sun
    avg_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    std_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_download_mbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_upload_mbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    sample_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


# AuditLog (immutable record of admin actions, ACC-9)

class AuditLog(Base):
    __tablename__ = "audit_log"

    log_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    actor_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("member.member_id", ondelete="SET NULL"), nullable=True
    )
    # e.g. CREATE_RULE | DELETE_VOUCHER | APPROVE_DEVICE | BLOCK_DEVICE | LOGIN_FAIL
    action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)  # e.g. "Device"
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)    # stringified PK
    detail_json: Mapped[str] = mapped_column(Text, default="{}")

    actor: Mapped["Member | None"] = relationship(back_populates="audit_logs")

    @property
    def detail(self) -> dict:
        return json.loads(self.detail_json)

    @detail.setter
    def detail(self, value: dict) -> None:
        self.detail_json = json.dumps(value)


# Settings (key/value store for runtime configuration)

class Settings(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    def __repr__(self) -> str:
        return f"<Settings {self.key}={self.value!r}>"


# PingRecord (ICMP latency time-series)

class PingRecord(Base):
    """Stores every ICMP measurement made by the pinger so charts can render latency history."""
    __tablename__ = "ping_record"

    record_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    measured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    # "router" | "google_dns" | "cloudflare"
    target: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(64), nullable=False)
    avg_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    min_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    max_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_loss: Mapped[float] = mapped_column(Float, default=0.0)   # 0.0–1.0
    reachable: Mapped[bool] = mapped_column(Boolean, default=True)

