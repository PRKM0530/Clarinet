"""
clarinet/models/security.py
Tables used by the security checks (ARP history, trusted access points,
known networks, router audit findings).
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from clarinet.database import Base
from clarinet.models.core import _now


class ArpBinding(Base):
    """Last MAC seen answering for an IP, kept across restarts for spoof detection."""
    __tablename__ = "arp_binding"

    ip_address: Mapped[str] = mapped_column(String(45), primary_key=True)
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class TrustedAccessPoint(Base):
    """A Wi-Fi access point (SSID + BSSID) the admin has said is legitimate."""
    __tablename__ = "trusted_access_point"

    ap_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ssid: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    bssid: Mapped[str] = mapped_column(String(17), nullable=False, unique=True)
    label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class SeenAccessPoint(Base):
    """Every access point seen in the latest scans, so the admin can trust one with a click."""
    __tablename__ = "seen_access_point"

    bssid: Mapped[str] = mapped_column(String(17), primary_key=True)
    ssid: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    signal: Mapped[int | None] = mapped_column(Integer, nullable=True)
    security: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # OK | UNKNOWN | SUSPECT (set by the scanner on every pass)
    verdict: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    reason: Mapped[str | None] = mapped_column(String(160), nullable=True)


class KnownNetwork(Base):
    """A network this server has been connected to (identified by gateway MAC)."""
    __tablename__ = "known_network"

    network_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    gateway_mac: Mapped[str] = mapped_column(String(17), nullable=False, unique=True)
    gateway_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    subnet: Mapped[str | None] = mapped_column(String(45), nullable=True)
    ssid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trusted: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class RouterAuditFinding(Base):
    """One result line from a router audit run."""
    __tablename__ = "router_audit_finding"

    finding_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    run_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    found_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    gateway_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    check: Mapped[str] = mapped_column(String(48), nullable=False)
    # HIGH | MEDIUM | LOW | OK
    severity: Mapped[str] = mapped_column(String(8), nullable=False)
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="")
