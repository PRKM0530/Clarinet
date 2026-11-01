"""
clarinet/core_svc/permissions.py
Member–device permission helpers for M1.

Members can only view/act on their own devices (Device.owner_member_id == member_id).
Admins can see everything.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from clarinet.models import Device, Member


def member_device_ids(db: Session, member: Member) -> list[int]:
    """
    Return list of device_ids that `member` is allowed to view.
    Admins get all device_ids; Members get only their own.
    """
    if member.is_admin:
        return [row[0] for row in db.query(Device.device_id).all()]
    return [
        row[0]
        for row in db.query(Device.device_id)
        .filter(Device.owner_member_id == member.member_id)
        .all()
    ]


def can_view_device(db: Session, member: Member, device_id: int) -> bool:
    """True if `member` is allowed to view the given device."""
    if member.is_admin:
        return True
    device = db.get(Device, device_id)
    if device is None:
        return False
    return device.owner_member_id == member.member_id


def can_edit_device(db: Session, member: Member, device_id: int) -> bool:
    """Only admins can edit device labels / states."""
    return member.is_admin


def require_device_access(
    db: Session, member: Member, device_id: int
) -> "Device | None":
    """
    Return the Device if member can view it, else None.
    Convenience wrapper for route handlers.
    """
    if not can_view_device(db, member, device_id):
        return None
    return db.get(Device, device_id)
