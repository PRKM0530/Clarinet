"""
clarinet/core_svc/accounts.py
Shared steps for admin-access requests and device claims.
"""
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from clarinet.models import Alert, Device, Member
from clarinet.models.accounts import AdminRequest, DeviceClaim


def request_title(username: str) -> str:
    return f"{username} asked for administrator access"


def ask_for_admin(db: Session, member: Member) -> bool:
    """Record (or renew) a request and tell the admins. False if the person is already an admin or already waiting."""
    from clarinet.core_svc.alerts import raise_alert
    if member.is_admin:
        return False
    row = db.get(AdminRequest, member.member_id)
    if row is not None and row.status == "PENDING":
        return False
    if row is None:
        db.add(AdminRequest(member_id=member.member_id, status="PENDING"))
    else:
        row.status, row.requested_at, row.decided_by, row.decided_at = "PENDING", datetime.now(timezone.utc), None, None
    db.commit()
    raise_alert(db, "WARNING", "ADMIN_REQUEST", request_title(member.username),
                "Open Settings to approve or decline this request.", dedupe_key=member.username, cooldown_s=3600)
    return True


def decide_admin_request(db: Session, member_id: int, approve: bool, actor_id: int) -> Member | None:
    row = db.get(AdminRequest, member_id)
    member = db.get(Member, member_id)
    if row is None or member is None or row.status != "PENDING":
        return None
    row.status = "APPROVED" if approve else "DECLINED"
    row.decided_by, row.decided_at = actor_id, datetime.now(timezone.utc)
    if approve:
        member.role = "ADMIN"
    for alert in db.query(Alert).filter(Alert.type == "ADMIN_REQUEST", Alert.title == request_title(member.username),
                                         Alert.status != "RESOLVED"):
        alert.status = "RESOLVED"
    db.commit()
    return member


def detect_device(db: Session, ip: str) -> Device | None:
    """The device the scan knows at this address (the one the person is browsing from)."""
    return db.query(Device).filter(Device.ip_address == ip).first() if ip else None


def claim_state(db: Session, device: Device | None, member: Member) -> str:
    """none | mine | pending | taken | claimable  for the device this person is using."""
    if device is None:
        return "none"
    if device.owner_member_id == member.member_id:
        return "mine"
    if device.owner_member_id is not None:
        return "taken"
    waiting = db.query(DeviceClaim).filter(DeviceClaim.device_id == device.device_id, DeviceClaim.status == "PENDING").first()
    if waiting is not None:
        return "pending" if waiting.member_id == member.member_id else "taken"
    return "claimable"
