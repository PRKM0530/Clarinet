"""
tests/member/test_member_audit.py
Privacy audit: member must not see other members' devices or usage.

Data-model checks only. The route-level privacy checks (devices, usage, alerts,
priority, audit log, dashboard, APIs) run against the real pages in
test_member_privacy.py.
"""
from __future__ import annotations

import pytest
from clarinet.models import Device, Member, PriorityGrant, UsageRecord


# ── S-01: device ownership ────────────────────────────────────────────────────

def test_device_owner_field_set(db, alice, alice_device):
    """Device.owner_member_id is correctly stored and links back to member."""
    db.commit()
    loaded = db.query(Device).filter_by(device_id=alice_device.device_id).first()
    assert loaded.owner_member_id == alice.member_id


def test_devices_filtered_by_owner(db, alice, bob, alice_device, bob_device):
    """ORM query correctly filters devices by owner."""
    db.commit()
    alice_devices = (
        db.query(Device)
        .filter(Device.owner_member_id == alice.member_id)
        .all()
    )
    device_ids = [d.device_id for d in alice_devices]

    assert alice_device.device_id in device_ids
    assert bob_device.device_id not in device_ids, (
        "Alice can see Bob's device — privacy violation (S-01)"
    )


# ── S-02: usage isolation ─────────────────────────────────────────────────────

def test_usage_records_linked_to_device(db, alice, alice_device):
    """UsageRecord rows link to a device (and through it to an owner)."""
    from datetime import date
    usage = UsageRecord(
        device_id=alice_device.device_id,
        date=date.today().isoformat(),
        hour=12,
        activity="BROWSING",
        bytes_in=1000,
        bytes_out=500,
    )
    db.add(usage)
    db.commit()

    loaded = db.query(UsageRecord).filter_by(device_id=alice_device.device_id).first()
    assert loaded is not None
    assert loaded.device.owner_member_id == alice.member_id


# ── S-03: audit log ───────────────────────────────────────────────────────────

# ── S-04: priority grants ─────────────────────────────────────────────────────

def test_priority_grant_links_to_member(db, alice, alice_device):
    """PriorityGrant correctly records requesting member."""
    from datetime import datetime, timezone
    grant = PriorityGrant(
        member_id=alice.member_id,
        device_id=alice_device.device_id,
        requested_at=datetime.now(timezone.utc),
        decision="PENDING",
    )
    db.add(grant)
    db.commit()

    loaded = db.query(PriorityGrant).filter_by(member_id=alice.member_id).first()
    assert loaded is not None
    assert loaded.member_id == alice.member_id


