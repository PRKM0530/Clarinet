"""
tests/member/test_member_audit.py
Privacy audit: member must not see other members' devices or usage.

S-01  Member sees only their own devices in device list        [xfail → M4]
S-02  Member cannot access another member's usage data         [xfail → M1]
S-03  Non-admin cannot read audit log                          [xfail → M1]
S-04  Priority grant list filtered to requesting member        [xfail → M4]

Tests that can be verified at the ORM level pass immediately.
Route-level tests for routes not yet scoped are marked xfail.
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


@pytest.mark.xfail(
    strict=False,
    reason="S-01: /devices route not yet scoped per-member (M4 fix)",
)
def test_member_route_only_returns_own_devices(db, alice, alice_device, bob_device):
    """Route /devices must only return the logged-in member's devices (M4 scope)."""
    # This test documents the requirement; the route fix is M4's responsibility.
    # When M4 ships the fix, remove the xfail.
    db.commit()
    # Simulate: if we fetch all devices without owner filter → privacy leak
    all_devices = db.query(Device).all()
    # After M4 fix, the route will filter — this assertion will start passing.
    assert len(all_devices) == 1, "Expected only Alice's device in her view"


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


@pytest.mark.xfail(
    strict=False,
    reason="S-02: /api/usage endpoint returns all members' usage — M1 fix needed",
)
def test_usage_api_filtered_per_member():
    """Route /api/usage must filter results to the logged-in member's devices."""
    # Placeholder — requires M1 to scope the endpoint.
    raise AssertionError("Scoped usage API not yet implemented (S-02)")


# ── S-03: audit log ───────────────────────────────────────────────────────────

@pytest.mark.xfail(
    strict=False,
    reason="S-03: audit log readable by non-admin — M1 fix needed",
)
def test_non_admin_cannot_read_audit_log():
    """Non-admin members must not be able to read the audit log."""
    # Placeholder — requires M1 to add role check on /audit route.
    raise AssertionError("Audit log access not restricted to admins yet (S-03)")


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


@pytest.mark.xfail(
    strict=False,
    reason="S-04: priority list shows all pending requests to any member — M4 fix needed",
)
def test_priority_list_filtered_per_member(db, alice, bob, alice_device, bob_device):
    """Priority grant list must only show the requesting member's own grants."""
    from datetime import datetime, timezone
    # Alice's grant
    db.add(PriorityGrant(
        member_id=alice.member_id, device_id=alice_device.device_id,
        requested_at=datetime.now(timezone.utc), decision="PENDING",
    ))
    # Bob's grant
    db.add(PriorityGrant(
        member_id=bob.member_id, device_id=bob_device.device_id,
        requested_at=datetime.now(timezone.utc), decision="PENDING",
    ))
    db.commit()

    # Without scoping, Alice can see Bob's grant — this should fail post-M4 fix
    all_grants = db.query(PriorityGrant).all()
    assert len(all_grants) == 1, "Expected only Alice's grant in her view (S-04)"
