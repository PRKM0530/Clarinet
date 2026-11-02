"""
clarinet/core_svc/device_merge.py
Merge two device entries into one, and split an address off again (DEV-5).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

log = logging.getLogger("clarinet.core_svc.device_merge")


class MergeError(Exception):
    """The merge or split was refused; the message is safe to show to the admin."""


def merge_devices(db: Session, primary_id: int, secondary_id: int, actor_id: int | None = None) -> None:
    """
    Fold the `secondary` device into the `primary` one.

    Usage, activity, history, alerts and rules move to the primary device. The
    primary keeps its own label and owner. The secondary's address is remembered
    as an alias, then the secondary entry is removed.
    """
    from clarinet.models import (
        Alert, Device, DeviceHistory, PriorityGrant, RuleException, TimeRule, UsageRecord,
    )
    from clarinet.models.devices_ext import DeviceEvent, DeviceMerge
    from clarinet.models.merging import MergedMac
    from clarinet.models.traffic import DomainObservation, TrafficSample, UsageActivity, UsageDaily

    if primary_id == secondary_id:
        raise MergeError("Choose a different device to merge.")
    primary = db.get(Device, primary_id)
    secondary = db.get(Device, secondary_id)
    if primary is None or secondary is None:
        raise MergeError("One of the devices no longer exists.")

    # Usage is one row per device, day and hour: add up where both have one, move otherwise.
    mine = {(r.date, r.hour): r for r in db.query(UsageRecord).filter(UsageRecord.device_id == primary_id)}
    for rec in db.query(UsageRecord).filter(UsageRecord.device_id == secondary_id).all():
        keep = mine.get((rec.date, rec.hour))
        if keep is None:
            rec.device_id = primary_id
        else:
            keep.bytes_in += rec.bytes_in
            keep.bytes_out += rec.bytes_out
            db.delete(rec)

    mine_daily = {r.date: r for r in db.query(UsageDaily).filter(UsageDaily.device_id == primary_id)}
    for rec in db.query(UsageDaily).filter(UsageDaily.device_id == secondary_id).all():
        keep = mine_daily.get(rec.date)
        if keep is None:
            rec.device_id = primary_id
        else:
            keep.bytes_in += rec.bytes_in
            keep.bytes_out += rec.bytes_out
            db.delete(rec)

    # The activity table can hold several rows per hour, so these just move over
    for model in (UsageActivity, TrafficSample, DomainObservation, DeviceHistory, DeviceEvent,
                  Alert, TimeRule, RuleException, PriorityGrant):
        db.query(model).filter(model.device_id == secondary_id).update(
            {model.device_id: primary_id}, synchronize_session=False
        )

    # Addresses the secondary had already absorbed now belong to the primary
    db.query(MergedMac).filter(MergedMac.primary_device_id == secondary_id).update(
        {MergedMac.primary_device_id: primary_id}, synchronize_session=False
    )
    db.merge(MergedMac(
        mac_address=secondary.mac_address.upper(), primary_device_id=primary_id,
        former_label=secondary.label or secondary.hostname, merged_by=actor_id,
        merged_at=datetime.now(timezone.utc),
    ))

    primary.first_seen = min(primary.first_seen, secondary.first_seen) if primary.first_seen and secondary.first_seen else primary.first_seen
    if primary.owner_member_id is None:
        primary.owner_member_id = secondary.owner_member_id
    if not primary.label and secondary.label:
        primary.label = secondary.label

    db.add(DeviceMerge(
        primary_device_id=primary_id, secondary_device_id=secondary_id, merged_by=actor_id,
        reason=f"merged {secondary.mac_address}",
    ))
    db.add(DeviceEvent(
        device_id=primary_id, event_type="MERGE", old_value=secondary.mac_address,
        new_value=primary.mac_address, actor_id=actor_id,
    ))
    db.flush()
    db.delete(secondary)
    db.commit()
    log.info("Merged device %s into %s", secondary_id, primary_id)


def split_address(db: Session, mac: str, actor_id: int | None = None) -> int:
    """
    Make a merged address its own device again. From now on traffic from that
    address is a separate device; usage already counted stays with the main
    device. Returns the new device's id.
    """
    from clarinet.models import Device
    from clarinet.models.devices_ext import DeviceEvent
    from clarinet.models.merging import MergedMac

    alias = db.get(MergedMac, mac.upper())
    if alias is None:
        raise MergeError("That address is not merged into another device.")

    now = datetime.now(timezone.utc)
    device = Device(
        mac_address=alias.mac_address, label=alias.former_label, state="NEW",
        first_seen=now, last_seen=now,
    )
    db.add(device)
    db.flush()
    db.add(DeviceEvent(
        device_id=alias.primary_device_id, event_type="SPLIT", old_value=alias.mac_address,
        new_value=str(device.device_id), actor_id=actor_id,
    ))
    db.delete(alias)
    db.commit()
    return device.device_id
