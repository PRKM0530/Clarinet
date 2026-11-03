"""
S-20: traffic from a merged address counts for the main device.   N-16: a second voucher on one device is refused.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tests._support import ADMIN, new_client, seed_world


@pytest.fixture()
def world():
    return seed_world()


def usage(device_id):
    from clarinet.database import SessionLocal
    from clarinet.models import UsageRecord
    with SessionLocal() as db:
        rows = db.query(UsageRecord).filter(UsageRecord.device_id == device_id).all()
        return sum(r.bytes_in for r in rows), sum(r.bytes_out for r in rows)


def test_s20_traffic_from_a_merged_address_counts_for_the_main_device(world):
    from clarinet.collector.traffic_counter import _write_deltas
    from clarinet.database import SessionLocal
    from clarinet.models.merging import MergedMac
    with SessionLocal() as db:
        db.add(MergedMac(mac_address="DE:AD:BE:EF:00:01", primary_device_id=world["d_alice"]))
        db.commit()
    before = usage(world["d_alice"])
    _write_deltas({"de:ad:be:ef:00:01": (1000, 2000)})            # the counters report the alias address
    after = usage(world["d_alice"])
    assert (after[0] - before[0], after[1] - before[1]) == (1000, 2000)


def test_s20_merged_addresses_get_counting_rules(world, monkeypatch):
    from clarinet.database import SessionLocal
    from clarinet.enforcer import accounting, reconcile
    from clarinet.models.merging import MergedMac
    with SessionLocal() as db:
        db.add(MergedMac(mac_address="DE:AD:BE:EF:00:01", primary_device_id=world["d_alice"]))
        db.commit()
    seen = {}
    monkeypatch.setattr(accounting, "sync_accounting", lambda devices: seen.setdefault("devices", devices) or True)
    monkeypatch.setattr("clarinet.enforcer.nft_wrapper.ensure_table_exists", lambda: True)
    reconcile.reconcile_now()
    assert ("DE:AD:BE:EF:00:01", None) in seen["devices"]


def test_n16_a_device_with_an_active_voucher_cannot_use_a_second_one(world, trusted_proxy):
    from clarinet.database import SessionLocal
    from clarinet.models import Voucher
    admin = new_client(ADMIN)
    codes = []
    for _ in range(2):
        admin.post("/vouchers/create", data={"expires_minutes": "60"})
        with SessionLocal() as db:
            codes.append(db.query(Voucher).order_by(Voucher.voucher_id.desc()).first().code)
    guest = {"X-Forwarded-For": "192.168.1.13"}                    # the NEW device in the shared world
    assert "already" not in new_client().post("/guest/redeem", data={"code": codes[0]}, headers=guest).text.lower()
    second = new_client().post("/guest/redeem", data={"code": codes[1]}, headers=guest)
    assert "already has an active voucher" in second.text
    with SessionLocal() as db:
        assert db.query(Voucher).filter(Voucher.code == codes[1]).one().status == "UNUSED"
