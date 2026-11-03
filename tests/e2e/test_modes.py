"""
MOD-01: which state-changing actions each network mode allows.
FULL may change the network; MONITOR and PUBLIC only observe (PUBLIC also skips speed tests).
"""
from __future__ import annotations

import pytest

from tests._support import ADMIN, new_client, seed_world


def post(mode, path, data=None):
    ids = seed_world(mode)
    return new_client(ADMIN).post(path.format(**ids), data=data or {}).headers.get("location", "")


def test_mod01_block_only_works_in_full_mode():
    assert "info=blocked" in post("FULL", "/devices/{d_new}/block")
    for mode in ("MONITOR", "PUBLIC"):
        assert "monitor_mode_only" in post(mode, "/devices/{d_new}/block")


def test_mod01_blocked_device_state_is_not_changed_outside_full_mode():
    from clarinet.database import SessionLocal
    from clarinet.models import Device
    ids = seed_world("MONITOR")
    new_client(ADMIN).post(f"/devices/{ids['d_new']}/block")
    with SessionLocal() as db:
        assert db.get(Device, ids["d_new"]).state == "NEW"


def test_mod01_speed_test_is_refused_in_public_mode_only():
    assert "info=Speed" in post("FULL", "/speed/run")
    assert "info=Speed" in post("MONITOR", "/speed/run")
    assert "error=" in post("PUBLIC", "/speed/run")


RULE = {"device_id": "{d_alice}", "days": "mon", "start_time": "22:00", "end_time": "23:00", "action": "BLOCK"}


@pytest.mark.parametrize("mode", ["MONITOR", "PUBLIC"])
def test_mod01_time_rules_cannot_be_created_outside_full_mode(mode):
    ids = seed_world(mode)
    r = new_client(ADMIN).post("/rules/create", data={**RULE, "device_id": ids["d_alice"]})
    assert "error=" in r.headers["location"]

