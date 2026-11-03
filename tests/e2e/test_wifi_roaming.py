"""
N-17: a network with many access points (campus, office, mesh) must not bury the admin in fake-AP alerts,
while a real impostor still has to be caught. Only the OS scan is faked (the nmcli edge).
"""
from __future__ import annotations

import pytest

from tests._support import seed_world

WPA = "WPA2 802.1X"
HOME = ("Campus", "E4:38:7E:26:F7:6E", WPA)


@pytest.fixture()
def scan(monkeypatch):
    from clarinet.collector import wifi_scan
    seed_world()

    def run(sightings):
        monkeypatch.setattr(wifi_scan, "scan", lambda: [wifi_scan.Sighting(s, b, 60, sec) for s, b, sec in sightings])
        monkeypatch.setattr(wifi_scan, "current_connection", lambda: wifi_scan.Sighting(*HOME[:2], 80, HOME[2]))
        from clarinet.database import SessionLocal
        from clarinet.models import Alert
        with SessionLocal() as db:
            db.query(Alert).delete()
            db.commit()
            summary = wifi_scan.scan_and_evaluate(db)
            return summary, [a.title for a in db.query(Alert).filter(Alert.type == "FAKE_AP")]
    return run


def test_other_access_points_of_the_same_network_are_not_reported(scan):
    sightings = [HOME] + [("Campus", f"E4:38:7E:26:F7:{i:02X}", WPA) for i in range(0x70, 0x80)]
    summary, alerts = scan(sightings)
    assert summary["suspect"] == 0 and alerts == []


def test_same_name_from_a_different_maker_is_still_suspect(scan):
    summary, alerts = scan([HOME, ("Campus", "AA:BB:CC:00:00:01", WPA)])
    assert summary["suspect"] == 1 and "AA:BB:CC:00:00:01" in alerts[0]


def test_an_open_copy_of_a_secured_network_is_critical(scan):
    from clarinet.database import SessionLocal
    from clarinet.models import Alert
    summary, alerts = scan([HOME, ("Campus", "E4:38:7E:26:F7:99", "")])
    assert summary["suspect"] == 1 and len(alerts) == 1


def test_same_maker_but_weaker_security_is_suspect(scan):
    summary, _ = scan([HOME, ("Campus", "E4:38:7E:26:F7:98", "WPA2")])
    assert summary["suspect"] == 1


def test_a_lookalike_name_is_still_suspect(scan):
    summary, alerts = scan([HOME, ("Campuz", "E4:38:7E:26:F7:97", WPA)])
    assert summary["suspect"] == 1 and "Campuz" in alerts[0]
