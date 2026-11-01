from datetime import datetime, timedelta, timezone

from clarinet.collector.arp_spoof import detect_arp_spoof
from clarinet.collector.port_scan import PortScanDetector
from clarinet.models import Alert
from clarinet.models.security import ArpBinding


def test_many_ports_in_a_short_time_is_a_scan():
    d = PortScanDetector(window=10, threshold=15)
    results = [d.observe("10.0.0.5", "10.0.0.1", port, now=port / 10) for port in range(1, 30)]
    hits = [r for r in results if r]
    assert len(hits) == 1 and hits[0] == 15


def test_normal_traffic_is_not_a_scan():
    d = PortScanDetector(window=10, threshold=15)
    # same port again and again, or a few ports over a long time
    assert not any(d.observe("10.0.0.5", "10.0.0.1", 443, now=i) for i in range(100))
    assert not any(d.observe("10.0.0.6", "10.0.0.1", 1000 + i, now=i * 20) for i in range(30))


def test_scan_alerts_once_then_again_after_the_cooldown():
    d = PortScanDetector(window=10, threshold=5, cooldown=300)
    first = [d.observe("10.0.0.5", "10.0.0.1", p, now=p * 0.1) for p in range(10)]
    assert sum(1 for r in first if r) == 1
    later = [d.observe("10.0.0.5", "10.0.0.1", p, now=1000 + p * 0.1) for p in range(10)]
    assert sum(1 for r in later if r) == 1


def alerts(db):
    return db.query(Alert).filter(Alert.type == "ARP_SPOOF").all()


def test_arp_first_sighting_and_same_mac_are_quiet(db):
    assert detect_arp_spoof("192.168.1.5", "aa:aa:aa:aa:aa:aa", db=db) is False
    assert detect_arp_spoof("192.168.1.5", "AA:AA:AA:AA:AA:AA", db=db) is False
    assert alerts(db) == []


def test_arp_quick_mac_change_is_spoofing(db):
    detect_arp_spoof("192.168.1.5", "AA:AA:AA:AA:AA:AA", db=db)
    assert detect_arp_spoof("192.168.1.5", "BB:BB:BB:BB:BB:BB", db=db) is True
    [alert] = alerts(db)
    assert alert.level == "CRITICAL" and "AA:AA:AA:AA:AA:AA" in alert.message


def test_arp_old_binding_is_treated_as_a_new_dhcp_lease(db):
    old = datetime.now(timezone.utc) - timedelta(hours=5)
    db.add(ArpBinding(ip_address="192.168.1.7", mac_address="AA:AA:AA:AA:AA:AA", first_seen=old, last_seen=old))
    db.commit()
    assert detect_arp_spoof("192.168.1.7", "BB:BB:BB:BB:BB:BB", db=db) is False
    assert alerts(db) == []
    assert db.get(ArpBinding, "192.168.1.7").mac_address == "BB:BB:BB:BB:BB:BB"


def test_arp_history_survives_a_restart(db):
    detect_arp_spoof("192.168.1.9", "AA:AA:AA:AA:AA:AA", db=db)
    db.close()                    # a fresh session stands in for a restarted app
    from clarinet.database import SessionLocal
    with SessionLocal() as fresh:
        assert detect_arp_spoof("192.168.1.9", "CC:CC:CC:CC:CC:CC", db=fresh) is True
