from clarinet.collector import network_check as nc
from clarinet.models import Alert
from clarinet.models.security import KnownNetwork

HOME = {"gateway_ip": "192.168.1.1", "gateway_mac": "aa:bb:cc:00:00:01", "subnet": "192.168.1.0/24", "ssid": "HomeWiFi"}


def alerts(db):
    return db.query(Alert).filter(Alert.type == "UNFAMILIAR_NETWORK").all()


def test_parse_default_gateway_windows_picks_lowest_metric():
    text = (
        "          0.0.0.0          0.0.0.0      10.0.0.1     10.0.0.50     50\n"
        "          0.0.0.0          0.0.0.0    192.168.1.1  192.168.1.20     25\n"
        "        127.0.0.0        255.0.0.0         On-link        127.0.0.1    331\n"
    )
    assert nc.parse_default_gateway_windows(text) == "192.168.1.1"


def test_parse_default_gateway_linux():
    assert nc.parse_default_gateway_linux("default via 192.168.1.1 dev wlan0 proto dhcp") == "192.168.1.1"
    assert nc.parse_default_gateway_linux("") is None


def test_parse_mac_from_arp():
    windows = "  192.168.1.1           aa-bb-cc-00-00-01     dynamic\n  192.168.1.10  11-22-33-44-55-66  dynamic\n"
    assert nc.parse_mac_from_arp(windows, "192.168.1.1") == "AA:BB:CC:00:00:01"
    linux = "192.168.1.1 dev wlan0 lladdr aa:bb:cc:00:00:01 REACHABLE\n"
    assert nc.parse_mac_from_arp(linux, "192.168.1.1") == "AA:BB:CC:00:00:01"
    assert nc.parse_mac_from_arp(linux, "192.168.1.9") is None


def test_first_run_learns_the_home_network_without_alerting(db):
    assert nc.evaluate(db, HOME) == "LEARNED"
    assert alerts(db) == []
    assert db.query(KnownNetwork).one().trusted is True


def test_known_network_is_quiet(db):
    nc.evaluate(db, HOME)
    assert nc.evaluate(db, HOME) == "KNOWN"
    assert alerts(db) == []


def test_new_network_raises_a_warning(db):
    nc.evaluate(db, HOME)
    other = {"gateway_ip": "10.5.0.1", "gateway_mac": "de:ad:be:ef:00:09", "subnet": "10.5.0.0/24", "ssid": "Cafe"}
    assert nc.evaluate(db, other) == "UNFAMILIAR"
    [alert] = alerts(db)
    assert alert.level == "WARNING"
    # the unknown network is stored but not trusted, and does not alert twice
    assert db.query(KnownNetwork).filter(KnownNetwork.trusted == False).count() == 1  # noqa: E712
    assert nc.evaluate(db, other) == "UNTRUSTED"
    assert len(alerts(db)) == 1


def test_same_wifi_name_with_a_different_router_is_critical(db):
    nc.evaluate(db, HOME)
    impostor = dict(HOME, gateway_mac="ff:ee:dd:cc:bb:aa")
    assert nc.evaluate(db, impostor) == "CHANGED"
    [alert] = alerts(db)
    assert alert.level == "CRITICAL"
    assert "impersonat" in alert.message
