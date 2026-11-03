from clarinet.collector import wifi_scan
from clarinet.collector.wifi_scan import Sighting, judge

NETSH = """
SSID 1 : HomeWiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 88%
         Radio type         : 802.11ax
    BSSID 2                 : aa:bb:cc:dd:ee:02
         Signal             : 40%

SSID 2 : HomeWiFi
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 95%

SSID 3 :
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    BSSID 1                 : de:ad:be:ef:00:01
         Signal             : 20%
"""

NMCLI = (
    "HomeWiFi:AA\\:BB\\:CC\\:DD\\:EE\\:01:88:WPA2\n"
    "Cafe Net:10\\:20\\:30\\:40\\:50\\:60:55:\n"
    "broken line\n"
)

TRUSTED = [("HomeWiFi", "AA:BB:CC:DD:EE:01"), ("HomeWiFi", "AA:BB:CC:DD:EE:02")]


def test_parse_netsh_networks():
    found = wifi_scan.parse_netsh_networks(NETSH)
    assert [(s.ssid, s.bssid, s.signal) for s in found] == [
        ("HomeWiFi", "AA:BB:CC:DD:EE:01", 88),
        ("HomeWiFi", "AA:BB:CC:DD:EE:02", 40),
        ("HomeWiFi", "11:22:33:44:55:66", 95),
        ("", "DE:AD:BE:EF:00:01", 20),
    ]
    assert found[2].security == "Open"


def test_parse_nmcli_networks_handles_escaped_colons_and_open_networks():
    found = wifi_scan.parse_nmcli_networks(NMCLI)
    assert [(s.ssid, s.bssid, s.signal, s.security) for s in found] == [
        ("HomeWiFi", "AA:BB:CC:DD:EE:01", 88, "WPA2"),
        ("Cafe Net", "10:20:30:40:50:60", 55, "Open"),
    ]


def test_parse_connections():
    # Real `netsh wlan show interfaces` output labels the line "AP BSSID"; older builds say "BSSID".
    for label in ("AP BSSID", "BSSID"):
        win = (
            "    State                  : connected\n"
            "    SSID                   : HomeWiFi\n"
            f"    {label:<23}: aa:bb:cc:dd:ee:01\n"
            "    Authentication         : WPA2-Personal\n"
            "    Signal                 : 91% \n"
        )
        s = wifi_scan.parse_netsh_connection(win)
        assert (s.ssid, s.bssid, s.signal) == ("HomeWiFi", "AA:BB:CC:DD:EE:01", 91), label

    lin = "no:Other:AA\\:AA\\:AA\\:AA\\:AA\\:AA:30:WPA2\nyes:HomeWiFi:AA\\:BB\\:CC\\:DD\\:EE\\:01:90:WPA2\n"
    s = wifi_scan.parse_nmcli_connection(lin)
    assert (s.ssid, s.bssid) == ("HomeWiFi", "AA:BB:CC:DD:EE:01")


def test_trusted_access_point_is_ok():
    assert judge(Sighting("HomeWiFi", "aa:bb:cc:dd:ee:02", 50, "WPA2"), TRUSTED)[0] == "OK"


def test_same_name_unknown_bssid_is_suspect_and_open_is_critical():
    verdict, _, level = judge(Sighting("HomeWiFi", "11:22:33:44:55:66", 90, "WPA2"), TRUSTED)
    assert (verdict, level) == ("SUSPECT", "WARNING")
    verdict, reason, level = judge(Sighting("homewifi", "11:22:33:44:55:66", 90, "Open"), TRUSTED)
    assert (verdict, level) == ("SUSPECT", "CRITICAL")
    assert "open" in reason


def test_lookalike_names_are_suspect():
    for fake in ("H0meWiFi", "HomeWiFi_", "Home-WiFi", "HomeWiF"):
        assert judge(Sighting(fake, "11:22:33:44:55:66", 50, "WPA2"), TRUSTED)[0] == "SUSPECT", fake


def test_unrelated_and_hidden_networks_are_ignored():
    assert judge(Sighting("Cafe Net", "10:20:30:40:50:60", 50, None), TRUSTED)[0] == "UNKNOWN"
    assert judge(Sighting("", "10:20:30:40:50:60", 50, None), TRUSTED)[0] == "UNKNOWN"


def test_scan_and_evaluate_raises_one_alert_for_a_fake_ap(db, monkeypatch):
    from clarinet.models import Alert
    from clarinet.models.security import SeenAccessPoint, TrustedAccessPoint

    db.add(TrustedAccessPoint(ssid="HomeWiFi", bssid="AA:BB:CC:DD:EE:01"))
    db.commit()
    monkeypatch.setattr(wifi_scan, "scan", lambda: wifi_scan.parse_netsh_networks(NETSH))
    monkeypatch.setattr(wifi_scan, "current_connection", lambda: None)

    summary = wifi_scan.scan_and_evaluate(db)
    wifi_scan.scan_and_evaluate(db)          # second scan must not duplicate the alert

    # Only the open clone is reported. The second radio has the same name, security and maker as the trusted
    # access point, so it is treated as another access point of the same network (see test_wifi_roaming.py).
    assert summary["suspect"] == 1
    titles = [a.title for a in db.query(Alert).filter(Alert.type == "FAKE_AP")]
    assert len(titles) == len(set(titles)) == 1
    assert db.get(SeenAccessPoint, "11:22:33:44:55:66").verdict == "SUSPECT"
    assert db.get(SeenAccessPoint, "AA:BB:CC:DD:EE:01").verdict == "OK"


def test_first_scan_trusts_the_connected_access_point(db, monkeypatch):
    from clarinet.models.security import TrustedAccessPoint

    monkeypatch.setattr(wifi_scan, "scan", lambda: [])
    monkeypatch.setattr(wifi_scan, "current_connection",
                        lambda: Sighting("HomeWiFi", "AA:BB:CC:DD:EE:01", 90, "WPA2"))
    wifi_scan.scan_and_evaluate(db)
    assert [t.bssid for t in db.query(TrustedAccessPoint)] == ["AA:BB:CC:DD:EE:01"]
