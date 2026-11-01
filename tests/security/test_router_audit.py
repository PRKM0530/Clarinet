from clarinet.collector import router_audit as ra


def checks(open_ports=(), upnp=False, http=None):
    http = http or (lambda ip, port, user, password="": (0, False))
    return ra.run_checks(
        "192.168.1.1",
        port_probe=lambda ip, port: port in open_ports,
        upnp_probe=lambda ip: upnp,
        http_status=http,
    )


def by_check(findings):
    return {f.check: f for f in findings}


def test_clean_router_gets_an_ok_summary():
    found = checks(open_ports={443})
    assert [f.severity for f in found] == ["OK"]


def test_telnet_and_smb_are_high_ftp_is_medium():
    found = by_check(checks(open_ports={23, 445, 21, 443}))
    assert found["port_23"].severity == "HIGH"
    assert found["port_445"].severity == "HIGH"
    assert found["port_21"].severity == "MEDIUM"
    assert "summary" not in found


def test_admin_page_without_https_is_flagged():
    assert "admin_plain_http" in by_check(checks(open_ports={80}))
    assert "admin_plain_http" not in by_check(checks(open_ports={80, 443}))


def test_upnp_is_flagged():
    assert by_check(checks(upnp=True))["upnp"].severity == "MEDIUM"


def test_default_password_is_found_on_basic_auth_routers():
    def http(ip, port, user, password=""):
        if user is None:
            return 401, True
        return (200, False) if (user, password) == ("admin", "1234") else (401, True)

    found = by_check(checks(open_ports={80, 443}, http=http))
    assert found["default_credentials"].severity == "HIGH"
    assert "admin" in found["default_credentials"].detail


def test_form_login_routers_are_not_probed_for_passwords():
    attempts = []

    def http(ip, port, user, password=""):
        attempts.append(user)
        return 200, False          # login page, no Basic auth challenge

    found = by_check(checks(open_ports={80, 443}, http=http))
    assert "default_credentials" not in found
    assert attempts == [None]      # only the initial request, no guessing


def test_run_audit_stores_findings_and_alerts_on_high(db, monkeypatch):
    from clarinet.models import Alert
    from clarinet.models.security import RouterAuditFinding

    monkeypatch.setattr(ra, "probe_port", lambda ip, port, timeout=1.0: port == 23)
    monkeypatch.setattr(ra, "probe_upnp", lambda ip, timeout=2.0: False)
    monkeypatch.setattr(ra, "http_basic_status", lambda *a, **k: (0, False))
    outcome = ra.run_audit(db, gateway_ip="192.168.1.1")
    assert outcome["ok"] and outcome["high"] == 1
    assert db.query(RouterAuditFinding).filter(RouterAuditFinding.severity == "HIGH").count() == 1
    assert db.query(Alert).filter(Alert.type == "ROUTER_AUDIT").count() == 1
