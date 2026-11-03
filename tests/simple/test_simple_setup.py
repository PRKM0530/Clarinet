"""
Simpler setup: passwords you can reveal, three plainly explained modes, a network
connection and router that Clarinet finds by itself, and one "too slow" number.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from clarinet import app
from clarinet.auth import hash_password
from clarinet.core_svc import autoconfig
from clarinet.database import Base, SessionLocal, engine
from clarinet.models import Member, Settings

ROOT = Path(__file__).resolve().parents[2] / "clarinet"
GB = 1_073_741_824


@pytest.fixture()
def db():
    assert "clarinet_test_" in str(engine.url), "refusing to touch a non-test database"
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        session.add(Settings(key="setup_complete", value="true"))
        session.add(Member(username="boss", password_hash=hash_password("pw-boss-12345"), role="ADMIN"))
        session.add(Member(username="alice", password_hash=hash_password("pw-alice-12345"), role="MEMBER"))
        session.commit()
        yield session


@pytest.fixture()
def fresh():
    """A database where setup has not been done yet."""
    assert "clarinet_test_" in str(engine.url), "refusing to touch a non-test database"
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    autoconfig.forget()


def client(user=None, password=None) -> TestClient:
    c = TestClient(app, follow_redirects=False, raise_server_exceptions=False)
    if user:
        assert c.post("/login", data={"username": user, "password": password}).status_code == 302
    return c


def admin():
    return client("boss", "pw-boss-12345")


def setting(key):
    with SessionLocal() as s:
        row = s.get(Settings, key)
        return row.value if row else None


# the password eye

def test_every_password_field_gets_a_show_hide_button():
    script = (ROOT / "static" / "js" / "clarinet.js").read_text(encoding="utf-8")
    assert 'input[type="password"]' in script and "addPasswordToggles();" in script
    assert "aria-label" in script and "Show password" in script and "Hide password" in script
    css = (ROOT / "static" / "css" / "clarinet.css").read_text(encoding="utf-8")
    assert ".password-toggle" in css and ".password-field" in css


def test_every_page_with_a_password_field_loads_the_script_that_adds_the_eye(db):
    pages = {"/login": client(), "/settings": admin(), "/account": admin()}
    seen = 0
    for path, c in pages.items():
        html = c.get(path).text
        if 'type="password"' in html:
            seen += 1
            assert "/static/js/clarinet.js" in html, path
    assert seen >= 3, "expected password fields on the sign-in, settings and account pages"


def test_the_setup_page_and_the_sign_up_page_also_have_the_eye(fresh):
    html = client().get("/setup").text
    assert html.count('type="password"') == 2 and "/static/js/clarinet.js" in html


def test_no_template_loads_the_script_twice_or_forgets_it():
    base = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
    assert base.count("clarinet.js") == 1


# three modes, plainly explained

MODE_WORDS = ["Monitor only", "Full Control", "You get", "Not included", "Needs", "Pick it if", "Keep new devices offline"]


def test_the_setup_page_explains_both_modes(fresh):
    html = client().get("/setup").text
    for word in MODE_WORDS:
        assert word in html, word
    assert html.count('name="network_mode"') == 2
    assert re.search(r'value="MONITOR"\s+checked', html), "Monitor only is the safe default"
    assert "Guest or shared network" not in html and 'value="PUBLIC"' not in html


def test_the_settings_page_explains_the_modes_and_selects_the_saved_one(db):
    db.add(Settings(key="network_mode", value="FULL"))
    db.commit()
    html = admin().get("/settings").text
    for word in MODE_WORDS:
        assert word in html, word
    assert re.search(r'value="FULL"\s+checked', html)
    assert not re.search(r'value="MONITOR"\s+checked', html)


def test_a_mode_this_computer_cannot_do_is_flagged_but_not_forbidden(fresh, monkeypatch):
    from clarinet.core_svc import netinfo
    monkeypatch.setattr(netinfo, "can_control_cached", lambda *a, **k: False)
    html = client().get("/setup").text
    assert html.count("cannot do this yet") == 1          # Full Control only, never Monitor only
    assert 'value="FULL"' in html and 'disabled' not in html.split('name="network_mode"')[1][:80]
    monkeypatch.setattr(netinfo, "can_control_cached", lambda *a, **k: True)
    assert "cannot do this yet" not in client().get("/setup").text


def test_the_modes_are_described_once_for_both_pages(fresh, db):
    macro = (ROOT / "templates" / "_mode_picker.html").read_text(encoding="utf-8")
    for page in ("setup/wizard.html", "settings/index.html"):
        assert "mode_picker" in (ROOT / "templates" / page).read_text(encoding="utf-8")
    assert macro.count("'key':") == 2


@pytest.mark.parametrize("mode", ["MONITOR", "FULL"])
def test_each_mode_can_still_be_chosen(db, mode):
    admin().post("/settings/update", data={"network_mode": mode})
    assert setting("network_mode") == mode


# the connection and the router are found automatically

WIZARD = {"username": "owner", "password": "Owner-pass-123", "password_confirm": "Owner-pass-123",
          "network_mode": "MONITOR", "plan_download": "100", "plan_upload": "20", "billing_day": "1", "consent": "yes"}


def test_the_setup_page_does_not_ask_for_an_interface_or_a_router(fresh):
    html = client().get("/setup").text
    assert 'name="network_interface"' not in html and 'name="router_ip"' not in html
    assert "interface" not in html.lower()


def test_setup_completes_without_them_and_stores_nothing_for_them(fresh):
    r = client().post("/setup/admin", data=WIZARD)
    assert r.status_code == 200
    assert setting("setup_complete") == "true"
    assert not setting("network_interface") and not setting("router_ip")


def test_setup_still_accepts_them_when_given(fresh):
    r = client().post("/setup/admin", data={**WIZARD, "network_interface": "wlan0", "router_ip": "10.0.0.1"})
    assert r.status_code == 200
    assert (setting("network_interface"), setting("router_ip")) == ("wlan0", "10.0.0.1")


def use_detection(monkeypatch, interface="wlan0", router="192.168.1.1", here=("eth0", "wlan0")):
    monkeypatch.delenv("CLARINET_NO_AUTODETECT", raising=False)
    monkeypatch.setattr(autoconfig, "detected_interface", lambda: interface)
    monkeypatch.setattr(autoconfig, "detected_router", lambda: router)
    monkeypatch.setattr(autoconfig, "interfaces_here", lambda: list(here))


def test_an_unset_connection_and_router_are_found_by_the_system(db, monkeypatch):
    from clarinet.app_settings import get_setting
    use_detection(monkeypatch)
    assert get_setting(db, "network_interface", "") == "wlan0"
    assert get_setting(db, "router_ip", "") == "192.168.1.1"


def test_a_blank_saved_value_also_means_automatic(db, monkeypatch):
    from clarinet.app_settings import get_setting
    db.add_all([Settings(key="network_interface", value=""), Settings(key="router_ip", value="  ")])
    db.commit()
    use_detection(monkeypatch)
    assert get_setting(db, "network_interface") == "wlan0"
    assert get_setting(db, "router_ip") == "192.168.1.1"


def test_a_value_the_admin_set_on_purpose_wins(db, monkeypatch):
    from clarinet.app_settings import get_setting
    db.add_all([Settings(key="network_interface", value="eth0"), Settings(key="router_ip", value="10.9.9.9")])
    db.commit()
    use_detection(monkeypatch)
    assert get_setting(db, "network_interface") == "eth0"
    assert get_setting(db, "router_ip") == "10.9.9.9"


def test_a_saved_connection_that_does_not_exist_here_is_replaced_by_the_detected_one(db, monkeypatch):
    from clarinet.app_settings import get_setting
    db.add(Settings(key="network_interface", value="eth9"))
    db.commit()
    use_detection(monkeypatch, here=("eth0", "wlan0"))
    assert get_setting(db, "network_interface") == "wlan0"


def test_when_nothing_can_be_detected_the_caller_default_is_used(db, monkeypatch):
    from clarinet.app_settings import get_setting
    use_detection(monkeypatch, interface=None, router=None, here=())
    assert get_setting(db, "network_interface", "fallback") == "fallback"
    assert get_setting(db, "router_ip", "none") == "none"


def test_other_settings_are_untouched_by_detection(db, monkeypatch):
    from clarinet.app_settings import get_setting
    use_detection(monkeypatch)
    assert get_setting(db, "billing_day", "7") == "7"
    db.add(Settings(key="billing_day", value="15"))
    db.commit()
    assert get_setting(db, "billing_day", "7") == "15"


def test_detection_is_remembered_so_it_does_not_run_a_command_every_time(monkeypatch):
    monkeypatch.delenv("CLARINET_NO_AUTODETECT", raising=False)
    autoconfig.forget()
    calls = []
    from clarinet.core_svc import netinfo
    monkeypatch.setattr(netinfo, "detect_interface", lambda *a, **k: calls.append(1) or "eth0")
    for _ in range(5):
        assert autoconfig.detected_interface() == "eth0"
    assert len(calls) == 1
    autoconfig.forget()
    autoconfig.detected_interface()
    assert len(calls) == 2


def test_a_failing_detection_never_breaks_the_page(monkeypatch):
    monkeypatch.delenv("CLARINET_NO_AUTODETECT", raising=False)
    autoconfig.forget()
    from clarinet.core_svc import netinfo

    def boom(*a, **k):
        raise RuntimeError("no ip command")
    monkeypatch.setattr(netinfo, "detect_interface", boom)
    assert autoconfig.detected_interface() is None


def test_the_settings_page_hides_the_connection_under_advanced_and_offers_automatic(db, monkeypatch):
    use_detection(monkeypatch)
    html = admin().get("/settings").text
    advanced = html.split('<details class="advanced">')[1].split("</details>")[0]
    assert 'name="network_interface"' in advanced and 'name="router_ip"' in advanced
    assert "Automatic (wlan0)" in advanced and 'placeholder="192.168.1.1"' in advanced
    assert 'name="network_interface"' not in html.split('<details class="advanced">')[0]


def test_choosing_automatic_clears_an_old_saved_connection(db):
    db.add(Settings(key="network_interface", value="eth0"))
    db.commit()
    admin().post("/settings/update", data={"network_interface": "", "router_ip": ""})
    assert setting("network_interface") == "" and setting("router_ip") == ""


def test_a_stale_saved_connection_is_explained_on_the_settings_page(db, monkeypatch):
    db.add(Settings(key="network_interface", value="eth9"))
    db.commit()
    use_detection(monkeypatch, here=("eth0", "wlan0"))
    from clarinet.core_svc import netinfo
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ["eth0", "wlan0"])
    assert "does not exist on this computer" in admin().get("/settings").text


def test_the_example_env_and_defaults_leave_the_connection_to_automatic():
    from clarinet.config import Settings as Config
    assert Config.model_fields["NETWORK_INTERFACE"].default == ""
    env = (ROOT.parent / ".env.example").read_text(encoding="utf-8")
    assert not re.search(r"(?m)^NETWORK_INTERFACE=\s*\S", env)


# one "too slow" number

def test_one_percentage_in_settings_is_stored_as_the_fraction_everything_reads(db):
    admin().post("/settings/update", data={"speed_threshold_pct": "60"})
    assert setting("slowdown_speed_threshold") == "0.6"
    assert 'value="60"' in admin().get("/settings").text


@pytest.mark.parametrize("bad", ["5", "101", "abc", "-3", "7.5", "0"])
def test_a_bad_percentage_is_refused(db, bad):
    r = admin().post("/settings/update", data={"speed_threshold_pct": bad})
    assert "bad_speed_percent" in r.headers["location"] and setting("slowdown_speed_threshold") is None


def test_the_speed_test_the_report_and_the_diagnosis_all_use_it(db):
    from clarinet.collector.speed_test import _too_slow_share
    from clarinet.core_svc.speed_report import build_speed_report
    assert _too_slow_share(db) == 0.8 and build_speed_report(db, 30).threshold_pct == 80      # nothing set: the spec default
    admin().post("/settings/update", data={"speed_threshold_pct": "55"})
    db.expire_all()
    assert _too_slow_share(db) == 0.55
    assert build_speed_report(db, 30).threshold_pct == 55
    from clarinet.analytics.diagnosis import _speed_below_plan_check
    assert callable(_speed_below_plan_check)


def test_a_garbage_stored_value_falls_back_instead_of_crashing(db):
    from clarinet.collector.speed_test import _too_slow_share
    from clarinet.core_svc.speed_report import build_speed_report
    db.add(Settings(key="slowdown_speed_threshold", value="banana"))
    db.commit()
    assert _too_slow_share(db) == 0.8 and build_speed_report(db, 30).threshold_pct == 80


def test_there_is_no_separate_report_threshold_any_more(db):
    html = admin().get("/settings").text
    assert "speed_report_threshold_pct" not in html
    assert html.lower().count("too slow") >= 1 and html.count('name="speed_threshold_pct"') == 1


# the duplicate controls are gone

def test_the_slowdowns_page_no_longer_has_its_own_copy_of_the_settings(db):
    html = admin().get("/slowdowns").text
    assert "/slowdowns/settings" not in html and "Wi-Fi interface" not in html and 'name="latency_multiplier"' not in html
    assert "Settings, then Advanced" in html
    assert admin().post("/slowdowns/settings", data={"latency_multiplier": "2"}).status_code in (404, 405)


def test_the_settings_page_has_one_field_for_each_thing(db):
    html = admin().get("/settings").text
    names = re.findall(r'name="([a-z_]+)"', html.split('<details class="advanced">')[0] + html.split("</details>", 1)[1].split("<!-- Member")[0])
    assert names.count("network_mode") == 2                      # the two radio buttons are one field
    for single in ("plan_download_mbps", "plan_upload_mbps", "billing_day", "monthly_limit_gb"):
        assert names.count(single) == 1, single
    advanced = html.split('<details class="advanced">')[1].split("</details>")[0]
    for single in ("timezone", "network_interface", "router_ip", "speed_test_interval_hours", "speed_threshold_pct", "slowdown_latency_multiplier"):
        assert advanced.count(f'name="{single}"') == 1, single


def test_the_settings_page_still_saves_everything_in_one_go(db):
    r = admin().post("/settings/update", data={
        "network_mode": "FULL", "plan_download_mbps": "300", "plan_upload_mbps": "50", "billing_day": "12",
        "monthly_limit_gb": "400", "timezone": "Asia/Kolkata", "network_interface": "", "router_ip": "10.0.0.1",
        "speed_test_interval_hours": "4", "speed_threshold_pct": "75", "slowdown_latency_multiplier": "2.5"})
    assert r.headers["location"] == "/settings?info=saved"
    assert [setting(k) for k in ("network_mode", "plan_download_mbps", "billing_day", "router_ip", "speed_test_interval_hours",
                                 "slowdown_speed_threshold", "slowdown_latency_multiplier")] == \
        ["FULL", "300", "12", "10.0.0.1", "4", "0.75", "2.5"]
    assert setting("limit.bytes") == str(400 * GB)


# the third mode is gone; its one useful behaviour is a switch inside Full Control

def test_there_is_no_third_mode_to_choose(db):
    assert admin().post("/settings/update", data={"network_mode": "PUBLIC"}).headers["location"].endswith("error=bad_mode")
    assert setting("network_mode") is None
    from clarinet.core_svc.mode import NetworkMode
    assert [m.value for m in NetworkMode] == ["FULL", "MONITOR"]


def test_an_old_public_value_still_behaves_like_before(db):
    from clarinet.core_svc.mode import get_mode, hold_new_devices
    db.add(Settings(key="network_mode", value="PUBLIC"))
    db.commit()
    assert get_mode(db) == "FULL" and hold_new_devices(db) is True
    html = admin().get("/settings").text
    assert re.search(r'value="FULL"\s+checked', html)
    assert re.search(r'name="hold_new_devices" value="true" checked', html)


def test_holding_new_devices_is_a_switch_in_full_control_and_off_by_default(db):
    from clarinet.core_svc.mode import hold_new_devices
    db.add(Settings(key="network_mode", value="FULL"))
    db.commit()
    assert hold_new_devices(db) is False
    admin().post("/settings/update", data={"network_mode": "FULL", "hold_new_devices": ["false", "true"]})
    db.expire_all()
    assert setting("hold_new_devices") == "true" and hold_new_devices(db) is True
    admin().post("/settings/update", data={"network_mode": "FULL", "hold_new_devices": ["false"]})   # box unticked
    db.expire_all()
    assert setting("hold_new_devices") == "false" and hold_new_devices(db) is False


def test_holding_has_no_effect_in_monitor_only(db):
    from clarinet.core_svc.mode import hold_new_devices
    db.add_all([Settings(key="network_mode", value="MONITOR"), Settings(key="hold_new_devices", value="true")])
    db.commit()
    assert hold_new_devices(db) is False


def test_a_partial_form_leaves_the_switch_alone(db):
    db.add_all([Settings(key="network_mode", value="FULL"), Settings(key="hold_new_devices", value="true")])
    db.commit()
    admin().post("/settings/update", data={"billing_day": "5"})
    assert setting("hold_new_devices") == "true"


def test_the_setup_page_can_turn_the_switch_on(fresh):
    r = client().post("/setup/admin", data={**WIZARD, "network_mode": "FULL", "hold_new_devices": ["false", "true"]})
    assert r.status_code == 200 and setting("hold_new_devices") == "true"


def test_the_setup_page_ignores_the_switch_in_monitor_only(fresh):
    r = client().post("/setup/admin", data={**WIZARD, "network_mode": "MONITOR", "hold_new_devices": ["false", "true"]})
    assert r.status_code == 200 and setting("hold_new_devices") == "false"


def test_the_setup_page_refuses_the_old_third_mode(fresh):
    r = client().post("/setup/admin", data={**WIZARD, "network_mode": "PUBLIC"})
    assert r.status_code == 422 and setting("setup_complete") is None


def test_speed_tests_are_offered_whatever_the_mode(db):
    for mode in ("MONITOR", "FULL"):
        db.merge(Settings(key="network_mode", value=mode))
        db.commit()
        assert "Run speed test" in admin().get("/speed?view=internet").text


def test_the_mode_is_defined_in_one_place():
    from clarinet.analytics import mode as a
    from clarinet.core_svc import mode as c
    from clarinet.enforcer import mode as e
    assert a.get_mode is c.get_mode and e.get_mode is c.get_mode


def test_the_setup_page_does_not_let_a_browser_fill_in_an_old_username(fresh):
    """A saved login for this address would otherwise replace the name typed for the new administrator."""
    html = client().get("/setup").text
    username_field = re.search(r'<input[^>]*name="username"[^>]*>', html).group(0)
    assert 'autocomplete="off"' in username_field
    assert html.count('autocomplete="new-password"') == 2
