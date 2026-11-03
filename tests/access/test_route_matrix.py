"""
ACC-01 / ACC-02: every route against every identity.

* The table is checked against app.routes, so a new route cannot escape it.
* Denied requests must be refused AND leave the database unchanged.
* Allowed requests must never return 5xx, including with a nonexistent id.
Real network probes, subprocesses and speed tests are blocked by tests/_support.py.
"""
from __future__ import annotations

import re

import pytest

from tests._support import ADMIN, ALICE, new_client, seed_world

IGNORED = {"/openapi.json", "/api/docs", "/docs/oauth2-redirect", "/static"}

# (method, path template, access level, form data for POST, response kind when denied)
# level: public | user | admin ;   kind: html (redirect) | json (401/403)
R = [
    ("GET", "/", "public", None, "html"),
    ("GET", "/login", "public", None, "html"),
    ("POST", "/login", "public", {"username": "nobody", "password": "wrong-pass"}, "html"),
    ("GET", "/logout", "public", None, "html"),
    ("GET", "/setup", "public", None, "html"),
    ("POST", "/setup/admin", "public", {"username": "x1", "password": "pw-12345678", "password_confirm": "pw-12345678"}, "html"),
    ("GET", "/guest", "public", None, "html"),
    ("POST", "/guest/redeem", "public", {"code": "NOPE-0000"}, "html"),
    ("GET", "/privacy", "public", None, "html"),
    ("GET", "/api/status/health", "public", None, "json"),

    ("GET", "/dashboard", "user", None, "html"),
    ("GET", "/devices", "user", None, "html"),
    ("GET", "/devices/{d_alice}", "user", None, "html"),
    ("GET", "/export/devices.csv", "user", None, "html"),
    ("GET", "/alerts", "user", None, "html"),
    ("POST", "/alerts/{alert_id}/ack", "user", {}, "html"),
    ("GET", "/export/alerts.csv", "user", None, "html"),
    ("GET", "/api/devices/summary", "user", None, "json"),
    ("GET", "/usage", "user", None, "html"),
    ("GET", "/usage/device/{d_alice}", "user", None, "html"),
    ("GET", "/api/usage/summary", "user", None, "json"),
    ("GET", "/api/limit/summary", "user", None, "json"),
    ("GET", "/export/usage.csv", "user", None, "html"),
    ("GET", "/reports", "user", None, "html"),
    ("GET", "/priority", "user", None, "html"),
    ("POST", "/priority/request", "user", {"device_id": "{d_alice}", "duration_min": "30"}, "html"),
    ("POST", "/priority/{grant_id}/cancel", "user", {}, "html"),
    ("GET", "/api/status/topbar", "user", None, "json"),
    ("GET", "/slowdowns/api/slowdowns/status", "user", None, "json"),
    ("GET", "/api/v1/status", "user", None, "json"),
    ("GET", "/api/v1/devices", "user", None, "json"),
    ("GET", "/api/v1/alerts", "user", None, "json"),
    ("GET", "/api/v1/latency", "user", None, "json"),
    ("GET", "/api/v1/usage/today", "user", None, "json"),

    ("POST", "/devices/{d_new}/rename", "admin", {"label": "x"}, "html"),
    ("POST", "/devices/{d_new}/approve", "admin", {"label": "x"}, "html"),
    ("POST", "/devices/{d_new}/owner", "admin", {"owner_id": "{alice}"}, "html"),
    ("POST", "/devices/{d_new}/merge", "admin", {"other_id": "{d_free}"}, "html"),
    ("POST", "/devices/{d_new}/split", "admin", {"mac": "AA:00:00:00:00:99"}, "html"),
    ("POST", "/devices/{d_new}/guest", "admin", {}, "html"),
    ("POST", "/devices/{d_new}/block", "admin", {}, "html"),
    ("POST", "/devices/{d_new}/unblock", "admin", {}, "html"),
    ("POST", "/devices/{d_new}/delete", "admin", {}, "html"),
    ("POST", "/alerts/{alert_id}/resolve", "admin", {}, "html"),
    ("GET", "/vouchers", "admin", None, "html"),
    ("POST", "/vouchers/create", "admin", {"expires_minutes": "60"}, "html"),
    ("POST", "/vouchers/{voucher_id}/revoke", "admin", {}, "html"),
    ("GET", "/api/guest/summary", "admin", None, "json"),
    ("POST", "/priority/{grant_id}/approve", "admin", {}, "html"),
    ("POST", "/priority/{grant_id}/deny", "admin", {}, "html"),
    ("GET", "/priority/summary", "admin", None, "json"),
    ("POST", "/priority/policy", "admin", {"default_duration_min": "30", "max_duration_min": "60", "daily_limit_min": "120"}, "html"),
    ("GET", "/rules", "admin", None, "html"),
    ("POST", "/rules/create", "admin", {"device_id": "{d_alice}", "days": "mon", "start_time": "22:00", "end_time": "23:00", "action": "BLOCK"}, "html"),
    ("POST", "/rules/{rule_id}/toggle", "admin", {}, "html"),
    ("POST", "/rules/{rule_id}/delete", "admin", {}, "html"),
    ("POST", "/rules/{rule_id}/exception", "admin", {"duration_hours": "1"}, "html"),
    ("GET", "/rules/summary", "admin", None, "json"),
    ("GET", "/rules/device/{d_alice}", "admin", None, "json"),
    ("GET", "/security", "admin", None, "html"),
    ("POST", "/security/router-audit/run", "admin", {}, "html"),
    ("POST", "/security/wifi/scan", "admin", {}, "html"),
    ("POST", "/security/access-points/trust", "admin", {"bssid": "CC:00:00:00:00:01"}, "html"),
    ("POST", "/security/access-points/{ap_id}/untrust", "admin", {}, "html"),
    ("POST", "/security/networks/{network_id}/trust", "admin", {}, "html"),
    ("POST", "/security/networks/{network_id}/forget", "admin", {}, "html"),
    ("GET", "/security/summary", "admin", None, "json"),
    ("GET", "/settings", "admin", None, "html"),
    ("POST", "/settings/update", "admin", {"network_mode": "FULL"}, "html"),
    ("POST", "/settings/purge", "admin", {"confirm": "no"}, "html"),
    ("POST", "/settings/members/create", "admin", {"username": "newbie", "password": "pw-12345678", "role": "MEMBER"}, "html"),
    ("POST", "/settings/members/{bob}/toggle", "admin", {}, "html"),
    ("POST", "/settings/members/{bob}/reset-password", "admin", {"new_password": "pw-98765432"}, "html"),
    ("GET", "/slowdowns", "admin", None, "html"),
    ("POST", "/slowdowns/settings", "admin", {"latency_multiplier": "2.0", "speed_threshold": "0.5"}, "html"),
    ("GET", "/slowdowns/api/slowdowns/summary", "admin", None, "json"),
    ("GET", "/speed", "admin", None, "html"),
    ("POST", "/speed/run", "admin", {}, "html"),
    ("GET", "/speed/export.csv", "admin", None, "html"),
    ("GET", "/speed/summary", "admin", None, "json"),
    ("GET", "/speed/report", "admin", None, "html"),
    ("GET", "/status", "admin", None, "html"),
    ("GET", "/api/v1/speed", "admin", None, "json"),
    ("GET", "/api/v1/slowdowns", "admin", None, "json"),
]

PARAM_TO_KEY = {"device_id": "d_new", "alert_id": "alert_id", "voucher_id": "voucher_id", "grant_id": "grant_id",
                "rule_id": "rule_id", "ap_id": "ap_id", "network_id": "network_id", "member_id": "bob"}


def _fill(text, ids):
    return re.sub(r"\{(\w+)\}", lambda m: str(ids.get(m.group(1), 1)), text)


def _form(form, ids):
    return None if form is None else {k: _fill(str(v), ids) for k, v in form.items()}


def _table_keys():
    return {(m, re.sub(r"\{\w+\}", "{}", p)) for m, p, *_ in R}


def test_acc01_table_covers_every_route_in_the_app():
    from clarinet import app
    actual = set()
    for r in app.routes:
        methods = getattr(r, "methods", None)
        if r.path in IGNORED:
            continue
        for m in sorted(methods or []):
            if m != "HEAD":
                actual.add((m, re.sub(r"\{\w+\}", "{}", r.path)))
        if not methods:
            actual.add(("WS", r.path))
    actual.discard(("WS", "/ws/alerts"))     # websocket: covered in tests/access/test_websocket.py
    missing = actual - _table_keys()
    stale = _table_keys() - actual
    assert not missing, f"routes with no matrix entry (add them): {sorted(missing)}"
    assert not stale, f"matrix entries with no route (remove them): {sorted(stale)}"


@pytest.fixture(scope="module")
def sessions():
    """Log in once per identity (bcrypt is slow) and reuse the cookies."""
    ids = seed_world()
    return {name: new_client(who).cookies for name, who in (("admin", ADMIN), ("alice", ALICE))} | {"ids": ids}


def _client(sessions, who):
    c = new_client()
    if who != "anon":
        c.cookies.update(sessions[who])
    return c


def _snapshot():
    from clarinet.database import SessionLocal
    from clarinet.models import Alert, AuditLog, Device, Member, Settings, TimeRule, UsageRecord
    with SessionLocal() as db:
        return (
            sorted((d.device_id, d.state, d.label, d.owner_member_id) for d in db.query(Device)),
            sorted((m.member_id, m.is_active, m.password_hash) for m in db.query(Member)),
            sorted((s.key, s.value) for s in db.query(Settings)),
            sorted((a.alert_id, a.status) for a in db.query(Alert)),
            db.query(TimeRule).count(), db.query(UsageRecord).count(), db.query(AuditLog).count(),
        )


def _is_denied(resp, who, kind):
    if kind == "json":
        return resp.status_code in (401, 403)
    loc = resp.headers.get("location", "")
    if resp.status_code not in (302, 303):
        return False
    return loc.startswith("/login") if who == "anon" else (loc.startswith("/dashboard") or loc.startswith("/login"))


CASES = [(m, p, lvl, f, k) for m, p, lvl, f, k in R if lvl != "public"]


DENIED = [(w, *c) for c in CASES for w in ("anon", "alice") if not (w == "alice" and c[2] == "user")]
ALLOWED = [(w, *c) for c in CASES for w in ("admin", "alice") if not (w == "alice" and c[2] == "admin")]


def _case_id(c):
    return f"{c[0]}:{c[1]} {c[2]}"


@pytest.mark.parametrize("who,method,path,level,form,kind", DENIED, ids=[_case_id(c) for c in DENIED])
def test_acc02_denied_identities_are_refused_and_change_nothing(sessions, who, method, path, level, form, kind):
    ids = seed_world()
    ids.update(alert_id=1, voucher_id=1, grant_id=1, rule_id=1, ap_id=1, network_id=1)
    before = _snapshot()
    resp = _client(sessions, who).request(method, _fill(path, ids), data=_form(form, ids))
    assert _is_denied(resp, who, kind), f"{who} {method} {path} -> {resp.status_code} {resp.headers.get('location')}"
    assert _snapshot() == before, f"{who} {method} {path} was refused but still changed data"


@pytest.mark.parametrize("who,method,path,level,form,kind", ALLOWED, ids=[_case_id(c) for c in ALLOWED])
def test_acc02_allowed_identities_are_not_refused_and_never_crash(sessions, who, method, path, level, form, kind):
    ids = seed_world()
    ids.update(alert_id=1, voucher_id=1, grant_id=1, rule_id=1, ap_id=1, network_id=1)
    resp = _client(sessions, who).request(method, _fill(path, ids), data=_form(form, ids))
    assert resp.status_code < 500, f"{who} {method} {path} -> {resp.status_code}"
    loc = resp.headers.get("location", "")
    assert resp.status_code not in (401, 403), f"{who} {method} {path} was refused"
    assert "/login" not in loc and "error=forbidden" not in loc, f"{who} {method} {path} -> {loc}"


@pytest.mark.parametrize("path", ["/devices/999999", "/usage/device/999999", "/rules/device/999999"])
def test_acc02_nonexistent_ids_do_not_crash(sessions, path):
    seed_world()
    assert _client(sessions, "admin").get(path).status_code < 500


@pytest.mark.parametrize("method,path,level,form,kind",
                         [c for c in R if c[2] == "public"], ids=[f"{c[0]} {c[1]}" for c in R if c[2] == "public"])
def test_acc02_public_routes_work_for_anonymous(method, path, level, form, kind):
    ids = seed_world()
    resp = new_client().request(method, path, data=_form(form, ids))
    assert resp.status_code < 500
