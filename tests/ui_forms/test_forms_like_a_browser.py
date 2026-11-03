"""
Every form on every page, submitted the way a browser submits it, for each kind of user.
A form passes when its target exists and the server accepts what the browser sent: no 404, no 405, no 422
(raw validation JSON), no 500, and no error redirect. Links must lead somewhere that exists.
"""
from __future__ import annotations

import re

import pytest

from tests._support import ADMIN, ALICE, new_client, register_sessions, seed_world
from tests.ui_forms.formtools import parse, target

ADMIN_PAGES = ["/dashboard", "/devices", "/devices/{d_new}", "/devices/{d_alice}", "/alerts", "/vouchers", "/rules",
               "/priority", "/speed", "/slowdowns", "/security", "/settings", "/usage", "/reports", "/status",
               "/account"]
MEMBER_PAGES = ["/dashboard", "/devices", "/devices/{d_alice}", "/alerts", "/priority", "/usage", "/reports",
                "/account"]
PUBLIC_PAGES = ["/login", "/guest", "/privacy"]

# What a person types into boxes the page marks as required (anything else stays as the browser leaves it)
TYPED = {"username": "newperson", "password": "pw-newperson-123", "new_password": "pw-changed-12345",
         "confirm_password": "pw-changed-12345", "password_confirm": "pw-newperson-123", "label": "Living Room TV",
         "code": "ABCD1234", "confirm": "DELETE", "reason": "video call", "bssid": "CC:00:00:00:00:01",
         "other_id": lambda ids: str(ids["d_free"]), "mac": "AA:00:00:00:00:99"}
PASSWORD = {"admin": ADMIN[1], "member": ALICE[1]}

# Forms whose address is filled in by the page's script when a button is pressed
SCRIPTED = {"approve-form": "/devices/{d_new}/approve"}

# Forms that may legitimately answer with an error message in this scenario
# Pressing Delete-all-data with the confirmation box left empty must be refused with a message
OK_ERRORS: set[tuple[str, str]] = {("/settings", "/settings/purge")}


def _id_map(world):
    return {k: world[k] for k in ("d_new", "d_alice", "d_bob", "d_free")}


def _client(who):
    ensure_sessions()
    c = new_client()
    if who != "anon":
        register_sessions([_SESSIONS["admin"], _SESSIONS["member"]])
        c.cookies.update(_SESSIONS[who])
    return c


_SESSIONS: dict = {}


def ensure_sessions():
    """Log in once per kind of user (bcrypt is slow) and reuse the cookies."""
    if not _SESSIONS:
        seed_world("FULL")
        _SESSIONS["admin"] = new_client(ADMIN).cookies
        _SESSIONS["member"] = new_client(ALICE).cookies


def _forms(who, pages):
    """(who, page, index, action, method) for every form, found on a freshly seeded app."""
    world = seed_world("FULL")
    ids = _id_map(world)
    out = []
    for page in pages:
        path = page.format(**ids)
        html = _client(who).get(path).text
        for i, form in enumerate(parse(html).forms):
            out.append((who, page, i, form.action, form.method))
    return out


def _all_forms():
    return (_forms("admin", ADMIN_PAGES) + _forms("member", MEMBER_PAGES) + _forms("anon", PUBLIC_PAGES))


FORMS = _all_forms()


def _fill(who, form, ids):
    over = {}
    for name in form.empty_required():
        if name == "current_password":
            over[name] = PASSWORD.get(who, "x")
        elif callable(TYPED.get(name)):
            over[name] = TYPED[name](ids)
        elif name in TYPED and TYPED[name] is not None:
            over[name] = TYPED[name]
        else:
            pytest.fail(f"form {form.action!r} has a required box {name!r} the test does not know how to fill")
    return over


@pytest.mark.parametrize("who,page,index,action,method", FORMS, ids=[f"{f[0]}:{f[1]}#{f[2]}->{f[3] or 'self'}" for f in FORMS])
def test_form_works_when_a_browser_submits_it(who, page, index, action, method):
    world = seed_world("FULL")
    ids = _id_map(world)
    path = page.format(**ids)
    client = _client(who)
    form = parse(client.get(path).text).forms[index]
    where = SCRIPTED[form.form_id].format(**ids) if form.form_id in SCRIPTED and not form.action else target(path, form.action)
    assert form.has_submit, f"{who} {path}: a form with no submit button"
    data = form.browser_data(_fill(who, form, ids))
    if method == "post" and where.split("?")[0] in ("/login", "/guest/redeem"):
        pytest.skip("covered by the login and voucher tests")
    resp = client.request(method.upper(), where, data=data) if method == "post" else client.get(where, params=data)
    detail = f"{who} {path} -> {method.upper()} {where} sent {data} got {resp.status_code} {resp.headers.get('location', '')}"
    assert resp.status_code in (200, 302, 303), detail
    loc = resp.headers.get("location", "")
    assert "error=" not in loc or (path, where) in OK_ERRORS, detail


LINK_CASES = [("admin", p) for p in ADMIN_PAGES] + [("member", p) for p in MEMBER_PAGES] + [("anon", p) for p in PUBLIC_PAGES]


@pytest.mark.parametrize("who,page", LINK_CASES, ids=[f"{w}:{p}" for w, p in LINK_CASES])
def test_every_link_leads_somewhere(who, page):
    world = seed_world("FULL")
    path = page.format(**_id_map(world))
    client = _client(who)
    html = client.get(path).text
    broken = []
    for href in sorted(set(parse(html).links)):
        if href.startswith(("#", "mailto:", "http", "javascript:")) or href.startswith("/static") or href == "/logout":
            continue
        r = client.get(target(path, href))
        if r.status_code >= 400:
            broken.append((href, r.status_code))
    assert not broken, f"{who} {path} has links that do not work: {broken}"
