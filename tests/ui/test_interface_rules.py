"""
Interface rules that hold on every page: titles and headings, labelled form
fields, no empty buttons, no emoji, and nothing loaded from a third party.
"""
from __future__ import annotations

import re
from datetime import date, datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from clarinet import _size, app
from clarinet.auth import hash_password
from clarinet.database import Base, SessionLocal, engine
from clarinet.models import Alert, Device, Member, Settings, SpeedTestResult, UsageRecord, Voucher

ROOT = Path(__file__).resolve().parents[2] / "clarinet"
EMOJI = re.compile("[\U0001F300-\U0001FAFF☀-➿⭐✨✅❌️]")


@pytest.fixture(scope="module")
def pages():
    """Every page, rendered for the role that can open it."""
    assert "clarinet_test_" in str(engine.url), "refusing to touch a non-test database"
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.add(Settings(key="setup_complete", value="true"))
        alice = Member(username="alice", password_hash=hash_password("pw-alice-1"), role="MEMBER")
        boss = Member(username="boss", password_hash=hash_password("pw-boss-1"), role="ADMIN")
        db.add_all([alice, boss])
        db.flush()
        device = Device(mac_address="AA:00:00:00:00:01", label="Laptop", state="NEW", owner_member_id=alice.member_id,
                        first_seen=now, last_seen=now)
        db.add(device)
        db.flush()
        db.add(UsageRecord(device_id=device.device_id, date=date.today().isoformat(), hour=9, bytes_in=5_000_000, bytes_out=1_000_000))
        db.add(Alert(level="WARNING", type="NEW_DEVICE", title="New device", message="x", device_id=device.device_id))
        db.add(SpeedTestResult(download_mbps=90, upload_mbps=18, latency_ms=20))
        db.add(Voucher(code="ABCD-1234", created_by=boss.member_id, expires_at=now.replace(year=now.year + 1)))
        db.commit()
        device_id = device.device_id

    def login(user, password):
        client = TestClient(app, follow_redirects=False)
        assert client.post("/login", data={"username": user, "password": password}).status_code == 302
        return client

    public = TestClient(app, follow_redirects=False)
    admin, member = login("boss", "pw-boss-1"), login("alice", "pw-alice-1")
    rendered = {}
    for path in ("/login", "/privacy", "/guest"):
        rendered[("public", path)] = public.get(path).text
    for path in ("/dashboard", "/devices", f"/devices/{device_id}", "/usage", "/reports", "/alerts", "/priority", "/speed",
                 "/speed/report", "/rules", "/vouchers", "/slowdowns", "/security", "/settings", "/status"):
        rendered[("admin", path)] = admin.get(path).text
    for path in ("/dashboard", "/devices", "/usage", "/reports", "/alerts", "/priority"):
        rendered[("member", path)] = member.get(path).text
    return rendered


class Scan(HTMLParser):
    def __init__(self):
        super().__init__()
        self.lang = None
        self.title = ""
        self.h1 = 0
        self.fields, self.label_for, self.wrapped = [], set(), 0
        self.empty_controls = []
        self._in_title = False
        self._label_depth = 0
        self._ctl = None            # [tag, attrs, text]

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "html":
            self.lang = a.get("lang")
        elif tag == "title":
            self._in_title = True
        elif tag == "h1":
            self.h1 += 1
        elif tag == "label":
            self._label_depth += 1
            if a.get("for"):
                self.label_for.add(a["for"])
        elif tag in ("input", "select", "textarea"):
            if a.get("type") not in ("hidden", "submit", "button"):
                self.fields.append((tag, a, self._label_depth > 0))
        elif tag in ("button", "a"):
            self._ctl = [tag, a, ""]

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "label":
            self._label_depth -= 1
        elif tag in ("button", "a") and self._ctl and self._ctl[0] == tag:
            t, a, text = self._ctl
            if not text.strip() and not a.get("aria-label") and not a.get("title") and (t == "button" or a.get("href")):
                self.empty_controls.append((t, a.get("href") or a.get("id") or a.get("class")))
            self._ctl = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._ctl is not None:
            self._ctl[2] += data

    def unlabelled(self):
        return [
            (tag, a.get("name") or a.get("id"))
            for tag, a, inside in self.fields
            if not inside and not a.get("aria-label") and not (a.get("id") and a["id"] in self.label_for)
        ]


def scan(html: str) -> Scan:
    s = Scan()
    s.feed(html)
    return s


def test_every_page_has_a_language_a_title_and_one_main_heading(pages):
    problems = []
    for key, html in pages.items():
        s = scan(html)
        if s.lang != "en":
            problems.append((key, "missing lang"))
        if not s.title.strip():
            problems.append((key, "empty title"))
        if s.h1 != 1 and key[0] != "public":
            problems.append((key, f"{s.h1} h1 headings"))
    assert problems == []


def test_every_form_field_has_a_label(pages):
    problems = {key: scan(html).unlabelled() for key, html in pages.items()}
    problems = {k: v for k, v in problems.items() if v}
    report = ("\n").join(f"{role} {path}: {fields}" for (role, path), fields in problems.items())
    assert problems == {}, "form fields without a label:" + ("\n") + report


def test_no_button_or_link_is_empty(pages):
    problems = {key: scan(html).empty_controls for key, html in pages.items()}
    problems = {k: v for k, v in problems.items() if v}
    report = ("\n").join(f"{role} {path}: {controls}" for (role, path), controls in problems.items())
    assert problems == {}, "buttons or links with no text:" + ("\n") + report


def test_no_page_has_emoji(pages):
    assert [key for key, html in pages.items() if EMOJI.search(html)] == []


def test_the_templates_and_scripts_have_no_emoji():
    files = list((ROOT / "templates").rglob("*.html")) + [ROOT / "static" / "js" / "clarinet.js", ROOT / "static" / "css" / "clarinet.css"]
    assert [f.name for f in files if EMOJI.search(f.read_text(encoding="utf-8"))] == []


def test_nothing_is_loaded_from_another_website():
    """The privacy page says nothing leaves the network, so no page may fetch fonts, scripts or images from outside."""
    loads = re.compile(r"""(?:src|href)\s*=\s*["']https?://|@import\s+url\(\s*["']?https?://|url\(\s*["']?https?://""", re.I)
    files = list((ROOT / "templates").rglob("*.html")) + [ROOT / "static" / "css" / "clarinet.css", ROOT / "static" / "js" / "clarinet.js"]
    offenders = [f.name for f in files if loads.search(f.read_text(encoding="utf-8"))]
    assert offenders == []


def test_the_page_scripts_use_a_secure_websocket_on_https():
    script = (ROOT / "static" / "js" / "clarinet.js").read_text(encoding="utf-8")
    assert "wss" in script and "location.protocol" in script


def test_pages_have_a_skip_link_and_a_viewport(pages):
    for key, html in pages.items():
        assert 'class="skip-link"' in html and 'name="viewport"' in html, key


def test_the_stylesheet_has_no_gradients_or_glows_and_follows_the_system_theme():
    css = (ROOT / "static" / "css" / "clarinet.css").read_text(encoding="utf-8")
    assert "gradient" not in css
    assert "prefers-color-scheme: dark" in css
    assert "@media print" in css and "(max-width: 600px)" in css


@pytest.mark.parametrize("value, shown", [
    (0, "0 B"), (900, "900 B"), (5_000, "5 KB"), (3_000_000, "2.9 MB"),
    (700_000_000, "668 MB"), (48_000_000_000, "44.7 GB"), (5_000_000_000_000, "4.5 TB"), (None, "0 B"),
])
def test_sizes_are_written_the_same_way_everywhere(value, shown):
    assert _size(value) == shown


def test_the_mode_is_always_visible_in_the_top_bar(pages):
    """DASH-5: the current mode is shown on every page, filled in by the page script."""
    for key, html in pages.items():
        if key[0] != "public":
            assert 'id="mode-label"' in html, key
