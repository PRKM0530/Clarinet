"""
Reads the forms and links off a rendered page and submits them the way a browser does:
a blank optional box is sent as an empty string, an unticked checkbox is left out, a select sends its
selected (or first) option. This is what the older tests never did, and why broken forms went unnoticed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse


@dataclass
class Field:
    name: str
    kind: str                 # text, number, password, checkbox, radio, hidden, select, textarea, ...
    value: str = ""
    checked: bool = False
    required: bool = False
    options: list = field(default_factory=list)        # (value, selected) for select


@dataclass
class Form:
    action: str
    method: str
    fields: list = field(default_factory=list)
    has_submit: bool = False
    form_id: str = ""

    def browser_data(self, overrides: dict | None = None) -> dict:
        """What a browser would send if the person pressed the submit button without changing anything."""
        data: dict = {}
        for f in self.fields:
            if f.kind in ("checkbox", "radio"):
                if f.checked:
                    data.setdefault(f.name, []).append(f.value or "on")
            elif f.kind == "select":
                chosen = next((v for v, sel in f.options if sel), f.options[0][0] if f.options else None)
                if chosen is not None:
                    data[f.name] = chosen
            else:
                data[f.name] = f.value
        for key, value in (overrides or {}).items():
            data[key] = value
        return data

    def empty_required(self) -> list[str]:
        sent = self.browser_data()
        return [f.name for f in self.fields if f.required and not sent.get(f.name)]


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[Form] = []
        self.links: list[str] = []
        self._form: Form | None = None
        self._select: Field | None = None
        self._textarea: Field | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = Form(action=a.get("action", ""), method=(a.get("method") or "get").lower(), form_id=a.get("id", ""))
            self.forms.append(self._form)
        elif self._form is not None:
            if tag == "input":
                kind = (a.get("type") or "text").lower()
                if kind == "submit":
                    self._form.has_submit = True
                if a.get("name") and kind not in ("submit", "button", "image", "file"):
                    self._form.fields.append(Field(a["name"], kind, a.get("value") or "", "checked" in a, "required" in a))
            elif tag == "button":
                if (a.get("type") or "submit") == "submit":
                    self._form.has_submit = True
            elif tag == "select" and a.get("name"):
                self._select = Field(a["name"], "select", required="required" in a)
                self._form.fields.append(self._select)
            elif tag == "option" and self._select is not None:
                self._select.options.append((a.get("value", ""), "selected" in a))
            elif tag == "textarea" and a.get("name"):
                self._textarea = Field(a["name"], "textarea", required="required" in a)
                self._form.fields.append(self._textarea)

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "select":
            self._select = None
        elif tag == "textarea":
            self._textarea = None

    def handle_data(self, data):
        if self._textarea is not None:
            self._textarea.value += data


def parse(html: str) -> _Page:
    p = _Page()
    p.feed(html)
    return p


def target(page_path: str, action: str) -> str:
    """Path a form or link on `page_path` really points to."""
    if not action:
        return page_path
    return urlparse(urljoin("http://x" + page_path, action)).path + (("?" + urlparse(urljoin("http://x" + page_path, action)).query) if urlparse(urljoin("http://x" + page_path, action)).query else "")
