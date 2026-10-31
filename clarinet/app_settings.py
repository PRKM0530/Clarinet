"""
clarinet/app_settings.py
Small helpers for the key/value Settings table.

Use these instead of adding new keys to DEFAULT_SETTINGS: pass the default at
the call site and nothing shared has to change.
"""

from clarinet.models import Settings as AppSettings


def get_setting(db, key: str, default: str | None = None) -> str | None:
    row = db.get(AppSettings, key)
    return row.value if row is not None and row.value is not None else default


def set_setting(db, key: str, value: str) -> None:
    row = db.get(AppSettings, key)
    if row is None:
        db.add(AppSettings(key=key, value=value))
    else:
        row.value = value
    db.commit()
