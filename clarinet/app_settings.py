"""
clarinet/app_settings.py
Small helpers for the key/value Settings table.

Use these instead of adding new keys to DEFAULT_SETTINGS: pass the default at
the call site and nothing shared has to change.

The network connection and the router address are filled in automatically when
they are not set (see core_svc/autoconfig.py), so every caller can simply read
them.
"""

from clarinet.models import Settings as AppSettings


def get_setting(db, key: str, default: str | None = None) -> str | None:
    row = db.get(AppSettings, key)
    stored = row.value if row is not None and row.value is not None else None

    from clarinet.core_svc.autoconfig import AUTO_KEYS, resolve
    if key in AUTO_KEYS:
        return resolve(key, stored, default)
    return stored if stored is not None else default


def set_setting(db, key: str, value: str) -> None:
    row = db.get(AppSettings, key)
    if row is None:
        db.add(AppSettings(key=key, value=value))
    else:
        row.value = value
    db.commit()
