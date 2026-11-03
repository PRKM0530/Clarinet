"""
clarinet/core_svc/device_names.py
One rule for what a device is called, so it reads the same on every page and in every alert.
"""


def device_name(device) -> str:
    """The label the admin gave it, else its own host name, else the maker and the end of its address."""
    for text in (getattr(device, "label", None), getattr(device, "hostname", None)):
        if text and text.strip():
            return text.strip()
    mac = getattr(device, "mac_address", "") or ""
    vendor = (getattr(device, "vendor", None) or "").strip()
    if vendor:
        return f"{vendor} {mac[-5:].upper()}".strip()
    return mac or "Unknown device"


def is_saved(device) -> bool:
    """A device someone has dealt with: approved, given a name, or assigned to a member. Unknown ones are not."""
    return (getattr(device, "state", None) == "APPROVED"
            or bool((getattr(device, "label", None) or "").strip())
            or getattr(device, "owner_member_id", None) is not None)


def saved_first(devices):
    """Saved devices on top; inside each group, the most recently seen first."""
    from datetime import datetime, timezone
    floor = datetime.min.replace(tzinfo=timezone.utc)
    def seen(d):
        t = getattr(d, "last_seen", None) or floor
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return sorted(devices, key=lambda d: (0 if is_saved(d) else 1, -seen(d).timestamp()))


def device_mono(device) -> str:
    """Up to two capital letters from the name, for the small square that stands for the device."""
    words = [w for w in device_name(device).replace("-", " ").replace("_", " ").split() if any(c.isalnum() for c in w)]
    letters = "".join(next(c for c in w if c.isalnum()) for w in words[:2])
    return (letters or "?").upper()
