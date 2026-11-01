"""
clarinet/enforcer/limits.py
Data-limit throttling helpers.

Contract C-08:
  clarinet.enforcer.limits.throttle_low_priority(db, rate_kbps) -> None
  clarinet.enforcer.limits.release_throttle() -> None
Called by M1's limit_service at 100% usage.
"""
from __future__ import annotations

import logging

log = logging.getLogger("clarinet.enforcer.limits")

_throttle_active = False


def throttle_low_priority(db, rate_kbps: int = 1024) -> None:
    """
    Apply a global rate limit on the network interface so all low-priority
    traffic is capped at rate_kbps.  Only effective in FULL mode on Linux.
    """
    global _throttle_active
    from clarinet.enforcer.mode import get_mode
    if get_mode(db) != "FULL":
        log.info("throttle_low_priority: skipped (not FULL mode)")
        return

    from clarinet.app_settings import get_setting
    from clarinet.enforcer.tc_wrapper import set_rate_limit
    iface = get_setting(db, "network_interface", "")
    if not iface:
        log.warning("throttle_low_priority: no interface configured")
        return

    # Apply to all APPROVED devices (not priority-granted ones)
    from clarinet.models import Device
    approved = db.query(Device).filter(Device.state == "APPROVED").all()
    for dev in approved:
        set_rate_limit(iface, dev.mac_address, rate_kbps)

    _throttle_active = True
    log.info("Data-limit throttle applied: %d kbps on %s", rate_kbps, iface)


def release_throttle() -> None:
    """Remove the data-limit throttle from all devices."""
    global _throttle_active
    if not _throttle_active:
        return

    try:
        from clarinet.database import SessionLocal
        from clarinet.models import Device
        from clarinet.app_settings import get_setting
        from clarinet.enforcer.tc_wrapper import remove_rate_limit

        with SessionLocal() as db:
            iface = get_setting(db, "network_interface", "")
            if iface:
                approved = db.query(Device).filter(Device.state == "APPROVED").all()
                for dev in approved:
                    remove_rate_limit(iface, dev.mac_address)
    except Exception as exc:
        log.error("release_throttle error: %s", exc)
    finally:
        _throttle_active = False
    log.info("Data-limit throttle released")

