"""
clarinet/enforcer/guest_net.py
Guest-network helpers.

Contract R-04 / TS-03d:
  clarinet.enforcer.guest_net.is_guest_ip(ip, db) -> bool
Used by M4's optional ASGI middleware to refuse dashboard access from guest subnet.
"""
from __future__ import annotations

import ipaddress
import logging

log = logging.getLogger("clarinet.enforcer.guest_net")


def is_guest_ip(ip: str, db) -> bool:
    """
    Return True when `ip` is inside the configured guest subnet.
    Returns False if no subnet is configured or on any error.
    """
    try:
        from clarinet.app_settings import get_setting
        subnet_str = get_setting(db, "guest.subnet", "")
        if not subnet_str:
            return False
        subnet = ipaddress.ip_network(subnet_str, strict=False)
        addr = ipaddress.ip_address(ip)
        return addr in subnet
    except Exception as exc:
        log.debug("is_guest_ip error: %s", exc)
        return False

