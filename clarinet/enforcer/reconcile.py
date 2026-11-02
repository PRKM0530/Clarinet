"""
clarinet/enforcer/reconcile.py
Request a reconciliation of nftables rules after a device state change.

Contract C-08: clarinet.enforcer.reconcile.request_reconcile()
Called by M1's devices router after block/unblock.
"""
from __future__ import annotations

import logging
import threading

log = logging.getLogger("clarinet.enforcer.reconcile")

_lock = threading.Lock()
_pending = threading.Event()


def request_reconcile() -> None:
    """
    Signal that a reconciliation of blocking/voucher rules is needed.
    Thread-safe. The reconcile job picks this up within its next run.
    """
    with _lock:
        _pending.set()
    log.debug("Reconcile requested")


def consume_reconcile() -> bool:
    """Return True and clear the flag if a reconcile was requested."""
    with _lock:
        if _pending.is_set():
            _pending.clear()
            return True
        return False


def reconcile_now(db=None) -> None:
    """
    Immediately apply current device states to nftables.
    Safe to call from any thread.
    """
    try:
        from clarinet.database import SessionLocal
        from clarinet.models import Device
        from clarinet.enforcer.nft_wrapper import ensure_table_exists, block_device, unblock_device
        from clarinet.app_settings import get_setting

        with (db or SessionLocal()) as session:
            iface = get_setting(session, "network_interface", "")
            ensure_table_exists()

            blocked = (
                session.query(Device)
                .filter(Device.state == "BLOCKED")
                .all()
            )
            for dev in blocked:
                block_device(dev.mac_address)
            log.info("Reconcile complete: %d blocked device(s)", len(blocked))
    except Exception as exc:
        log.error("Reconcile error: %s", exc)

