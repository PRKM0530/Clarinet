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


def apply_now(db=None) -> None:
    """Request a reconcile and run it immediately. `db`, if given, is committed first so the new state is visible."""
    if db is not None:
        try:
            db.commit()
        except Exception:
            db.rollback()
    request_reconcile()
    reconcile_now()
    consume_reconcile()


def reconcile_now(db=None) -> None:
    """
    Make nftables match the database. Idempotent and safe to call from any thread.

    * counters: one pair of accounting rules per known device (Full Control and Monitor modes)
    * Full Control only:
        - BLOCKED devices are dropped, and blocks for devices that are no longer BLOCKED are removed
        - GUEST devices are denied unless they hold an unexpired voucher, which opens them
    """
    try:
        from datetime import datetime, timezone
        from clarinet.app_settings import get_setting
        from clarinet.core_svc.mode import NetworkMode, parse_mode
        from clarinet.database import SessionLocal
        from clarinet.enforcer import accounting, nft_wrapper as nft
        from clarinet.models import Device
        from clarinet.models.guest import EnforcementStatus

        own = db is None
        session = db or SessionLocal()
        try:
            mode = parse_mode(get_setting(session, "network_mode"))
            if mode == NetworkMode.PUBLIC:
                return
            nft.ensure_table_exists()
            devices = session.query(Device).all()
            counted = [(d.mac_address, d.ip_address) for d in devices]
            from clarinet.models.merging import MergedMac
            counted += [(a.mac_address, None) for a in session.query(MergedMac).all()]    # upload side only
            accounting.sync_accounting(counted)
            if mode != NetworkMode.FULL:
                return

            iface = get_setting(session, "network_interface", "")
            # Administrator blocks
            wanted = {d.mac_address.lower(): d.ip_address for d in devices if d.state == "BLOCKED"}
            have = nft.macs_with_rules(nft.NFT_CHAIN_BLOCK, "block")
            for mac in have - wanted.keys():
                nft.unblock_device(mac)
            for mac, ip in wanted.items():
                nft.block_device(mac, ip)

            # Guests: denied unless a voucher is active
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            vouchered = {e.mac.lower() for e in session.query(EnforcementStatus).all()
                         if e.expires_at is None or e.expires_at.replace(tzinfo=None) > now}
            guests = {d.mac_address.lower() for d in devices if d.state == "GUEST"}
            for mac in guests:
                if mac in vouchered:
                    nft.open_guest_access(mac, interface=iface)
                else:
                    nft.close_guest_access(mac)
                    nft.deny_guest(mac)
            for mac in nft.macs_with_rules(nft.NFT_CHAIN_GUEST, "guestdeny") - guests:
                nft.allow_guest_again(mac)               # no longer a guest
            for mac in nft.macs_with_rules(nft.NFT_CHAIN_GUEST, "guest") - guests:
                nft.close_guest_access(mac)
            log.info("Reconcile complete: %d blocked, %d guest(s)", len(wanted), len(guests))
        finally:
            if own:
                session.close()
    except Exception as exc:
        log.error("Reconcile error: %s", exc)
