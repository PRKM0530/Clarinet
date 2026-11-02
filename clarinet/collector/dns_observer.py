"""
clarinet/collector/dns_observer.py
Records which domain names each device looks up, so its traffic can be sorted
into activity types (see core_svc/activity.py).

Only the registrable domain is kept ("youtube.com", not the full address or
anything after it), and never any content. Lookups are counted in memory and
written to the database once a minute, so the sniffer thread never waits on
the database.

Needs Scapy and root on Linux, like the ARP scanner. Without them nothing is
observed and all usage is shown as "Other".
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from datetime import datetime, timezone

log = logging.getLogger("clarinet.collector.dns_observer")


class DnsObserver:
    """Counts DNS lookups per (source IP, domain). Thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: dict[tuple[str, str, str], int] = defaultdict(int)

    def observe(self, src_ip: str, qname: str) -> bool:
        """Count one lookup. Returns False when the name is not worth recording."""
        from clarinet.core_svc.activity import classify_name, registrable_domain

        domain = registrable_domain(qname)
        if domain is None:
            return False
        category = classify_name(qname)
        with self._lock:
            self._counts[(src_ip, domain, category)] += 1
        return True

    def drain(self) -> dict[tuple[str, str, str], int]:
        with self._lock:
            counts, self._counts = dict(self._counts), defaultdict(int)
        return counts


observer = DnsObserver()


def flush(db, obs: DnsObserver | None = None, now: datetime | None = None) -> int:
    """Write the counted lookups to the database. Returns the number of rows written."""
    from clarinet.models import Device
    from clarinet.models.traffic import DomainObservation

    obs = obs or observer
    counts = obs.drain()
    if not counts:
        return 0

    minute = (now or datetime.now(timezone.utc)).replace(second=0, microsecond=0, tzinfo=None)
    by_ip = {ip: device_id for device_id, ip in db.query(Device.device_id, Device.ip_address) if ip}

    written = 0
    for (ip, domain, category), hits in counts.items():
        device_id = by_ip.get(ip)
        if device_id is None:
            continue          # not one of our devices (the router itself, a stray address)
        db.add(DomainObservation(
            device_id=device_id, domain=domain, category=category,
            observed_at=minute, hit_count=hits,
        ))
        written += 1
    db.commit()
    return written


def _handle_packet(pkt) -> None:
    try:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP
        if IP in pkt and DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
            qname = pkt[DNSQR].qname
            observer.observe(pkt[IP].src, qname.decode("ascii", "ignore") if isinstance(qname, bytes) else str(qname))
    except Exception as exc:
        log.debug("DNS packet handler error: %s", exc)


_started = False
_lock = threading.Lock()


def start_sniffer(interface: str) -> bool:
    """Start the DNS sniffer once. Returns False where sniffing isn't possible."""
    global _started
    with _lock:
        if _started:
            return True
        try:
            from scapy.sendrecv import sniff
        except ImportError:
            log.info("Activity classification off: Scapy not installed")
            return False

        def run() -> None:
            try:
                sniff(iface=interface, filter="udp port 53", prn=_handle_packet, store=False)
            except Exception as exc:
                log.warning("DNS sniffer stopped: %s", exc)

        threading.Thread(target=run, name="dns-observer", daemon=True).start()
        _started = True
        log.info("DNS observer started on %s", interface)
        return True
