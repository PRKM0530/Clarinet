"""
clarinet/collector/port_scan.py
Port-scan detection.

A source that sends connection attempts (TCP SYN) to many different ports in a
short time is scanning. The detector is plain Python so it can be tested without
sniffing; the sniffer feeds it packets on Linux when Scapy and root are available.
"""

import logging
import threading
import time
from collections import defaultdict, deque

log = logging.getLogger("clarinet.collector.port_scan")

WINDOW_SECONDS = 10
PORT_THRESHOLD = 15          # distinct (host, port) targets inside the window
COOLDOWN_SECONDS = 300       # don't re-alert for the same source for 5 minutes


class PortScanDetector:
    def __init__(self, window: float = WINDOW_SECONDS, threshold: int = PORT_THRESHOLD,
                 cooldown: float = COOLDOWN_SECONDS):
        self.window = window
        self.threshold = threshold
        self.cooldown = cooldown
        self._events: dict[str, deque] = defaultdict(deque)     # src -> deque[(time, dst, port)]
        self._last_alert: dict[str, float] = {}

    def observe(self, src: str, dst: str, port: int, now: float | None = None) -> int | None:
        """
        Record one connection attempt. Returns the number of distinct targets when
        this attempt makes `src` cross the scan threshold, otherwise None.
        """
        now = time.time() if now is None else now
        events = self._events[src]
        events.append((now, dst, port))
        while events and now - events[0][0] > self.window:
            events.popleft()

        targets = {(d, p) for _, d, p in events}
        if len(targets) < self.threshold:
            return None
        if now - self._last_alert.get(src, float("-inf")) < self.cooldown:
            return None
        self._last_alert[src] = now
        return len(targets)


detector = PortScanDetector()


def report_scan(src_ip: str, target_count: int) -> None:
    from clarinet.collector.security_alerts import raise_alert
    from clarinet.database import SessionLocal
    from clarinet.models import Device

    with SessionLocal() as db:
        device = db.query(Device).filter(Device.ip_address == src_ip).first()
        who = (device.label or device.mac_address) if device else src_ip
        raise_alert(
            "PORT_SCAN", "WARNING",
            f"Port scan from {who}",
            f"{src_ip} tried {target_count} different ports/hosts within {WINDOW_SECONDS} seconds. "
            "A device on your network may be infected or someone is probing it.",
            device_id=device.device_id if device else None,
            extra={"ip": src_ip},
            db=db,
        )


def _handle_packet(pkt) -> None:
    try:
        from scapy.layers.inet import IP, TCP
        if IP in pkt and TCP in pkt and (pkt[TCP].flags & 0x02) and not (pkt[TCP].flags & 0x10):
            count = detector.observe(pkt[IP].src, pkt[IP].dst, int(pkt[TCP].dport))
            if count:
                report_scan(pkt[IP].src, count)
    except Exception as e:
        log.debug("Port-scan packet handler error: %s", e)


_sniffer_started = False
_lock = threading.Lock()


def start_sniffer(interface: str) -> bool:
    """Start a background sniffer once. Returns False where sniffing isn't possible."""
    global _sniffer_started
    with _lock:
        if _sniffer_started:
            return True
        try:
            from scapy.sendrecv import sniff
        except ImportError:
            log.info("Port-scan detection off: Scapy not installed")
            return False

        def run():
            try:
                sniff(iface=interface, filter="tcp", prn=_handle_packet, store=False)
            except Exception as e:
                log.warning("Port-scan sniffer stopped: %s", e)

        threading.Thread(target=run, name="port-scan-sniffer", daemon=True).start()
        _sniffer_started = True
        log.info("Port-scan sniffer started on %s", interface)
        return True
