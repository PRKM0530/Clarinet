"""
clarinet/collector/dns_timer.py
Measures DNS resolution time for the slowdown diagnosis system.

Compares resolution time against the baseline.
A DNS time > 500 ms with ICMP < 100 ms → SLOW_DNS cause (Diagram 8).
"""

import logging
import time
from dataclasses import dataclass

import dns.resolver

log = logging.getLogger("clarinet.collector.dns")

DNS_TARGETS = ["google.com", "cloudflare.com", "example.com"]
DNS_TIMEOUT = 5.0


@dataclass
class DnsResult:
    target: str
    server: str
    response_ms: float | None
    success: bool
    error: str | None = None


def query_dns(hostname: str, nameserver: str | None = None) -> DnsResult:
    """
    Resolve `hostname` using the system resolver (or a specific nameserver)
    and return the round-trip time in milliseconds.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    if nameserver:
        resolver.nameservers = [nameserver]

    server = nameserver or "system"
    start = time.perf_counter()
    try:
        resolver.resolve(hostname, "A")
        elapsed_ms = (time.perf_counter() - start) * 1000
        return DnsResult(target=hostname, server=server,
                         response_ms=round(elapsed_ms, 1), success=True)
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return DnsResult(target=hostname, server=server,
                         response_ms=round(elapsed_ms, 1), success=False, error=str(e))


def measure_dns() -> list[DnsResult]:
    """Measure DNS for all configured targets against the system resolver."""
    results = []
    for target in DNS_TARGETS:
        r = query_dns(target)
        log.debug("DNS %s: %.1f ms (ok=%s)", target, r.response_ms or 0, r.success)
        results.append(r)
    return results


def average_dns_ms(results: list[DnsResult]) -> float | None:
    """Average response time across successful queries."""
    times = [r.response_ms for r in results if r.success and r.response_ms is not None]
    return round(sum(times) / len(times), 1) if times else None
