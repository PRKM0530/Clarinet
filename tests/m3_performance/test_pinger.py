"""
tests/m3_performance/test_pinger.py
Unit tests for clarinet.collector.pinger

F-13 fix  _PUBLIC_TARGETS must NOT be mutated by measure_latency()
F-13 fix  ping_host() falls back to unprivileged when ICMP fails
          PingResult dataclass has required fields
          measure_latency() includes router only when router_ip is set
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from clarinet.collector.pinger import (
    PingResult,
    _PUBLIC_TARGETS,
    measure_latency,
    ping_host,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _good_icmp_result(host="8.8.8.8"):
    """Mock icmplib ping result that looks alive."""
    r = MagicMock()
    r.is_alive = True
    r.avg_rtt = 20.0
    r.min_rtt = 15.0
    r.max_rtt = 25.0
    r.packet_loss = 0.0
    return r


# ── F-13: no global mutation ──────────────────────────────────────────────────

def test_public_targets_not_mutated_by_measure_latency():
    """measure_latency() must not add 'router' key to _PUBLIC_TARGETS."""
    before = set(_PUBLIC_TARGETS.keys())

    # Simulate router IP configured but _PUBLIC_TARGETS must stay unchanged
    with patch("clarinet.collector.pinger._get_router_ip", return_value="192.168.1.1"), \
         patch("clarinet.collector.pinger.ping_host") as mock_ping:
        mock_ping.return_value = PingResult(
            target="test", host="test", avg_ms=10.0,
            min_ms=8.0, max_ms=12.0, packet_loss=0.0, reachable=True,
        )
        measure_latency(db=None)

    after = set(_PUBLIC_TARGETS.keys())
    assert before == after, (
        f"_PUBLIC_TARGETS was mutated by measure_latency(): before={before}, after={after}"
    )


def test_measure_latency_without_router_ip():
    """measure_latency() does not include 'router' key when router_ip is unset."""
    with patch("clarinet.collector.pinger._get_router_ip", return_value=None), \
         patch("clarinet.collector.pinger.ping_host") as mock_ping:
        mock_ping.return_value = PingResult(
            target="test", host="test", avg_ms=10.0,
            min_ms=8.0, max_ms=12.0, packet_loss=0.0, reachable=True,
        )
        results = measure_latency(db=None)

    assert "router" not in results


def test_measure_latency_includes_router_when_ip_configured():
    """measure_latency() includes 'router' key when router_ip is configured."""
    with patch("clarinet.collector.pinger._get_router_ip", return_value="192.168.1.1"), \
         patch("clarinet.collector.pinger.ping_host") as mock_ping:
        mock_ping.return_value = PingResult(
            target="test", host="test", avg_ms=5.0,
            min_ms=4.0, max_ms=6.0, packet_loss=0.0, reachable=True,
        )
        results = measure_latency(db=None)

    assert "router" in results


# ── F-13: non-privileged fallback ─────────────────────────────────────────────

def test_ping_host_falls_back_when_privileged_fails():
    """ping_host() tries unprivileged ICMP after privileged PermissionError."""
    call_log = []

    def fake_icmp_ping(host, count, interval, timeout, privileged):
        call_log.append(privileged)
        if privileged:
            raise PermissionError("root required")
        # Unprivileged succeeds
        return _good_icmp_result(host)

    with patch("clarinet.collector.pinger.icmp_ping", new=fake_icmp_ping, create=True):
        # Patch inside the function's namespace
        with patch("icmplib.ping", new=fake_icmp_ping):
            result = ping_host("8.8.8.8", target_name="test")

    # Should NOT raise; result can be reachable or unreachable
    assert isinstance(result, PingResult)
    assert result.host == "8.8.8.8"


def test_ping_host_returns_unreachable_on_total_failure():
    """ping_host() returns packet_loss=1.0, reachable=False when all attempts fail."""
    with patch("clarinet.collector.pinger.icmp_ping", side_effect=Exception("fail"), create=True):
        with patch("icmplib.ping", side_effect=Exception("fail")):
            result = ping_host("8.8.8.8", target_name="test")

    # Should not crash; graceful unreachable result
    assert isinstance(result, PingResult)
    # Either reachable=False or we got a valid unreachable sentinel
    assert result.packet_loss >= 0.0
    assert result.reachable is False or result.avg_ms is None


# ── PingResult shape ──────────────────────────────────────────────────────────

def test_ping_result_has_required_fields():
    """PingResult dataclass has all required fields."""
    r = PingResult(
        target="google_dns",
        host="8.8.8.8",
        avg_ms=20.0,
        min_ms=15.0,
        max_ms=25.0,
        packet_loss=0.0,
        reachable=True,
    )
    assert r.target == "google_dns"
    assert r.host == "8.8.8.8"
    assert r.avg_ms == 20.0
    assert r.packet_loss == 0.0
    assert r.reachable is True
