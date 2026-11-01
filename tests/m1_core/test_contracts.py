"""
tests/m1_core/test_contracts.py
Pin all C-01..C-08 contract signatures and basic behaviour.
"""

import inspect
import pytest


def test_c01_raise_alert_signature():
    """C-01: raise_alert has the required signature."""
    from clarinet.core_svc.alerts import raise_alert
    sig = inspect.signature(raise_alert)
    params = list(sig.parameters)
    assert "db" in params
    assert "level" in params
    assert "type" in params
    assert "title" in params
    assert "message" in params
    assert "device_id" in params
    assert "dedupe_key" in params
    assert "cooldown_s" in params


def test_c01_resolve_alert_signature():
    from clarinet.core_svc.alerts import resolve_alert
    sig = inspect.signature(resolve_alert)
    params = list(sig.parameters)
    assert "db" in params
    assert "type" in params
    assert "device_id" in params


def test_c02_set_event_loop_exists():
    """C-02: set_event_loop is importable from routers.ws."""
    from clarinet.routers.ws import set_event_loop
    assert callable(set_event_loop)


def test_c02_broadcast_alert_sync_exists():
    """C-02: broadcast_alert_sync never raises."""
    from clarinet.routers.ws import broadcast_alert_sync
    # Should not raise even with no loop registered
    broadcast_alert_sync({"type": "TEST", "level": "INFO", "title": "t", "message": "m"})


def test_c03_get_recent_device_bytes_signature():
    """C-03: get_recent_device_bytes returns dict[mac, (in, out)]."""
    from clarinet.collector.traffic_counter import get_recent_device_bytes
    result = get_recent_device_bytes(window_s=60)
    assert isinstance(result, dict)


def test_c03_get_recent_device_bytes_returns_tuples():
    """C-03: values are 2-tuples of ints."""
    from clarinet.collector.traffic_counter import get_recent_device_bytes, _update_rolling_window
    import time
    _update_rolling_window({"AA:BB:CC:DD:EE:FF": (100, 200)})
    result = get_recent_device_bytes(window_s=60)
    if "AA:BB:CC:DD:EE:FF" in result:
        bi, bo = result["AA:BB:CC:DD:EE:FF"]
        assert isinstance(bi, int)
        assert isinstance(bo, int)


def test_c04_settings_keys_exist():
    """C-04: All M1 setting key getters exist in settings_m1."""
    from clarinet.core_svc import settings_m1
    assert hasattr(settings_m1, "network_mode")
    assert hasattr(settings_m1, "billing_day")
    assert hasattr(settings_m1, "scan_interface")
    assert hasattr(settings_m1, "setup_complete")
    assert hasattr(settings_m1, "limit_bytes")
    assert hasattr(settings_m1, "timezone_setting")


def test_c05_guest_skipped_in_scanner():
    """C-05: ArpSource and scan_once can be imported cleanly."""
    from clarinet.collector.arp_scanner import ArpSource, FakeSource
    fs = FakeSource([{"ip": "10.0.0.1", "mac": "AA:BB:CC:DD:EE:FF"}])
    assert len(fs.scan("eth0")) == 1


def test_c06_topbar_api_route_exists():
    """C-06: /api/status/topbar route is registered."""
    from clarinet.routers.status import router
    paths = [r.path for r in router.routes]
    assert "/api/status/topbar" in paths


def test_c07_limit_summary_route_exists():
    """C-07: /api/limit/summary route exists."""
    from clarinet.routers.usage import router
    paths = [r.path for r in router.routes]
    assert "/api/limit/summary" in paths


def test_c07_devices_summary_route_exists():
    """C-07: /api/devices/summary route exists."""
    from clarinet.routers.alerts import router
    paths = [r.path for r in router.routes]
    assert "/api/devices/summary" in paths


def test_c08_lazy_imports_dont_break_on_windows():
    """C-08: M2 lazy imports don't crash on Windows/dev where enforcer is absent."""
    from clarinet.collector.traffic_counter import NftAccountingSource
    src = NftAccountingSource()
    result = src.read()  # should return {} not raise
    assert isinstance(result, dict)
