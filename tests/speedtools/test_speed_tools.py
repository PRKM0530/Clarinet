"""
GST-03: each speed tool through its real subprocess and parsing code, plus the failure paths.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from tests._support import seed_world

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="builds fake Linux tools with symlinks")

OOKLA = json.dumps({"download": {"bandwidth": 12_500_000}, "upload": {"bandwidth": 2_500_000},
                    "ping": {"latency": 12.5}, "server": {"host": "ookla.example"}})
CLI = json.dumps({"download": 50_000_000, "upload": 10_000_000, "ping": 20.0, "server": {"host": "cli.example"}})
LIBRE = json.dumps([{"download": 75.5, "upload": 15.25, "ping": 8.0, "server": {"name": "libre"}}])


def run_cli():
    from clarinet.collector.speed_test import _run_speedtest_cli
    return _run_speedtest_cli()


def test_ookla_output_is_converted_from_bytes_to_mbit(tools):
    tools("speedtest", OOKLA)
    r = run_cli()
    assert (r["download_mbps"], r["upload_mbps"], r["latency_ms"], r["tool"]) == (100.0, 20.0, 12.5, "ookla")


def test_speedtest_cli_output_is_converted_from_bits_to_mbit(tools):
    tools("speedtest-cli", CLI)
    r = run_cli()
    assert (r["download_mbps"], r["upload_mbps"], r["tool"]) == (50.0, 10.0, "speedtest-cli")


def test_librespeed_list_output_is_read(tools):
    tools("librespeed-cli", LIBRE)
    r = run_cli()
    assert (r["download_mbps"], r["upload_mbps"], r["latency_ms"], r["tool"]) == (75.5, 15.25, 8.0, "librespeed")


def test_next_tool_is_tried_when_the_first_one_fails(tools):
    tools("speedtest", "oops", exit_code=1)
    tools("speedtest-cli", CLI)
    assert run_cli()["tool"] == "speedtest-cli"


def test_garbage_output_falls_through_to_the_next_tool(tools):
    tools("speedtest", "this is not json")
    tools("librespeed-cli", LIBRE)
    assert run_cli()["tool"] == "librespeed"


def test_no_tool_installed_returns_none(tools):
    assert run_cli() is None


def test_a_hung_tool_is_given_up_on(tools, monkeypatch):
    tools("speedtest", OOKLA, sleep=5)
    real = subprocess.run
    monkeypatch.setattr("clarinet.collector.speed_test.subprocess.run",
                        lambda *a, **k: real(*a, **{**k, "timeout": 0.5}))
    assert run_cli() is None


def test_tool_with_null_values_does_not_crash(tools):
    tools("speedtest", json.dumps({"download": {"bandwidth": None}, "upload": {"bandwidth": 1}, "ping": {"latency": 1}}))
    assert run_cli() is None


def test_full_run_stores_the_result_and_flags_below_plan(tools):
    from clarinet.collector.speed_test import _do_run
    from clarinet.database import SessionLocal
    from clarinet.models import Settings, SpeedTestResult
    seed_world("FULL")
    with SessionLocal() as db:
        db.add_all([Settings(key="plan_download_mbps", value="200"), Settings(key="plan_upload_mbps", value="40")])
        db.commit()
    tools("speedtest", OOKLA)                 # 100 Mbit down on a 200 Mbit plan = 50%
    _do_run()
    with SessionLocal() as db:
        row = db.query(SpeedTestResult).one()
        assert (row.download_mbps, row.upload_mbps, row.latency_ms) == (100.0, 20.0, 12.5)
        assert row.below_plan is True and row.server_host == "ookla.example"


def test_full_run_also_works_in_monitor_mode(tools):
    from clarinet.collector.speed_test import _do_run
    from clarinet.database import SessionLocal
    from clarinet.models import SpeedTestResult
    seed_world("MONITOR")
    tools("speedtest", OOKLA)
    _do_run()
    with SessionLocal() as db:
        assert db.query(SpeedTestResult).count() == 1
