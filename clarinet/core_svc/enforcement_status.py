"""
clarinet/core_svc/enforcement_status.py
Full Control mode only works when Clarinet is allowed to change the network: nftables and tc present, and
permission to use them (root). Without that, a click on Block records the wish but changes nothing, and the
pages must say so instead of reporting success.
"""
import shutil
import subprocess
import threading
import time

_lock = threading.Lock()
_cache: dict = {"at": 0.0, "problem": None}
_TTL_SECONDS = 20


def _check() -> str | None:
    if shutil.which("nft") is None or shutil.which("tc") is None:
        return "nftables and tc are not installed on this machine"
    try:
        probe = subprocess.run(["nft", "list", "tables"], capture_output=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return "Clarinet could not run nftables"
    if probe.returncode != 0:
        return "Clarinet is not running as root, so it is not allowed to change the firewall"
    return None


def problem() -> str | None:
    """Why Full Control cannot change the network right now, or None when it can. Cached for a few seconds."""
    with _lock:
        if time.time() - _cache["at"] > _TTL_SECONDS:
            _cache["problem"], _cache["at"] = _check(), time.time()
        return _cache["problem"]


def reset_cache() -> None:
    with _lock:
        _cache["at"] = 0.0
