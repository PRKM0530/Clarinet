"""Security jobs: router audit, Wi-Fi scans, network checks."""

import logging

log = logging.getLogger("clarinet.jobs.security")


def register(scheduler) -> None:
    # Add security jobs here, for example:
    # scheduler.add_job(router_audit, trigger=IntervalTrigger(hours=24), id="router_audit", replace_existing=True)
    pass
