"""
clarinet/scheduler.py
APScheduler setup. The jobs themselves live in clarinet/jobs/, one module per
area; each module's register(scheduler) adds its own jobs.
"""

import importlib
import logging
import pkgutil

from apscheduler.schedulers.background import BackgroundScheduler

from clarinet import jobs

log = logging.getLogger("clarinet.scheduler")

_scheduler: BackgroundScheduler | None = None


def start_scheduler() -> None:
    global _scheduler
    _scheduler = BackgroundScheduler(timezone="UTC", daemon=True)

    for mod in pkgutil.iter_modules(jobs.__path__):
        module = importlib.import_module(f"{jobs.__name__}.{mod.name}")
        register = getattr(module, "register", None)
        if register is not None:
            register(_scheduler)

    _scheduler.start()
    log.info("APScheduler started with %d jobs", len(_scheduler.get_jobs()))


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        log.info("APScheduler stopped")
