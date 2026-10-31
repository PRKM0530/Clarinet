"""
clarinet/__init__.py
FastAPI application factory.

Registers:
  - SessionMiddleware (HttpOnly signed cookie)
  - Static file mount
  - Jinja2 template engine
  - All routers
  - Startup event: create DB tables + seed default settings
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from clarinet.config import settings
from clarinet.database import Base, engine, SessionLocal
from clarinet.models import Settings as AppSettings, Member
from clarinet.auth import hash_password

# Paths
APP_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"


# Jinja2 templates (module-level so routers can import it)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# Default settings seeded on first run
DEFAULT_SETTINGS = {
    "network_mode": settings.NETWORK_MODE,
    "network_interface": settings.NETWORK_INTERFACE,
    "plan_download_mbps": str(settings.PLAN_DOWNLOAD_MBPS),
    "plan_upload_mbps": str(settings.PLAN_UPLOAD_MBPS),
    "billing_day": str(settings.BILLING_DAY),
    "setup_complete": "false",    # wizard flag
    "speed_test_interval_hours": "6",
    "slowdown_latency_multiplier": str(settings.SLOWDOWN_LATENCY_MULTIPLIER),
    "slowdown_speed_threshold": str(settings.SLOWDOWN_SPEED_THRESHOLD),
}


def _seed_defaults(db):
    """Insert default settings rows that don't already exist."""
    for key, value in DEFAULT_SETTINGS.items():
        if not db.get(AppSettings, key):
            db.add(AppSettings(key=key, value=value))
    db.commit()


def _setup_complete(db) -> bool:
    row = db.get(AppSettings, "setup_complete")
    return row is not None and row.value == "true"


# Lifespan (startup / shutdown)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    # Create all tables (idempotent on restart)
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        _seed_defaults(db)

    # Start the APScheduler background jobs
    from clarinet.scheduler import start_scheduler
    start_scheduler()

    yield  # app runs here

    # Shutdown
    from clarinet.scheduler import stop_scheduler
    stop_scheduler()


# FastAPI app
app = FastAPI(
    title="Clarinet",
    description="Home & small-office network monitor and manager",
    version="1.0.0",
    lifespan=lifespan,
    # Hide /docs on production
    docs_url="/api/docs" if settings.APP_ENV == "development" else None,
    redoc_url=None,
)

# Signed HttpOnly session cookie
# max_age=0 → session cookie (expires when browser closes)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="clarinet_session",
    max_age=settings.SESSION_IDLE_MINUTES * 60,
    https_only=False,   # set True behind Caddy HTTPS in production
    same_site="lax",
)

# Serve Bootstrap 5, Bootstrap Icons, Chart.js from /static/
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Routers
import importlib
import pkgutil

from clarinet import routers as _routers_pkg

# Every module in clarinet/routers/ that defines `router` is registered, so a
# new feature only needs to drop its router file there.
for _mod in sorted(pkgutil.iter_modules(_routers_pkg.__path__), key=lambda m: m.name):
    _router = getattr(importlib.import_module(f"{_routers_pkg.__name__}.{_mod.name}"), "router", None)
    if _router is not None:
        app.include_router(_router)
