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

import logging
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
def _page_context(request):
    """Variables every page can use: the network mode, and whether Full Control can really change the network."""
    mode = "MONITOR"
    try:
        from clarinet.enforcer.mode import get_mode
        with SessionLocal() as db:
            mode = get_mode(db)
    except Exception:
        pass
    problem = None
    if mode in ("FULL", "PUBLIC"):
        from clarinet.core_svc.enforcement_status import problem as _problem
        problem = _problem()
    return {"net_mode": mode, "enforcing": mode == "FULL", "quarantine": mode in ("FULL", "PUBLIC"),
            "enforce_problem": problem}


templates = Jinja2Templates(directory=str(TEMPLATES_DIR), context_processors=[_page_context])
from clarinet.core_svc.localtime import local_filter as _local_filter, zone_name as _zone_name  # noqa: E402
templates.env.filters["local"] = _local_filter
templates.env.globals["local_zone"] = _zone_name


def _size(num_bytes) -> str:
    """12345678 -> '11.8 MB'. Picks KB, MB, GB or TB so every page writes sizes the same way."""
    value = float(num_bytes or 0)
    for unit, step in (("B", 1024), ("KB", 1024), ("MB", 1024), ("GB", 1024)):
        if value < step:
            return f"{value:.0f} {unit}" if unit in ("B", "KB") else (f"{value:.1f} {unit}" if value < 100 else f"{value:.0f} {unit}")
        value /= step
    return f"{value:.1f} TB"


templates.env.filters["size"] = _size


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
    from clarinet.config import check_secret_key
    warning = check_secret_key()                       # raises in production when the key is the example value
    if warning:
        logging.getLogger("clarinet").warning(warning)
    # Create all tables (idempotent on restart)
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        _seed_defaults(db)

    # Background jobs raise alerts from threads; the websocket module needs the server's event loop to push them
    import asyncio
    from clarinet.routers.ws import set_event_loop
    set_event_loop(asyncio.get_running_loop())

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
    https_only=settings.COOKIE_SECURE,   # true when served over HTTPS (the install script's service sets it)
    same_site="lax",
)

# Refuse state-changing requests that a browser says came from another site (CSRF). The session cookie is
# SameSite=Lax, which already stops most cross-site POSTs; this checks the Origin header as a second layer.
from urllib.parse import urlparse
from fastapi import Request
from fastapi.responses import PlainTextResponse


@app.middleware("http")
async def refuse_cross_site_posts(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        fetch_site = request.headers.get("sec-fetch-site")
        if fetch_site == "cross-site" or (
            origin is not None and urlparse(origin).netloc != request.headers.get("host", "")
        ):
            return PlainTextResponse("Cross-site request refused.", status_code=403)
    return await call_next(request)


# Errors: a person gets a readable page with a way back; scripts and the JSON API keep a JSON body.
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

_ERROR_TEXT = {
    403: ("You cannot do that", "You do not have permission for this."),
    404: ("Page not found", "That page does not exist, or it was removed."),
    405: ("That is not allowed here", "This address cannot be used that way."),
    422: ("Some details were not right", "One of the boxes had a value the app could not use. Go back, check what you typed and try again."),
}


def _wants_json(request: Request) -> bool:
    path = request.url.path
    return path.startswith(("/api", "/slowdowns/api", "/speed/summary", "/rules/summary", "/priority/summary",
                            "/security/summary", "/ws")) or "text/html" not in request.headers.get("accept", "")


def _error_page(request: Request, status: int, fallback):
    from fastapi.responses import JSONResponse
    heading, message = _ERROR_TEXT.get(status, ("Something went wrong", "The app hit a problem. Try again, and tell the administrator if it keeps happening."))
    signed_in = bool(request.session.get("user_id")) if "session" in request.scope else False
    return templates.TemplateResponse("error.html", {
        "request": request, "heading": heading, "message": message,
        "home": "/dashboard" if signed_in else "/login", "home_label": "Dashboard" if signed_in else "Sign in",
    }, status_code=status)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    from fastapi.exception_handlers import http_exception_handler
    if _wants_json(request):
        return await http_exception_handler(request, exc)
    return _error_page(request, exc.status_code, exc)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    from fastapi.exception_handlers import request_validation_exception_handler
    if _wants_json(request):
        return await request_validation_exception_handler(request, exc)
    return _error_page(request, 422, exc)


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    import logging
    logging.getLogger("clarinet").exception("Unhandled error on %s", request.url.path)
    from fastapi.responses import PlainTextResponse
    if _wants_json(request):
        return PlainTextResponse("Internal Server Error", status_code=500)
    return _error_page(request, 500, exc)


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
