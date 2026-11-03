"""
clarinet/config.py
Centralised settings loaded from .env (or environment variables).
"""

from functools import lru_cache
from pydantic_settings import BaseSettings   # pip install pydantic-settings
from pathlib import Path

# Project root (the app/ directory)
BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    # Security
    SECRET_KEY: str = "change-me"

    # Database
    DATABASE_URL: str = f"sqlite:///{BASE_DIR}/clarinet.db"

    # App
    APP_ENV: str = "development"
    APP_HOST: str = "127.0.0.1"
    APP_PORT: int = 8000

    # Network
    NETWORK_INTERFACE: str = "eth0"
    NETWORK_MODE: str = "MONITOR"

    # ISP plan
    PLAN_DOWNLOAD_MBPS: float = 100.0
    PLAN_UPLOAD_MBPS: float = 20.0
    BILLING_DAY: int = 1

    # Thresholds
    SLOWDOWN_LATENCY_MULTIPLIER: float = 3.0
    SLOWDOWN_SPEED_THRESHOLD: float = 0.70
    ALERT_LOCKOUT_ATTEMPTS: int = 5
    ALERT_LOCKOUT_MINUTES: int = 5
    # Addresses of reverse proxies (for example Caddy) whose X-Forwarded-For header may be believed
    TRUSTED_PROXIES: str = "127.0.0.1,::1"
    # Send the session cookie only over HTTPS (set true when serving through Caddy)
    COOKIE_SECURE: bool = False
    SESSION_IDLE_MINUTES: int = 30

    model_config = {"env_file": BASE_DIR / ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


UNSAFE_SECRET_KEYS = {"", "change-me", "changeme", "secret"}


def check_secret_key(cfg: "Settings | None" = None) -> str | None:
    """The session cookie is signed with SECRET_KEY, so anyone who knows it can forge a login.
    Production refuses to start with the example value (RuntimeError); development returns a warning text."""
    cfg = cfg or get_settings()
    if cfg.SECRET_KEY.strip().lower() not in UNSAFE_SECRET_KEYS:
        return None
    message = ("SECRET_KEY is still the example value. Generate one with: "
               "python -c \"import secrets; print(secrets.token_hex(32))\" and put it in .env")
    if cfg.APP_ENV.lower() == "production":
        raise RuntimeError(message)
    return message


# Convenient module-level alias used throughout the project
settings = get_settings()
