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
    SESSION_IDLE_MINUTES: int = 30

    model_config = {"env_file": BASE_DIR / ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Convenient module-level alias used throughout the project
settings = get_settings()
