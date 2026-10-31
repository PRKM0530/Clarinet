"""
run.py – entry point for development.
Production: sudo uvicorn clarinet:app --host 0.0.0.0 --port 8000 --workers 1
(single worker keeps SQLite WAL safe; swap for Postgres if you want multi-worker)
"""

import uvicorn
from clarinet.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "clarinet:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.APP_ENV == "development",
        log_level="info",
    )
