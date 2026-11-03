"""Starts the real Clarinet app with debug logging so swallowed errors are visible. Used by test_full_app.py."""
import logging
import os
import sys

import uvicorn

sys.path.insert(0, os.getcwd())
logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s %(message)s", stream=sys.stderr)
logging.getLogger("clarinet").setLevel(logging.DEBUG)
logging.getLogger("apscheduler").setLevel(logging.INFO)
uvicorn.run("clarinet:app", host="0.0.0.0", port=int(os.environ.get("APP_PORT", "8765")), log_level="warning")
