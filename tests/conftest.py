"""
tests/conftest.py
Runs before any test module imports clarinet, so the whole test session uses a
throw-away SQLite file and never touches the real clarinet.db.
"""

import os
import sys
import tempfile
from pathlib import Path

_test_db = Path(tempfile.mkdtemp(prefix="clarinet_test_")) / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_test_db.as_posix()}"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["APP_ENV"] = "test"
os.environ["CLARINET_NO_AUTODETECT"] = "1"      # results must not depend on the computer running the tests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests._support import trusted_proxy  # noqa: E402,F401  (fixture shared by every folder)
