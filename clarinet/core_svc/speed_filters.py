"""
clarinet/core_svc/speed_filters.py
A speed test that could not run (no tool installed, tool crashed) is stored as a row with
server_host == "failed" so the history page can show it. It carries no speed information, so
anything that reasons about speed must leave it out.
"""
from sqlalchemy import or_

from clarinet.models import SpeedTestResult

FAILED_SERVER = "failed"


def valid_only(query):
    """Restrict a SpeedTestResult query to tests that actually measured something."""
    return query.filter(or_(SpeedTestResult.server_host.is_(None), SpeedTestResult.server_host != FAILED_SERVER))
