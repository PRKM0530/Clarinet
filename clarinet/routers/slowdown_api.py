"""
clarinet/routers/slowdown_api.py
The slowdown JSON endpoints at the paths the team agreed on (/api/slowdowns/...). The same handlers are also
served under /slowdowns/api/slowdowns/... for the existing page code.
"""
from fastapi import APIRouter

from clarinet.routers.slowdowns import slowdowns_status, slowdowns_summary

router = APIRouter(tags=["slowdowns"])
router.add_api_route("/api/slowdowns/summary", slowdowns_summary, methods=["GET"])
router.add_api_route("/api/slowdowns/status", slowdowns_status, methods=["GET"])
