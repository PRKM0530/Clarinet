"""
clarinet/routers/reports.py
Daily and weekly reports are the Usage page with a different period, so the old address forwards there.
"""
from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter(tags=["reports"])


@router.get("/reports")
def reports_page(view: str = "week"):
    return RedirectResponse(url="/usage?period=" + ("today" if view == "day" else "week"), status_code=301)
