"""
tests/guest/test_guest_audit.py
Guest-role audit: guests must never reach any dashboard route.
"""
import pytest

# Routes that guests (unauthenticated) must NEVER access.
# Acceptable responses: 302 (redirect to login), 401, 403, or 404 (route not yet registered by M1).
FORBIDDEN_ROUTES = [
    "/",
    "/dashboard",
    "/devices",
    "/alerts",
    "/usage",
    "/settings",
    "/vouchers",
    "/rules",
    "/speed",
    "/priority",
    "/slowdowns",
    "/security",
    "/export/devices.csv",
    "/api/devices/summary",
    "/speed/summary",        # M2 speed summary API
    "/rules/summary",        # M2 rules summary API
    "/api/guest/summary",    # M2 guest summary API
    "/priority/summary",     # M2 priority summary API
]


class TestGuestCannotAccessDashboard:
    @pytest.mark.parametrize("route", FORBIDDEN_ROUTES)
    def test_guest_cannot_reach_route(self, guest_client, route):
        """An unauthenticated guest must get a redirect, 401/403, or 404 — never 200 with data."""
        resp = guest_client.get(route, follow_redirects=False)
        assert resp.status_code in (302, 401, 403, 404), (
            f"Route {route} returned {resp.status_code} for unauthenticated user"
        )


class TestGuestPortalPublicRoutes:
    """Guest portal routes MUST be publicly accessible."""

    def test_guest_portal_is_public(self, guest_client):
        resp = guest_client.get("/guest")
        assert resp.status_code == 200

    def test_guest_redeem_is_public(self, guest_client):
        resp = guest_client.post("/guest/redeem", data={"code": "TESTCODE"})
        # Returns 200 with an error message (invalid code), not a redirect to login
        assert resp.status_code == 200
        assert "login" not in str(resp.url)


class TestGuestIssues:
    """
    Known issues discovered by guest audit.
    Tracked here; owners are M2 (guest routes) unless indicated.
    """
    # Add ISSUES.md entries here when found
    pass
