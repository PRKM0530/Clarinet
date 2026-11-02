# tests/member/ISSUES.md

## Member privacy issues

All four issues originally tracked here (S-01 to S-04) were placeholder tests that
could not fail, so they proved nothing. They have been replaced by
`test_member_privacy.py`, which logs in as a member and requests the real pages
and APIs. That audit found, and the code now fixes:

| What leaked to a member | Fixed in |
|---|---|
| Other members' devices and usage on `/dashboard` | `routers/dashboard.py` |
| Every alert (including security alerts) on `/alerts`, `/api/v1/alerts`, `/api/status/topbar` and the dashboard | `core_svc/permissions.visible_alerts` |
| Network-wide device counts in `/api/devices/summary` | `routers/alerts.py` |

Any page or API that lists alerts must start from `visible_alerts(db, user)`.
