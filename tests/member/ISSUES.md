# tests/member/ISSUES.md

## Known Cross-Member Privacy Issues

These are tracked as `xfail` tests until the owning milestone resolves them.

| ID | Description | Owner | Status |
|----|-------------|-------|--------|
| S-01 | Member can see all devices in `/devices` list (not filtered to their own) | M4 | `xfail` |
| S-02 | `/api/usage` endpoint returns all members' usage totals | M1 | `xfail` |
| S-03 | Audit log visible to non-admin members | M1 | `xfail` |
| S-04 | Priority grants list shows all members' pending requests | M4 | `xfail` |

### Ownership

- **S-01, S-04** → M4 (device list & priority scoping)
- **S-02, S-03** → M1 (usage API & audit log scoping)

These tests are marked `@pytest.mark.xfail(strict=False)` so CI stays green
until the owning milestone ships the fix. Remove the `xfail` marker when fixed.
