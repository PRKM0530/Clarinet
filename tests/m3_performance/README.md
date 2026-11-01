# tests/m3_performance/README.md

## M3 Performance Tests

Tests for M3 (slowdown detection, diagnosis, baseline, early warning) owned by **Om Prakash (M3)**.

### Coverage

| File | Tests |
|------|-------|
| `test_baseline.py` | `rebuild_all`, `latency_is_elevated`, outlier rejection |
| `test_diagnosis.py` | AT-09.x — fake pings → slowdown / outage / no-event, 2-min hold |
| `test_early_warning.py` | trend detection, threshold breach |
| `test_summary_api.py` | `slowdowns_between`, `build_summary`, `build_status`, contracts C-09/C-10 |
| `test_pinger.py` | non-privileged fallback, no global mutation |

### Running

```bash
# From repo root
pytest tests/m3_performance -v
```

### Findings fixed

| Finding | Description |
|---------|-------------|
| F-09 | Diagnosis: 2-min hold, SRS thresholds, outage vs slowdown |
| F-10 | Baseline from PingRecord (not SpeedTestResult), IQR outlier rejection |
| F-13 | Pinger: no global mutation, non-privileged fallback |
| F-14 | Jobs: IST timezone crons, early-warning job |
| F-15 | Slowdowns router: duration fix, no "AI-powered" |

