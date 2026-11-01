# tests/m2_access

Tests for M2: guest vouchers, speed tests, time rules, priority grants.

## Run

```
python -m pytest tests/m2_access -q
```

Linux-lab tests (nft/tc) are marked `linux_lab` and skipped unless `CLARINET_LAB=1`.
