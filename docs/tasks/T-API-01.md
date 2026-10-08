# T-API-01 — Harden `/analyze`

**Status:** Implemented this phase (awaiting your acceptance)

## Goal

Make PCAP upload safe and honest without changing IKE detection logic or scoring weights.

## Allowlist used

- `app/main.py` (upload/CORS/temp-file only)
- `tests/test_analyze_upload.py`
- `docs/evidence/T-API-01.md`, board, traceability

## Must not (kept)

- Policy engine, IsolationForest, dashboard, score 30/20 unchanged, no ESP decrypt
