# T-INFRA-00 — Repository integration

**Status:** Phase 1 (complete when this workspace contains vpn-sentinel product files + REQUIREMENTS.md)

## WHAT

Use **this workspace** as the product tree: GitHub `vpn-sentinel` code (`app/`, `samples/`, `policies/`, `requirements.txt`) plus `REQUIREMENTS.md` and workflow docs.

## WHY

Two copies cause drift. Judges and CI need one tree.

## Allowlist

- Copy product files from GitHub vpn-sentinel
- Preserve `REQUIREMENTS.md`
- Do not rewrite `app/main.py`

## Tests

Workspace contains original `app/main.py` (health + analyze as upstream). pytest health tests land in T-INFRA-01.

## Acceptance

- [x] Product sources present (`app/main.py`, `samples/`, `policies/`)
- [x] `REQUIREMENTS.md` retained
- [x] Premature dashboard scaffold not kept as “the product UI”
- [x] Original analyzer logic not replaced in this task
