# T-INFRA-01 — Engineering foundation

**Status:** Phase 1

## WHAT

UTF-8 `requirements.txt`, `app` as a package, pytest, `.gitignore`, Ruff config, GitHub Actions CI. Health test only.

## WHY

We cannot safely change `/analyze` later if imports and CI are unreliable.

## Allowlist

- `app/__init__.py`
- `requirements.txt` (encoding / comments / httpx for TestClient)
- `pyproject.toml`
- `tests/`
- `.gitignore`
- `.github/workflows/ci.yml`
- `README.md` (run instructions only; no fake features)

## Tests (required)

- App importable
- `GET /health` → 200 `{"status":"ok"}`

## Must not

Rewrite `main.py`. Policy engine, parser, ML, dashboard, Docker, StrongSwan.

## OWASP this task

No new endpoints. Do not “fix” CORS in this task (that is T-API-01). Do not add secrets.
