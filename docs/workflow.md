# Agent workflow (Cursor)

We do **not** run a custom multi-agent server. Orchestration is a **human + Cursor Cloud Agent** following this repo’s docs.

**Gates (required order):**

Requirements → Planning → Task card → Implementation → Independent testing → Security review → 5-axis review → QA → Documentation → Orchestrator acceptance

**Implementation never marks a task Accepted.** Only the Orchestrator (this session’s lead agent, or you) may move a card to Accepted after evidence exists.

## How to use Cursor here

1. Open the task card in `docs/tasks/` (status, file allowlist, tests, OWASP notes).
2. Implementation: edit only allowlisted files.
3. Testing: another pass (or a Testing subagent) checks whether tests would fail if the requirement were missing; run `pytest`.
4. Security + 5-axis: write a short note under `docs/evidence/<task-id>/` when we start collecting evidence (Phase 1 records reviews in the Phase 1 report).
5. You approve Critical/High waivers and the next task by name (e.g. `Start T-API-01.`).

## Subagent types (Cursor Task tool)

Use role files in this folder as the prompt for a subagent. Do not give Implementation write access to `REQUIREMENTS.md` meaning or to scoring weights unless the task card says so.

| Role file | Writes |
| --- | --- |
| `orchestrator.md` | `docs/tasks/board.md`, traceability status only |
| `planner.md` | ADRs, task cards |
| `implementation.md` | Allowlisted product code |
| `testing.md` | `tests/` |
| `security.md` | Evidence notes (no silent weakening) |
| `review.md` | Evidence notes only |
| `qa.md` | `docs/evidence/` |
| `documentation.md` | `README.md`, `docs/` |
