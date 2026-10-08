# Phase 3 — Risk assessment and reporting

## Scoring formula (VPN Sentinel Risk Score)

This is a **project-specific** metric, not CVSS.

```
score = min(100, sum(finding.score))
```

Weights come from `policies/rules.yaml` (already used in Phase 2):

| Finding | Severity | Points |
| --- | --- | --- |
| IKE-001 IKEv1 | critical | 30 |
| IKE-002 IKEv2 | info | 0 |
| ENC-001 DES/3DES | high | 20 |
| DH-001 weak DH | high | 20 |
| PFS-001 PFS off | high | 15 |

**Higher = riskier** (`REQUIREMENTS.md` SEC-06).

The SIH PPT formula `100 − (Critical×25 + Warning×10)` is **not** used here: leftover points would make a clean capture look like “high risk” if we also used the PPT 70–100 = HIGH band. We keep additive scoring that was already in the code.

**Bands** (same thresholds as the previous helper):

| Score | Level |
| --- | --- |
| 80–100 | critical |
| 60–79 | high |
| 30–59 | moderate |
| 0–29 | low |

IKEv1 alone = 30 → **moderate** overall, even though the finding severity is **critical**. Severity describes the issue class; the score is stacked penalties.

## IMPLEMENTED

- Dedicated `app/risk/` (not inside packet parsing)
- Explainable contributors + equation
- Prioritized findings and recommendations
- Threat matrix grouping
- JSON + escaped HTML report in `/analyze` (`report.json` / `report.html`)
- Limitations list from Phase 2

## PARTIALLY IMPLEMENTED

- Score only reflects **observable** findings (no PFS penalty on current samples)

## NOT IMPLEMENTED

Dashboard, ML, StrongSwan, Docker/K8s, PPT subtractive formula
