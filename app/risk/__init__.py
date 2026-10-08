"""VPN Sentinel Risk Score: additive, deterministic, from findings only."""

from __future__ import annotations

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}

# Existing bands from the previous calculate_risk() helper (higher = riskier).
# REQUIREMENTS.md: 0–100, higher = riskier. PPT 100−penalty formula is not used
# because it conflicts with that definition.
BANDS = (
    (80, "critical"),
    (60, "high"),
    (30, "moderate"),
    (0, "low"),
)

FORMULA_NAME = "VPN Sentinel Risk Score"
FORMULA_DOC = (
    "min(100, sum of finding.score from policies/rules.yaml). "
    "Informational findings use score 0. Not an industry CVSS."
)


def level_for(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "low"


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK.get(str(f.get("severity", "info")).lower(), 9), f.get("id", "")),
    )


def assess(findings: list[dict]) -> dict:
    ordered = sort_findings(findings)
    contributors = []
    total = 0
    for finding in ordered:
        points = int(finding.get("score") or 0)
        total += points
        contributors.append(
            {
                "finding_id": finding.get("id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "points": points,
                "evidence_packets": [
                    e.get("packet_number")
                    for e in (finding.get("evidence") or [])
                    if isinstance(e, dict) and "packet_number" in e
                ],
                "recommendation": finding.get("recommendation"),
            }
        )
    score = min(100, max(0, total))
    equation = " + ".join(str(c["points"]) for c in contributors) if contributors else "0"
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in ordered:
        sev = str(finding.get("severity", "info")).lower()
        if sev == "informational":
            sev = "info"
        if sev in severity_counts:
            severity_counts[sev] += 1
    return {
        "name": FORMULA_NAME,
        "score": score,
        "level": level_for(score),
        "formula": FORMULA_DOC,
        "equation": f"min(100, {equation}) = {score}",
        "contributors": contributors,
        "finding_count": len(ordered),
        "penalty_finding_count": sum(1 for f in ordered if int(f.get("score") or 0) > 0),
        "severity_counts": severity_counts,
        "bands": {
            "critical": "80-100",
            "high": "60-79",
            "moderate": "30-59",
            "low": "0-29",
        },
    }


def threat_matrix(findings: list[dict]) -> list[dict]:
    grouped: dict[str, list] = {}
    for finding in sort_findings(findings):
        if str(finding.get("origin") or "") == "ml_anomaly":
            continue
        sev = str(finding.get("severity", "info")).lower()
        grouped.setdefault(sev, []).append(
            {"id": finding.get("id"), "title": finding.get("title")}
        )
    order = ["critical", "high", "medium", "low", "info"]
    return [{"severity": s, "findings": grouped[s]} for s in order if s in grouped]


def security_summary(findings: list[dict], risk: dict) -> dict:
    actionable = [f for f in sort_findings(findings) if int(f.get("score") or 0) > 0]
    if not actionable:
        why = "No penalty findings were raised from observable IKE/IPsec fields in this capture."
        action = "Keep reviewing cipher policy; absence of a finding is not a proof of a perfect VPN."
        status = risk["level"]
    else:
        top = actionable[0]
        why = top.get("reason") or top.get("title")
        action = top.get("recommendation") or "Review the highest-severity finding."
        status = risk["level"]
    return {
        "security_status": status,
        "why": why,
        "most_important_action": action,
        "penalty_finding_count": len(actionable),
    }


def prioritize_recommendations(findings: list[dict]) -> dict:
    buckets = {"immediate": [], "recommended": [], "informational": []}
    for finding in sort_findings(findings):
        rec = finding.get("recommendation")
        if not rec:
            continue
        sev = str(finding.get("severity", "info")).lower()
        item = {
            "finding_id": finding.get("id"),
            "severity": finding.get("severity"),
            "recommendation": rec,
        }
        if sev in ("critical", "high"):
            buckets["immediate"].append(item)
        elif sev in ("medium", "low"):
            buckets["recommended"].append(item)
        else:
            buckets["informational"].append(item)
    return buckets
