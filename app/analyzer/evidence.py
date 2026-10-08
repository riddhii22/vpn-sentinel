"""Cap and flatten finding evidence for the API. Does not invent packets."""

from __future__ import annotations

MAX_EVIDENCE_ROWS = 80


def index_findings(findings: list[dict], limit: int = MAX_EVIDENCE_ROWS) -> list[dict]:
    """Flatten evidence already attached to findings. Empty if none exist."""
    rows: list[dict] = []
    for finding in findings:
        for item in finding.get("evidence") or []:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "finding_id": finding.get("id"),
                    "finding_title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "packet_number": item.get("packet_number"),
                    "timestamp": item.get("timestamp"),
                    "source": item.get("source"),
                    "destination": item.get("destination"),
                    "protocol": item.get("protocol"),
                    "note": item.get("note") or "",
                }
            )
            if len(rows) >= limit:
                return rows
    return rows
