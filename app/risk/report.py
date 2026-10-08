"""Human-readable report from an already-computed analysis dict (no second parse)."""

from __future__ import annotations

import html


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def build_report(analysis: dict) -> dict:
    """JSON-serializable report plus escaped HTML. Does not write to disk."""
    risk = analysis.get("risk") or {}
    findings = analysis.get("findings") or []
    capture = analysis.get("capture") or {}
    ike = analysis.get("ike") or {}
    params = analysis.get("security_parameters") or {}
    summary = analysis.get("summary") or {}
    recs = analysis.get("recommendations_prioritized") or {}
    limits = analysis.get("limitations") or []

    traffic = analysis.get("traffic_analysis") or {}
    feat = traffic.get("features") or {}
    json_report = {
        "product": "VPN Sentinel",
        "team": "ENTROPY",
        "analyzed_at": analysis.get("analyzed_at"),
        "file_name": analysis.get("file_name"),
        "packet_count": analysis.get("packet_count"),
        "capture": capture,
        "ike": ike,
        "ipsec": analysis.get("ipsec"),
        "security_parameters": params,
        "findings": findings,
        "threat_matrix": analysis.get("threat_matrix"),
        "risk": risk,
        "security_summary": analysis.get("security_summary"),
        "recommendations": recs,
        "evidence": analysis.get("evidence"),
        "evidence_index": analysis.get("evidence_index"),
        "limitations": limits,
        "traffic_analysis": {
            "model_available": traffic.get("model_available"),
            "prediction": traffic.get("prediction"),
            "confidence": traffic.get("confidence"),
            "message": traffic.get("message"),
            "anomaly": traffic.get("anomaly"),
            "packet_count": feat.get("packet_count"),
            "avg_packet_size": feat.get("avg_packet_size"),
            "packets_per_second": feat.get("packets_per_second"),
            "bytes_per_second": feat.get("bytes_per_second"),
        },
    }

    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{_e(finding.get('id'))}</td>"
            f"<td>{_e(finding.get('title'))}</td>"
            f"<td>{_e(finding.get('severity'))}</td>"
            f"<td>{_e(finding.get('score'))}</td>"
            f"<td>{_e(finding.get('recommendation'))}</td>"
            "</tr>"
        )

    contrib = []
    for c in risk.get("contributors") or []:
        contrib.append(
            f"<li>{_e(c.get('finding_id'))}: {_e(c.get('title'))} "
            f"({_e(c.get('severity'))}) → +{_e(c.get('points'))}</li>"
        )

    html_report = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>VPN Sentinel report — {_e(analysis.get("file_name"))}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #121314; color: #F3F4F6; }}
h1,h2 {{ font-weight: 600; color: #F3F4F6; }}
a {{ color: #E05A26; }}
table {{ border-collapse: collapse; width: 100%; }}
th,td {{ border: 1px solid #2D3139; padding: 0.4rem 0.6rem; text-align: left; }}
th {{ background: #1A1C1E; color: #8C92AC; }}
.muted {{ color: #8C92AC; }}
</style></head><body>
<h1>VPN Sentinel security report</h1>
<p class="muted">Team ENTROPY · PS 26160 · project-specific score, not CVSS
 · generated {_e(analysis.get("analyzed_at"))}</p>
<p><strong>Capture:</strong> {_e(analysis.get("file_name"))}
 ({_e(analysis.get("packet_count"))} packets)</p>
<p><strong>VPN Sentinel Risk Score:</strong> {_e(risk.get("score"))}/100
 ({_e(risk.get("level"))})</p>
<p>{_e(risk.get("equation"))}</p>
<p><strong>Why:</strong> {_e((analysis.get("security_summary") or {}).get("why"))}</p>
<p><strong>Most important action:</strong>
{_e((analysis.get("security_summary") or {}).get("most_important_action"))}</p>
<h2>IKE / IPsec</h2>
<p>IKE version: {_e((ike.get("version") or {}).get("value"))}
 · UDP/500: {_e(summary.get("udp_500_packets"))}
 · ESP: {_e(summary.get("esp_packets"))}
 · AH: {_e(summary.get("ah_packets"))}</p>
<p>Encryption: {_e((params.get("encryption") or {}).get("value"))}
 · Integrity: {_e((params.get("integrity") or {}).get("value"))}
 · DH: {_e((params.get("dh_group") or {}).get("value"))}
 · Lifetime: {_e((params.get("lifetime_seconds") or {}).get("value"))}</p>
<h2>Findings</h2>
<table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Points</th><th>Recommendation</th></tr></thead>
<tbody>{"".join(rows) or "<tr><td colspan='5'>No findings</td></tr>"}</tbody></table>
<h2>Score contributors</h2>
<ul>{"".join(contrib) or "<li>None</li>"}</ul>
<h2>Traffic intelligence (metadata)</h2>
<p>Packets: {_e(feat.get("packet_count"))}
 · avg size: {_e(feat.get("avg_packet_size"))} B
 · packets/s: {_e(feat.get("packets_per_second"))}</p>
<p>Traffic-type classification: {_e(traffic.get("message") or "unavailable")}</p>
<p>ESP IsolationForest: {_e(((traffic.get("anomaly") or {}).get("message")))}</p>
<p>ESP-ANOM flagged: {_e((traffic.get("anomaly") or {}).get("flagged"))}
 · does not change risk score
 · origin ml_anomaly</p>
<h2>Limitations</h2>
<ul>{"".join(f"<li>{_e(x)}</li>" for x in limits)}</ul>
</body></html>
"""
    return {"json": json_report, "html": html_report}
