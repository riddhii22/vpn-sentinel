"""PCAP parsed once → facts → findings → risk → report."""

from __future__ import annotations

from datetime import datetime, timezone

from app.analyzer.capture import inventory_packets
from app.analyzer.evidence import index_findings
from app.analyzer.ike import analyze_ike
from app.analyzer.ipsec import analyze_ipsec
from app.analyzer.rules import evaluate, finding_from_esp_anomaly, limitations, recommendations_from
from app.analyzer.traffic import extract_traffic_features
from app.ml import predict_from_features
from app.ml.anomaly import analyze_esp_anomaly
from app.risk import assess, prioritize_recommendations, security_summary, threat_matrix
from app.risk.report import build_report


def analyze_packets(packets, file_name: str) -> dict:
    capture = inventory_packets(packets)
    ike = analyze_ike(packets)
    ipsec = analyze_ipsec(packets)
    traffic_features = extract_traffic_features(packets)
    traffic_analysis = predict_from_features(traffic_features)
    traffic_analysis["anomaly"] = analyze_esp_anomaly(packets)
    findings = evaluate(ike, ipsec)
    ml_finding = finding_from_esp_anomaly(traffic_analysis["anomaly"])
    if ml_finding:
        findings.append(ml_finding)
    risk = assess(findings)
    prioritized = prioritize_recommendations(findings)
    evidence_index = index_findings(findings)
    analyzed_at = datetime.now(timezone.utc).isoformat()
    result = {
        "file_name": file_name,
        "packet_count": capture["packet_count"],
        "analyzed_at": analyzed_at,
        "capture": capture,
        "ike": {
            "present": ike["present"],
            "version": ike["version"],
            "ikev1_packet_count": ike["ikev1_packet_count"],
            "ikev2_packet_count": ike["ikev2_packet_count"],
            "exchange_types": ike["exchange_types"],
            "encrypted_ike_packets": ike["encrypted_ike_packets"],
            "messages": ike["messages"],
        },
        "ipsec": ipsec,
        "security_parameters": ike.get("parameters") or {},
        "vpn_analysis": {
            "ike_version": (ike.get("version") or {}).get("value"),
            "ike": {
                "present": ike["present"],
                "version": ike["version"],
                "exchange_types": ike["exchange_types"],
            },
            "ipsec": {
                "esp_packets": ipsec["esp_packets"],
                "ah_packets": ipsec["ah_packets"],
                "udp_500": ipsec["ike_udp_500"],
                "udp_4500": ipsec["natt_udp_4500"],
                "natt_present": ipsec["natt_present"],
            },
            "security_parameters": ike.get("parameters") or {},
        },
        "findings": findings,
        "threat_matrix": threat_matrix(findings),
        "risk": risk,
        "security_summary": security_summary(findings, risk),
        "recommendations": recommendations_from(findings),
        "recommendations_prioritized": prioritized,
        "evidence": ike.get("evidence") or {"ikev1": [], "ikev2": []},
        "evidence_index": evidence_index,
        "limitations": limitations(),
        "summary": {
            "udp_500_packets": ipsec["ike_udp_500"],
            "udp_4500_packets": ipsec["natt_udp_4500"],
            "esp_packets": ipsec["esp_packets"],
            "ah_packets": ipsec["ah_packets"],
            "ikev1_packets": ike["ikev1_packet_count"],
            "ikev2_packets": ike["ikev2_packet_count"],
        },
        "pcap": {"file_name": file_name, "packet_count": capture["packet_count"]},
        "overview": {
            "ike_version": (ike.get("version") or {}).get("value"),
            "risk_preview": None,
        },
        "protocols": capture.get("protocols"),
        "traffic_analysis": traffic_analysis,
    }
    result["overview"]["risk_preview"] = result["risk"]["score"]
    result["report"] = build_report(result)
    return result
