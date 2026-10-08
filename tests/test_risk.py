"""Phase 3: VPN Sentinel Risk Score from findings only."""

from app.risk import assess, level_for, sort_findings


def test_no_findings_is_zero_low():
    risk = assess([])
    assert risk["score"] == 0
    assert risk["level"] == "low"
    assert risk["contributors"] == []
    assert risk["severity_counts"]["critical"] == 0


def test_informational_does_not_add_risk():
    findings = [
        {"id": "IKE-002", "title": "IKEv2", "severity": "info", "score": 0, "evidence": []},
    ]
    risk = assess(findings)
    assert risk["score"] == 0
    assert risk["level"] == "low"
    assert risk["contributors"][0]["points"] == 0


def test_single_critical_ikev1_weight():
    findings = [
        {
            "id": "IKE-001",
            "title": "IKEv1 Detected",
            "severity": "critical",
            "score": 30,
            "evidence": [{"packet_number": 15}],
            "recommendation": "Migrate to IKEv2.",
        }
    ]
    risk = assess(findings)
    assert risk["score"] == 30
    assert risk["level"] == "moderate"
    assert risk["contributors"][0]["finding_id"] == "IKE-001"
    assert risk["contributors"][0]["points"] == 30
    assert risk["contributors"][0]["evidence_packets"] == [15]
    assert risk["severity_counts"]["critical"] == 1


def test_multiple_findings_sum_and_clamp():
    findings = [
        {"id": "A", "title": "a", "severity": "critical", "score": 30, "evidence": []},
        {"id": "B", "title": "b", "severity": "high", "score": 20, "evidence": []},
        {"id": "C", "title": "c", "severity": "info", "score": 0, "evidence": []},
    ]
    risk = assess(findings)
    assert risk["score"] == 50
    assert risk["level"] == "moderate"
    assert sum(c["points"] for c in risk["contributors"]) == 50


def test_clamp_at_100():
    findings = [{"id": "X", "title": "x", "severity": "critical", "score": 80, "evidence": []}]
    findings *= 3
    for i, f in enumerate(findings):
        findings[i] = {**f, "id": f"X{i}"}
    risk = assess(findings)
    assert risk["score"] == 100


def test_determinism():
    findings = [
        {"id": "B", "title": "b", "severity": "high", "score": 20, "evidence": []},
        {"id": "A", "title": "a", "severity": "critical", "score": 30, "evidence": []},
    ]
    assert assess(findings) == assess(list(reversed(findings)))


def test_ordering_critical_before_info():
    findings = [
        {"id": "IKE-002", "title": "v2", "severity": "info", "score": 0, "evidence": []},
        {"id": "IKE-001", "title": "v1", "severity": "critical", "score": 30, "evidence": []},
    ]
    ordered = sort_findings(findings)
    assert ordered[0]["id"] == "IKE-001"
    assert ordered[1]["id"] == "IKE-002"


def test_every_contributor_maps_to_finding():
    findings = [
        {"id": "IKE-001", "title": "v1", "severity": "critical", "score": 30, "evidence": []},
    ]
    ids = {c["finding_id"] for c in assess(findings)["contributors"]}
    assert ids == {"IKE-001"}


def test_html_report_escapes_filename():
    from app.risk.report import build_report

    analysis = {
        "file_name": "<script>alert(1)</script>.pcap",
        "packet_count": 0,
        "capture": {},
        "ike": {"version": {"value": "n/a"}},
        "findings": [],
        "risk": {"score": 0, "level": "low", "equation": "min(100, 0) = 0", "contributors": []},
        "security_summary": {"why": "none", "most_important_action": "n/a"},
        "limitations": [],
        "summary": {},
    }
    html = build_report(analysis)["html"]
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_level_boundaries():
    assert level_for(0) == "low"
    assert level_for(29) == "low"
    assert level_for(30) == "moderate"
    assert level_for(60) == "high"
    assert level_for(80) == "critical"
