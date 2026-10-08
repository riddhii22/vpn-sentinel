from app.analyzer.evidence import index_findings


def test_evidence_index_is_capped_and_tied_to_findings():
    findings = [
        {
            "id": "IKE-001",
            "title": "IKEv1 Detected",
            "severity": "critical",
            "evidence": [
                {"packet_number": i, "source": "a", "destination": "b", "protocol": "ISAKMP"}
                for i in range(200)
            ],
        }
    ]
    rows = index_findings(findings, limit=80)
    assert len(rows) == 80
    assert rows[0]["finding_id"] == "IKE-001"
    assert rows[0]["packet_number"] == 0


def test_evidence_index_empty_when_none():
    assert index_findings([]) == []
