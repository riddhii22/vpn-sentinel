from pathlib import Path

from app.main import app
from fastapi.testclient import TestClient

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
client = TestClient(app)


def test_analyze_includes_risk_and_report():
    pcap = (SAMPLES / "IKEv1.pcap").read_bytes()
    res = client.post("/analyze", files={"file": ("IKEv1.pcap", pcap, "application/vnd.tcpdump.pcap")})
    assert res.status_code == 200
    body = res.json()
    assert body["risk"]["score"] == 30
    assert body["risk"]["level"] == "moderate"
    assert body["risk"]["contributors"][0]["finding_id"] == "IKE-001"
    assert "<html" in body["report"]["html"].lower()
    assert "VPN Sentinel" in body["report"]["html"]
    assert body["security_summary"]["security_status"] == "moderate"
    assert body["recommendations_prioritized"]["immediate"]
    assert body["traffic_analysis"]["model_available"] is False
    assert body["traffic_analysis"]["prediction"] is None
    assert body["traffic_analysis"]["features"]["packet_count"] == 309
    assert body["traffic_analysis"]["features"]["decrypts_payload"] is False
    assert body["traffic_analysis"]["features"]["protocol_distribution"]["esp"] == 296
    assert body["traffic_analysis"]["features"]["bytes_per_second"] is not None
    assert body["vpn_analysis"]["ike_version"] == "IKEv1"
    assert body["evidence_index"]
    assert body["risk"]["severity_counts"]["critical"] == 1
    assert body["risk"]["finding_count"] >= 1
    assert body["risk"]["score"] == 30


def test_analyze_ikev2_still_low_risk_with_features():
    pcap = (SAMPLES / "IKEv2.pcap").read_bytes()
    res = client.post("/analyze", files={"file": ("IKEv2.pcap", pcap, "application/vnd.tcpdump.pcap")})
    assert res.status_code == 200
    body = res.json()
    assert body["risk"]["score"] == 0
    assert body["risk"]["level"] == "low"
    assert body["traffic_analysis"]["model_available"] is False
    assert body["traffic_analysis"]["confidence"] is None
    assert body["traffic_analysis"]["features"]["packet_count"] == 197
    assert body["traffic_analysis"]["features"]["windows"]
