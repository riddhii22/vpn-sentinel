from pathlib import Path

from app.analyzer import analyze_packets
from app.analyzer.rules import recommendations_from
from scapy.all import rdpcap

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_ikev1_finding_and_recommendation():
    result = analyze_packets(rdpcap(str(SAMPLES / "IKEv1.pcap")), "capture.pcap")
    ids = {f["id"] for f in result["findings"]}
    assert "IKE-001" in ids
    assert "ENC-001" not in ids  # sample uses AES-256, not DES
    recs = recommendations_from(result["findings"])
    assert any("IKEv2" in r["recommendation"] for r in recs)
    ev = result["findings"][0]["evidence"]
    assert ev and ev[0]["packet_number"] >= 1


def test_ikev2_info_finding():
    result = analyze_packets(rdpcap(str(SAMPLES / "IKEv2.pcap")), "x.pcap")
    ids = {f["id"] for f in result["findings"]}
    assert "IKE-002" in ids
    assert "IKE-001" not in ids


def test_des_and_weak_dh_rules_on_lab_fixture():
    result = analyze_packets(rdpcap(str(FIXTURES / "lab_ikev1_des_dh2.pcap")), "lab.pcap")
    ids = {f["id"] for f in result["findings"]}
    assert "IKE-001" in ids
    assert "ENC-001" in ids
    assert "DH-001" in ids
    recs = {r["finding_id"]: r["recommendation"] for r in result["recommendations"]}
    assert "AES" in recs["ENC-001"]
    assert "DH" in recs["DH-001"]
    assert "HASH-001" in ids


def test_pfs_not_invented_on_samples():
    result = analyze_packets(rdpcap(str(SAMPLES / "IKEv1.pcap")), "c.pcap")
    assert result["security_parameters"]["pfs"]["status"] == "not_detected"
    assert result["security_parameters"]["replay_protection"]["status"] == "not_detected"
    assert "PFS-001" not in {f["id"] for f in result["findings"]}


def test_aes_cbc_256_from_real_ikev1_pcap():
    result = analyze_packets(rdpcap(str(SAMPLES / "IKEv1.pcap")), "IKEv1.pcap")
    enc = result["security_parameters"]["encryption"]
    assert enc["status"] == "detected"
    assert enc["value"] == "AES-CBC-256"
    assert result["security_parameters"]["dh_group"]["value"] == 20
    ids = {f["id"] for f in result["findings"]}
    assert "ENC-002" in ids
    assert "ENC-005" in ids
    assert "ENC-004" not in ids
    assert "LIFE-001" not in ids
    assert "ENC-001" not in ids
    cbc = next(f for f in result["findings"] if f["id"] == "ENC-002")
    assert cbc["rule_id"] == "ENC-002"
    assert "AES-CBC" in str(cbc["detected_value"])
    assert cbc["score"] == 0
    assert result["risk"]["score"] == 30


def test_filename_does_not_decide_version():
    data = analyze_packets(rdpcap(str(SAMPLES / "IKEv2.pcap")), "IKEv1.pcap")
    assert data["ike"]["version"]["value"] == "IKEv2"
