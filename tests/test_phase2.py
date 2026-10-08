"""Phase 2 DoD: distinct findings and scores on the two shipped samples."""

from pathlib import Path

from app.analyzer import analyze_packets
from scapy.all import rdpcap

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _run(name: str) -> dict:
    return analyze_packets(rdpcap(str(SAMPLES / name)), name)


def test_phase2_ikev1_and_ikev2_differ():
    v1 = _run("IKEv1.pcap")
    v2 = _run("IKEv2.pcap")
    ids1 = {f["id"] for f in v1["findings"]}
    ids2 = {f["id"] for f in v2["findings"]}

    assert "IKE-001" in ids1
    assert "IKE-002" not in ids1
    assert v1["risk"]["score"] == 30
    assert v1["risk"]["level"] == "moderate"

    assert "IKE-002" in ids2
    assert "IKE-001" not in ids2
    assert v2["risk"]["score"] == 0
    assert v2["risk"]["level"] == "low"

    assert ids1 != ids2
    assert v1["risk"]["score"] != v2["risk"]["score"]

    # Wireshark packet 1: Life-Duration 28800 — under 24h, so LIFE-001 stays off.
    life = v1["security_parameters"]["lifetime_seconds"]
    assert life["status"] == "detected"
    assert life["value"] == 28800
    assert "LIFE-001" not in ids1

    # AES-256, DH 20 — not weak.
    assert "ENC-001" not in ids1
    assert "DH-001" not in ids1
    assert "ENC-002" in ids1

    for row in (v1, v2):
        assert row["security_parameters"]["pfs"]["status"] == "not_detected"
        assert row["security_parameters"]["mode"]["status"] == "not_detected"
        assert "PFS-001" not in {f["id"] for f in row["findings"]}
        assert "MODE-001" not in {f["id"] for f in row["findings"]}
