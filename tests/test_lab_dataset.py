from pathlib import Path

from app.analyzer import analyze_packets
from scapy.all import rdpcap

DATASET = Path(__file__).resolve().parent.parent / "dataset"
LABELS = DATASET / "labels.csv"


def test_labels_csv_lists_day2_configs():
    text = LABELS.read_text(encoding="utf-8")
    for token in ("C2,ping", "C7,ping", "C8,ping", "C10,ping", "C1,web"):
        assert token in text


def test_c10_lab_pcap_is_ikev1_and_flags_weak_dh():
    pcap = DATASET / "C10" / "ping.pcap"
    result = analyze_packets(rdpcap(str(pcap)), "C10-ping.pcap")
    ids = {f["id"] for f in result["findings"]}
    assert result["vpn_analysis"]["ike_version"] == "IKEv1"
    assert "IKE-001" in ids
    assert "DH-001" in ids


def test_c8_lab_pcap_flags_3des():
    pcap = DATASET / "C8" / "ping.pcap"
    result = analyze_packets(rdpcap(str(pcap)), "C8-ping.pcap")
    ids = {f["id"] for f in result["findings"]}
    assert "ENC-001" in ids
    assert "DH-001" in ids
