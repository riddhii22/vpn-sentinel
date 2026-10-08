from pathlib import Path

from app.analyzer.ike import analyze_ike
from scapy.all import rdpcap

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_detects_ikev1_from_headers_not_filename():
    packets = rdpcap(str(SAMPLES / "IKEv1.pcap"))
    result = analyze_ike(packets)
    assert result["version"]["value"] == "IKEv1"
    assert result["ikev1_packet_count"] == 13
    assert result["ikev2_packet_count"] == 0
    assert result["parameters"]["encryption"]["value"] == "AES-CBC-256"
    assert result["parameters"]["dh_group"]["value"] == 20
    assert result["parameters"]["integrity"]["value"] == "SHA2-512"
    assert result["parameters"]["pfs"]["status"] == "not_detected"
    assert result["parameters"]["mode"]["status"] == "not_detected"
    assert result["evidence"]["ikev1"][0]["packet_number"] == 1


def test_detects_ikev2_from_headers():
    packets = rdpcap(str(SAMPLES / "IKEv2.pcap"))
    result = analyze_ike(packets)
    assert result["version"]["value"] == "IKEv2"
    assert result["messages"][0]["source"]
    assert result["messages"][0]["destination"]
    assert result["messages"][0]["timestamp"]
    assert result["messages"][0]["exchange"]
    assert result["parameters"]["encryption"]["status"] == "detected"
    assert "AES-CBC-256" in str(result["parameters"]["encryption"]["value"])


def test_lab_des_and_weak_dh():
    packets = rdpcap(str(FIXTURES / "lab_ikev1_des_dh2.pcap"))
    result = analyze_ike(packets)
    assert result["version"]["value"] == "IKEv1"
    assert "DES" in str(result["parameters"]["encryption"]["value"])
    assert result["parameters"]["dh_group"]["value"] == 2
    assert result["weak_dh_observed"] == [2]
