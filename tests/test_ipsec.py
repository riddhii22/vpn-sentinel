from pathlib import Path

from app.analyzer.ipsec import analyze_ipsec
from scapy.all import rdpcap

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_sample_esp_and_udp500():
    packets = rdpcap(str(SAMPLES / "IKEv1.pcap"))
    result = analyze_ipsec(packets)
    assert result["esp_packets"] == 296
    assert result["ike_udp_500"] == 13
    assert result["natt_udp_4500"] == 0
    assert result["ah_packets"] == 0


def test_natt_fixture():
    packets = rdpcap(str(FIXTURES / "lab_natt_esp.pcap"))
    result = analyze_ipsec(packets)
    assert result["natt_udp_4500"] == 1
    assert result["esp_packets"] == 1


def test_ah_fixture():
    packets = rdpcap(str(SAMPLES / "IKEv2.pcap"))
    # production sample has no AH
    assert analyze_ipsec(packets)["ah_packets"] == 0
    lab = analyze_ipsec(rdpcap(str(FIXTURES / "lab_ah.pcap")))
    assert lab["ah_packets"] == 1
