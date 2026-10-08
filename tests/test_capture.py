from pathlib import Path

from app.analyzer.capture import inventory_packets
from scapy.all import rdpcap

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_ikev1_sample_packet_count_and_esp():
    packets = rdpcap(str(SAMPLES / "IKEv1.pcap"))
    inv = inventory_packets(packets)
    assert inv["packet_count"] == 309
    assert inv["protocols"]["esp"] == 296
    assert inv["protocols"]["udp_500_ike"] == 13
    assert inv["address_families"]["ipv6_packets"] == 309


def test_ikev2_sample_counts():
    packets = rdpcap(str(SAMPLES / "IKEv2.pcap"))
    inv = inventory_packets(packets)
    assert inv["packet_count"] == 197
    assert inv["protocols"]["esp"] == 162
    assert inv["protocols"]["ike_isakmp"] == 35


def test_ah_fixture_counts_ah_not_esp():
    packets = rdpcap(str(FIXTURES / "lab_ah.pcap"))
    inv = inventory_packets(packets)
    assert inv["protocols"]["ah"] == 1
    assert inv["protocols"]["esp"] == 0
