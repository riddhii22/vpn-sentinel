"""Step 2: parse_ikev1_sa / parse_ikev2_sa vs Wireshark on shipped samples."""

from pathlib import Path

from app.analyzer.ike import parse_ikev1_sa, parse_ikev2_sa
from scapy.all import rdpcap
from scapy.layers.isakmp import ISAKMP

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _first_ike(path):
    for packet in rdpcap(str(path)):
        if packet.haslayer(ISAKMP):
            return bytes(packet[ISAKMP])
    raise AssertionError(f"no ISAKMP in {path}")


def test_parse_ikev1_sa_matches_wireshark_sample():
    parsed = parse_ikev1_sa(_first_ike(SAMPLES / "IKEv1.pcap"))
    assert parsed["encryption"] == "AES-CBC"
    assert parsed["encryption_id"] == 7
    assert parsed["key_length"] == 256
    assert parsed["dh_group"] == 20
    assert parsed["auth_method"] == "PSK"
    assert parsed["hash"] == "SHA2-512"


def test_parse_ikev2_sa_matches_confirmed_layout():
    """samples/IKEv2.pcap packet 1 — user-confirmed Wireshark decode."""
    parsed = parse_ikev2_sa(_first_ike(SAMPLES / "IKEv2.pcap"))
    assert parsed["encryption_id"] == 12
    assert parsed["key_length"] == 256
    assert parsed["encryption"] == "AES-CBC-256"
    assert parsed["prf"] == "HMAC-SHA2-512"
    assert parsed["integrity"] == "HMAC-SHA2-512-256"
    assert parsed["dh_group"] == 20
    assert parsed["auth_method"] is None


def test_ikev1_des_fixture():
    parsed = parse_ikev1_sa(_first_ike(FIXTURES / "lab_ikev1_des_dh2.pcap"))
    assert parsed["encryption"] == "DES"
    assert parsed["dh_group"] == 2


def test_shared_8001_hunter_is_wrong_on_ikev2():
    raw = _first_ike(SAMPLES / "IKEv2.pcap")
    idx = raw.find(b"\x80\x01")
    parsed = parse_ikev2_sa(raw)
    assert parsed["encryption_id"] == 12
    if idx != -1:
        fake_id = int.from_bytes(raw[idx + 2 : idx + 4], "big")
        assert fake_id != parsed["encryption_id"]
