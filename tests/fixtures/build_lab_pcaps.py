"""Build labeled lab PCAPs for rule tests (not production traffic)."""

from pathlib import Path

from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import AH, ESP
from scapy.layers.isakmp import (
    ISAKMP,
    ISAKMP_payload_Proposal,
    ISAKMP_payload_SA,
    ISAKMP_payload_Transform,
)
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

OUT = Path(__file__).resolve().parent


def _ikev1_sa(enc_name: str, group: int, keylen: int | None = None):
    transforms = [
        ("LifeType", "Seconds"),
        ("LifeDuration", 28800),
        ("Encryption", enc_name),
        ("Authentication", "PSK"),
        ("Hash", "SHA"),
        ("GroupDesc", group),
    ]
    if keylen:
        transforms.insert(3, ("KeyLength", keylen))
    trans = ISAKMP_payload_Transform(
        transform_count=1,
        transform_id=1,
        transforms=transforms,
    )
    prop = ISAKMP_payload_Proposal(proposal=1, proto=1, trans_nb=1, trans=trans)
    sa = ISAKMP_payload_SA(doi=1, situation=1, prop=prop)
    ike = ISAKMP(
        init_cookie=b"\x11" * 8,
        resp_cookie=b"\x00" * 8,
        next_payload=1,
        version=0x10,
        exch_type=2,
        flags=0,
        id=0,
    )
    pkt = (
        Ether(dst="00:11:22:33:44:55", src="00:11:22:33:44:66")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / UDP(sport=500, dport=500)
        / ike
        / sa
    )
    return pkt


def main():
    des = _ikev1_sa("DES-CBC", 2)
    wrpcap(str(OUT / "lab_ikev1_des_dh2.pcap"), [des])

    ah = (
        Ether(dst="00:11:22:33:44:55", src="00:11:22:33:44:66")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / AH(spi=0x11111111, seq=1)
    )
    wrpcap(str(OUT / "lab_ah.pcap"), [ah])

    natt = (
        Ether(dst="00:11:22:33:44:55", src="00:11:22:33:44:66")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / UDP(sport=4500, dport=4500)
        / ESP(spi=0x22222222, seq=1, data=b"\x00" * 32)
    )
    wrpcap(str(OUT / "lab_natt_esp.pcap"), [natt])
    print("wrote lab fixtures to", OUT)


if __name__ == "__main__":
    main()
