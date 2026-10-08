"""Print SA fields from sample pcaps using version-specific parsers.

  PYTHONPATH=. python test_parsing.py
"""

from pathlib import Path

from scapy.all import rdpcap
from scapy.layers.isakmp import ISAKMP

from app.analyzer.ike import parse_ikev1_sa, parse_ikev2_sa

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT / "samples"


def _major(raw: bytes) -> int | None:
    if len(raw) <= 17:
        return None
    return raw[17] >> 4


def show(label: str, path: Path) -> None:
    print(f"\n=== {label} ({path.name}) ===")
    if not path.is_file():
        print("missing file")
        return
    printed = 0
    for packet in rdpcap(str(path)):
        if not packet.haslayer(ISAKMP):
            continue
        raw = bytes(packet[ISAKMP])
        major = _major(raw)
        flags = str(getattr(packet[ISAKMP], "flags", "") or "")
        if "encrypt" in flags.lower():
            continue
        if major == 1:
            parsed = parse_ikev1_sa(raw)
        elif major == 2:
            parsed = parse_ikev2_sa(raw)
        else:
            continue
        if parsed.get("encryption") is None and parsed.get("dh_group") is None:
            continue
        print(
            f"packet major={major}  enc={parsed.get('encryption')}  "
            f"id={parsed.get('encryption_id')}  keylen={parsed.get('key_length')}  "
            f"dh={parsed.get('dh_group')}  auth={parsed.get('auth_method')}  "
            f"prf={parsed.get('prf')}  integ={parsed.get('integrity')}"
        )
        printed += 1
        if printed >= 3:
            break
    if printed == 0:
        print("no cleartext SA parsed")


if __name__ == "__main__":
    show("IKEv1", SAMPLES / "IKEv1.pcap")
    show("IKEv2", SAMPLES / "IKEv2.pcap")
