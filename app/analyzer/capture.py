"""Single-pass capture inventory. Does not decrypt payloads."""

from __future__ import annotations

from collections import Counter

from scapy.layers.isakmp import ISAKMP

from app.analyzer.models import EvidenceItem


def _addrs(packet) -> tuple[str, str]:
    if packet.haslayer("IP"):
        return packet["IP"].src, packet["IP"].dst
    if packet.haslayer("IPv6"):
        return packet["IPv6"].src, packet["IPv6"].dst
    return "unknown", "unknown"


def inventory_packets(packets) -> dict:
    layers: Counter[str] = Counter()
    udp_500 = 0
    udp_4500 = 0
    esp = 0
    ah = 0
    ike = 0
    other_udp = 0
    tcp = 0
    sizes: list[int] = []
    endpoints: Counter[tuple[str, str]] = Counter()
    times: list[str] = []

    for index, packet in enumerate(packets, start=1):
        sizes.append(len(packet))
        times.append(str(packet.time))
        src, dst = _addrs(packet)
        endpoints[(src, dst)] += 1

        if packet.haslayer("IP"):
            layers["IPv4"] += 1
        if packet.haslayer("IPv6"):
            layers["IPv6"] += 1
        if packet.haslayer("TCP"):
            tcp += 1
            layers["TCP"] += 1
        if packet.haslayer("ESP"):
            esp += 1
            layers["ESP"] += 1
        if packet.haslayer("AH"):
            ah += 1
            layers["AH"] += 1
        if packet.haslayer(ISAKMP):
            ike += 1
            layers["ISAKMP"] += 1

        if packet.haslayer("UDP"):
            sport = int(packet["UDP"].sport)
            dport = int(packet["UDP"].dport)
            layers["UDP"] += 1
            if sport == 500 or dport == 500:
                udp_500 += 1
            elif sport == 4500 or dport == 4500:
                udp_4500 += 1
            elif not packet.haslayer("ESP"):
                other_udp += 1

    mean_size = round(sum(sizes) / len(sizes), 1) if sizes else 0
    return {
        "packet_count": len(packets),
        "first_timestamp": times[0] if times else None,
        "last_timestamp": times[-1] if times else None,
        "address_families": {
            "ipv4_packets": layers.get("IPv4", 0),
            "ipv6_packets": layers.get("IPv6", 0),
        },
        "protocols": {
            "udp_500_ike": udp_500,
            "udp_4500_natt": udp_4500,
            "esp": esp,
            "ah": ah,
            "ike_isakmp": ike,
            "tcp": tcp,
            "other_udp": other_udp,
        },
        "packet_sizes": {
            "min": min(sizes) if sizes else 0,
            "max": max(sizes) if sizes else 0,
            "mean": mean_size,
        },
        "endpoints": [
            {"source": s, "destination": d, "packets": n}
            for (s, d), n in endpoints.most_common(16)
        ],
        "layers": dict(layers),
    }


def packet_endpoint(packet, index: int, protocol: str, note: str = "") -> EvidenceItem:
    src, dst = _addrs(packet)
    return EvidenceItem(
        packet_number=index,
        timestamp=str(packet.time),
        source=src,
        destination=dst,
        protocol=protocol,
        note=note,
    )
