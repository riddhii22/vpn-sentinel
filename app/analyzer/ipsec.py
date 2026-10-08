"""Observable IPsec traffic (ESP/AH/NAT-T) without decrypting ESP."""

from __future__ import annotations

from app.analyzer.models import NOT_DETECTED


def analyze_ipsec(packets) -> dict:
    esp = 0
    ah = 0
    udp_500 = 0
    udp_4500 = 0
    natt_ike = 0
    natt_esp = 0
    spis = set()
    examples = []

    for index, packet in enumerate(packets, start=1):
        if packet.haslayer("UDP"):
            sport = int(packet["UDP"].sport)
            dport = int(packet["UDP"].dport)
            if sport == 500 or dport == 500:
                udp_500 += 1
            if sport == 4500 or dport == 4500:
                udp_4500 += 1
                payload = bytes(packet["UDP"].payload) if packet["UDP"].payload else b""
                # RFC 3948: four zero bytes then IKE; otherwise ESP over UDP.
                if len(payload) >= 4 and payload[:4] == b"\x00\x00\x00\x00":
                    natt_ike += 1
                elif packet.haslayer("ESP") or (len(payload) >= 8 and payload[:4] != b"\x00\x00\x00\x00"):
                    natt_esp += 1

        if packet.haslayer("ESP"):
            esp += 1
            spi = getattr(packet["ESP"], "spi", None)
            if spi is not None:
                spis.add(int(spi))
            if len(examples) < 8:
                examples.append(
                    {
                        "packet_number": index,
                        "protocol": "ESP",
                        "spi": int(spi) if spi is not None else NOT_DETECTED,
                    }
                )
        if packet.haslayer("AH"):
            ah += 1

    return {
        "ike_udp_500": udp_500,
        "natt_udp_4500": udp_4500,
        "esp_packets": esp,
        "ah_packets": ah,
        "natt_ike_packets": natt_ike,
        "natt_esp_packets": natt_esp,
        "esp_spi_count": len(spis),
        "esp_present": esp > 0,
        "ah_present": ah > 0,
        "natt_present": udp_4500 > 0,
        "examples": examples,
        "note": (
            "ESP payloads are not decrypted. Presence of ESP means IPsec-protected "
            "traffic was observed, not that inner applications were identified."
        ),
    }
