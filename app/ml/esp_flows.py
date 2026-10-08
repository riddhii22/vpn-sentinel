"""Group ESP packets into flows. Never inspect ciphertext contents."""

from __future__ import annotations

import math
from collections import defaultdict


def _addrs(packet) -> tuple[str, str]:
    if packet.haslayer("IP"):
        return packet["IP"].src, packet["IP"].dst
    if packet.haslayer("IPv6"):
        return packet["IPv6"].src, packet["IPv6"].dst
    return "unknown", "unknown"

# size mean, size variance, IAT mean, IAT variance, duration, byte volume
FLOW_FEATURE_NAMES: tuple[str, ...] = (
    "size_mean",
    "size_variance",
    "iat_mean",
    "iat_variance",
    "duration_seconds",
    "byte_volume",
)


def _var(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return sum((x - mean) ** 2 for x in values) / len(values)


def _esp_spi(packet) -> int | None:
    if packet.haslayer("ESP"):
        return int(packet["ESP"].spi)
    if not packet.haslayer("UDP"):
        return None
    sport = int(packet["UDP"].sport)
    dport = int(packet["UDP"].dport)
    if sport != 4500 and dport != 4500:
        return None
    payload = bytes(packet["UDP"].payload) if packet["UDP"].payload else b""
    # RFC 3948: four-zero IKE marker; anything else with ≥8 bytes is ESP-in-UDP.
    if len(payload) < 8 or payload[:4] == b"\x00\x00\x00\x00":
        return None
    return int.from_bytes(payload[:4], "big")


def extract_esp_flows(packets) -> list[dict]:
    """One flow = (src IP, dst IP, SPI). ESP has no TCP ports."""
    buckets: dict[tuple[str, str, int], list] = defaultdict(list)
    for packet in packets:
        spi = _esp_spi(packet)
        if spi is None:
            continue
        src, dst = _addrs(packet)
        buckets[(src, dst, spi)].append(packet)

    flows: list[dict] = []
    for (src, dst, spi), group in buckets.items():
        ordered = sorted(group, key=lambda p: float(p.time))
        sizes = [float(len(p)) for p in ordered]
        times = [float(p.time) for p in ordered]
        iats = [times[i] - times[i - 1] for i in range(1, len(times))]
        duration = max(0.0, times[-1] - times[0]) if times else 0.0
        features = {
            "size_mean": round(sum(sizes) / len(sizes), 4) if sizes else 0.0,
            "size_variance": round(_var(sizes), 4),
            "iat_mean": round(sum(iats) / len(iats), 6) if iats else 0.0,
            "iat_variance": round(_var(iats), 8) if iats else 0.0,
            "duration_seconds": round(duration, 6),
            "byte_volume": int(sum(sizes)),
        }
        flows.append(
            {
                "src": src,
                "dst": dst,
                "spi": spi,
                "spi_hex": f"0x{spi:08x}",
                "packet_count": len(ordered),
                "features": features,
                "vector": [features[name] for name in FLOW_FEATURE_NAMES],
                "decrypts_payload": False,
            }
        )
    return flows


def synthetic_weird_vector() -> list[float]:
    """Far outside lab ESP size/timing (scaled IsolationForest sanity check)."""
    return [50000.0, 1.0e8, 5.0, 25.0, 3600.0, 5.0e7]


def features_from_vector(vector: list[float]) -> dict:
    return dict(zip(FLOW_FEATURE_NAMES, vector, strict=True))
