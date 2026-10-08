"""Observable traffic metadata. Never reads ESP/IKE payload plaintext.

This is **not** a security finding and **not** an ML prediction.
It is packet-size and timing statistics taken from the capture as stored.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import asdict, dataclass, field

from scapy.layers.isakmp import ISAKMP

from app.analyzer.capture import _addrs

# Keep window work cheap on a laptop demo.
WINDOW_SECONDS = 0.5
MAX_WINDOWS = 40
BURST_GAP_S = 0.001


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    var = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(var)


def _protocol_distribution(packets) -> dict[str, int]:
    dist = {
        "ike_isakmp": 0,
        "esp": 0,
        "ah": 0,
        "udp_500": 0,
        "udp_4500": 0,
        "tcp": 0,
        "other": 0,
    }
    for packet in packets:
        classified = False
        if packet.haslayer(ISAKMP):
            dist["ike_isakmp"] += 1
            classified = True
        if packet.haslayer("ESP"):
            dist["esp"] += 1
            classified = True
        if packet.haslayer("AH"):
            dist["ah"] += 1
            classified = True
        if packet.haslayer("UDP"):
            sport = int(packet["UDP"].sport)
            dport = int(packet["UDP"].dport)
            if sport == 500 or dport == 500:
                dist["udp_500"] += 1
                classified = True
            elif sport == 4500 or dport == 4500:
                dist["udp_4500"] += 1
                classified = True
        if packet.haslayer("TCP"):
            dist["tcp"] += 1
            classified = True
        if not classified:
            dist["other"] += 1
    return dist


@dataclass
class DirectionStatistics:
    side_a: str | None
    side_b: str | None
    packets_a_to_b: int
    packets_b_to_a: int
    note: str


@dataclass
class WindowStats:
    index: int
    packets: int
    bytes: int
    avg_packet_size: float
    avg_interarrival_time: float | None
    burst_activity: bool


@dataclass
class TrafficFeatures:
    """Structured metadata vector. Values come from the PCAP, never hardcoded."""

    packet_count: int
    avg_packet_size: float
    min_packet_size: int
    max_packet_size: int
    packet_size_std: float
    avg_interarrival_time: float | None
    packets_per_second: float | None
    traffic_frequency_hz: float | None
    total_bytes: int
    bytes_per_second: float | None
    duration_seconds: float
    burst_count: int
    direction_statistics: DirectionStatistics
    protocol_distribution: dict[str, int]
    windows: list[WindowStats] = field(default_factory=list)
    window_seconds: float = WINDOW_SECONDS
    decrypts_payload: bool = False

    def to_dict(self) -> dict:
        payload = asdict(self)
        return payload


def _empty_features() -> TrafficFeatures:
    return TrafficFeatures(
        packet_count=0,
        avg_packet_size=0.0,
        min_packet_size=0,
        max_packet_size=0,
        packet_size_std=0.0,
        avg_interarrival_time=None,
        packets_per_second=None,
        traffic_frequency_hz=None,
        total_bytes=0,
        bytes_per_second=None,
        duration_seconds=0.0,
        burst_count=0,
        direction_statistics=DirectionStatistics(
            side_a=None,
            side_b=None,
            packets_a_to_b=0,
            packets_b_to_a=0,
            note="Not detected from available capture",
        ),
        protocol_distribution={
            "ike_isakmp": 0,
            "esp": 0,
            "ah": 0,
            "udp_500": 0,
            "udp_4500": 0,
            "tcp": 0,
            "other": 0,
        },
        windows=[],
    )


def extract_traffic_features(
    packets, window_s: float = WINDOW_SECONDS
) -> dict:
    """Metadata only: sizes, timing, protocol mix, first-pair direction."""
    return _compute_features(packets, window_s=window_s).to_dict()


def _compute_features(packets, window_s: float = WINDOW_SECONDS) -> TrafficFeatures:
    n = len(packets)
    if n == 0:
        return _empty_features()

    ordered = sorted(packets, key=lambda p: float(p.time))
    sizes = [len(p) for p in ordered]
    times = [float(p.time) for p in ordered]
    iats = [times[i] - times[i - 1] for i in range(1, n)]
    duration = max(0.0, times[-1] - times[0])
    pps = round(n / duration, 4) if duration > 0 else None
    total_bytes = sum(sizes)
    bps = round(total_bytes / duration, 1) if duration > 0 else None
    avg_iat = round(sum(iats) / len(iats), 6) if iats else None

    burst_count = 0
    in_burst = False
    for gap in iats:
        if 0 <= gap < BURST_GAP_S:
            if not in_burst:
                burst_count += 1
                in_burst = True
        else:
            in_burst = False

    side_a = side_b = None
    a_to_b = b_to_a = 0
    for p in ordered:
        src, dst = _addrs(p)
        if src == "unknown":
            continue
        if side_a is None:
            side_a = src
            side_b = dst
        if src == side_a and dst == side_b:
            a_to_b += 1
        elif src == side_b and dst == side_a:
            b_to_a += 1

    windows: list[WindowStats] = []
    if window_s > 0:
        buckets: dict[int, list[tuple[float, int]]] = defaultdict(list)
        t0 = times[0]
        for t, sz in zip(times, sizes):
            idx = int((t - t0) / window_s)
            buckets[idx].append((t, sz))
        for idx in sorted(buckets)[:MAX_WINDOWS]:
            chunk = buckets[idx]
            chunk_sizes = [sz for _, sz in chunk]
            chunk_times = [t for t, _ in chunk]
            chunk_iats = [
                chunk_times[i] - chunk_times[i - 1] for i in range(1, len(chunk_times))
            ]
            windows.append(
                WindowStats(
                    index=idx,
                    packets=len(chunk),
                    bytes=sum(chunk_sizes),
                    avg_packet_size=round(sum(chunk_sizes) / len(chunk_sizes), 1),
                    avg_interarrival_time=(
                        round(sum(chunk_iats) / len(chunk_iats), 6) if chunk_iats else None
                    ),
                    burst_activity=any(0 <= g < BURST_GAP_S for g in chunk_iats),
                )
            )

    return TrafficFeatures(
        packet_count=n,
        avg_packet_size=round(sum(sizes) / n, 1),
        min_packet_size=min(sizes),
        max_packet_size=max(sizes),
        packet_size_std=round(_std([float(s) for s in sizes]), 2),
        avg_interarrival_time=avg_iat,
        packets_per_second=pps,
        traffic_frequency_hz=pps,
        total_bytes=total_bytes,
        bytes_per_second=bps,
        duration_seconds=round(duration, 6),
        burst_count=burst_count,
        direction_statistics=DirectionStatistics(
            side_a=side_a,
            side_b=side_b,
            packets_a_to_b=a_to_b,
            packets_b_to_a=b_to_a,
            note=(
                "First observed address pair. Upload vs download is not labeled: "
                "the capture does not identify which host is the VPN client."
            ),
        ),
        protocol_distribution=_protocol_distribution(ordered),
        windows=windows,
        window_seconds=window_s,
        decrypts_payload=False,
    )
