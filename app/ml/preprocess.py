"""Deterministic numeric vector from TrafficFeatures. No learned scaling yet."""

from __future__ import annotations

# Fixed order so a future model and tests share the same layout.
FEATURE_NAMES: tuple[str, ...] = (
    "packet_count",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "packet_size_std",
    "avg_interarrival_time",
    "packets_per_second",
    "burst_count",
    "duration_seconds",
    "bytes_per_second",
    "packets_a_to_b",
    "packets_b_to_a",
    "ike_isakmp",
    "esp",
    "ah",
)


def features_to_vector(features: dict) -> list[float]:
    """Map a features dict to a stable list of floats.

    Missing timing values become 0.0 (documented imputation). Other missing
    or non-numeric fields are rejected.
    """
    if not isinstance(features, dict):
        raise ValueError("features must be a dict")

    direction = features.get("direction_statistics") or {}
    protocols = features.get("protocol_distribution") or {}
    if not isinstance(direction, dict) or not isinstance(protocols, dict):
        raise ValueError("direction_statistics and protocol_distribution must be objects")

    raw = {
        "packet_count": features.get("packet_count"),
        "avg_packet_size": features.get("avg_packet_size"),
        "min_packet_size": features.get("min_packet_size"),
        "max_packet_size": features.get("max_packet_size"),
        "packet_size_std": features.get("packet_size_std"),
        "avg_interarrival_time": features.get("avg_interarrival_time"),
        "packets_per_second": features.get("packets_per_second"),
        "burst_count": features.get("burst_count"),
        "duration_seconds": features.get("duration_seconds"),
        "bytes_per_second": features.get("bytes_per_second"),
        "packets_a_to_b": direction.get("packets_a_to_b"),
        "packets_b_to_a": direction.get("packets_b_to_a"),
        "ike_isakmp": protocols.get("ike_isakmp"),
        "esp": protocols.get("esp"),
        "ah": protocols.get("ah"),
    }

    vector: list[float] = []
    for name in FEATURE_NAMES:
        value = raw[name]
        if value is None and name in {
            "avg_interarrival_time",
            "packets_per_second",
            "bytes_per_second",
        }:
            vector.append(0.0)
            continue
        if value is None:
            raise ValueError(f"missing feature: {name}")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"non-numeric feature: {name}")
        vector.append(float(value))
    return vector
