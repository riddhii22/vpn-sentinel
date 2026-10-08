"""Shared analysis constants and small value objects."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

NOT_DETECTED = "Not detected from available capture"


def detected(value, extra: dict | None = None) -> dict:
    out = {"status": "detected", "value": value}
    if extra:
        out.update(extra)
    return out


def not_detected(reason: str | None = None) -> dict:
    out = {"status": "not_detected", "value": None, "detail": NOT_DETECTED}
    if reason:
        out["reason"] = reason
    return out


@dataclass
class EvidenceItem:
    packet_number: int
    timestamp: str
    source: str
    destination: str
    protocol: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
