#!/usr/bin/env python3
"""Rebuild dataset/labels.csv from per-capture metadata JSON files."""

from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
OUT = DATASET / "labels.csv"
FIELDS = [
    "config_id",
    "traffic_type",
    "path",
    "ike_version",
    "mode",
    "requested_mode",
    "encryption",
    "integrity",
    "dh_group",
    "pfs",
    "weak",
    "ground_truth",
]


def main() -> None:
    rows: list[dict] = []
    for meta in sorted(DATASET.glob("C*/*.json")):
        if meta.name == "metadata.json" and (meta.parent / "ping.metadata.json").is_file():
            continue
        data = json.loads(meta.read_text(encoding="utf-8"))
        pcap_name = data.get("pcap") or "ping.pcap"
        rel = (meta.parent / pcap_name).relative_to(DATASET).as_posix()
        rows.append(
            {
                "config_id": data.get("config_id"),
                "traffic_type": data.get("traffic_type"),
                "path": rel,
                "ike_version": data.get("ike_version"),
                "mode": data.get("mode"),
                "requested_mode": data.get("requested_mode"),
                "encryption": data.get("encryption"),
                "integrity": data.get("integrity"),
                "dh_group": data.get("dh_group"),
                "pfs": data.get("pfs"),
                "weak": data.get("weak"),
                "ground_truth": data.get("ground_truth", True),
            }
        )
    rows.sort(key=lambda r: (str(r["config_id"]), str(r["traffic_type"])))
    with OUT.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {OUT} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
