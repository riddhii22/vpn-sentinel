#!/usr/bin/env python3
"""Render swanctl.conf for one lab config id (C1, C3, C5, ...)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
MATRIX_PATH = ROOT / "matrix.yaml"
RUNTIME = ROOT / "runtime"
DEFAULT_PSK = "vpn-sentinel-lab-psk-not-a-secret"


def load_matrix() -> dict:
    return yaml.safe_load(MATRIX_PATH.read_text(encoding="utf-8"))


def get_config(config_id: str) -> tuple[dict, dict]:
    matrix = load_matrix()
    defaults = matrix.get("defaults") or {}
    configs = matrix.get("configs") or {}
    if config_id not in configs:
        known = ", ".join(sorted(configs))
        raise SystemExit(f"unknown CONFIG={config_id}. Known: {known}")
    row = {**defaults, **configs[config_id]}
    row["id"] = config_id
    if not row.get("enabled"):
        raise SystemExit(
            f"{config_id} is defined but not enabled (stretch/out of scope). "
            "Enabled: C1–C8, C10."
        )
    return matrix, row


def lab_psk() -> str:
    env = os.environ.get("LAB_PSK")
    if env:
        return env.strip()
    psk_file = ROOT / "secrets" / "psk.env"
    if psk_file.is_file():
        for line in psk_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("LAB_PSK="):
                return line.split("=", 1)[1].strip().strip('"')
    return DEFAULT_PSK


def _ts(row: dict, side: str) -> tuple[str, str]:
    mode = row["mode"]
    gw_a = row["gw_a_transit"]
    gw_b = row["gw_b_transit"]
    if mode == "transport":
        if side == "a":
            return f"{gw_a}/32", f"{gw_b}/32"
        return f"{gw_b}/32", f"{gw_a}/32"
    left = row["left_subnet"]
    right = row["right_subnet"]
    if side == "a":
        return left, right
    return right, left


def swanctl_conf(row: dict, side: str) -> str:
    psk = lab_psk()
    if side == "a":
        local_addr = row["gw_a_transit"]
        remote_addr = row["gw_b_transit"]
        local_id = row["local_id"]
        remote_id = row["remote_id"]
    else:
        local_addr = row["gw_b_transit"]
        remote_addr = row["gw_a_transit"]
        local_id = row["remote_id"]
        remote_id = row["local_id"]
    local_ts, remote_ts = _ts(row, side)
    version = int(row.get("ike_version") or 2)
    mode = row["mode"]
    ike = row["ike_proposal"]
    esp = row["esp_proposal"]
    aggressive = "        aggressive = no\n" if version == 1 else ""
    return f"""# Generated for {row["id"]} side={side} — lab dummy PSK only.
connections {{
    lab {{
        version = {version}
        local_addrs = {local_addr}
        remote_addrs = {remote_addr}
        mobike = no
{aggressive}        proposals = {ike}
        local {{
            auth = psk
            id = {local_id}
        }}
        remote {{
            auth = psk
            id = {remote_id}
        }}
        children {{
            child {{
                local_ts = {local_ts}
                remote_ts = {remote_ts}
                esp_proposals = {esp}
                mode = {mode}
                start_action = none
                dpd_action = restart
            }}
        }}
    }}
}}

secrets {{
    ike-lab {{
        id = {row["local_id"]}
        id2 = {row["remote_id"]}
        secret = "{psk}"
    }}
}}
"""


def write_runtime(row: dict) -> None:
    for side in ("a", "b"):
        dest = RUNTIME / f"gw-{side}" / "conf.d"
        dest.mkdir(parents=True, exist_ok=True)
        for extra in (
            "x509",
            "x509ca",
            "x509ocsp",
            "x509aa",
            "x509ac",
            "x509crl",
            "pubkey",
            "private",
            "rsa",
            "ecdsa",
            "pkcs8",
            "pkcs12",
        ):
            (RUNTIME / f"gw-{side}" / extra).mkdir(parents=True, exist_ok=True)
        (dest / "lab.conf").write_text(swanctl_conf(row, side), encoding="utf-8")
        # swanctl also reads /etc/swanctl/swanctl.conf — keep a stub.
        (RUNTIME / f"gw-{side}" / "swanctl.conf").write_text(
            "include conf.d/*.conf\n", encoding="utf-8"
        )


def metadata_dict(row: dict, pcap_rel: str) -> dict:
    return {
        "config_id": row["id"],
        "ike_version": int(row.get("ike_version") or 2),
        "mode": row["mode"],
        "requested_mode": row.get("requested_mode") or row["mode"],
        "encryption": row["encryption"],
        "integrity": row["integrity"],
        "dh_group": int(row["dh_group"]),
        "pfs": bool(row["pfs"]),
        "ip": row.get("ip") or "v4",
        "ike_proposal": row["ike_proposal"],
        "esp_proposal": row["esp_proposal"],
        "traffic_type": row.get("traffic") or "ping",
        "weak": bool(row.get("weak")),
        "ping_from": row.get("ping_from"),
        "ping_target": row.get("ping_target"),
        "pcap": pcap_rel,
        "ground_truth": True,
        "lab_only": True,
        "generated_at": datetime.now(UTC).isoformat(),
        "note": row.get("note")
        or "Lab capture. PSK is a published dummy. Do not use on a real network.",
    }


def write_metadata(row: dict, dest: Path, pcap_name: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = metadata_dict(row, pcap_name)
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render strongSwan lab configs")
    parser.add_argument("config_id", help="e.g. C1")
    parser.add_argument(
        "--metadata",
        type=Path,
        help="Write metadata JSON to this path",
    )
    parser.add_argument(
        "--traffic",
        default="ping",
        help="Ground-truth traffic_type stored in metadata",
    )
    parser.add_argument(
        "--pcap-name",
        default="ping.pcap",
        help="Relative pcap filename stored in metadata",
    )
    args = parser.parse_args(argv)
    _, row = get_config(args.config_id)
    row["traffic"] = args.traffic
    write_runtime(row)
    if args.metadata:
        write_metadata(row, args.metadata, args.pcap_name)
    print(f"rendered {args.config_id} -> {RUNTIME}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
