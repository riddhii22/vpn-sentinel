"""Configuration-driven findings. Analyzer facts vs YAML policy stay separate."""

from __future__ import annotations

from pathlib import Path

import yaml

from app.analyzer.models import NOT_DETECTED

ROOT = Path(__file__).resolve().parent.parent.parent
RULES_PATH = ROOT / "policies" / "rules.yaml"


def load_rules(path: Path | None = None) -> dict:
    target = path or RULES_PATH
    with target.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _evidence_slice(items: list, limit: int = 8) -> list:
    return items[:limit]


def _finding(rule: dict, reason: str, evidence: list, category: str, detected_value=None) -> dict:
    rec = rule.get("recommendation", "")
    rid = rule["id"]
    title = rule.get("title", rid)
    return {
        "id": rid,
        "rule_id": rid,
        "title": title,
        "severity": rule.get("severity", "info"),
        "category": category,
        "detected_value": detected_value,
        "score": int(rule.get("score", 0)),
        "description": rule.get("description", ""),
        "reason": reason,
        "explanation": reason,
        "recommendation": rec,
        "evidence": evidence,
        "source": "pcap",
        "origin": rule.get("origin") or "security_rule",
        "status": "detected",
    }


def _ev(ike: dict) -> list:
    ev_v1 = ike.get("evidence", {}).get("ikev1") or []
    ev_v2 = ike.get("evidence", {}).get("ikev2") or []
    return _evidence_slice(ev_v1 or ev_v2)


def _max_lifetime(ike: dict) -> int | None:
    life = (ike.get("parameters") or {}).get("lifetime_seconds") or {}
    if life.get("status") != "detected":
        return None
    values = list(life.get("all_observed") or [])
    if life.get("value") is not None:
        values.append(life["value"])
    nums = [int(v) for v in values if isinstance(v, (int, float))]
    return max(nums) if nums else None


def _match(rule: dict, ike: dict, ipsec: dict) -> dict | None:
    """Return finding extras if this YAML rule's `when` matches analyzer facts."""
    when = rule.get("when")
    pfs = (ike.get("parameters") or {}).get("pfs") or {}
    mode = (ike.get("parameters") or {}).get("mode") or {}

    if when == "ikev1_present" and ike.get("ikev1_packet_count", 0) > 0:
        return {
            "reason": "ISAKMP version major=1 was present in the capture. IKEv1 is deprecated (RFC 9395).",
            "category": "protocol",
            "detected_value": "IKEv1",
            "evidence": _evidence_slice(ike.get("evidence", {}).get("ikev1") or []),
        }
    if when == "ikev2_present" and ike.get("ikev2_packet_count", 0) > 0:
        return {
            "reason": "ISAKMP version major=2 was present. Cryptographic policy still needs review.",
            "category": "protocol",
            "detected_value": "IKEv2",
            "evidence": _evidence_slice(ike.get("evidence", {}).get("ikev2") or []),
        }
    if when == "weak_encryption":
        names = ike.get("weak_encryption_observed") or []
        if names:
            joined = ", ".join(names)
            rule["title"] = f"Weak encryption algorithm detected ({joined})"
            return {
                "reason": f"Cleartext IKE SA transforms listed {joined}, which are legacy ciphers.",
                "category": "crypto",
                "detected_value": joined,
                "evidence": _ev(ike),
            }
    if when == "aes_cbc":
        names = ike.get("aes_cbc_observed") or []
        if names:
            return {
                "reason": "AES-CBC was advertised. It is acceptable; AEAD (AES-GCM) is preferred when both peers support it.",
                "category": "crypto",
                "detected_value": ", ".join(names),
                "evidence": _ev(ike),
            }
    if when == "aes_gcm":
        names = ike.get("aes_gcm_observed") or []
        if names:
            return {
                "reason": "AES-GCM (AEAD) was advertised in cleartext IKE SA transforms.",
                "category": "crypto",
                "detected_value": ", ".join(names),
                "evidence": _ev(ike),
            }
    if when == "aes_128":
        names = ike.get("aes_128_observed") or []
        if names:
            return {
                "reason": "AES with 128-bit keys was advertised. Recorded for policy review; not treated as weak in this prototype.",
                "category": "crypto",
                "detected_value": ", ".join(names),
                "evidence": _ev(ike),
            }
    if when == "aes_256":
        names = ike.get("aes_256_observed") or []
        if names:
            return {
                "reason": "AES with 256-bit keys was advertised in cleartext IKE SA transforms.",
                "category": "crypto",
                "detected_value": ", ".join(names),
                "evidence": _ev(ike),
            }
    if when == "weak_dh":
        groups = ike.get("weak_dh_observed") or []
        if groups:
            return {
                "reason": f"Cleartext IKE SA advertised DH group(s) {groups}, which are considered weak.",
                "category": "crypto",
                "detected_value": str(groups),
                "evidence": _ev(ike),
            }
    if when == "weak_hash":
        names = ike.get("weak_integrity_observed") or []
        if names:
            joined = ", ".join(str(x) for x in names)
            return {
                "reason": f"Cleartext IKE listed integrity/hash {joined}. SHA-1/MD5 are outdated (PPT: SHA-1 warning).",
                "category": "crypto",
                "detected_value": joined,
                "evidence": _ev(ike),
            }
    if when == "pfs_disabled" and pfs.get("status") == "detected" and pfs.get("value") is False:
        return {
            "reason": "Child SA / Quick Mode negotiation indicated Perfect Forward Secrecy was off.",
            "category": "crypto",
            "detected_value": "disabled",
            "evidence": _ev(ike),
        }
    if when == "natt_present" and ipsec.get("natt_present"):
        return {
            "reason": "UDP/4500 NAT-T packets were present. This is informational, not a weakness by itself.",
            "category": "protocol",
            "detected_value": f"{ipsec.get('natt_udp_4500', 0)} packets",
            "evidence": [],
        }
    if when == "mode_transport" and mode.get("status") == "detected" and str(mode.get("value")).lower() == "transport":
        return {
            "reason": "Transport mode was observed (inner IP headers are less hidden than tunnel mode).",
            "category": "protocol",
            "detected_value": "transport",
            "evidence": _ev(ike),
        }
    if when == "lifetime_gt":
        limit = int(rule.get("max_seconds") or 86400)
        observed = _max_lifetime(ike)
        if observed is not None and observed > limit:
            return {
                "reason": f"Advertised SA lifetime {observed}s exceeds the policy threshold of {limit}s.",
                "category": "crypto",
                "detected_value": observed,
                "evidence": _ev(ike),
            }
    return None


def evaluate(ike: dict, ipsec: dict, rules_doc: dict | None = None) -> list[dict]:
    doc = rules_doc or load_rules()
    findings: list[dict] = []
    for rule in doc.get("rules") or []:
        if not isinstance(rule, dict) or not rule.get("id"):
            continue
        working = dict(rule)
        hit = _match(working, ike, ipsec)
        if not hit:
            continue
        findings.append(
            _finding(
                working,
                hit["reason"],
                hit.get("evidence") or [],
                hit.get("category") or "policy",
                detected_value=hit.get("detected_value"),
            )
        )
    return findings


def finding_from_esp_anomaly(anomaly: dict | None, rules_doc: dict | None = None) -> dict | None:
    """ESP-ANOM is origin ml_anomaly and score 0 — never mixed into cipher grade."""
    if not anomaly or not anomaly.get("flagged"):
        return None
    doc = rules_doc or load_rules()
    rule = next(
        (r for r in (doc.get("rules") or []) if isinstance(r, dict) and r.get("id") == "ESP-ANOM"),
        None,
    )
    if not rule:
        return None
    outliers = [f for f in (anomaly.get("flows") or []) if f.get("outlier")]
    evidence = []
    for flow in outliers[:8]:
        evidence.append(
            {
                "packet_number": None,
                "source": flow.get("src"),
                "destination": flow.get("dst"),
                "protocol": "ESP",
                "note": (
                    f"SPI {flow.get('spi_hex')} · {flow.get('packet_count')} packets · "
                    f"radius {flow.get('baseline_radius')} (threshold {anomaly.get('flag_threshold')})"
                ),
            }
        )
    n = int(anomaly.get("outlier_flow_count") or len(outliers))
    flow_word = "flow" if n == 1 else "flows"
    verb = "sits" if n == 1 else "sit"
    reason = (
        f"{n} ESP {flow_word} {verb} farther from the bundled-sample size/timing cloud "
        f"than {anomaly.get('flag_margin')}× the farthest training flow "
        f"(threshold {anomaly.get('flag_threshold')}). "
        "IsolationForest scores are shown for the same metadata. Ciphertext was not read."
    )
    working = dict(rule)
    finding = _finding(
        working,
        reason,
        evidence,
        "ml_anomaly",
        detected_value=f"{n} unusual ESP {flow_word}",
    )
    finding["origin"] = "ml_anomaly"
    finding["score"] = 0
    return finding


def recommendations_from(findings: list[dict]) -> list[dict]:
    recs = []
    for item in findings:
        text = item.get("recommendation")
        if not text:
            continue
        recs.append(
            {
                "finding_id": item["id"],
                "severity": item.get("severity"),
                "recommendation": text,
            }
        )
    return recs


def limitations() -> list[str]:
    return [
        f"PFS: {NOT_DETECTED} unless Child SA/Quick Mode is cleartext.",
        f"Tunnel vs transport mode: {NOT_DETECTED} when ESP proposals are encrypted.",
        f"Replay protection: {NOT_DETECTED} (no ESN/window evidence in these captures).",
        "ESP inner traffic type is not classified (no decryption; no traffic-type model).",
        "IsolationForest on ESP size/timing is metadata-only. ESP-ANOM (if present) does not change the VPN risk score.",
        "A PCAP is observed traffic, not a complete VPN configuration dump.",
        "Baseline ML prediction unavailable — insufficient validated training data.",
    ]
