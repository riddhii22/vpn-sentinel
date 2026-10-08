"""IsolationForest on ESP flow metadata (size/timing). Not traffic-type classification."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.ml.esp_flows import (
    FLOW_FEATURE_NAMES,
    extract_esp_flows,
    features_from_vector,
    synthetic_weird_vector,
)

ROOT = Path(__file__).resolve().parent.parent.parent
SAMPLES = ROOT / "samples"
# Finding fires only if a capture flow sits farther from the bundled-sample
# cloud than those samples themselves (IsolationForest scores are still shown).
FLAG_MARGIN = 1.5

MESSAGE = (
    "IsolationForest scores how unusual an ESP flow's size and timing look "
    "compared with the bundled lab captures. Encrypted payloads are not read. "
    "This is not web/video/voice classification and it does not set the VPN risk score. "
    "ESP-ANOM is a separate finding (origin ml_anomaly) when a flow is an outlier "
    "versus that baseline cloud."
)


@lru_cache(maxsize=1)
def _baseline_matrix() -> tuple[tuple[tuple[float, ...], ...], int]:
    """Fit-time rows: ESP flows from shipped IKEv1 and IKEv2 samples only."""
    rows: list[tuple[float, ...]] = []
    for name in ("IKEv1.pcap", "IKEv2.pcap"):
        path = SAMPLES / name
        if not path.is_file():
            continue
        from scapy.all import rdpcap

        packets = rdpcap(str(path))
        for flow in extract_esp_flows(packets):
            rows.append(tuple(float(x) for x in flow["vector"]))
    return tuple(rows), len(rows)


@lru_cache(maxsize=1)
def _forest():
    matrix, n = _baseline_matrix()
    if n < 2:
        return None, None, n
    xs = [list(row) for row in matrix]
    scaler = StandardScaler()
    scaled = scaler.fit_transform(xs)
    model = IsolationForest(
        n_estimators=64,
        contamination="auto",
        random_state=42,
    )
    model.fit(scaled)
    return model, scaler, n


def score_vector(vector: list[float], model, scaler) -> float:
    scaled = scaler.transform([vector])
    return float(model.score_samples(scaled)[0])


def _scaled_cloud(scaler, matrix) -> tuple:
    xs = np.asarray(scaler.transform([list(row) for row in matrix]), dtype=float)
    centroid = xs.mean(axis=0)
    radii = np.linalg.norm(xs - centroid, axis=1)
    return centroid, float(radii.max()) if len(radii) else 0.0


def _radius(vector: list[float], scaler, centroid) -> float:
    z = np.asarray(scaler.transform([vector])[0], dtype=float)
    return float(np.linalg.norm(z - centroid))


def analyze_esp_anomaly(packets) -> dict:
    """Score this capture's ESP flows. ESP-ANOM is attached later if flagged."""
    model, scaler, n_train = _forest()
    flows = extract_esp_flows(packets)
    matrix, _n = _baseline_matrix()
    if model is None or scaler is None:
        return {
            "available": False,
            "model_type": None,
            "decrypts_payload": False,
            "n_training_flows": n_train,
            "feature_names": list(FLOW_FEATURE_NAMES),
            "flows": [],
            "message": "Not enough bundled ESP flows to fit IsolationForest.",
            "affects_risk_score": False,
            "flagged": False,
        }

    centroid, max_train_radius = _scaled_cloud(scaler, matrix)
    max_train_radius = round(max_train_radius, 6)
    threshold = round(max_train_radius * FLAG_MARGIN, 6)
    scored = []
    for flow in flows:
        s = score_vector(flow["vector"], model, scaler)
        radius = _radius(flow["vector"], scaler, centroid)
        row = dict(flow)
        row["anomaly_score"] = round(s, 6)
        row["baseline_radius"] = round(radius, 6)
        row["outlier"] = bool(radius > threshold)
        row.pop("vector", None)
        scored.append(row)

    weird = synthetic_weird_vector()
    weird_score = score_vector(weird, model, scaler)
    weird_radius = _radius(weird, scaler, centroid)
    capture_scores = [f["anomaly_score"] for f in scored]
    capture_radii = [f["baseline_radius"] for f in scored]
    flagged = any(f["outlier"] for f in scored)
    outliers = [f for f in scored if f["outlier"]]

    return {
        "available": True,
        "model_type": "IsolationForest",
        "decrypts_payload": False,
        "n_training_flows": n_train,
        "feature_names": list(FLOW_FEATURE_NAMES),
        "flows": scored,
        "min_anomaly_score": min(capture_scores) if capture_scores else None,
        "max_baseline_radius": max(capture_radii) if capture_radii else None,
        "train_max_radius": max_train_radius,
        "flag_threshold": threshold,
        "flag_margin": FLAG_MARGIN,
        "flagged": flagged,
        "outlier_flow_count": len(outliers),
        "synthetic_weird": {
            "features": features_from_vector(weird),
            "anomaly_score": round(weird_score, 6),
            "baseline_radius": round(weird_radius, 6),
            "note": "Synthetic oversized/bursty ESP metadata used as a sanity check, not a real capture.",
        },
        "message": MESSAGE,
        "affects_risk_score": False,
        "explains": (
            "Lower IsolationForest score_samples values are more unusual. "
            "ESP-ANOM fires when a flow's scaled size/timing vector is farther "
            f"from the bundled-sample cloud than {FLAG_MARGIN}× the farthest training flow. "
            "ESP ciphertext is never decrypted."
        ),
    }
