"""Phase 3: IsolationForest on ESP flow metadata, not payload and not risk score."""

from pathlib import Path

from scapy.all import rdpcap
from sklearn.ensemble import IsolationForest

from app.analyzer import analyze_packets
from app.ml.anomaly import _forest, analyze_esp_anomaly, score_vector
from app.ml.esp_flows import extract_esp_flows, synthetic_weird_vector

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_esp_flows_group_by_ip_and_spi():
    packets = rdpcap(str(SAMPLES / "IKEv1.pcap"))
    flows = extract_esp_flows(packets)
    assert len(flows) >= 2
    keys = {(f["src"], f["dst"], f["spi"]) for f in flows}
    assert len(keys) == len(flows)
    for flow in flows:
        assert flow["decrypts_payload"] is False
        feats = flow["features"]
        assert feats["byte_volume"] > 0
        assert feats["size_mean"] > 0
        assert "size_variance" in feats
        assert "iat_mean" in feats
        assert "iat_variance" in feats
        assert "duration_seconds" in feats


def test_weird_flow_more_anomalous_than_lab_flows():
    model, scaler, n_train = _forest()
    assert model is not None and scaler is not None
    assert n_train >= 2
    packets = rdpcap(str(SAMPLES / "IKEv1.pcap"))
    lab_scores = [
        score_vector(flow["vector"], model, scaler) for flow in extract_esp_flows(packets)
    ]
    from app.ml.anomaly import _baseline_matrix

    train_rows, _ = _baseline_matrix()
    train_scores = [score_vector(list(row), model, scaler) for row in train_rows]
    weird = score_vector(synthetic_weird_vector(), model, scaler)
    assert lab_scores
    assert weird < (sum(train_scores) / len(train_scores))
    assert weird < sorted(train_scores)[len(train_scores) // 2]


def test_analyze_exposes_anomaly_without_changing_risk():
    v1 = analyze_packets(rdpcap(str(SAMPLES / "IKEv1.pcap")), "IKEv1.pcap")
    v2 = analyze_packets(rdpcap(str(SAMPLES / "IKEv2.pcap")), "IKEv2.pcap")
    for row in (v1, v2):
        anomaly = row["traffic_analysis"]["anomaly"]
        assert anomaly["available"] is True
        assert anomaly["model_type"] == "IsolationForest"
        assert anomaly["decrypts_payload"] is False
        assert anomaly["affects_risk_score"] is False
        assert row["traffic_analysis"]["model_available"] is False
        assert row["traffic_analysis"]["prediction"] is None
        assert "ESP-ANOM" not in {f["id"] for f in row["findings"]}
    assert v1["risk"]["score"] == 30
    assert v2["risk"]["score"] == 0
    weird = v1["traffic_analysis"]["anomaly"]["synthetic_weird"]["anomaly_score"]
    flow_scores = [f["anomaly_score"] for f in v1["traffic_analysis"]["anomaly"]["flows"]]
    assert flow_scores
    assert weird < (sum(flow_scores) / len(flow_scores))


def test_isolation_forest_is_sklearn():
    model, _scaler, _n = _forest()
    assert isinstance(model, IsolationForest)
