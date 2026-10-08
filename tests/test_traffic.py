import json

from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.isakmp import ISAKMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from app.analyzer.traffic import extract_traffic_features
from app.ml import UNAVAILABLE, FEATURE_NAMES, features_to_vector, predict_from_features
from app.ml.dataset import inventory, load_labeled_rows, training_is_possible
from app.ml.model import load_trained_model


def test_empty_traffic():
    feat = extract_traffic_features([])
    assert feat["packet_count"] == 0
    assert feat["decrypts_payload"] is False
    assert feat["avg_interarrival_time"] is None
    assert feat["protocol_distribution"]["esp"] == 0
    assert feat["windows"] == []


def test_single_packet_no_iat():
    pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=500, dport=500) / ISAKMP()
    pkt.time = 1.0
    feat = extract_traffic_features([pkt])
    assert feat["packet_count"] == 1
    assert feat["min_packet_size"] == feat["max_packet_size"]
    assert feat["avg_interarrival_time"] is None
    assert feat["packet_size_std"] == 0.0
    assert feat["packets_per_second"] is None
    assert feat["protocol_distribution"]["ike_isakmp"] == 1
    assert feat["protocol_distribution"]["udp_500"] == 1


def test_timing_and_direction():
    a = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP() / Raw(b"x" * 10)
    b = Ether() / IPv6(src="2001:db8::2", dst="2001:db8::1") / UDP() / Raw(b"y" * 20)
    a.time = 10.0
    b.time = 10.5
    feat = extract_traffic_features([a, b])
    assert feat["avg_interarrival_time"] == 0.5
    assert feat["packets_per_second"] == 4.0
    assert feat["bytes_per_second"] is not None
    assert feat["total_bytes"] > 0
    assert feat["traffic_frequency_hz"] == 4.0
    assert feat["direction_statistics"]["packets_a_to_b"] == 1
    assert feat["direction_statistics"]["packets_b_to_a"] == 1
    assert feat["windows"]
    assert feat["windows"][0]["packets"] == 1 or feat["windows"][0]["bytes"] > 0


def test_burst_count():
    pkts = []
    for i in range(3):
        p = Ether() / IPv6() / UDP() / Raw(b"z")
        p.time = 1.0 + i * 0.0004
        pkts.append(p)
    feat = extract_traffic_features(pkts)
    assert feat["burst_count"] == 1
    assert feat["windows"][0]["burst_activity"] is True


def test_size_stats_and_json_safe():
    pkts = []
    for i, sz in enumerate((100, 200, 300)):
        p = Ether() / IPv6() / UDP() / Raw(b"a" * (sz - 62))
        p.time = i * 0.01
        pkts.append(p)
    feat = extract_traffic_features(pkts)
    assert feat["min_packet_size"] <= feat["avg_packet_size"] <= feat["max_packet_size"]
    assert feat["packet_size_std"] >= 0
    json.dumps(feat)
    vec = features_to_vector(feat)
    assert len(vec) == len(FEATURE_NAMES)
    assert features_to_vector(feat) == vec


def test_ml_unavailable_even_with_features():
    out = predict_from_features({"packet_count": 3, "avg_packet_size": 10})
    assert out["model_available"] is False
    assert out["prediction"] is None
    assert out["confidence"] is None
    assert out["message"] == UNAVAILABLE
    assert out["feature_importance"] is None


def test_ml_rejects_non_dict():
    try:
        predict_from_features("nope")  # type: ignore[arg-type]
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_preprocess_rejects_malformed():
    try:
        features_to_vector({"packet_count": "many"})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_dataset_has_no_invented_labels():
    info = inventory()
    assert info["labeled_file_count"] == 0
    assert info["sufficient_for_training"] is False
    assert load_labeled_rows() == []
    assert training_is_possible() is False
    assert load_trained_model() is None
    assert "IKEv1.pcap" in info["unlabeled_demo_samples"]


def test_real_samples_features_and_speed():
    import time
    from pathlib import Path

    from scapy.all import rdpcap

    from app.analyzer import analyze_packets

    root = Path(__file__).resolve().parent.parent / "samples"
    for name, n in (("IKEv1.pcap", 309), ("IKEv2.pcap", 197)):
        packets = rdpcap(str(root / name))
        t0 = time.perf_counter()
        out = analyze_packets(packets, name)
        elapsed = time.perf_counter() - t0
        assert elapsed < 8.0
        feat = out["traffic_analysis"]["features"]
        assert feat["packet_count"] == n
        assert feat["decrypts_payload"] is False
        assert out["traffic_analysis"]["model_available"] is False
        assert "/tmp/" not in json.dumps(out["file_name"])
        vec = features_to_vector(feat)
        assert len(vec) == len(FEATURE_NAMES)

