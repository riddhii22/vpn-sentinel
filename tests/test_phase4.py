"""Day 3 / Phase 4: ESP-ANOM finding, score 0, not inner-traffic class."""

from pathlib import Path

from scapy.all import rdpcap

from app.analyzer import analyze_packets
from app.ml.anomaly import FLAG_MARGIN, analyze_esp_anomaly
from app.ml.esp_flows import extract_esp_flows

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_shipped_ike_samples_do_not_raise_esp_anom():
    for name in ("IKEv1.pcap", "IKEv2.pcap"):
        row = analyze_packets(rdpcap(str(SAMPLES / name)), name)
        ids = {f["id"] for f in row["findings"]}
        assert "ESP-ANOM" not in ids
        assert row["traffic_analysis"]["anomaly"]["flagged"] is False
        assert row["traffic_analysis"]["anomaly"]["affects_risk_score"] is False
    v1 = analyze_packets(rdpcap(str(SAMPLES / "IKEv1.pcap")), "IKEv1.pcap")
    v2 = analyze_packets(rdpcap(str(SAMPLES / "IKEv2.pcap")), "IKEv2.pcap")
    assert v1["risk"]["score"] == 30
    assert v2["risk"]["score"] == 0


def test_esp_weird_sample_raises_esp_anom_without_changing_risk():
    pcap = SAMPLES / "esp_weird.pcap"
    result = analyze_packets(rdpcap(str(pcap)), "esp_weird.pcap")
    ids = {f["id"] for f in result["findings"]}
    assert "ESP-ANOM" in ids
    finding = next(f for f in result["findings"] if f["id"] == "ESP-ANOM")
    assert finding["origin"] == "ml_anomaly"
    assert finding["score"] == 0
    assert finding["detected_value"] == "1 unusual ESP flow"
    assert "1 ESP flow sits" in finding["reason"]
    assert finding["category"] == "ml_anomaly"
    assert result["risk"]["score"] == 0
    assert result["traffic_analysis"]["anomaly"]["flagged"] is True
    assert result["traffic_analysis"]["anomaly"]["decrypts_payload"] is False
    assert result["traffic_analysis"]["prediction"] is None
    html = result["report"]["html"]
    assert "ESP-ANOM" in html
    assert "flagged" in html.lower()
    matrix_ids = {
        item["id"]
        for group in result["threat_matrix"]
        for item in group["findings"]
    }
    assert "ESP-ANOM" not in matrix_ids


def test_esp_anom_threshold_is_margin_on_training_cloud():
    anom = analyze_esp_anomaly(rdpcap(str(SAMPLES / "esp_weird.pcap")))
    assert anom["flag_margin"] == FLAG_MARGIN
    assert anom["flag_threshold"] == round(anom["train_max_radius"] * FLAG_MARGIN, 6)
    assert anom["max_baseline_radius"] > anom["flag_threshold"]


def test_natt_esp_without_esp_layer_still_groups():
    packets = rdpcap(str(FIXTURES / "lab_natt_esp.pcap"))
    flows = extract_esp_flows(packets)
    assert flows
    assert all(f["decrypts_payload"] is False for f in flows)
