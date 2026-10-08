"""T-API-01: upload hardening for POST /analyze. Scoring/IKE logic is unchanged."""

from pathlib import Path

from app import main
from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)
SAMPLES = Path(__file__).resolve().parent.parent / "samples"

# Valid global header, no packets (libpcap little-endian v2.4, Ethernet).
EMPTY_PCAP_HEADER = (
    b"\xd4\xc3\xb2\xa1"
    b"\x02\x00\x04\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\xff\xff\x00\x00"
    b"\x01\x00\x00\x00"
)


def test_health_still_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_empty_body_is_error():
    response = client.post(
        "/analyze",
        files={"file": ("empty.pcap", b"", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_non_pcap_is_error():
    response = client.post(
        "/analyze",
        files={"file": ("notes.txt", b"this is not a packet capture", "text/plain")},
    )
    assert response.status_code == 400
    assert "pcap" in response.json()["detail"].lower()


def test_pcap_header_with_no_packets_is_error():
    response = client.post(
        "/analyze",
        files={"file": ("none.pcap", EMPTY_PCAP_HEADER, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 400
    assert "no packets" in response.json()["detail"].lower()


def test_traversal_filename_is_sanitized(tmp_path):
    pcap = (SAMPLES / "IKEv2.pcap").read_bytes()
    response = client.post(
        "/analyze",
        files={"file": ("../../etc/passwd.pcap", pcap, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 200
    assert response.json()["file_name"] == "passwd.pcap"
    # Must not have written next to the test file using the client path.
    assert not (tmp_path / "etc" / "passwd.pcap").exists()


def test_oversize_upload_is_rejected(monkeypatch):
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 64)
    pcap = (SAMPLES / "IKEv2.pcap").read_bytes()
    assert len(pcap) > 64
    response = client.post(
        "/analyze",
        files={"file": ("IKEv2.pcap", pcap, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 413


def test_cors_does_not_combine_wildcard_and_credentials():
    cors = [m for m in app.user_middleware if "CORS" in m.cls.__name__]
    assert cors, "CORS middleware should be installed"
    kwargs = cors[0].kwargs
    origins = kwargs.get("allow_origins")
    credentials = kwargs.get("allow_credentials")
    assert not (origins == ["*"] and credentials is True)


def test_ikev1_sample_still_flags_ikev1():
    pcap = (SAMPLES / "IKEv1.pcap").read_bytes()
    response = client.post(
        "/analyze",
        files={"file": ("IKEv1.pcap", pcap, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 200
    body = response.json()
    ids = {f["id"] for f in body["findings"]}
    assert "IKE-001" in ids
    ike = next(f for f in body["findings"] if f["id"] == "IKE-001")
    assert ike["score"] == 30
    assert ike["severity"] == "critical"
    assert body["file_name"] == "IKEv1.pcap"
    assert body["packet_count"] > 0


def test_ikev2_sample_still_detects_ikev2():
    pcap = (SAMPLES / "IKEv2.pcap").read_bytes()
    response = client.post(
        "/analyze",
        files={"file": ("IKEv2.pcap", pcap, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["ikev2_packets"] >= 1
    ids = {f["id"] for f in body["findings"]}
    assert "IKE-002" in ids
    ike = next(f for f in body["findings"] if f["id"] == "IKE-002")
    assert ike["score"] == 0
