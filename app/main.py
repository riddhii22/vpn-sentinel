"""FastAPI layer: upload hardening + one analysis pass."""

import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from scapy.all import rdpcap
from starlette.requests import Request

from app.analyzer import analyze_packets
from app.analyzer.rules import load_rules
from app.ml.train import train_baseline
from app.risk import FORMULA_DOC

MAX_UPLOAD_BYTES = 20 * 1024 * 1024
_READ_CHUNK = 1024 * 1024
_PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
)

app = FastAPI(title="VPN Sentinel Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


def _safe_filename(name: str | None) -> str:
    if not name:
        return "capture.pcap"
    base = Path(name.replace("\x00", "")).name.strip()
    return base or "capture.pcap"


def _looks_like_pcap(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] in _PCAP_MAGICS


async def _read_upload_capped(upload: UploadFile) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = await upload.read(_READ_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail="Capture exceeds the 20 MB lab upload limit.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


@app.exception_handler(Exception)
async def unexpected_error(_request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        raise exc
    return JSONResponse(
        status_code=500,
        content={"detail": "Analysis failed unexpectedly. The capture could not be processed."},
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/rules")
def list_rules():
    """Public policy document. Analyzer facts vs YAML decisions stay separate."""
    doc = load_rules()
    rules = []
    for rule in doc.get("rules") or []:
        if not isinstance(rule, dict) or not rule.get("id"):
            continue
        rules.append(
            {
                "id": rule.get("id"),
                "when": rule.get("when"),
                "title": rule.get("title"),
                "severity": rule.get("severity"),
                "score": int(rule.get("score") or 0),
                "description": rule.get("description", ""),
                "recommendation": rule.get("recommendation", ""),
                "origin": rule.get("origin") or "security_rule",
            }
        )
    return {
        "formula": FORMULA_DOC,
        "rules": rules,
        "note": (
            "Crypto/protocol findings come from these rules applied to parsed facts. "
            "ESP-ANOM is IsolationForest telemetry (origin ml_anomaly) and does not set the VPN risk score. "
            "This is not an ML model for IKE fields or inner traffic type."
        ),
    }


@app.get("/ml/status")
def ml_status():
    """Honest model status. Never invents a class or confidence."""
    return train_baseline()


@app.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    file_name = _safe_filename(file.filename)
    file_bytes = await _read_upload_capped(file)

    if not file_bytes:
        raise HTTPException(status_code=400, detail="The capture is empty.")
    if not _looks_like_pcap(file_bytes):
        raise HTTPException(
            status_code=400,
            detail="File is not a PCAP/PCAPNG capture (unrecognized header).",
        )

    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix="vpn-sentinel-",
            suffix=".pcap",
            dir=tempfile.gettempdir(),
        )
        try:
            os.write(fd, file_bytes)
        finally:
            os.close(fd)
        try:
            packets = rdpcap(tmp_path)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Could not parse capture (malformed PCAP).",
            ) from None
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    if len(packets) == 0:
        raise HTTPException(status_code=400, detail="The capture contains no packets.")

    try:
        return analyze_packets(packets, file_name)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Analysis failed unexpectedly. The capture could not be processed.",
        ) from None


# Same-origin aliases so the built UI can run without the Vite proxy.
app.add_api_route("/api/analyze", analyze_pcap, methods=["POST"])
app.add_api_route("/api/health", health, methods=["GET"])
app.add_api_route("/api/rules", list_rules, methods=["GET"])
app.add_api_route("/api/ml/status", ml_status, methods=["GET"])

_SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
if _SAMPLES_DIR.is_dir():
    app.mount("/samples", StaticFiles(directory=str(_SAMPLES_DIR)), name="samples")

_DIST_DIR = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _DIST_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_DIST_DIR), html=True), name="ui")
