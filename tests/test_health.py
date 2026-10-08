"""Phase 1: prove the FastAPI app imports and /health works.

T-API-01 (upload hardening) is not covered here on purpose.
"""

from app.main import app
from fastapi.testclient import TestClient


def test_app_importable():
    assert app.title == "VPN Sentinel Analyzer"


def test_health_ok():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_api_health_alias():
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
