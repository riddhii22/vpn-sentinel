from app.main import app
from app.ml.train import train_baseline
from fastapi.testclient import TestClient

client = TestClient(app)


def test_train_refuses_without_labels():
    out = train_baseline()
    assert out["trained"] is False
    assert out["model_available"] is False
    assert out["samples_used"] == 0


def test_ml_status_endpoint():
    res = client.get("/ml/status")
    assert res.status_code == 200
    body = res.json()
    assert body["model_available"] is False
    assert "insufficient" in body["message"].lower()
