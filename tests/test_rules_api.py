from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_rules_endpoint_lists_yaml_policy():
    res = client.get("/rules")
    assert res.status_code == 200
    body = res.json()
    ids = {r["id"] for r in body["rules"]}
    assert "IKE-001" in ids
    assert "IKE-002" in ids
    ike = next(r for r in body["rules"] if r["id"] == "IKE-001")
    assert ike["score"] == 30
    assert ike["when"] == "ikev1_present"
    assert "min(100" in body["formula"]
    assert "not an ML" in body["note"].lower() or "not an ML" in body["note"]
