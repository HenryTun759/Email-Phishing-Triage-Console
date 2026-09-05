import os
os.environ["DATABASE_URL"] = "sqlite:///./test_api.db"

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_unauthorized_target_cannot_scan():
    target = client.post("/api/targets", json={"name":"Nope","host":"127.0.0.1","port":8000,"authorized":False})
    assert target.status_code == 201
    scan = client.post("/api/scans", json={"target_id":target.json()["id"]})
    assert scan.status_code == 403
