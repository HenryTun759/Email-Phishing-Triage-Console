import os

os.environ["DATABASE_URL"] = "sqlite:///./test_api.db"

from fastapi.testclient import TestClient

from app.main import app
from app.models import User
from app.auth import hash_password
from app.database import SessionLocal

client = TestClient(app)


def _login() -> dict[str, str]:
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "admin").first()
        if not user:
            user = User(username="admin", password_hash=hash_password("CI-Test-Password-123!"), role="admin", is_active=True)
            db.add(user)
            db.commit()
    response = client.post(
        "/api/auth/login",
        data={"username": "admin", "password": "CI-Test-Password-123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_unauthorized_target_cannot_scan():
    headers = _login()
    target = client.post(
        "/api/targets",
        json={"name": "Nope", "host": "127.0.0.1", "port": 8000, "authorized": False},
        headers=headers,
    )
    assert target.status_code == 201
    scan = client.post("/api/scans", json={"target_id": target.json()["id"]}, headers=headers)
    assert scan.status_code == 403
