import os

os.environ.setdefault("JWT_SECRET", "test-secret-that-is-at-least-32-characters-long")
os.environ.setdefault("ADMIN_PASSWORD", "Test-Admin-Password-123!")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_suite.db")

from fastapi.testclient import TestClient
import pytest

from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
