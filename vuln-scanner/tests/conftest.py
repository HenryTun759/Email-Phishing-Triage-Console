import os
os.environ.setdefault("JWT_SECRET", "test-secret-change-me")
os.environ.setdefault("ADMIN_PASSWORD", "Test-Admin-Password-123!")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_suite.db")

from fastapi.testclient import TestClient
from app.main import app

import pytest

@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
