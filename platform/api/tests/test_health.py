import os

os.environ["SESSION_SECRET"] = "test-secret"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["ENVIRONMENT"] = "test"
os.environ["AUTO_CREATE_SCHEMA"] = "false"

from fastapi.testclient import TestClient
from app.main import app

def test_healthz():
    with TestClient(app) as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"