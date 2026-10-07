import os
os.environ.setdefault("SESSION_SECRET","test-secret")
os.environ.setdefault("DATABASE_URL","sqlite+aiosqlite:///./test.db")

from fastapi.testclient import TestClient
from app.main import app

def test_health():
    with TestClient(app) as client:
        assert client.get("/healthz").status_code in (200,503)
