
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_health_endpoint():
    settings = Settings(
        app_env="test",
        rate_limit_backend="memory",
    )

    with TestClient(create_app(settings)) as client:
        response = client.get("/health")

        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.headers.get("x-request-id")
