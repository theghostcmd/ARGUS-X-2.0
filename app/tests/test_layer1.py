
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_rate_limit_blocks_excess_requests():
    settings = Settings(
        app_env="test",
        rate_limit_backend="memory",
        rate_limit_requests=2,
        rate_limit_window_seconds=60,
        rate_limit_block_seconds=10,
    )

    with TestClient(create_app(settings)) as client:
        first = client.get("/")
        second = client.get("/")
        third = client.get("/")

        assert first.status_code == 200
        assert second.status_code == 200
        assert third.status_code == 429
        assert third.json()["error"] == "too_many_requests"


def test_health_endpoint_is_not_rate_limited():
    settings = Settings(
        app_env="test",
        rate_limit_backend="memory",
        rate_limit_requests=1,
    )

    with TestClient(create_app(settings)) as client:
        client.get("/")
        client.get("/")

        health = client.get("/health")
        assert health.status_code == 200
