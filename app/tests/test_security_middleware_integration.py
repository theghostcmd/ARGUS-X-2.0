from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def make_settings(**overrides):
    values = {
        "app_env": "test",
        "rate_limit_backend": "memory",
        "rate_limit_requests": 100,
        "rate_limit_window_seconds": 60,
        "rate_limit_block_seconds": 60,
        "application_security_enabled": True,
        "application_security_max_body_bytes": 1_048_576,
    }
    values.update(overrides)
    return Settings(**values)


def test_health_endpoint_has_request_id_and_security_header():
    app = create_app(make_settings())

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers.get("x-request-id")
    assert response.headers.get("x-content-type-options") == "nosniff"


def test_disallowed_http_method_is_blocked():
    app = create_app(make_settings())

    with TestClient(app) as client:
        response = client.request("TRACE", "/")

    assert response.status_code == 403
    assert response.json()["error"] == "request_blocked"
    assert response.headers.get("x-request-id")


def test_request_body_is_replayed_to_fastapi_route():
    app = create_app(make_settings())

    @app.post("/integration-test/echo")
    async def echo(payload: dict):
        return {"received": payload}

    payload = {"message": "hello from ARGUS-X"}

    with TestClient(app) as client:
        response = client.post("/integration-test/echo", json=payload)

    assert response.status_code == 200
    assert response.json() == {"received": payload}
    assert response.headers.get("x-request-id")


def test_oversized_request_body_is_blocked():
    app = create_app(
        make_settings(application_security_max_body_bytes=8)
    )

    @app.post("/integration-test/large")
    async def large(payload: dict):
        return {"received": payload}

    with TestClient(app) as client:
        response = client.post(
            "/integration-test/large",
            json={"message": "this body is too large"},
        )

    assert response.status_code == 413
    assert response.json()["error"] == "request_blocked"
    assert response.headers.get("x-request-id")


def test_application_security_can_be_disabled():
    app = create_app(
        make_settings(application_security_enabled=False)
    )

    with TestClient(app) as client:
        response = client.request("TRACE", "/")

    # With Layer 9 disabled, FastAPI handles the unsupported method.
    assert response.status_code == 405