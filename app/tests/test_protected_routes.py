
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi.testclient import TestClient

from app.config import Settings
from app.core.auth_dependencies import get_authenticated_user
from app.layers.layer6_iam.schemas import UserIdentity
from app.main import create_app


def make_user() -> UserIdentity:
    """Create a minimal test user without depending on role enum names."""
    return UserIdentity.model_construct(
        user_id="user-123",
        username="test-user",
        email="test@example.com",
        roles=[],
    )


def make_app(controller=None, device_trust_resolver=None):
    app = create_app(
        settings=Settings(app_env="test"),
        access_controller=controller,
        device_trust_resolver=device_trust_resolver,
    )

    async def override_authenticated_user():
        return make_user()

    # Isolate endpoint authorization behavior from JWT/IAM dependency tests.
    app.dependency_overrides[get_authenticated_user] = (
        override_authenticated_user
    )
    return app


def test_alerts_fail_closed_when_authorization_is_not_configured():
    app = make_app()

    with TestClient(app) as client:
        response = client.get("/api/alerts")

    assert response.status_code == 503
    assert response.json()["detail"] == "authorization_not_configured"


def test_alerts_return_403_when_access_controller_denies():
    controller = SimpleNamespace(
        authorize=Mock(
            return_value=SimpleNamespace(
                allowed=False,
                status_code=403,
                reason="access_denied",
            )
        )
    )
    app = make_app(controller=controller)

    with TestClient(app) as client:
        response = client.get("/api/alerts")

    assert response.status_code == 403
    assert response.json()["detail"] == "access_denied"
    controller.authorize.assert_called_once()


def test_alerts_return_data_when_access_is_authorized():
    controller = SimpleNamespace(
        authorize=Mock(
            return_value=SimpleNamespace(
                allowed=True,
                status_code=200,
                reason="allowed",
            )
        )
    )
    app = make_app(controller=controller)

    with TestClient(app) as client:
        response = client.get("/api/alerts")

    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "ok"
    assert body["user_id"] == "user-123"
    assert body["data"] == []

    controller.authorize.assert_called_once()
    kwargs = controller.authorize.call_args.kwargs
    assert kwargs["user_id"] == "user-123"
    assert kwargs["device_trust"] == "unknown"
    assert kwargs["method"] == "GET"
    assert kwargs["path"] == "/api/alerts"


def test_device_trust_comes_from_server_side_resolver():
    controller = SimpleNamespace(
        authorize=Mock(
            return_value=SimpleNamespace(
                allowed=True,
                status_code=200,
                reason="allowed",
            )
        )
    )

    app = make_app(
        controller=controller,
        device_trust_resolver=lambda request, user: "trusted",
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/alerts",
            headers={"X-Device-Trust": "untrusted"},
        )

    assert response.status_code == 200

    kwargs = controller.authorize.call_args.kwargs
    assert kwargs["device_trust"] == "trusted"
