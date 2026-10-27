
from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient

from app.config import Settings
from app.core.access_controller import (
    IntegratedAccessController,
    RouteAuthorization,
)
from app.core.authentication import JWTAuthenticator
from app.layers.layer4_api_gateway.gateway import APIGateway
from app.layers.layer4_api_gateway.schemas import GatewayRoute
from app.layers.layer5_zero_trust.policy_engine import ZeroTrustPolicyEngine
from app.layers.layer5_zero_trust.schemas import ZeroTrustPolicy
from app.layers.layer6_iam.access_manager import IAMAccessManager
from app.layers.layer6_iam.schemas import (
    MFAStatus,
    Permission,
    Role,
    RolePermission,
    UserIdentity,
)
from app.main import create_app


TEST_SECRET = "test-only-secret-key-at-least-32-bytes"
TEST_ISSUER = "argus-x"
TEST_AUDIENCE = "argus-x-api"


def make_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)

    return jwt.encode(
        {
            "sub": user_id,
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "iat": now,
            "exp": now + timedelta(minutes=10),
        },
        TEST_SECRET,
        algorithm="HS256",
    )


def make_user(user_id: str = "user-123") -> UserIdentity:
    return UserIdentity(
        user_id=user_id,
        username=user_id,
        email=f"{user_id}@example.com",
        roles=[Role.VIEWER],
        active=True,
        mfa_status=MFAStatus.VERIFIED,
    )


def make_test_app(
    *,
    user: UserIdentity | None = None,
    permissions: list[Permission] | None = None,
    device_trust: str = "trusted",
):
    if permissions is None:
        permissions = [Permission.VIEW_ALERTS]

    iam = IAMAccessManager(
        role_permissions=[
            RolePermission(
                role=Role.VIEWER,
                permissions=permissions,
            )
        ]
    )

    if user is not None:
        iam.add_user(user)

    authenticator = JWTAuthenticator(
        secret=TEST_SECRET,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
    )

    gateway = APIGateway(
        routes=[
            GatewayRoute(
                route_id="alerts-read",
                path="/api/alerts",
                methods=["GET"],
                backend_url="http://127.0.0.1:8000",
                auth_mode="bearer",
            )
        ]
    )

    zero_trust = ZeroTrustPolicyEngine(
        policies=[
            ZeroTrustPolicy(
                policy_id="alerts-read-policy",
                resource="alerts",
                actions=["read"],
                effect="allow",
                require_mfa=True,
                allowed_device_trust=["trusted"],
            )
        ]
    )

    route_authorizations = {
        "alerts-read": RouteAuthorization(
            resource="alerts",
            permission=Permission.VIEW_ALERTS,
            action="read",
        )
    }

    controller = IntegratedAccessController(
        gateway=gateway,
        iam=iam,
        zero_trust=zero_trust,
        route_authorizations=route_authorizations,
    )

    settings = Settings(
        _env_file=None,
        app_env="test",
        jwt_secret=TEST_SECRET,
        jwt_issuer=TEST_ISSUER,
        jwt_audience=TEST_AUDIENCE,
    )

    app = create_app(
        settings=settings,
        jwt_authenticator=authenticator,
        iam_manager=iam,
        access_controller=controller,
        device_trust_resolver=lambda request, identity: device_trust,
    )

    return app


def test_valid_jwt_and_authorized_user_can_access_alerts():
    user = make_user()
    app = make_test_app(user=user)

    with TestClient(
        app,
        client=("127.0.0.1", 50000),
    ) as client:
        response = client.get(
            "/api/alerts",
            headers={
                "Authorization": f"Bearer {make_token(user.user_id)}"
            },
        )

    assert response.status_code == 200, response.text
    assert response.json()["user_id"] == user.user_id
    assert response.json()["data"] == []


def test_missing_jwt_is_rejected():
    app = make_test_app(user=make_user())

    with TestClient(
        app,
        client=("127.0.0.1", 50001),
    ) as client:
        response = client.get("/api/alerts")

    assert response.status_code == 401


def test_jwt_for_unknown_user_is_rejected():
    app = make_test_app(user=make_user("known-user"))

    with TestClient(
        app,
        client=("127.0.0.1", 50002),
    ) as client:
        response = client.get(
            "/api/alerts",
            headers={
                "Authorization": f"Bearer {make_token('unknown-user')}"
            },
        )

    assert response.status_code == 401


def test_user_without_alert_permission_is_denied():
    user = make_user()
    app = make_test_app(user=user, permissions=[])

    with TestClient(
        app,
        client=("127.0.0.1", 50003),
    ) as client:
        response = client.get(
            "/api/alerts",
            headers={
                "Authorization": f"Bearer {make_token(user.user_id)}"
            },
        )

    assert response.status_code == 403


def test_untrusted_device_is_denied():
    user = make_user()
    app = make_test_app(user=user, device_trust="untrusted")

    with TestClient(
        app,
        client=("127.0.0.1", 50004),
    ) as client:
        response = client.get(
            "/api/alerts",
            headers={
                "Authorization": f"Bearer {make_token(user.user_id)}"
            },
        )

    assert response.status_code == 403
