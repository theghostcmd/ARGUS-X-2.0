
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core.auth_dependencies import get_authenticated_user
from app.core.authentication import JWTAuthenticator
from app.layers.layer6_iam.access_manager import IAMAccessManager
from app.layers.layer6_iam.schemas import (
    MFAStatus,
    Role,
    UserIdentity,
)


SECRET = "test-only-secret-key-with-at-least-32-bytes"
ISSUER = "argus-x-test"
AUDIENCE = "argus-x-api"


def make_token(
    *,
    subject="user-001",
    roles=None,
    mfa_status="verified",
    secret=SECRET,
):
    now = datetime.now(timezone.utc)

    claims = {
        "sub": subject,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=5),
        # These claims must NOT override IAM's user record.
        "roles": roles or ["admin"],
        "mfa_status": mfa_status,
    }

    return jwt.encode(claims, secret, algorithm="HS256")


def make_client(*, user_active=True, configure=True):
    app = FastAPI()

    if configure:
        app.state.jwt_authenticator = JWTAuthenticator(
            secret=SECRET,
            issuer=ISSUER,
            audience=AUDIENCE,
        )

        app.state.iam_manager = IAMAccessManager(
            users=[
                UserIdentity(
                    user_id="user-001",
                    username="viewer01",
                    email="viewer01@example.test",
                    roles=[Role.VIEWER],
                    active=user_active,
                    mfa_status=MFAStatus.NOT_ENROLLED,
                )
            ]
        )

    @app.get("/protected")
    async def protected(user: UserIdentity = Depends(get_authenticated_user)):
        return {
            "user_id": user.user_id,
            "roles": [role.value for role in user.roles],
            "mfa_status": user.mfa_status.value,
        }

    return TestClient(app)


def test_valid_token_resolves_user_from_server_side_iam():
    client = make_client()

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {make_token()}"},
    )

    assert response.status_code == 200
    assert response.json()["user_id"] == "user-001"


def test_token_role_and_mfa_claims_do_not_override_iam():
    client = make_client()

    token = make_token(
        roles=["admin"],
        mfa_status="verified",
    )

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["roles"] == ["viewer"]
    assert response.json()["mfa_status"] == "not_enrolled"


def test_missing_token_is_rejected():
    client = make_client()

    response = client.get("/protected")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_unknown_user_is_rejected():
    client = make_client()

    token = make_token(subject="unknown-user")

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_inactive_user_is_rejected():
    client = make_client(user_active=False)

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {make_token()}"},
    )

    assert response.status_code == 401


def test_authentication_fails_closed_when_not_configured():
    client = make_client(configure=False)

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {make_token()}"},
    )

    assert response.status_code == 503


def test_invalid_signature_is_rejected():
    client = make_client()

    token = make_token(
        secret="another-test-secret-key-with-32-bytes",
    )

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
