from datetime import datetime, timedelta, timezone

from app.core.access_controller import (
    IntegratedAccessController,
    RouteAuthorization,
)
from app.layers.layer4_api_gateway.gateway import APIGateway
from app.layers.layer4_api_gateway.schemas import GatewayRoute
from app.layers.layer6_iam.access_manager import IAMAccessManager
from app.layers.layer6_iam.schemas import (
    MFAStatus as IAMMFAStatus,
    Permission,
    Role,
    RolePermission,
    UserIdentity,
)
from app.layers.layer5_zero_trust.policy_engine import ZeroTrustPolicyEngine
from app.layers.layer5_zero_trust.schemas import ZeroTrustPolicy


def build_controller(*, user_active=True, mfa_verified=True):
    route = GatewayRoute(
        route_id="alerts-read",
        path="/api/alerts",
        methods=["GET"],
        backend_url="https://backend.example.test",
        auth_mode="bearer",
    )
    gateway = APIGateway(routes=[route])

    user = UserIdentity(
        user_id="user-001",
        username="analyst01",
        email="analyst01@example.test",
        roles=[Role.SECURITY_ANALYST],
        active=user_active,
        mfa_status=(
            IAMMFAStatus.VERIFIED
            if mfa_verified
            else IAMMFAStatus.NOT_ENROLLED
        ),
    )

    iam = IAMAccessManager(
        users=[user],
        role_permissions=[
            RolePermission(
                role=Role.SECURITY_ANALYST,
                permissions=[Permission.VIEW_ALERTS],
            )
        ],
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

    controller = IntegratedAccessController(
        gateway=gateway,
        iam=iam,
        zero_trust=zero_trust,
        route_authorizations={
            "alerts-read": RouteAuthorization(
                resource="alerts",
                permission=Permission.VIEW_ALERTS,
                action="read",
            )
        },
    )
    return controller


def authorize(controller, **overrides):
    args = {
        "request_id": "integration-test-request",
        "method": "GET",
        "path": "/api/alerts",
        "content_length": 0,
        "user_id": "user-001",
        "device_trust": "trusted",
        "source_ip": "192.0.2.10",
    }
    args.update(overrides)
    return controller.authorize(**args)


def test_authorizes_request_when_all_three_layers_allow():
    decision = authorize(build_controller())

    assert decision.allowed is True
    assert decision.status_code == 200
    assert decision.reason == "access_granted"
    assert decision.route_id == "alerts-read"


def test_gateway_denies_unknown_route():
    decision = authorize(
        build_controller(),
        path="/api/unknown",
    )

    assert decision.allowed is False
    assert decision.status_code == 404
    assert decision.reason == "route_not_found"


def test_gateway_denies_wrong_method():
    decision = authorize(
        build_controller(),
        method="POST",
    )

    assert decision.allowed is False
    assert decision.status_code == 405
    assert decision.reason == "method_not_allowed"


def test_iam_denies_inactive_user():
    decision = authorize(build_controller(user_active=False))

    assert decision.allowed is False
    assert decision.status_code == 403
    assert decision.reason == "iam_access_denied"


def test_iam_denies_user_without_verified_mfa():
    decision = authorize(
        build_controller(mfa_verified=False),
    )

    assert decision.allowed is False
    assert decision.reason == "iam_access_denied"


def test_zero_trust_denies_untrusted_device():
    decision = authorize(
        build_controller(),
        device_trust="untrusted",
    )

    assert decision.allowed is False
    assert decision.status_code == 403
    assert decision.reason == "device_trust_not_allowed"


def test_zero_trust_denies_unknown_device_by_default():
    decision = authorize(
        build_controller(),
        device_trust="unknown",
    )

    assert decision.allowed is False
    assert decision.reason == "device_trust_not_allowed"


def test_missing_route_authorization_fails_closed():
    controller = build_controller()
    controller.route_authorizations.clear()

    decision = authorize(controller)

    assert decision.allowed is False
    assert decision.status_code == 403
    assert decision.reason == "route_authorization_not_configured"


def test_disabled_gateway_route_is_denied():
    controller = build_controller()
    controller.gateway.get_route("alerts-read").enabled = False

    decision = authorize(controller)

    assert decision.allowed is False
    assert decision.status_code == 403
    assert decision.reason == "route_disabled"


def test_explicit_zero_trust_deny_policy_blocks_request():
    controller = build_controller()
    controller.zero_trust.add_policy(
        ZeroTrustPolicy(
            policy_id="alerts-extra-deny",
            resource="alerts",
            actions=["read"],
            effect="deny",
            require_mfa=False,
            allowed_device_trust=["trusted"],
        )
    )

    # Two matching policies are ambiguous; Zero Trust denies.
    decision = authorize(controller)

    assert decision.allowed is False
    assert decision.reason == "ambiguous_policies"


def test_invalid_request_metadata_is_denied():
    decision = authorize(
        build_controller(),
        content_length=-1,
    )

    assert decision.allowed is False
    assert decision.status_code == 400
    assert decision.reason == "invalid_request_metadata"