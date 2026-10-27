from dataclasses import dataclass
from typing import Mapping

from pydantic import ValidationError

from app.layers.layer4_api_gateway.gateway import APIGateway
from app.layers.layer4_api_gateway.schemas import GatewayRequestMetadata
from app.layers.layer6_iam.access_manager import IAMAccessManager
from app.layers.layer6_iam.schemas import (
    AccessRequest as IAMAccessRequest,
    MFAStatus as IAMMFAStatus,
    Permission,
)
from app.layers.layer5_zero_trust.policy_engine import ZeroTrustPolicyEngine
from app.layers.layer5_zero_trust.schemas import (
    AccessAction,
    AccessRequest as ZeroTrustAccessRequest,
    DeviceTrust,
    MFAStatus as ZeroTrustMFAStatus,
)


@dataclass(frozen=True)
class RouteAuthorization:
    """Server-configured authorization requirements for a gateway route."""

    resource: str
    permission: Permission
    action: AccessAction


@dataclass(frozen=True)
class IntegratedAccessDecision:
    """Combined decision from API Gateway, IAM and Zero Trust."""

    allowed: bool
    status_code: int
    reason: str
    route_id: str | None = None


class IntegratedAccessController:
    """
    Coordinates the existing Layer 4, Layer 6 and Layer 5 policy engines.

    This class does not authenticate HTTP credentials or forward requests.
    The caller must provide a user identity established by a trusted
    authentication mechanism. Device trust must also come from a trusted
    server-side posture verifier, not a client-supplied header.
    """

    def __init__(
        self,
        gateway: APIGateway,
        iam: IAMAccessManager,
        zero_trust: ZeroTrustPolicyEngine,
        route_authorizations: Mapping[str, RouteAuthorization],
    ) -> None:
        self.gateway = gateway
        self.iam = iam
        self.zero_trust = zero_trust
        self.route_authorizations = dict(route_authorizations)

    def authorize(
        self,
        *,
        request_id: str,
        method: str,
        path: str,
        content_length: int,
        user_id: str,
        device_trust: DeviceTrust = "unknown",
        source_ip: str | None = None,
    ) -> IntegratedAccessDecision:
        # 1. Validate and select the configured gateway route.
        try:
            gateway_request = GatewayRequestMetadata(
                request_id=request_id,
                method=method.upper(),
                path=path,
                content_length=content_length,
            )
        except (ValidationError, TypeError, ValueError):
            return IntegratedAccessDecision(
                allowed=False,
                status_code=400,
                reason="invalid_request_metadata",
            )

        gateway_decision = self.gateway.evaluate(gateway_request)

        if not gateway_decision.allowed or not gateway_decision.route_id:
            return IntegratedAccessDecision(
                allowed=False,
                status_code=gateway_decision.status_code,
                reason=gateway_decision.reason,
                route_id=gateway_decision.route_id,
            )

        route_id = gateway_decision.route_id

        # Authorization requirements must be configured by the server.
        requirements = self.route_authorizations.get(route_id)
        if requirements is None:
            return IntegratedAccessDecision(
                allowed=False,
                status_code=403,
                reason="route_authorization_not_configured",
                route_id=route_id,
            )

        # 2. IAM checks active user, verified MFA and RBAC permission.
        iam_request = IAMAccessRequest(
            request_id=request_id,
            user_id=user_id,
            permission=requirements.permission,
            resource=requirements.resource,
        )

        if not self.iam.authorize(iam_request):
            return IntegratedAccessDecision(
                allowed=False,
                status_code=403,
                reason="iam_access_denied",
                route_id=route_id,
            )

        user = self.iam.get_user(user_id)
        if user is None or not user.active:
            return IntegratedAccessDecision(
                allowed=False,
                status_code=403,
                reason="inactive_or_unknown_user",
                route_id=route_id,
            )

        # MFA status is derived from the server-side IAM user record.
        mfa_verified = user.mfa_status == IAMMFAStatus.VERIFIED
        zero_trust_mfa: ZeroTrustMFAStatus = (
            "verified" if mfa_verified else "not_verified"
        )

        # 3. Zero Trust evaluates the server-configured resource/action.
        # device_trust must be supplied by a trusted server-side verifier.
        try:
            zero_trust_request = ZeroTrustAccessRequest(
                request_id=request_id,
                subject_id=user.user_id,
                resource=requirements.resource,
                action=requirements.action,
                device_trust=device_trust,
                mfa_status=zero_trust_mfa,
                source_ip=source_ip,
            )
        except (ValidationError, TypeError, ValueError):
            return IntegratedAccessDecision(
                allowed=False,
                status_code=403,
                reason="invalid_zero_trust_context",
                route_id=route_id,
            )

        zero_trust_decision = self.zero_trust.evaluate(
            zero_trust_request
        )

        if not zero_trust_decision.allowed:
            return IntegratedAccessDecision(
                allowed=False,
                status_code=403,
                reason=zero_trust_decision.reason,
                route_id=route_id,
            )

        return IntegratedAccessDecision(
            allowed=True,
            status_code=200,
            reason="access_granted",
            route_id=route_id,
        )