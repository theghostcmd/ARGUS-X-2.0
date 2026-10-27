
from datetime import datetime, timezone

from app.layers.layer5_zero_trust.schemas import (
    AccessDecision,
    AccessRequest,
    ZeroTrustPolicy,
)


class ZeroTrustPolicyEngine:
    """
    Evaluates access requests using explicit Zero Trust policies.

    Security behavior:
    - Default deny when no policy matches.
    - Deny if the device is not trusted when trust is required.
    - Deny if required MFA is not verified.
    - Deny if multiple enabled policies match the same request.
    - Disabled policies are ignored.

    MFA status and device trust must come from trusted,
    server-verified sources in a real deployment.
    """

    def __init__(
        self,
        policies: list[ZeroTrustPolicy] | None = None,
    ) -> None:
        self._policies: dict[str, ZeroTrustPolicy] = {}

        for policy in policies or []:
            self.add_policy(policy)

    def add_policy(self, policy: ZeroTrustPolicy) -> None:
        """Register a policy and reject duplicate policy IDs."""
        if policy.policy_id in self._policies:
            raise ValueError(
                f"Duplicate policy ID: {policy.policy_id}"
            )

        self._policies[policy.policy_id] = policy

    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy. Return False if it does not exist."""
        return self._policies.pop(policy_id, None) is not None

    def list_policies(self) -> list[ZeroTrustPolicy]:
        """Return all configured policies."""
        return list(self._policies.values())

    def evaluate(self, request: AccessRequest) -> AccessDecision:
        """Evaluate an access request against enabled policies."""
        now = datetime.now(timezone.utc)

        def deny(
            reason: str,
            policy_id: str | None = None,
        ) -> AccessDecision:
            return AccessDecision(
                allowed=False,
                request_id=request.request_id,
                policy_id=policy_id,
                reason=reason,
                evaluated_at=now,
            )

        matching = [
            policy
            for policy in self._policies.values()
            if policy.enabled
            and policy.resource == request.resource
            and request.action in policy.actions
        ]

        if not matching:
            return deny("no_matching_policy")

        # Ambiguous policies must not accidentally grant access.
        if len(matching) > 1:
            return deny("ambiguous_policies")

        policy = matching[0]

        if policy.effect == "deny":
            return deny("explicitly_denied", policy.policy_id)

        if policy.require_mfa and request.mfa_status != "verified":
            return deny("mfa_required", policy.policy_id)

        if request.device_trust not in policy.allowed_device_trust:
            return deny("device_trust_not_allowed", policy.policy_id)

        return AccessDecision(
            allowed=True,
            request_id=request.request_id,
            policy_id=policy.policy_id,
            reason="policy_matched",
            evaluated_at=now,
        )
