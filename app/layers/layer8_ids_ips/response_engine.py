
from app.layers.layer8_ids_ips.schemas import (
    DetectionAction,
    ResponseDecision,
    ResponseRequest,
    ThreatAlert,
    ThreatSeverity,
)


class IDSIPSResponseEngine:
    """
    Determines a response to an IDS alert.

    This component makes response decisions only. It does not change
    firewall rules or block network traffic by itself.
    """

    def __init__(
        self,
        auto_block_enabled: bool = False,
        block_severities: set[ThreatSeverity] | None = None,
    ) -> None:
        self.auto_block_enabled = auto_block_enabled

        self.block_severities = (
            block_severities
            if block_severities is not None
            else {ThreatSeverity.CRITICAL}
        )

    def respond(self, alert: ThreatAlert) -> ResponseDecision:
        """Generate a response decision from a detection alert."""

        if alert.action == DetectionAction.MONITOR:
            return ResponseDecision(
                alert_id=alert.alert_id,
                action=DetectionAction.MONITOR,
                executed=False,
                message="Event recorded for monitoring; no blocking performed.",
            )

        if alert.action == DetectionAction.ALERT:
            return ResponseDecision(
                alert_id=alert.alert_id,
                action=DetectionAction.ALERT,
                executed=False,
                message="Security alert generated; no blocking performed.",
            )

        # A BLOCK recommendation is not the same as an enforced block.
        if not self.auto_block_enabled:
            return ResponseDecision(
                alert_id=alert.alert_id,
                action=DetectionAction.BLOCK,
                executed=False,
                message=(
                    "Blocking recommended but not executed because "
                    "automatic blocking is disabled."
                ),
            )

        if alert.severity not in self.block_severities:
            return ResponseDecision(
                alert_id=alert.alert_id,
                action=DetectionAction.BLOCK,
                executed=False,
                message=(
                    "Blocking recommended but not executed because "
                    "the alert severity is not approved for auto-blocking."
                ),
            )

        return ResponseDecision(
            alert_id=alert.alert_id,
            action=DetectionAction.BLOCK,
            executed=False,
            message=(
                "Alert meets the configured auto-block policy. "
                "An external enforcement adapter is still required; "
                "no network block was executed."
            ),
        )

    def evaluate_request(
        self,
        request: ResponseRequest,
        severity: ThreatSeverity,
    ) -> ResponseDecision:
        """
        Evaluate a response request against the configured policy.

        This method does not trust the requested action alone.
        It checks the configured policy and severity before recommending
        a block. No external network action is performed.
        """

        if request.action == DetectionAction.MONITOR:
            return ResponseDecision(
                alert_id=request.alert_id,
                action=DetectionAction.MONITOR,
                executed=False,
                message="Monitoring requested; no network action performed.",
            )

        if request.action == DetectionAction.ALERT:
            return ResponseDecision(
                alert_id=request.alert_id,
                action=DetectionAction.ALERT,
                executed=False,
                message="Alert requested; no network action performed.",
            )

        if not self.auto_block_enabled:
            return ResponseDecision(
                alert_id=request.alert_id,
                action=DetectionAction.BLOCK,
                executed=False,
                message="Block rejected by policy: automatic blocking is disabled.",
            )

        if severity not in self.block_severities:
            return ResponseDecision(
                alert_id=request.alert_id,
                action=DetectionAction.BLOCK,
                executed=False,
                message="Block rejected by policy: severity is not approved.",
            )

        return ResponseDecision(
            alert_id=request.alert_id,
            action=DetectionAction.BLOCK,
            executed=False,
            message=(
                f"Block recommendation accepted for review: {request.reason}. "
                "No network block was executed."
            ),
        )
