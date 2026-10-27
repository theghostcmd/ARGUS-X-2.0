
from datetime import datetime, timezone

from app.layers.layer8_ids_ips.detection_engine import IDSDetectionEngine
from app.layers.layer8_ids_ips.schemas import (
    DetectionRule,
    EventType,
    SecurityEvent,
    ThreatAlert,
    ThreatSeverity,
)
from app.layers.layer11_intelligence.intelligence_engine import (
    IntelligenceEngine,
)
from app.layers.layer11_intelligence.schemas import (
    IntelligenceAnalysisResult,
    IntelligenceEvent,
    IntelligenceEventType,
    IntelligenceRule,
    IntelligenceSeverity,
)
# Explicit, conservative default rules.
# These rules generate alerts/findings only; they do not block traffic.
DEFAULT_DETECTION_RULES = [
    DetectionRule(
        rule_id="auth-failure-detection",
        name="Authentication failure detection",
        description="An authentication failure was observed.",
        event_types=[EventType.AUTHENTICATION_FAILURE],
        severity=ThreatSeverity.HIGH,
    ),
    DetectionRule(
        rule_id="port-scan-detection",
        name="Port scan detection",
        description="A port scan event was observed.",
        event_types=[EventType.PORT_SCAN],
        severity=ThreatSeverity.HIGH,
    ),
    DetectionRule(
        rule_id="suspicious-payload-detection",
        name="Suspicious payload detection",
        description="A suspicious payload event was observed.",
        event_types=[EventType.SUSPICIOUS_PAYLOAD],
        severity=ThreatSeverity.HIGH,
    ),
]

DEFAULT_INTELLIGENCE_RULES = [
    IntelligenceRule(
        rule_id="repeated-auth-failures",
        name="Repeated authentication failures",
        event_types=[IntelligenceEventType.AUTHENTICATION_FAILURE],
        minimum_events=3,
        window_seconds=300,
        severity=IntelligenceSeverity.HIGH,
        description=(
            "Multiple authentication failures were correlated "
            "within five minutes."
        ),
    ),
]

class SecurityIntelligenceService:
    """Connect Layer 8 detection to Layer 11 batch correlation."""

    def __init__(
        self,
        detection_rules: list[DetectionRule] | None = None,
        intelligence_rules: list[IntelligenceRule] | None = None,
    ) -> None:
        self.detection_engine = IDSDetectionEngine(
            detection_rules
            if detection_rules is not None
            else DEFAULT_DETECTION_RULES
        )
        self.intelligence_engine = IntelligenceEngine(
            intelligence_rules
            if intelligence_rules is not None
            else DEFAULT_INTELLIGENCE_RULES
        )

    @staticmethod
    def _to_intelligence_event(
        event: SecurityEvent,
    ) -> IntelligenceEvent:
        event_type_map = {
            EventType.AUTHENTICATION_FAILURE:
                IntelligenceEventType.AUTHENTICATION_FAILURE,
            EventType.PORT_SCAN:
                IntelligenceEventType.PORT_SCAN,
            EventType.POLICY_VIOLATION:
                IntelligenceEventType.POLICY_VIOLATION,
            EventType.SUSPICIOUS_PAYLOAD:
                IntelligenceEventType.MALICIOUS_REQUEST,
            EventType.NETWORK_CONNECTION:
                IntelligenceEventType.OTHER,
            EventType.RATE_ANOMALY:
                IntelligenceEventType.OTHER,
        }

        attributes = dict(event.attributes)
        attributes.update(
            {
                "destination_ip": event.destination_ip,
                "destination_port": event.destination_port,
                "protocol": event.protocol,
            }
        )

        return IntelligenceEvent(
            event_id=event.event_id,
            event_type=event_type_map[event.event_type],
            source_ip=event.source_ip,
            principal=event.username,
            asset_id=event.destination_ip,
            description=event.description,
            occurred_at=event.timestamp,
            confidence=0.8,
            attributes=attributes,
        )

    def analyze_batch(
        self,
        events: list[SecurityEvent],
        *,
        now: datetime | None = None,
    ) -> dict:
        """Return Layer 8 alerts and Layer 11 correlated findings."""

        if now is not None and now.tzinfo is None:
            raise ValueError("now must be timezone-aware")

        # Layer 8: inspect every supplied event.
        alerts: list[ThreatAlert] = []
        for event in events:
            alerts.extend(self.detection_engine.inspect(event))

        # Layer 11: map the same batch and correlate it.
        intelligence_events = [
            self._to_intelligence_event(event)
            for event in events
        ]

        analysis: IntelligenceAnalysisResult = (
            self.intelligence_engine.analyze(
                intelligence_events,
                now=now or datetime.now(timezone.utc),
            )
        )

        return {
            "processed_events": len(events),
            "alerts": [
                alert.model_dump(mode="json")
                for alert in alerts
            ],
            "intelligence": analysis.model_dump(mode="json"),
            "message": (
                f"Processed {len(events)} events; generated "
                f"{len(alerts)} detection alerts and "
                f"{len(analysis.findings)} intelligence findings."
            ),
        }
