
from uuid import uuid4

from app.layers.layer8_ids_ips.schemas import (
    DetectionAction,
    DetectionRule,
    SecurityEvent,
    ThreatAlert,
)


class IDSDetectionEngine:
    """
    Evaluates normalized security events against configured detection rules.

    This engine performs rule-based detection only. It does not inspect
    raw network packets or automatically block network traffic.
    """

    def __init__(
        self,
        rules: list[DetectionRule] | None = None,
    ) -> None:
        self._rules: dict[str, DetectionRule] = {}

        for rule in rules or []:
            self.add_rule(rule)

    def add_rule(self, rule: DetectionRule) -> None:
        """Add a detection rule with a unique ID."""

        if rule.rule_id in self._rules:
            raise ValueError(
                f"Detection rule already exists: {rule.rule_id}"
            )

        self._rules[rule.rule_id] = rule

    def get_rules(self) -> list[DetectionRule]:
        """Return a copy of the registered rules list."""

        return list(self._rules.values())

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule. Return False if the rule does not exist."""

        return self._rules.pop(rule_id, None) is not None

    @staticmethod
    def _matches(
        event: SecurityEvent,
        rule: DetectionRule,
    ) -> bool:
        """Check event type and exact attribute conditions."""

        if event.event_type not in rule.event_types:
            return False

        for key, expected_value in rule.attribute_equals.items():
            if key not in event.attributes:
                return False

            actual_value = event.attributes[key]

            # Avoid treating True as the integer 1, or False as 0.
            if type(actual_value) is not type(expected_value):
                return False

            if actual_value != expected_value:
                return False

        return True

    def inspect(self, event: SecurityEvent) -> list[ThreatAlert]:
        """
        Evaluate an event and return all matching alerts.

        Matching rules are evaluated in ascending priority order.
        Lower numeric priority values are evaluated first.
        """

        matching_rules = [
            rule
            for rule in self._rules.values()
            if rule.enabled and self._matches(event, rule)
        ]

        matching_rules.sort(
            key=lambda rule: (rule.priority, rule.rule_id)
        )

        alerts: list[ThreatAlert] = []

        for rule in matching_rules:
            alerts.append(
                ThreatAlert(
                    alert_id=f"alert-{uuid4().hex}",
                    event_id=event.event_id,
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    action=rule.action,
                    message=(
                        f"Rule '{rule.name}' matched event "
                        f"'{event.event_id}'. {rule.description}"
                    ).strip(),
                )
            )

        return alerts

    def inspect_one(
        self,
        event: SecurityEvent,
    ) -> ThreatAlert | None:
        """
        Return the highest-priority matching alert, if one exists.

        Use inspect() when every matching rule should generate an alert.
        """

        alerts = self.inspect(event)

        if not alerts:
            return None

        return alerts[0]
