
from collections import defaultdict
from datetime import datetime, timezone
from uuid import uuid4

from app.layers.layer11_intelligence.schemas import (
    IntelligenceAnalysisResult,
    IntelligenceEvent,
    IntelligenceEventType,
    IntelligenceFinding,
    IntelligenceRule,
    IntelligenceSeverity,
)


SEVERITY_BASE_SCORE = {
    IntelligenceSeverity.LOW: 20,
    IntelligenceSeverity.MEDIUM: 40,
    IntelligenceSeverity.HIGH: 70,
    IntelligenceSeverity.CRITICAL: 90,
}


class IntelligenceEngine:
    """
    Correlates a supplied batch of security events using explicit rules.

    This is deterministic rule-based analysis, not an autonomous AI model.
    It does not collect events or take enforcement actions itself.
    """

    def __init__(
        self,
        rules: list[IntelligenceRule] | None = None,
    ) -> None:
        self._rules: dict[str, IntelligenceRule] = {}

        for rule in rules or []:
            self.add_rule(rule)

    def add_rule(self, rule: IntelligenceRule) -> None:
        if rule.rule_id in self._rules:
            raise ValueError(
                f"Intelligence rule already exists: {rule.rule_id}"
            )

        self._rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: str) -> bool:
        return self._rules.pop(rule_id, None) is not None

    def get_rules(self) -> list[IntelligenceRule]:
        return list(self._rules.values())

    @staticmethod
    def calculate_risk_score(
        severity: IntelligenceSeverity,
        events: list[IntelligenceEvent],
    ) -> int:
        """
        Calculate a bounded score using rule severity, event volume,
        and the average confidence supplied with the events.
        """

        base = SEVERITY_BASE_SCORE[severity]
        volume_bonus = min(max(len(events) - 1, 0) * 3, 10)

        average_confidence = (
            sum(event.confidence for event in events) / len(events)
            if events
            else 0.0
        )

        confidence_adjustment = round(average_confidence * 10)

        return min(100, max(0, base + volume_bonus + confidence_adjustment))

    @staticmethod
    def _same_entity(
        first: IntelligenceEvent,
        second: IntelligenceEvent,
    ) -> bool:
        """
        Correlate by a shared source IP, principal, or asset ID.

        Events without any shared non-empty identifier are not grouped.
        """

        if first.source_ip and first.source_ip == second.source_ip:
            return True

        if first.principal and first.principal == second.principal:
            return True

        if first.asset_id and first.asset_id == second.asset_id:
            return True

        return False

    def analyze(
        self,
        events: list[IntelligenceEvent],
        *,
        now: datetime | None = None,
    ) -> IntelligenceAnalysisResult:
        """Generate findings for event groups that meet configured rules."""

        current_time = now or datetime.now(timezone.utc)

        if current_time.tzinfo is None:
            raise ValueError("now must be timezone-aware")

        seen_event_ids: set[str] = set()

        for event in events:
            if event.event_id in seen_event_ids:
                raise ValueError(
                    f"Duplicate event ID in batch: {event.event_id}"
                )
            seen_event_ids.add(event.event_id)

        findings: list[IntelligenceFinding] = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            candidates = [
                event
                for event in events
                if event.event_type in rule.event_types
                and 0 <= (current_time - event.occurred_at).total_seconds()
                <= rule.window_seconds
            ]

            # Group correlated events by shared identity.
            groups: list[list[IntelligenceEvent]] = []

            for event in sorted(
                candidates,
                key=lambda item: (item.occurred_at, item.event_id),
            ):
                matching_groups = [
                    group
                    for group in groups
                    if any(
                        self._same_entity(event, existing)
                        for existing in group
                    )
                ]

                if not matching_groups:
                    groups.append([event])
                else:
                    primary_group = matching_groups[0]
                    primary_group.append(event)

                    for extra_group in matching_groups[1:]:
                        primary_group.extend(extra_group)
                        groups.remove(extra_group)

            for group in groups:
                if len(group) < rule.minimum_events:
                    continue

                # Use only events whose time falls within the rule window
                # relative to the group's newest event.
                newest = max(event.occurred_at for event in group)
                windowed_group = [
                    event
                    for event in group
                    if 0 <= (newest - event.occurred_at).total_seconds()
                    <= rule.window_seconds
                ]

                if len(windowed_group) < rule.minimum_events:
                    continue

                risk_score = self.calculate_risk_score(
                    rule.severity,
                    windowed_group,
                )

                findings.append(
                    IntelligenceFinding(
                        finding_id=f"finding-{uuid4().hex}",
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        risk_score=risk_score,
                        event_ids=[
                            event.event_id
                            for event in sorted(
                                windowed_group,
                                key=lambda item: (
                                    item.occurred_at,
                                    item.event_id,
                                ),
                            )
                        ],
                        summary=(
                            f"Rule '{rule.name}' correlated "
                            f"{len(windowed_group)} related security events. "
                            f"{rule.description}"
                        ).strip(),
                        generated_at=current_time,
                    )
                )

        return IntelligenceAnalysisResult(
            analyzed_events=len(events),
            findings=findings,
            message=(
                f"Analyzed {len(events)} events and generated "
                f"{len(findings)} intelligence findings."
            ),
        )
