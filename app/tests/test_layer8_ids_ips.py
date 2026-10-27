
import pytest
from pydantic import ValidationError

from app.layers.layer8_ids_ips.schemas import (
    DetectionAction,
    DetectionRule,
    EventType,
    ResponseRequest,
    SecurityEvent,
    ThreatAlert,
    ThreatSeverity,
)
from app.layers.layer8_ids_ips.detection_engine import IDSDetectionEngine
from app.layers.layer8_ids_ips.response_engine import IDSIPSResponseEngine


def make_event(
    event_id: str = "event-001",
    event_type: EventType = EventType.AUTHENTICATION_FAILURE,
    attributes: dict | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_type=event_type,
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        protocol="tcp",
        attributes=attributes or {},
    )


def make_rule(
    rule_id: str = "auth-failure-rule",
    event_types: list[EventType] | None = None,
    severity: ThreatSeverity = ThreatSeverity.HIGH,
    action: DetectionAction = DetectionAction.ALERT,
    enabled: bool = True,
    priority: int = 100,
    attribute_equals: dict | None = None,
) -> DetectionRule:
    return DetectionRule(
        rule_id=rule_id,
        name="Authentication failure detection",
        description="Detects suspicious authentication events.",
        event_types=event_types or [EventType.AUTHENTICATION_FAILURE],
        severity=severity,
        action=action,
        enabled=enabled,
        priority=priority,
        attribute_equals=attribute_equals or {},
    )


def make_alert(
    alert_id: str = "alert-001",
    action: DetectionAction = DetectionAction.BLOCK,
    severity: ThreatSeverity = ThreatSeverity.CRITICAL,
) -> ThreatAlert:
    return ThreatAlert(
        alert_id=alert_id,
        event_id="event-001",
        rule_id="test-rule",
        severity=severity,
        action=action,
        message="Test alert.",
    )


def test_matching_event_generates_alert():
    engine = IDSDetectionEngine([make_rule()])

    alerts = engine.inspect(make_event())

    assert len(alerts) == 1
    assert alerts[0].event_id == "event-001"
    assert alerts[0].rule_id == "auth-failure-rule"
    assert alerts[0].severity == ThreatSeverity.HIGH


def test_unmatched_event_generates_no_alert():
    engine = IDSDetectionEngine([make_rule()])

    alerts = engine.inspect(
        make_event(event_type=EventType.PORT_SCAN)
    )

    assert alerts == []


def test_disabled_rule_is_ignored():
    engine = IDSDetectionEngine([make_rule(enabled=False)])

    assert engine.inspect(make_event()) == []


def test_multiple_matching_rules_generate_multiple_alerts():
    engine = IDSDetectionEngine(
        [
            make_rule(rule_id="rule-a", priority=20),
            make_rule(rule_id="rule-b", priority=10),
        ]
    )

    alerts = engine.inspect(make_event())

    assert len(alerts) == 2
    assert alerts[0].rule_id == "rule-b"
    assert alerts[1].rule_id == "rule-a"


def test_inspect_one_returns_highest_priority_match():
    engine = IDSDetectionEngine(
        [
            make_rule(rule_id="rule-a", priority=20),
            make_rule(rule_id="rule-b", priority=10),
        ]
    )

    alert = engine.inspect_one(make_event())

    assert alert is not None
    assert alert.rule_id == "rule-b"


def test_inspect_one_returns_none_when_no_rule_matches():
    engine = IDSDetectionEngine([make_rule()])

    assert engine.inspect_one(
        make_event(event_type=EventType.PORT_SCAN)
    ) is None


def test_exact_attribute_condition_matches():
    engine = IDSDetectionEngine(
        [
            make_rule(
                attribute_equals={"failed_attempts": 5}
            )
        ]
    )

    alerts = engine.inspect(
        make_event(attributes={"failed_attempts": 5})
    )

    assert len(alerts) == 1


def test_attribute_condition_mismatch_does_not_match():
    engine = IDSDetectionEngine(
        [
            make_rule(
                attribute_equals={"failed_attempts": 5}
            )
        ]
    )

    alerts = engine.inspect(
        make_event(attributes={"failed_attempts": 2})
    )

    assert alerts == []


def test_boolean_attribute_does_not_match_integer_condition():
    engine = IDSDetectionEngine(
        [
            make_rule(attribute_equals={"suspicious": 1})
        ]
    )

    alerts = engine.inspect(
        make_event(attributes={"suspicious": True})
    )

    assert alerts == []


def test_duplicate_rule_id_is_rejected():
    engine = IDSDetectionEngine()
    rule = make_rule()

    engine.add_rule(rule)

    with pytest.raises(ValueError, match="already exists"):
        engine.add_rule(rule)


def test_remove_rule():
    engine = IDSDetectionEngine([make_rule()])

    assert engine.remove_rule("auth-failure-rule") is True
    assert engine.remove_rule("auth-failure-rule") is False
    assert engine.inspect(make_event()) == []


def test_invalid_source_ip_is_rejected():
    with pytest.raises(ValidationError):
        make_event_with_invalid_ip()


def make_event_with_invalid_ip():
    return SecurityEvent(
        event_id="event-invalid",
        event_type=EventType.PORT_SCAN,
        source_ip="not-an-ip",
    )


def test_blank_event_id_is_rejected():
    with pytest.raises(ValidationError):
        make_event(event_id="   ")


def test_protocol_is_normalized():
    event = make_event()
    assert event.protocol == "TCP"


def test_duplicate_event_types_are_rejected():
    with pytest.raises(ValidationError):
        make_rule(
            event_types=[
                EventType.PORT_SCAN,
                EventType.PORT_SCAN,
            ]
        )


def test_default_response_does_not_execute_block():
    engine = IDSIPSResponseEngine()

    decision = engine.respond(make_alert())

    assert decision.action == DetectionAction.BLOCK
    assert decision.executed is False
    assert "disabled" in decision.message.lower()


def test_alert_action_does_not_block():
    engine = IDSIPSResponseEngine(auto_block_enabled=True)

    decision = engine.respond(
        make_alert(action=DetectionAction.ALERT)
    )

    assert decision.action == DetectionAction.ALERT
    assert decision.executed is False


def test_monitor_action_does_not_block():
    engine = IDSIPSResponseEngine(auto_block_enabled=True)

    decision = engine.respond(
        make_alert(action=DetectionAction.MONITOR)
    )

    assert decision.action == DetectionAction.MONITOR
    assert decision.executed is False


def test_critical_block_is_recommended_but_not_executed():
    engine = IDSIPSResponseEngine(
        auto_block_enabled=True,
        block_severities={ThreatSeverity.CRITICAL},
    )

    decision = engine.respond(make_alert())

    assert decision.action == DetectionAction.BLOCK
    assert decision.executed is False
    assert "external enforcement adapter" in decision.message.lower()


def test_low_severity_block_is_not_approved():
    engine = IDSIPSResponseEngine(
        auto_block_enabled=True,
        block_severities={ThreatSeverity.CRITICAL},
    )

    decision = engine.respond(
        make_alert(severity=ThreatSeverity.LOW)
    )

    assert decision.executed is False
    assert "severity" in decision.message.lower()


def test_response_request_rejects_invalid_ip():
    with pytest.raises(ValidationError):
        ResponseRequest(
            alert_id="alert-002",
            action=DetectionAction.BLOCK,
            reason="Suspicious traffic",
            source_ip="invalid-ip",
        )


def test_response_request_rejects_blank_reason():
    with pytest.raises(ValidationError):
        ResponseRequest(
            alert_id="alert-002",
            action=DetectionAction.BLOCK,
            reason="   ",
        )


def test_evaluate_request_obeys_disabled_auto_block_policy():
    engine = IDSIPSResponseEngine(auto_block_enabled=False)

    request = ResponseRequest(
        alert_id="alert-003",
        action=DetectionAction.BLOCK,
        reason="Repeated suspicious events",
        source_ip="10.0.0.5",
    )

    decision = engine.evaluate_request(
        request,
        severity=ThreatSeverity.CRITICAL,
    )

    assert decision.executed is False
    assert "disabled" in decision.message.lower()


def test_evaluate_request_does_not_execute_real_block():
    engine = IDSIPSResponseEngine(
        auto_block_enabled=True,
        block_severities={ThreatSeverity.CRITICAL},
    )

    request = ResponseRequest(
        alert_id="alert-004",
        action=DetectionAction.BLOCK,
        reason="Critical security event",
        source_ip="10.0.0.5",
    )

    decision = engine.evaluate_request(
        request,
        severity=ThreatSeverity.CRITICAL,
    )

    assert decision.executed is False
    assert "no network block was executed" in decision.message.lower()
