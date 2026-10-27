
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.layers.layer11_intelligence.schemas import (
    IntelligenceEvent,
    IntelligenceEventType,
    IntelligenceRule,
    IntelligenceSeverity,
)
from app.layers.layer11_intelligence.intelligence_engine import (
    IntelligenceEngine,
)


@pytest.fixture
def now():
    return datetime.now(timezone.utc)


def make_event(
    event_id,
    *,
    event_type=IntelligenceEventType.AUTHENTICATION_FAILURE,
    source_ip="10.0.0.5",
    principal=None,
    asset_id=None,
    occurred_at=None,
    confidence=0.8,
):
    return IntelligenceEvent(
        event_id=event_id,
        event_type=event_type,
        source_ip=source_ip,
        principal=principal,
        asset_id=asset_id,
        occurred_at=occurred_at or datetime.now(timezone.utc),
        confidence=confidence,
    )


def make_rule(
    rule_id="auth-correlation",
    *,
    event_types=None,
    minimum_events=2,
    window_seconds=300,
    severity=IntelligenceSeverity.HIGH,
    enabled=True,
):
    return IntelligenceRule(
        rule_id=rule_id,
        name="Authentication event correlation",
        event_types=event_types or [
            IntelligenceEventType.AUTHENTICATION_FAILURE
        ],
        minimum_events=minimum_events,
        window_seconds=window_seconds,
        severity=severity,
        enabled=enabled,
    )


def test_correlated_events_generate_finding(now):
    engine = IntelligenceEngine([make_rule()])
    events = [
        make_event("event-1", occurred_at=now - timedelta(seconds=20)),
        make_event("event-2", occurred_at=now - timedelta(seconds=10)),
    ]

    result = engine.analyze(events, now=now)

    assert result.analyzed_events == 2
    assert len(result.findings) == 1
    assert set(result.findings[0].event_ids) == {"event-1", "event-2"}


def test_single_event_does_not_meet_minimum(now):
    engine = IntelligenceEngine([make_rule(minimum_events=2)])

    result = engine.analyze(
        [make_event("event-1", occurred_at=now)],
        now=now,
    )

    assert result.findings == []


def test_unrelated_entities_are_not_correlated(now):
    engine = IntelligenceEngine([make_rule()])
    events = [
        make_event("event-1", source_ip="10.0.0.1", occurred_at=now),
        make_event("event-2", source_ip="10.0.0.2", occurred_at=now),
    ]

    result = engine.analyze(events, now=now)

    assert result.findings == []


def test_events_outside_rule_window_are_ignored(now):
    engine = IntelligenceEngine([
        make_rule(window_seconds=60, minimum_events=2)
    ])
    events = [
        make_event("event-1", occurred_at=now - timedelta(minutes=5)),
        make_event("event-2", occurred_at=now),
    ]

    result = engine.analyze(events, now=now)

    assert result.findings == []


def test_disabled_rule_generates_no_findings(now):
    engine = IntelligenceEngine([make_rule(enabled=False)])
    events = [
        make_event("event-1", occurred_at=now),
        make_event("event-2", occurred_at=now),
    ]

    assert engine.analyze(events, now=now).findings == []


def test_wrong_event_type_does_not_match(now):
    engine = IntelligenceEngine([make_rule()])
    events = [
        make_event(
            "event-1",
            event_type=IntelligenceEventType.PORT_SCAN,
            occurred_at=now,
        ),
        make_event(
            "event-2",
            event_type=IntelligenceEventType.PORT_SCAN,
            occurred_at=now,
        ),
    ]

    assert engine.analyze(events, now=now).findings == []


def test_duplicate_event_ids_are_rejected(now):
    engine = IntelligenceEngine([make_rule()])
    events = [
        make_event("duplicate", occurred_at=now),
        make_event("duplicate", occurred_at=now),
    ]

    with pytest.raises(ValueError, match="Duplicate event ID"):
        engine.analyze(events, now=now)


def test_duplicate_rule_ids_are_rejected():
    engine = IntelligenceEngine()
    rule = make_rule()

    engine.add_rule(rule)

    with pytest.raises(ValueError, match="already exists"):
        engine.add_rule(rule)


def test_remove_rule():
    engine = IntelligenceEngine([make_rule()])

    assert engine.remove_rule("auth-correlation") is True
    assert engine.remove_rule("auth-correlation") is False


def test_risk_score_is_bounded():
    events = [
        make_event("event-1", confidence=1.0),
        make_event("event-2", confidence=1.0),
        make_event("event-3", confidence=1.0),
    ]

    score = IntelligenceEngine.calculate_risk_score(
        IntelligenceSeverity.CRITICAL,
        events,
    )

    assert 0 <= score <= 100


def test_higher_severity_has_higher_base_score():
    event = make_event("event-1")

    low = IntelligenceEngine.calculate_risk_score(
        IntelligenceSeverity.LOW,
        [event],
    )
    high = IntelligenceEngine.calculate_risk_score(
        IntelligenceSeverity.HIGH,
        [event],
    )

    assert high > low


def test_invalid_ip_is_rejected():
    with pytest.raises(ValidationError):
        make_event("event-1", source_ip="not-an-ip")


def test_invalid_confidence_is_rejected():
    with pytest.raises(ValidationError):
        make_event("event-1", confidence=1.5)


def test_naive_analysis_time_is_rejected():
    engine = IntelligenceEngine()

    with pytest.raises(ValueError, match="timezone-aware"):
        engine.analyze([], now=datetime(2026, 1, 1))


def test_no_events_returns_empty_result():
    engine = IntelligenceEngine([make_rule()])

    result = engine.analyze([])

    assert result.analyzed_events == 0
    assert result.findings == []
