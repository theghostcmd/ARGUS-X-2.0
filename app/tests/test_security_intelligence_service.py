
from datetime import datetime, timedelta, timezone

from app.layers.layer8_ids_ips.schemas import (
    EventType,
    SecurityEvent,
)
from app.services.security_intelligence_service import (
    SecurityIntelligenceService,
)


def make_event(event_id: str, timestamp: datetime) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_type=EventType.AUTHENTICATION_FAILURE,
        timestamp=timestamp,
        source_ip="10.0.0.5",
        username="test-user",
        description="Failed login",
    )


def test_layer8_detection_and_layer11_correlation():
    now = datetime.now(timezone.utc)
    service = SecurityIntelligenceService()

    events = [
        make_event(
            "event-1",
            now - timedelta(seconds=20),
        ),
        make_event(
            "event-2",
            now - timedelta(seconds=10),
        ),
        make_event(
            "event-3",
            now,
        ),
    ]

    result = service.analyze_batch(events, now=now)

    assert result["processed_events"] == 3
    assert len(result["alerts"]) == 3
    assert result["intelligence"]["analyzed_events"] == 3
    assert len(result["intelligence"]["findings"]) == 1

    finding = result["intelligence"]["findings"][0]
    assert finding["risk_score"] > 0
    assert set(finding["event_ids"]) == {
        "event-1",
        "event-2",
        "event-3",
    }


def test_empty_batch_returns_no_alerts_or_findings():
    service = SecurityIntelligenceService()

    result = service.analyze_batch([])

    assert result["processed_events"] == 0
    assert result["alerts"] == []
    assert result["intelligence"]["findings"] == []


def test_naive_analysis_time_is_rejected():
    service = SecurityIntelligenceService()

    try:
        service.analyze_batch(
            [],
            now=datetime(2026, 1, 1),
        )
    except ValueError as exc:
        assert "timezone-aware" in str(exc)
    else:
        raise AssertionError("Expected ValueError")
