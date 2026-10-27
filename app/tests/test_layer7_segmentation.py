
import pytest
from pydantic import ValidationError

from app.layers.layer7_network_segmentation.schemas import (
    NetworkProtocol,
    NetworkSegment,
    NetworkZone,
    SegmentationAction,
    SegmentationDecision,
    SegmentationPolicy,
    SegmentationRequest,
)
from app.layers.layer7_network_segmentation.segmentation_engine import (
    NetworkSegmentationEngine,
)


def make_segment(
    segment_id: str = "app-segment",
    zone: NetworkZone = NetworkZone.APPLICATION,
    cidrs: list[str] | None = None,
    enabled: bool = True,
) -> NetworkSegment:
    return NetworkSegment(
        segment_id=segment_id,
        zone=zone,
        cidrs=cidrs or ["10.10.0.0/24"],
        enabled=enabled,
    )


def make_policy(
    policy_id: str = "allow-app-db",
    source_zone: NetworkZone = NetworkZone.APPLICATION,
    destination_zone: NetworkZone = NetworkZone.DATABASE,
    action: SegmentationAction = SegmentationAction.ALLOW,
    priority: int = 100,
    protocols: list[NetworkProtocol] | None = None,
    destination_ports: list[int] | None = None,
    enabled: bool = True,
) -> SegmentationPolicy:
    return SegmentationPolicy(
        policy_id=policy_id,
        source_zone=source_zone,
        destination_zone=destination_zone,
        action=action,
        priority=priority,
        protocols=protocols or [NetworkProtocol.TCP],
        destination_ports=destination_ports or [5432],
        enabled=enabled,
    )


def make_request(
    request_id: str = "request-001",
    source_zone: NetworkZone = NetworkZone.APPLICATION,
    destination_zone: NetworkZone = NetworkZone.DATABASE,
    protocol: NetworkProtocol = NetworkProtocol.TCP,
    destination_port: int | None = 5432,
) -> SegmentationRequest:
    return SegmentationRequest(
        request_id=request_id,
        source_zone=source_zone,
        destination_zone=destination_zone,
        protocol=protocol,
        destination_port=destination_port,
    )


def test_no_matching_policy_defaults_to_deny():
    engine = NetworkSegmentationEngine()

    decision = engine.evaluate(make_request())

    assert decision.allowed is False
    assert decision.policy_id is None
    assert "default deny" in decision.reason.lower()


def test_matching_allow_policy_allows_traffic():
    engine = NetworkSegmentationEngine(
        policies=[make_policy()]
    )

    decision = engine.evaluate(make_request())

    assert decision.allowed is True
    assert decision.policy_id == "allow-app-db"


def test_matching_deny_policy_blocks_traffic():
    engine = NetworkSegmentationEngine(
        policies=[
            make_policy(action=SegmentationAction.DENY)
        ]
    )

    decision = engine.evaluate(make_request())

    assert decision.allowed is False
    assert decision.policy_id == "allow-app-db"


def test_wrong_destination_port_does_not_match_policy():
    engine = NetworkSegmentationEngine(
        policies=[make_policy(destination_ports=[5432])]
    )

    decision = engine.evaluate(
        make_request(destination_port=3306)
    )

    assert decision.allowed is False
    assert decision.policy_id is None


def test_wrong_protocol_does_not_match_policy():
    engine = NetworkSegmentationEngine(
        policies=[
            make_policy(protocols=[NetworkProtocol.TCP])
        ]
    )

    decision = engine.evaluate(
        make_request(protocol=NetworkProtocol.UDP)
    )

    assert decision.allowed is False


def test_any_protocol_matches_tcp_request():
    engine = NetworkSegmentationEngine(
        policies=[
            make_policy(
                protocols=[NetworkProtocol.ANY],
                destination_ports=[5432],
            )
        ]
    )

    decision = engine.evaluate(make_request())

    assert decision.allowed is True


def test_disabled_policy_is_ignored():
    engine = NetworkSegmentationEngine(
        policies=[make_policy(enabled=False)]
    )

    decision = engine.evaluate(make_request())

    assert decision.allowed is False


def test_same_zone_traffic_is_denied():
    engine = NetworkSegmentationEngine(
        policies=[
            make_policy(
                source_zone=NetworkZone.APPLICATION,
                destination_zone=NetworkZone.APPLICATION,
            )
        ]
    )

    decision = engine.evaluate(
        make_request(
            source_zone=NetworkZone.APPLICATION,
            destination_zone=NetworkZone.APPLICATION,
        )
    )

    assert decision.allowed is False


def test_lower_numeric_priority_wins():
    engine = NetworkSegmentationEngine(
        policies=[
            make_policy(
                policy_id="allow-priority-100",
                action=SegmentationAction.ALLOW,
                priority=100,
            ),
            make_policy(
                policy_id="deny-priority-10",
                action=SegmentationAction.DENY,
                priority=10,
            ),
        ]
    )

    decision = engine.evaluate(make_request())

    assert decision.allowed is False
    assert decision.policy_id == "deny-priority-10"


def test_equal_top_priority_is_denied_as_ambiguous():
    engine = NetworkSegmentationEngine(
        policies=[
            make_policy(
                policy_id="allow-policy",
                action=SegmentationAction.ALLOW,
                priority=10,
            ),
            make_policy(
                policy_id="deny-policy",
                action=SegmentationAction.DENY,
                priority=10,
            ),
        ]
    )

    decision = engine.evaluate(make_request())

    assert decision.allowed is False
    assert decision.policy_id is None
    assert "ambiguity" in decision.reason.lower()


def test_duplicate_policy_id_is_rejected():
    engine = NetworkSegmentationEngine()
    policy = make_policy()

    engine.add_policy(policy)

    with pytest.raises(ValueError, match="Policy already exists"):
        engine.add_policy(policy)


def test_duplicate_segment_id_is_rejected():
    engine = NetworkSegmentationEngine()
    segment = make_segment()

    engine.add_segment(segment)

    with pytest.raises(ValueError, match="Segment already exists"):
        engine.add_segment(segment)


def test_overlapping_enabled_cidr_ranges_are_rejected():
    engine = NetworkSegmentationEngine(
        segments=[
            make_segment(
                segment_id="segment-a",
                cidrs=["10.10.0.0/24"],
            )
        ]
    )

    with pytest.raises(ValueError, match="Overlapping CIDR"):
        engine.add_segment(
            make_segment(
                segment_id="segment-b",
                zone=NetworkZone.DATABASE,
                cidrs=["10.10.0.128/25"],
            )
        )


def test_disabled_segment_does_not_block_overlap_registration():
    engine = NetworkSegmentationEngine(
        segments=[
            make_segment(
                segment_id="disabled-segment",
                cidrs=["10.10.0.0/24"],
                enabled=False,
            )
        ]
    )

    engine.add_segment(
        make_segment(
            segment_id="enabled-segment",
            zone=NetworkZone.DATABASE,
            cidrs=["10.10.0.0/24"],
        )
    )

    assert len(engine.get_segments()) == 2


def test_resolve_zone_returns_configured_zone():
    engine = NetworkSegmentationEngine(
        segments=[
            make_segment(
                zone=NetworkZone.APPLICATION,
                cidrs=["10.10.0.0/24"],
            )
        ]
    )

    assert engine.resolve_zone("10.10.0.15") == "application"


def test_resolve_zone_returns_none_for_unknown_ip():
    engine = NetworkSegmentationEngine(
        segments=[
            make_segment(
                cidrs=["10.10.0.0/24"],
            )
        ]
    )

    assert engine.resolve_zone("192.168.1.10") is None


def test_resolve_zone_returns_none_for_invalid_ip():
    engine = NetworkSegmentationEngine()

    assert engine.resolve_zone("not-an-ip") is None


def test_disabled_segment_is_not_resolved():
    engine = NetworkSegmentationEngine(
        segments=[
            make_segment(
                cidrs=["10.10.0.0/24"],
                enabled=False,
            )
        ]
    )

    assert engine.resolve_zone("10.10.0.15") is None


def test_tcp_request_requires_destination_port():
    with pytest.raises(
        ValidationError,
        match="require a destination port",
    ):
        make_request(destination_port=None)


def test_invalid_destination_port_is_rejected():
    with pytest.raises(ValidationError):
        make_request(destination_port=70000)


def test_duplicate_destination_ports_are_rejected():
    with pytest.raises(
        ValidationError,
        match="Duplicate destination ports",
    ):
        make_policy(destination_ports=[5432, 5432])


def test_invalid_cidr_is_rejected():
    with pytest.raises(
        ValidationError,
        match="Invalid IP network or CIDR",
    ):
        make_segment(cidrs=["not-a-network"])


def test_duplicate_cidr_is_rejected():
    with pytest.raises(
        ValidationError,
        match="Duplicate network range",
    ):
        make_segment(
            cidrs=["10.10.0.0/24", "10.10.0.0/24"]
        )


def test_extra_policy_fields_are_rejected():
    with pytest.raises(ValidationError):
        SegmentationPolicy(
            policy_id="invalid-policy",
            source_zone=NetworkZone.APPLICATION,
            destination_zone=NetworkZone.DATABASE,
            unexpected_field="not-allowed",
        )


def test_decision_schema_accepts_valid_decision():
    decision = SegmentationDecision(
        allowed=True,
        request_id="request-001",
        policy_id="allow-app-db",
        reason="Traffic allowed by segmentation policy.",
    )

    assert decision.allowed is True
    assert decision.policy_id == "allow-app-db"
