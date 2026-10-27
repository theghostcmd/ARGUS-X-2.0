
import pytest

from app.layers.layer3_perimeter_firewall.schemas import FirewallRule
from app.layers.layer3_perimeter_firewall.policy_engine import (
    ConnectionRequest,
    FirewallPolicyEngine,
)


def test_allows_matching_connection():
    rule = FirewallRule(
        rule_id="ALLOW_HTTPS",
        action="ALLOW",
        protocol="TCP",
        source_ips=["192.168.1.10"],
        destination_ports=[443],
    )
    engine = FirewallPolicyEngine([rule])

    result = engine.evaluate(
        ConnectionRequest("192.168.1.10", 443, "TCP")
    )

    assert result.action == "ALLOW"
    assert result.rule_id == "ALLOW_HTTPS"


def test_blocks_explicitly_denied_connection():
    rule = FirewallRule(
        rule_id="BLOCK_TELNET",
        action="BLOCK",
        protocol="TCP",
        destination_ports=[23],
    )
    engine = FirewallPolicyEngine([rule])

    result = engine.evaluate(
        ConnectionRequest("192.168.1.10", 23, "TCP")
    )

    assert result.action == "BLOCK"
    assert result.rule_id == "BLOCK_TELNET"


def test_default_deny_when_no_rule_matches():
    engine = FirewallPolicyEngine()

    result = engine.evaluate(
        ConnectionRequest("192.168.1.10", 443, "TCP")
    )

    assert result.action == "BLOCK"
    assert result.rule_id == "DEFAULT_DENY"


def test_invalid_source_ip_is_blocked():
    engine = FirewallPolicyEngine()

    result = engine.evaluate(
        ConnectionRequest("not-an-ip", 443, "TCP")
    )

    assert result.action == "BLOCK"
    assert result.rule_id == "INVALID_SOURCE_IP"


def test_invalid_destination_port_is_blocked():
    engine = FirewallPolicyEngine()

    result = engine.evaluate(
        ConnectionRequest("192.168.1.10", 70000, "TCP")
    )

    assert result.action == "BLOCK"
    assert result.rule_id == "INVALID_DESTINATION_PORT"


def test_disabled_rule_is_ignored():
    rule = FirewallRule(
        rule_id="DISABLED_ALLOW",
        action="ALLOW",
        protocol="TCP",
        destination_ports=[443],
        enabled=False,
    )
    engine = FirewallPolicyEngine([rule])

    result = engine.evaluate(
        ConnectionRequest("192.168.1.10", 443, "TCP")
    )

    assert result.action == "BLOCK"
    assert result.rule_id == "DEFAULT_DENY"


def test_first_matching_rule_wins():
    rules = [
        FirewallRule(
            rule_id="BLOCK_HTTPS",
            action="BLOCK",
            protocol="TCP",
            destination_ports=[443],
        ),
        FirewallRule(
            rule_id="ALLOW_HTTPS",
            action="ALLOW",
            protocol="TCP",
            destination_ports=[443],
        ),
    ]
    engine = FirewallPolicyEngine(rules)

    result = engine.evaluate(
        ConnectionRequest("192.168.1.10", 443, "TCP")
    )

    assert result.action == "BLOCK"
    assert result.rule_id == "BLOCK_HTTPS"


def test_duplicate_rule_id_is_rejected():
    rule = FirewallRule(
        rule_id="RULE_1",
        action="ALLOW",
    )
    engine = FirewallPolicyEngine([rule])

    with pytest.raises(ValueError, match="Duplicate rule ID"):
        engine.add_rule(rule)


def test_invalid_protocol_is_blocked():
    engine = FirewallPolicyEngine()

    result = engine.evaluate(
        ConnectionRequest("192.168.1.10", 443, "SCTP")
    )

    assert result.action == "BLOCK"
    assert result.rule_id == "INVALID_PROTOCOL"
    