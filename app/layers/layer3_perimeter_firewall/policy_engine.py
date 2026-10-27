
from dataclasses import dataclass
from ipaddress import ip_address

from app.layers.layer3_perimeter_firewall.schemas import (
    FirewallRule,
)


@dataclass(frozen=True)
class ConnectionRequest:
    source_ip: str
    destination_port: int
    protocol: str


@dataclass(frozen=True)
class FirewallDecision:
    action: str
    rule_id: str
    reason: str


class FirewallPolicyEngine:
    """
    Evaluates connection metadata against configured firewall rules.

    Rules are evaluated in order. The first matching rule wins.
    If no rule matches, the connection is blocked by default.

    This is a policy engine, not an OS-level packet filter.
    """

    def __init__(self, rules: list[FirewallRule] | None = None):
        self.rules = list(rules or [])

    def add_rule(self, rule: FirewallRule) -> None:
        """Add a validated firewall rule."""
        if any(existing.rule_id == rule.rule_id for existing in self.rules):
            raise ValueError(f"Duplicate rule ID: {rule.rule_id}")

        self.rules.append(rule)

    def evaluate(
        self, request: ConnectionRequest
    ) -> FirewallDecision:
        """Return the decision for a connection request."""

        try:
            source_ip = ip_address(request.source_ip)
        except ValueError:
            return FirewallDecision(
                action="BLOCK",
                rule_id="INVALID_SOURCE_IP",
                reason="Invalid source IP address",
            )

        protocol = request.protocol.upper()

        if protocol not in {"TCP", "UDP", "ICMP"}:
            return FirewallDecision(
                action="BLOCK",
                rule_id="INVALID_PROTOCOL",
                reason="Unsupported network protocol",
            )

        if not 1 <= request.destination_port <= 65535:
            return FirewallDecision(
                action="BLOCK",
                rule_id="INVALID_DESTINATION_PORT",
                reason="Destination port is outside the valid range",
            )

        for rule in self.rules:
            if not rule.enabled:
                continue

            if rule.protocol != "ANY" and rule.protocol != protocol:
                continue

            if (
                rule.source_ips
                and source_ip not in rule.source_ips
            ):
                continue

            if (
                rule.destination_ports
                and request.destination_port
                not in rule.destination_ports
            ):
                continue

            return FirewallDecision(
                action=rule.action,
                rule_id=rule.rule_id,
                reason=(
                    rule.description
                    or f"Matched firewall rule {rule.rule_id}"
                ),
            )

        return FirewallDecision(
            action="BLOCK",
            rule_id="DEFAULT_DENY",
            reason="No firewall rule matched; blocked by default",
        )
