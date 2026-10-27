
from ipaddress import ip_address

from app.layers.layer7_network_segmentation.schemas import (
    NetworkProtocol,
    NetworkSegment,
    SegmentationAction,
    SegmentationDecision,
    SegmentationPolicy,
    SegmentationRequest,
)


class NetworkSegmentationEngine:
    """
    Evaluates network-zone traffic against segmentation policies.

    Security defaults:
    - Deny traffic when no matching policy exists.
    - Ignore disabled policies and disabled network segments.
    - Deny ambiguous configurations with multiple matching policies.
    - Evaluate policies in ascending priority order.
    """

    def __init__(
        self,
        segments: list[NetworkSegment] | None = None,
        policies: list[SegmentationPolicy] | None = None,
    ) -> None:
        self._segments: dict[str, NetworkSegment] = {}
        self._policies: list[SegmentationPolicy] = []

        for segment in segments or []:
            self.add_segment(segment)

        for policy in policies or []:
            self.add_policy(policy)

    def add_segment(self, segment: NetworkSegment) -> None:
        """Register a segment after checking its identity and address ranges."""

        if segment.segment_id in self._segments:
            raise ValueError(
                f"Segment already exists: {segment.segment_id}"
            )

        for existing in self._segments.values():
            if not segment.enabled or not existing.enabled:
                continue

            for new_cidr in segment.cidrs:
                new_network = __import__("ipaddress").ip_network(
                    new_cidr,
                    strict=False,
                )

                for existing_cidr in existing.cidrs:
                    existing_network = __import__("ipaddress").ip_network(
                        existing_cidr,
                        strict=False,
                    )

                    if new_network.version != existing_network.version:
                        continue

                    if new_network.overlaps(existing_network):
                        raise ValueError(
                            "Overlapping CIDR ranges are not allowed "
                            f"between segments {segment.segment_id!r} "
                            f"and {existing.segment_id!r}"
                        )

        self._segments[segment.segment_id] = segment

    def add_policy(self, policy: SegmentationPolicy) -> None:
        """Register a policy with a unique policy ID."""

        if any(
            existing.policy_id == policy.policy_id
            for existing in self._policies
        ):
            raise ValueError(
                f"Policy already exists: {policy.policy_id}"
            )

        self._policies.append(policy)

    def get_segments(self) -> list[NetworkSegment]:
        """Return registered segments."""

        return list(self._segments.values())

    def get_policies(self) -> list[SegmentationPolicy]:
        """Return registered policies."""

        return list(self._policies)

    def resolve_zone(self, address: str) -> str | None:
        """
        Resolve an IP address to an enabled segment's zone.

        Returns None if the IP does not belong to a configured segment.
        """

        try:
            parsed_address = ip_address(address)
        except ValueError:
            return None

        matches: list[str] = []

        for segment in self._segments.values():
            if not segment.enabled:
                continue

            for cidr in segment.cidrs:
                from ipaddress import ip_network

                network = ip_network(cidr, strict=False)

                if (
                    parsed_address.version == network.version
                    and parsed_address in network
                ):
                    matches.append(segment.zone.value)
                    break

        if len(matches) > 1:
            return None

        return matches[0] if matches else None

    def evaluate(
        self,
        request: SegmentationRequest,
    ) -> SegmentationDecision:
        """Evaluate a proposed connection using the configured policies."""

        if request.source_zone == request.destination_zone:
            return SegmentationDecision(
                allowed=False,
                request_id=request.request_id,
                reason="Same-zone traffic is denied by this engine's "
                       "cross-zone-only policy model.",
            )

        matching_policies = [
            policy
            for policy in self._policies
            if policy.enabled
            and policy.source_zone == request.source_zone
            and policy.destination_zone == request.destination_zone
            and (
                NetworkProtocol.ANY in policy.protocols
                or request.protocol in policy.protocols
            )
            and (
                not policy.destination_ports
                or request.destination_port in policy.destination_ports
            )
        ]

        if not matching_policies:
            return SegmentationDecision(
                allowed=False,
                request_id=request.request_id,
                reason="No matching segmentation policy; default deny.",
            )

        matching_policies.sort(
            key=lambda policy: (policy.priority, policy.policy_id)
        )

        highest_priority = matching_policies[0].priority
        top_policies = [
            policy
            for policy in matching_policies
            if policy.priority == highest_priority
        ]

        if len(top_policies) > 1:
            return SegmentationDecision(
                allowed=False,
                request_id=request.request_id,
                reason=(
                    "Multiple matching policies share the highest priority; "
                    "traffic denied due to policy ambiguity."
                ),
            )

        selected_policy = top_policies[0]

        if selected_policy.action == SegmentationAction.DENY:
            return SegmentationDecision(
                allowed=False,
                request_id=request.request_id,
                policy_id=selected_policy.policy_id,
                reason="Traffic denied by segmentation policy.",
            )

        return SegmentationDecision(
            allowed=True,
            request_id=request.request_id,
            policy_id=selected_policy.policy_id,
            reason="Traffic allowed by segmentation policy.",
        )
