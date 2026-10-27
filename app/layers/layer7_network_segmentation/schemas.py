
from enum import Enum
from ipaddress import ip_network

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


class NetworkZone(str, Enum):
    INTERNET = "internet"
    DMZ = "dmz"
    APPLICATION = "application"
    DATABASE = "database"
    MANAGEMENT = "management"
    SECURITY = "security"


class NetworkProtocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ANY = "ANY"


class SegmentationAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class NetworkSegment(BaseModel):
    """Defines a network segment and its address ranges."""

    model_config = ConfigDict(extra="forbid")

    segment_id: str = Field(min_length=1, max_length=64)
    zone: NetworkZone
    cidrs: list[str] = Field(min_length=1, max_length=100)
    enabled: bool = True
    description: str = Field(default="", max_length=500)

    @field_validator("segment_id")
    @classmethod
    def validate_segment_id(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("segment_id cannot be blank")

        return value

    @field_validator("cidrs")
    @classmethod
    def validate_cidrs(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []

        for value in values:
            try:
                network = ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid IP network or CIDR: {value}"
                ) from exc

            canonical = str(network)

            if canonical in normalized:
                raise ValueError(
                    f"Duplicate network range: {canonical}"
                )

            normalized.append(canonical)

        return normalized


class SegmentationPolicy(BaseModel):
    """Defines whether traffic between two zones is allowed."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=64)
    source_zone: NetworkZone
    destination_zone: NetworkZone

    action: SegmentationAction = SegmentationAction.DENY
    protocols: list[NetworkProtocol] = Field(
        default_factory=lambda: [NetworkProtocol.ANY],
        min_length=1,
    )
    destination_ports: list[int] = Field(
        default_factory=list,
        max_length=1000,
    )

    enabled: bool = True
    priority: int = Field(default=100, ge=1, le=65535)
    description: str = Field(default="", max_length=500)

    @field_validator("policy_id")
    @classmethod
    def validate_policy_id(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("policy_id cannot be blank")

        return value

    @field_validator("protocols")
    @classmethod
    def validate_protocols(
        cls, values: list[NetworkProtocol]
    ) -> list[NetworkProtocol]:
        if len(values) != len(set(values)):
            raise ValueError("Duplicate protocols are not allowed")

        if (
            NetworkProtocol.ANY in values
            and len(values) > 1
        ):
            raise ValueError(
                "ANY cannot be combined with specific protocols"
            )

        return values

    @field_validator("destination_ports")
    @classmethod
    def validate_destination_ports(
        cls, ports: list[int]
    ) -> list[int]:
        if len(ports) != len(set(ports)):
            raise ValueError("Duplicate destination ports are not allowed")

        for port in ports:
            if not 1 <= port <= 65535:
                raise ValueError(
                    "Destination ports must be between 1 and 65535"
                )

        return ports


class SegmentationRequest(BaseModel):
    """Metadata for a proposed connection between network zones."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1, max_length=128)
    source_zone: NetworkZone
    destination_zone: NetworkZone
    protocol: NetworkProtocol
    destination_port: int | None = Field(default=None, ge=1, le=65535)

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("request_id cannot be blank")

        return value

    @field_validator("destination_port")
    @classmethod
    def validate_port_for_protocol(
        cls,
        port: int | None,
        info,
    ) -> int | None:
        protocol = info.data.get("protocol")

        if (
            protocol in {NetworkProtocol.TCP, NetworkProtocol.UDP}
            and port is None
        ):
            raise ValueError(
                "TCP and UDP requests require a destination port"
            )

        return port


class SegmentationDecision(BaseModel):
    """Result of a network segmentation policy evaluation."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    request_id: str = Field(min_length=1, max_length=128)
    policy_id: str | None = None
    reason: str = Field(min_length=1, max_length=256)
