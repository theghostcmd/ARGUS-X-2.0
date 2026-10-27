
from typing import Literal

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator


Protocol = Literal["TCP", "UDP", "ICMP", "ANY"]
Action = Literal["ALLOW", "BLOCK"]


class FirewallRule(BaseModel):
    rule_id: str = Field(min_length=1, max_length=64)
    action: Action
    protocol: Protocol = "ANY"

    source_ips: list[IPvAnyAddress] = Field(
        default_factory=list
    )

    destination_ports: list[int] = Field(
        default_factory=list
    )

    enabled: bool = True
    description: str = Field(default="", max_length=500)

    @field_validator("destination_ports")
    @classmethod
    def validate_ports(cls, ports: list[int]) -> list[int]:
        for port in ports:
            if not 1 <= port <= 65535:
                raise ValueError(
                    "Ports must be between 1 and 65535"
                )
        return ports

    @field_validator("source_ips")
    @classmethod
    def validate_source_ips(
        cls, addresses: list[IPvAnyAddress]
    ) -> list[IPvAnyAddress]:
        if len(addresses) > 1000:
            raise ValueError(
                "A maximum of 1000 source IPs is allowed"
            )
        return addresses
