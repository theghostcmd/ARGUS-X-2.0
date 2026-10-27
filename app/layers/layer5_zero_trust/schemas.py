
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


AccessAction = Literal[
    "read",
    "write",
    "update",
    "delete",
    "execute",
]

DeviceTrust = Literal[
    "trusted",
    "unknown",
    "untrusted",
]

MFAStatus = Literal[
    "verified",
    "not_verified",
]

PolicyEffect = Literal[
    "allow",
    "deny",
]


class AccessRequest(BaseModel):
    """Context for a user or service requesting resource access."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1, max_length=128)
    subject_id: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=256)
    action: AccessAction

    device_trust: DeviceTrust = "unknown"
    mfa_status: MFAStatus = "not_verified"

    source_ip: str | None = Field(default=None, max_length=45)
    requested_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("request_id", "subject_id", "resource")
    @classmethod
    def validate_non_blank(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Value cannot be blank")

        return value

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None

        import ipaddress

        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("Invalid source IP address") from exc

        return value


class ZeroTrustPolicy(BaseModel):
    """A policy defining access conditions for a resource."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=64)
    resource: str = Field(min_length=1, max_length=256)
    actions: list[AccessAction] = Field(min_length=1)
    effect: PolicyEffect = "deny"

    require_mfa: bool = True
    allowed_device_trust: list[DeviceTrust] = Field(
        default_factory=lambda: ["trusted"]
    )

    enabled: bool = True
    description: str = Field(default="", max_length=500)

    @field_validator("policy_id", "resource")
    @classmethod
    def validate_non_blank(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Value cannot be blank")

        return value

    @field_validator("actions")
    @classmethod
    def validate_actions(
        cls, actions: list[AccessAction]
    ) -> list[AccessAction]:
        if len(actions) != len(set(actions)):
            raise ValueError("Duplicate actions are not allowed")

        return actions

    @field_validator("allowed_device_trust")
    @classmethod
    def validate_device_trust(
        cls, values: list[DeviceTrust]
    ) -> list[DeviceTrust]:
        if len(values) != len(set(values)):
            raise ValueError(
                "Duplicate device trust values are not allowed"
            )

        return values


class AccessDecision(BaseModel):
    """The result returned by the Zero Trust policy engine."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    request_id: str = Field(min_length=1, max_length=128)
    policy_id: str | None = None
    reason: str = Field(min_length=1, max_length=256)
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
