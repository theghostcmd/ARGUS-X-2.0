
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IntelligenceEventType(str, Enum):
    AUTHENTICATION_FAILURE = "authentication_failure"
    PORT_SCAN = "port_scan"
    MALICIOUS_REQUEST = "malicious_request"
    POLICY_VIOLATION = "policy_violation"
    MALWARE_DETECTED = "malware_detected"
    DATA_EXFILTRATION = "data_exfiltration"
    OTHER = "other"


class IntelligenceSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IntelligenceEvent(BaseModel):
    """Normalized security event for correlation and risk analysis."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    event_type: IntelligenceEventType
    source_ip: str | None = Field(default=None, max_length=64)
    principal: str | None = Field(default=None, max_length=128)
    asset_id: str | None = Field(default=None, max_length=128)
    description: str = Field(default="", max_length=1000)
    occurred_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    attributes: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict
    )

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("event_id cannot be blank")
        return value

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None

        from ipaddress import ip_address

        try:
            return str(ip_address(value))
        except ValueError as exc:
            raise ValueError("Invalid source IP address") from exc


class IntelligenceRule(BaseModel):
    """A configurable rule for correlating event types."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    event_types: list[IntelligenceEventType] = Field(
        min_length=1,
        max_length=20,
    )
    minimum_events: int = Field(default=2, ge=1, le=10000)
    window_seconds: int = Field(default=300, ge=1, le=86400)
    severity: IntelligenceSeverity = IntelligenceSeverity.MEDIUM
    enabled: bool = True
    description: str = Field(default="", max_length=500)

    @field_validator("rule_id", "name")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be blank")
        return value

    @field_validator("event_types")
    @classmethod
    def validate_event_types(
        cls,
        values: list[IntelligenceEventType],
    ) -> list[IntelligenceEventType]:
        if len(values) != len(set(values)):
            raise ValueError("Duplicate event types are not allowed")
        return values


class IntelligenceFinding(BaseModel):
    """A correlated security finding."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=128)
    rule_id: str = Field(min_length=1, max_length=64)
    severity: IntelligenceSeverity
    risk_score: int = Field(ge=0, le=100)
    event_ids: list[str] = Field(min_length=1, max_length=10000)
    summary: str = Field(min_length=1, max_length=1000)
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class IntelligenceAnalysisResult(BaseModel):
    """Combined result from a batch intelligence analysis."""

    model_config = ConfigDict(extra="forbid")

    analyzed_events: int = Field(ge=0)
    findings: list[IntelligenceFinding] = Field(default_factory=list)
    message: str = Field(min_length=1, max_length=500)
