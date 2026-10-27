
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ApplicationCheckType(str, Enum):
    INPUT_VALIDATION = "input_validation"
    SECURITY_HEADERS = "security_headers"
    HTTP_METHOD = "http_method"
    CONTENT_TYPE = "content_type"
    BODY_SIZE = "body_size"


class ApplicationSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApplicationAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ALERT = "alert"


class ApplicationSecurityConfig(BaseModel):
    """Defines application-level request security settings."""

    model_config = ConfigDict(extra="forbid")

    config_id: str = Field(min_length=1, max_length=64)

    allowed_methods: list[
        Literal["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    ] = Field(
        default_factory=lambda: ["GET", "POST"],
        min_length=1,
    )

    allowed_content_types: list[str] = Field(
        default_factory=lambda: [
            "application/json",
            "application/x-www-form-urlencoded",
        ],
        min_length=1,
        max_length=50,
    )

    max_body_size_bytes: int = Field(
        default=1_048_576,
        ge=1,
        le=100_000_000,
    )

    required_security_headers: list[str] = Field(
        default_factory=lambda: [
            "x-content-type-options",
            "content-security-policy",
        ],
        max_length=50,
    )

    enabled: bool = True

    @field_validator("config_id")
    @classmethod
    def validate_config_id(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("config_id cannot be blank")
        return value

    @field_validator("allowed_methods")
    @classmethod
    def validate_methods(
        cls, values: list[str]
    ) -> list[str]:
        normalized = [value.upper() for value in values]

        if len(normalized) != len(set(normalized)):
            raise ValueError("Duplicate HTTP methods are not allowed")

        return normalized

    @field_validator("allowed_content_types")
    @classmethod
    def normalize_content_types(
        cls, values: list[str]
    ) -> list[str]:
        normalized = [value.strip().lower() for value in values]

        if any(not value for value in normalized):
            raise ValueError("Content types cannot be blank")

        if len(normalized) != len(set(normalized)):
            raise ValueError("Duplicate content types are not allowed")

        return normalized

    @field_validator("required_security_headers")
    @classmethod
    def normalize_headers(
        cls, values: list[str]
    ) -> list[str]:
        normalized = [value.strip().lower() for value in values]

        if any(not value for value in normalized):
            raise ValueError("Header names cannot be blank")

        if len(normalized) != len(set(normalized)):
            raise ValueError("Duplicate header names are not allowed")

        return normalized


class ApplicationRequest(BaseModel):
    """Normalized request metadata for application security checks."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1, max_length=128)
    method: str = Field(min_length=1, max_length=16)
    path: str = Field(min_length=1, max_length=2048)

    content_type: str | None = Field(default=None, max_length=255)
    content_length: int | None = Field(default=None, ge=0)

    headers: dict[str, str] = Field(default_factory=dict)
    input_values: dict[str, str] = Field(default_factory=dict)

    @field_validator("request_id", "path")
    @classmethod
    def validate_nonblank_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be blank")
        return value

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        value = value.strip().upper()
        if not value:
            raise ValueError("HTTP method cannot be blank")
        return value

    @field_validator("content_type")
    @classmethod
    def normalize_content_type(
        cls, value: str | None
    ) -> str | None:
        if value is None:
            return None
        return value.split(";", 1)[0].strip().lower()

    @field_validator("headers")
    @classmethod
    def normalize_header_names(
        cls, values: dict[str, str]
    ) -> dict[str, str]:
        normalized: dict[str, str] = {}

        for key, value in values.items():
            header_name = key.strip().lower()

            if not header_name:
                raise ValueError("Header names cannot be blank")

            if header_name in normalized:
                raise ValueError("Duplicate normalized header names")

            normalized[header_name] = value

        return normalized


class ApplicationSecurityFinding(BaseModel):
    """One application security finding."""

    model_config = ConfigDict(extra="forbid")

    check_type: ApplicationCheckType
    severity: ApplicationSeverity
    action: ApplicationAction

    code: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=500)


class ApplicationSecurityDecision(BaseModel):
    """Final result returned by the application security engine."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1, max_length=128)
    allowed: bool
    findings: list[ApplicationSecurityFinding] = Field(
        default_factory=list,
        max_length=100,
    )
    reason: str = Field(min_length=1, max_length=500)
