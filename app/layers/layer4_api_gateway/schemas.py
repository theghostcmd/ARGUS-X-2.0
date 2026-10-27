
from typing import Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


HTTPMethod = Literal[
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "HEAD",
]

AuthMode = Literal[
    "none",
    "api_key",
    "bearer",
]


class GatewayRoute(BaseModel):
    """Configuration for one API route."""

    model_config = ConfigDict(extra="forbid")

    route_id: str = Field(min_length=1, max_length=64)
    path: str = Field(min_length=1, max_length=2048)
    methods: list[HTTPMethod] = Field(
        min_length=1,
        default_factory=lambda: ["GET"],
    )

    backend_url: str = Field(min_length=1, max_length=2048)

    auth_mode: AuthMode = "bearer"
    enabled: bool = True

    timeout_seconds: float = Field(
        default=10.0,
        gt=0,
        le=120,
    )

    max_request_body_bytes: int = Field(
        default=1_048_576,
        ge=0,
        le=10_485_760,
    )

    @field_validator("route_id")
    @classmethod
    def validate_route_id(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("route_id cannot be blank")

        return value

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("Route path must start with '/'")

        if "?" in value or "#" in value:
            raise ValueError(
                "Route path must not contain a query or fragment"
            )

        if "\\" in value:
            raise ValueError("Backslashes are not allowed in paths")

        return value

    @field_validator("methods")
    @classmethod
    def validate_methods(
        cls, methods: list[HTTPMethod]
    ) -> list[HTTPMethod]:
        if len(set(methods)) != len(methods):
            raise ValueError("Duplicate HTTP methods are not allowed")

        return methods

    @field_validator("backend_url")
    @classmethod
    def validate_backend_url(cls, value: str) -> str:
        parsed = urlsplit(value)

        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Backend URL must use HTTP or HTTPS")

        if not parsed.hostname:
            raise ValueError("Backend URL must contain a hostname")

        if parsed.username or parsed.password:
            raise ValueError(
                "Credentials must not be embedded in backend URLs"
            )

        if parsed.query or parsed.fragment:
            raise ValueError(
                "Backend URL must not contain a query or fragment"
            )

        return value.rstrip("/")


class GatewayRequestMetadata(BaseModel):
    """Validated metadata describing an incoming API request."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1, max_length=128)
    method: HTTPMethod
    path: str = Field(min_length=1, max_length=2048)

    content_length: int = Field(
        default=0,
        ge=0,
        le=10_485_760,
    )


class GatewayDecision(BaseModel):
    """Structured result of a gateway routing decision."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    route_id: str | None = None
    reason: str
    status_code: int = Field(ge=100, le=599)
