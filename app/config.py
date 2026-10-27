
from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application settings
    app_name: str = "ARGUS-X"
    app_env: Literal["development", "test", "production"] = "development"

    # JWT Authentication settings
    jwt_secret: str | None = Field(default=None)
    jwt_issuer: str | None = Field(default=None)
    jwt_audience: str | None = Field(default=None)

    # Layer 1: Traffic Guard settings
    rate_limit_backend: Literal["memory", "redis"] = "memory"
    redis_url: str | None = None

    rate_limit_requests: int = Field(default=100, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)
    rate_limit_block_seconds: int = Field(default=60, ge=1)
    rate_limit_fail_closed: bool = True

    health_path: str = "/health"

    # Layer 9: Application Security settings
    application_security_enabled: bool = True
    application_security_max_body_bytes: int = Field(
        default=1_048_576,
        ge=1,
        le=100_000_000,
    )

    @model_validator(mode="after")
    def validate_production_settings(self):
        # Production must use Redis
        if self.app_env == "production":
            if self.rate_limit_backend != "redis":
                raise ValueError(
                    "Production requires RATE_LIMIT_BACKEND=redis"
                )

            if not self.redis_url:
                raise ValueError(
                    "REDIS_URL is required in production"
                )

            # Production must have valid JWT configuration
            if not self.jwt_secret:
                raise ValueError(
                    "JWT_SECRET is required in production"
                )

            if len(self.jwt_secret.encode("utf-8")) < 32:
                raise ValueError(
                    "JWT_SECRET must be at least 32 UTF-8 bytes"
                )

            if not self.jwt_issuer:
                raise ValueError(
                    "JWT_ISSUER is required in production"
                )

            if not self.jwt_audience:
                raise ValueError(
                    "JWT_AUDIENCE is required in production"
                )

        # Redis URL is required whenever Redis is selected
        if (
            self.rate_limit_backend == "redis"
            and not self.redis_url
        ):
            raise ValueError(
                "REDIS_URL is required when RATE_LIMIT_BACKEND=redis"
            )

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
