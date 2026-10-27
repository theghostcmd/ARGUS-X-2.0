
from datetime import datetime, timezone
from enum import Enum
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Role(str, Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Permission(str, Enum):
    VIEW_ALERTS = "view_alerts"
    VIEW_LOGS = "view_logs"
    MANAGE_RULES = "manage_rules"
    MANAGE_USERS = "manage_users"
    MANAGE_POLICIES = "manage_policies"
    RESPOND_TO_INCIDENTS = "respond_to_incidents"


class MFAStatus(str, Enum):
    NOT_ENROLLED = "not_enrolled"
    PENDING = "pending"
    VERIFIED = "verified"


class UserIdentity(BaseModel):
    """Validated identity record for an ARGUS-X user."""

    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=3, max_length=64)
    email: str = Field(min_length=3, max_length=254)

    roles: list[Role] = Field(min_length=1)
    active: bool = True
    mfa_status: MFAStatus = MFAStatus.NOT_ENROLLED

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("user_id", "username", "email")
    @classmethod
    def validate_non_blank(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Field cannot be blank")

        return value

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", value):
            raise ValueError("Invalid username format")

        return value

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

        if not re.fullmatch(pattern, value):
            raise ValueError("Invalid email format")

        return value.lower()

    @field_validator("roles")
    @classmethod
    def validate_roles(cls, roles: list[Role]) -> list[Role]:
        if len(roles) != len(set(roles)):
            raise ValueError("Duplicate roles are not allowed")

        return roles


class RolePermission(BaseModel):
    """Permission assignments for a role."""

    model_config = ConfigDict(extra="forbid")

    role: Role
    permissions: list[Permission] = Field(default_factory=list)

    @field_validator("permissions")
    @classmethod
    def validate_permissions(
        cls, permissions: list[Permission]
    ) -> list[Permission]:
        if len(permissions) != len(set(permissions)):
            raise ValueError("Duplicate permissions are not allowed")

        return permissions


class AccessRequest(BaseModel):
    """Request to perform an action on a protected resource."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1, max_length=128)
    user_id: str = Field(min_length=1, max_length=128)
    permission: Permission
    resource: str = Field(min_length=1, max_length=256)

    requested_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class MFAChallenge(BaseModel):
    """Metadata for a short-lived MFA challenge; never store OTP secrets here."""

    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=16, max_length=128)
    user_id: str = Field(min_length=1, max_length=128)
    expires_at: datetime
    attempts_remaining: int = Field(default=3, ge=0, le=10)
    verified: bool = False

    @field_validator("challenge_id", "user_id")
    @classmethod
    def validate_non_blank(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Field cannot be blank")

        return value

    @field_validator("expires_at")
    @classmethod
    def validate_expiry_timezone(
        cls, value: datetime
    ) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a timezone")

        return value
