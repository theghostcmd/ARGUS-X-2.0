
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DatabaseOperation(str, Enum):
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    CREATE = "CREATE"
    ALTER = "ALTER"
    DROP = "DROP"
    EXECUTE = "EXECUTE"


class DatabaseRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DatabaseDecisionAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    AUDIT_ONLY = "audit_only"


class DatabaseAccessPolicy(BaseModel):
    """Defines allowed database operations for a principal and resource."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=64)
    principal: str = Field(min_length=1, max_length=128)
    database: str = Field(min_length=1, max_length=128)
    allowed_operations: list[DatabaseOperation] = Field(min_length=1)
    allowed_tables: list[str] = Field(default_factory=list, max_length=500)

    enabled: bool = True
    description: str = Field(default="", max_length=500)

    @field_validator("policy_id", "principal", "database")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Value cannot be blank")

        return value

    @field_validator("allowed_operations")
    @classmethod
    def validate_operations(
        cls,
        values: list[DatabaseOperation],
    ) -> list[DatabaseOperation]:
        if not values:
            raise ValueError("At least one operation is required")

        if len(values) != len(set(values)):
            raise ValueError("Duplicate operations are not allowed")

        return values

    @field_validator("allowed_tables")
    @classmethod
    def normalize_tables(cls, values: list[str]) -> list[str]:
        normalized = [value.strip().lower() for value in values]

        if any(not value for value in normalized):
            raise ValueError("Table names cannot be blank")

        if len(normalized) != len(set(normalized)):
            raise ValueError("Duplicate table names are not allowed")

        return normalized


class DatabaseAccessRequest(BaseModel):
    """A proposed database operation."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1, max_length=128)
    principal: str = Field(min_length=1, max_length=128)
    database: str = Field(min_length=1, max_length=128)
    operation: DatabaseOperation
    table: str = Field(min_length=1, max_length=256)

    # Query text is for risk inspection only, never executed by this layer.
    query_text: str = Field(default="", max_length=100_000)

    @field_validator("request_id", "principal", "database", "table")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Value cannot be blank")

        return value

    @field_validator("table")
    @classmethod
    def normalize_table(cls, value: str) -> str:
        return value.strip().lower()


class DatabaseSecurityFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=64)
    risk: DatabaseRiskLevel
    message: str = Field(min_length=1, max_length=500)


class DatabaseAccessDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(min_length=1, max_length=128)
    action: DatabaseDecisionAction
    policy_id: str | None = None
    findings: list[DatabaseSecurityFinding] = Field(
        default_factory=list,
        max_length=100,
    )
    reason: str = Field(min_length=1, max_length=500)
