
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class BackupType(str, Enum):
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"


class BackupStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    VERIFIED = "verified"


class RecoveryStatus(str, Enum):
    REQUESTED = "requested"
    VALIDATING = "validating"
    READY = "ready"
    FAILED = "failed"


class BackupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backup_id: str = Field(min_length=1, max_length=128)
    source_name: str = Field(min_length=1, max_length=256)
    backup_type: BackupType = BackupType.FULL
    destination: str = Field(min_length=1, max_length=1024)
    requested_by: str = Field(min_length=1, max_length=128)

    @field_validator("backup_id", "source_name", "destination", "requested_by")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be blank")
        return value


class BackupRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backup_id: str = Field(min_length=1, max_length=128)
    source_name: str = Field(min_length=1, max_length=256)
    backup_type: BackupType
    destination: str = Field(min_length=1, max_length=1024)
    status: BackupStatus = BackupStatus.PENDING
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    completed_at: datetime | None = None
    checksum_sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    size_bytes: int | None = Field(default=None, ge=0)
    error_message: str | None = Field(default=None, max_length=1000)


class RecoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recovery_id: str = Field(min_length=1, max_length=128)
    backup_id: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=1, max_length=1024)
    requested_by: str = Field(min_length=1, max_length=128)
    dry_run: bool = True

    @field_validator("recovery_id", "backup_id", "target", "requested_by")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be blank")
        return value


class RecoveryDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recovery_id: str = Field(min_length=1, max_length=128)
    backup_id: str = Field(min_length=1, max_length=128)
    status: RecoveryStatus
    approved: bool
    executed: bool = False
    message: str = Field(min_length=1, max_length=1000)
