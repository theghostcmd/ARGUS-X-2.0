
from app.layers.layer12_backup_recovery.schemas import (
    BackupRecord,
    BackupRequest,
    BackupStatus,
)


class BackupEngine:
    """
    Tracks backup requests and status in memory.

    This engine does not copy files or connect to storage.
    A trusted storage adapter is required for real backups.
    """

    def __init__(self) -> None:
        self._records: dict[str, BackupRecord] = {}

    def create_backup(self, request: BackupRequest) -> BackupRecord:
        if request.backup_id in self._records:
            raise ValueError(
                f"Backup already exists: {request.backup_id}"
            )

        record = BackupRecord(
            backup_id=request.backup_id,
            source_name=request.source_name,
            backup_type=request.backup_type,
            destination=request.destination,
            status=BackupStatus.PENDING,
        )

        self._records[record.backup_id] = record
        return record.model_copy(deep=True)

    def get_backup(self, backup_id: str) -> BackupRecord | None:
        record = self._records.get(backup_id)
        return record.model_copy(deep=True) if record else None

    def list_backups(self) -> list[BackupRecord]:
        return [
            record.model_copy(deep=True)
            for record in self._records.values()
        ]

    def update_status(
        self,
        backup_id: str,
        status: BackupStatus,
        *,
        checksum_sha256: str | None = None,
        size_bytes: int | None = None,
        error_message: str | None = None,
    ) -> BackupRecord:
        record = self._records.get(backup_id)

        if record is None:
            raise KeyError(f"Backup not found: {backup_id}")

        allowed_transitions = {
            BackupStatus.PENDING: {
                BackupStatus.RUNNING,
                BackupStatus.FAILED,
            },
            BackupStatus.RUNNING: {
                BackupStatus.COMPLETED,
                BackupStatus.FAILED,
            },
            BackupStatus.COMPLETED: {
                BackupStatus.VERIFIED,
                BackupStatus.FAILED,
            },
            BackupStatus.VERIFIED: set(),
            BackupStatus.FAILED: set(),
        }

        if status not in allowed_transitions[record.status]:
            raise ValueError(
                f"Invalid backup status transition: "
                f"{record.status.value} -> {status.value}"
            )

        changes: dict = {"status": status}

        if checksum_sha256 is not None:
            changes["checksum_sha256"] = checksum_sha256

        if size_bytes is not None:
            changes["size_bytes"] = size_bytes

        if error_message is not None:
            changes["error_message"] = error_message

        if status in {BackupStatus.COMPLETED, BackupStatus.VERIFIED}:
            changes["completed_at"] = record.completed_at or __import__(
                "datetime"
            ).datetime.now(__import__("datetime").timezone.utc)

        updated = record.model_copy(update=changes)
        self._records[backup_id] = updated

        # Re-validate changes made through model_copy(update=...).
        validated = BackupRecord.model_validate(updated.model_dump())
        self._records[backup_id] = validated

        return validated.model_copy(deep=True)
