
from app.layers.layer12_backup_recovery.backup_engine import BackupEngine
from app.layers.layer12_backup_recovery.schemas import (
    BackupStatus,
    RecoveryDecision,
    RecoveryRequest,
    RecoveryStatus,
)


class RecoveryEngine:
    """
    Validates whether a backup is eligible for recovery.

    No data is restored by this class. Actual restoration requires a
    storage adapter, authorization checks, and integrity verification.
    """

    def __init__(self, backup_engine: BackupEngine) -> None:
        self.backup_engine = backup_engine

    def evaluate(self, request: RecoveryRequest) -> RecoveryDecision:
        backup = self.backup_engine.get_backup(request.backup_id)

        if backup is None:
            return RecoveryDecision(
                recovery_id=request.recovery_id,
                backup_id=request.backup_id,
                status=RecoveryStatus.FAILED,
                approved=False,
                executed=False,
                message="Recovery denied: backup record was not found.",
            )

        if backup.status != BackupStatus.VERIFIED:
            return RecoveryDecision(
                recovery_id=request.recovery_id,
                backup_id=request.backup_id,
                status=RecoveryStatus.FAILED,
                approved=False,
                executed=False,
                message=(
                    "Recovery denied: backup must be verified before recovery."
                ),
            )

        if request.target.strip() == backup.destination.strip():
            return RecoveryDecision(
                recovery_id=request.recovery_id,
                backup_id=request.backup_id,
                status=RecoveryStatus.FAILED,
                approved=False,
                executed=False,
                message=(
                    "Recovery denied: target must not equal the backup "
                    "destination."
                ),
            )

        if request.dry_run:
            return RecoveryDecision(
                recovery_id=request.recovery_id,
                backup_id=request.backup_id,
                status=RecoveryStatus.READY,
                approved=True,
                executed=False,
                message=(
                    "Dry run successful. Backup is verified and eligible "
                    "for recovery; no data was restored."
                ),
            )

        return RecoveryDecision(
            recovery_id=request.recovery_id,
            backup_id=request.backup_id,
            status=RecoveryStatus.READY,
            approved=True,
            executed=False,
            message=(
                "Recovery eligibility approved, but restoration was not "
                "executed because no storage adapter is configured."
            ),
        )
