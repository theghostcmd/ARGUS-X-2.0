
import pytest
from pydantic import ValidationError

from app.layers.layer12_backup_recovery.schemas import (
    BackupRequest,
    BackupStatus,
    BackupType,
    RecoveryRequest,
    RecoveryStatus,
)
from app.layers.layer12_backup_recovery.backup_engine import BackupEngine
from app.layers.layer12_backup_recovery.recovery_engine import RecoveryEngine


def make_backup_request(backup_id="backup-001"):
    return BackupRequest(
        backup_id=backup_id,
        source_name="application-data",
        backup_type=BackupType.FULL,
        destination="backup-store/backup-001",
        requested_by="security-admin",
    )


def make_recovery_request(
    recovery_id="recovery-001",
    backup_id="backup-001",
    target="restore-target",
    dry_run=True,
):
    return RecoveryRequest(
        recovery_id=recovery_id,
        backup_id=backup_id,
        target=target,
        requested_by="security-admin",
        dry_run=dry_run,
    )


def verified_backup(engine):
    engine.create_backup(make_backup_request())
    engine.update_status("backup-001", BackupStatus.RUNNING)
    engine.update_status(
        "backup-001",
        BackupStatus.COMPLETED,
        checksum_sha256="a" * 64,
        size_bytes=1024,
    )
    engine.update_status("backup-001", BackupStatus.VERIFIED)


def test_create_backup():
    engine = BackupEngine()

    record = engine.create_backup(make_backup_request())

    assert record.backup_id == "backup-001"
    assert record.status == BackupStatus.PENDING


def test_duplicate_backup_is_rejected():
    engine = BackupEngine()
    engine.create_backup(make_backup_request())

    with pytest.raises(ValueError, match="already exists"):
        engine.create_backup(make_backup_request())


def test_get_missing_backup_returns_none():
    assert BackupEngine().get_backup("missing") is None


def test_list_backups():
    engine = BackupEngine()
    engine.create_backup(make_backup_request())

    assert len(engine.list_backups()) == 1


def test_valid_backup_status_transitions():
    engine = BackupEngine()
    engine.create_backup(make_backup_request())

    engine.update_status("backup-001", BackupStatus.RUNNING)
    engine.update_status(
        "backup-001",
        BackupStatus.COMPLETED,
        checksum_sha256="a" * 64,
        size_bytes=1024,
    )
    result = engine.update_status("backup-001", BackupStatus.VERIFIED)

    assert result.status == BackupStatus.VERIFIED
    assert result.checksum_sha256 == "a" * 64


def test_invalid_status_transition_is_rejected():
    engine = BackupEngine()
    engine.create_backup(make_backup_request())

    with pytest.raises(ValueError, match="Invalid backup status transition"):
        engine.update_status("backup-001", BackupStatus.VERIFIED)


def test_unknown_backup_status_update_is_rejected():
    engine = BackupEngine()

    with pytest.raises(KeyError, match="Backup not found"):
        engine.update_status("missing", BackupStatus.RUNNING)


def test_invalid_checksum_is_rejected():
    engine = BackupEngine()
    engine.create_backup(make_backup_request())
    engine.update_status("backup-001", BackupStatus.RUNNING)

    with pytest.raises(ValidationError):
        engine.update_status(
            "backup-001",
            BackupStatus.COMPLETED,
            checksum_sha256="invalid",
        )


def test_negative_backup_size_is_rejected():
    engine = BackupEngine()
    engine.create_backup(make_backup_request())
    engine.update_status("backup-001", BackupStatus.RUNNING)

    with pytest.raises(ValidationError):
        engine.update_status(
            "backup-001",
            BackupStatus.COMPLETED,
            size_bytes=-1,
        )


def test_recovery_rejects_missing_backup():
    engine = BackupEngine()
    recovery = RecoveryEngine(engine)

    decision = recovery.evaluate(make_recovery_request())

    assert decision.approved is False
    assert decision.status == RecoveryStatus.FAILED


def test_recovery_requires_verified_backup():
    engine = BackupEngine()
    engine.create_backup(make_backup_request())
    recovery = RecoveryEngine(engine)

    decision = recovery.evaluate(make_recovery_request())

    assert decision.approved is False


def test_verified_backup_passes_dry_run():
    engine = BackupEngine()
    verified_backup(engine)
    recovery = RecoveryEngine(engine)

    decision = recovery.evaluate(make_recovery_request())

    assert decision.approved is True
    assert decision.status == RecoveryStatus.READY
    assert decision.executed is False


def test_recovery_target_cannot_equal_backup_destination():
    engine = BackupEngine()
    verified_backup(engine)
    recovery = RecoveryEngine(engine)

    decision = recovery.evaluate(
        make_recovery_request(target="backup-store/backup-001")
    )

    assert decision.approved is False


def test_non_dry_run_still_does_not_restore_without_adapter():
    engine = BackupEngine()
    verified_backup(engine)
    recovery = RecoveryEngine(engine)

    decision = recovery.evaluate(
        make_recovery_request(dry_run=False)
    )

    assert decision.approved is True
    assert decision.executed is False
    assert "not executed" in decision.message.lower()


def test_blank_backup_id_is_rejected():
    with pytest.raises(ValidationError):
        make_backup_request(backup_id="   ")


def test_invalid_backup_type_is_rejected():
    with pytest.raises(ValidationError):
        BackupRequest(
            backup_id="backup-x",
            source_name="data",
            backup_type="unknown",
            destination="backup-store",
            requested_by="admin",
        )
