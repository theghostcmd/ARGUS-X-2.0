
from datetime import datetime, timedelta, timezone

import pytest

from app.layers.layer6_iam.schemas import (
    AccessRequest,
    MFAChallenge,
    MFAStatus,
    Permission,
    Role,
    RolePermission,
    UserIdentity,
)
from app.layers.layer6_iam.access_manager import IAMAccessManager


def make_user(**overrides):
    data = {
        "user_id": "user-001",
        "username": "security_user",
        "email": "security@example.com",
        "roles": [Role.SECURITY_ANALYST],
        "active": True,
        "mfa_status": MFAStatus.VERIFIED,
    }
    data.update(overrides)
    return UserIdentity(**data)


def make_request(**overrides):
    data = {
        "request_id": "request-001",
        "user_id": "user-001",
        "permission": Permission.VIEW_ALERTS,
        "resource": "alerts",
    }
    data.update(overrides)
    return AccessRequest(**data)


def make_challenge(**overrides):
    data = {
        "challenge_id": "challenge-123456789",
        "user_id": "user-001",
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
        "attempts_remaining": 3,
        "verified": False,
    }
    data.update(overrides)
    return MFAChallenge(**data)


def make_manager():
    user = make_user()
    permissions = RolePermission(
        role=Role.SECURITY_ANALYST,
        permissions=[Permission.VIEW_ALERTS],
    )
    return IAMAccessManager(
        users=[user],
        role_permissions=[permissions],
    )


def test_authorizes_user_with_permission_and_verified_mfa():
    manager = make_manager()

    assert manager.authorize(make_request()) is True


def test_denies_user_without_permission():
    manager = make_manager()

    request = make_request(permission=Permission.MANAGE_USERS)

    assert manager.authorize(request) is False


def test_denies_inactive_user():
    manager = IAMAccessManager(
        users=[make_user(active=False)],
        role_permissions=[
            RolePermission(
                role=Role.SECURITY_ANALYST,
                permissions=[Permission.VIEW_ALERTS],
            )
        ],
    )

    assert manager.authorize(make_request()) is False


def test_denies_user_without_verified_mfa():
    manager = IAMAccessManager(
        users=[make_user(mfa_status=MFAStatus.PENDING)],
        role_permissions=[
            RolePermission(
                role=Role.SECURITY_ANALYST,
                permissions=[Permission.VIEW_ALERTS],
            )
        ],
    )

    assert manager.authorize(make_request()) is False


def test_rejects_duplicate_user_id():
    manager = make_manager()

    with pytest.raises(ValueError, match="Duplicate user ID"):
        manager.add_user(make_user())


def test_rejects_duplicate_username():
    manager = make_manager()

    duplicate = make_user(
        user_id="user-002",
        email="another@example.com",
    )

    with pytest.raises(ValueError, match="Duplicate username"):
        manager.add_user(duplicate)


def test_rejects_duplicate_email():
    manager = make_manager()

    duplicate = make_user(
        user_id="user-002",
        username="another_user",
    )

    with pytest.raises(ValueError, match="Duplicate email"):
        manager.add_user(duplicate)


def test_role_permissions_are_returned_as_a_copy():
    manager = make_manager()

    permissions = manager.get_role_permissions(
        Role.SECURITY_ANALYST
    )
    permissions.clear()

    assert manager.authorize(make_request()) is True


def test_registers_mfa_challenge():
    manager = make_manager()
    challenge = make_challenge()

    manager.register_mfa_challenge(challenge)

    assert manager.get_mfa_challenge(
        challenge.challenge_id
    ) is challenge


def test_rejects_duplicate_mfa_challenge():
    manager = make_manager()
    challenge = make_challenge()

    manager.register_mfa_challenge(challenge)

    with pytest.raises(ValueError, match="Duplicate challenge ID"):
        manager.register_mfa_challenge(challenge)


def test_consumes_mfa_attempt():
    manager = make_manager()
    challenge = make_challenge(attempts_remaining=3)
    manager.register_mfa_challenge(challenge)

    assert manager.consume_mfa_attempt(
        challenge.challenge_id
    ) is True

    assert challenge.attempts_remaining == 2


def test_does_not_consume_expired_challenge():
    manager = make_manager()
    challenge = make_challenge(
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)
    )
    manager.register_mfa_challenge(challenge)

    assert manager.consume_mfa_attempt(
        challenge.challenge_id
    ) is False


def test_does_not_consume_exhausted_challenge():
    manager = make_manager()
    challenge = make_challenge(attempts_remaining=0)
    manager.register_mfa_challenge(challenge)

    assert manager.consume_mfa_attempt(
        challenge.challenge_id
    ) is False


def test_marks_pending_challenge_verified():
    manager = IAMAccessManager(users=[make_user(
        mfa_status=MFAStatus.PENDING
    )])
    challenge = make_challenge()
    manager.register_mfa_challenge(challenge)

    # Unit-test only: production must verify the OTP first.
    assert manager.mark_mfa_verified(challenge.challenge_id) is True
    assert challenge.verified is True
    assert manager.get_user("user-001").mfa_status == MFAStatus.VERIFIED


def test_rejects_blank_username():
    with pytest.raises(ValueError):
        make_user(username="   ")


def test_rejects_invalid_email():
    with pytest.raises(ValueError):
        make_user(email="not-an-email")
