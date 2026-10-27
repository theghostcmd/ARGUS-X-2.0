
import pytest

from app.layers.layer5_zero_trust.schemas import (
    AccessRequest,
    ZeroTrustPolicy,
)
from app.layers.layer5_zero_trust.policy_engine import (
    ZeroTrustPolicyEngine,
)


def make_policy(**overrides):
    data = {
        "policy_id": "POLICY_READ_REPORTS",
        "resource": "reports",
        "actions": ["read"],
        "effect": "allow",
        "require_mfa": True,
        "allowed_device_trust": ["trusted"],
        "enabled": True,
    }
    data.update(overrides)
    return ZeroTrustPolicy(**data)


def make_request(**overrides):
    data = {
        "request_id": "request-001",
        "subject_id": "user-123",
        "resource": "reports",
        "action": "read",
        "device_trust": "trusted",
        "mfa_status": "verified",
        "source_ip": "192.168.1.10",
    }
    data.update(overrides)
    return AccessRequest(**data)


def test_allows_verified_request():
    engine = ZeroTrustPolicyEngine([make_policy()])

    result = engine.evaluate(make_request())

    assert result.allowed is True
    assert result.policy_id == "POLICY_READ_REPORTS"
    assert result.reason == "policy_matched"


def test_denies_when_no_policy_matches():
    engine = ZeroTrustPolicyEngine([make_policy()])

    result = engine.evaluate(
        make_request(resource="financial_records")
    )

    assert result.allowed is False
    assert result.reason == "no_matching_policy"


def test_denies_when_mfa_is_not_verified():
    engine = ZeroTrustPolicyEngine([make_policy()])

    result = engine.evaluate(
        make_request(mfa_status="not_verified")
    )

    assert result.allowed is False
    assert result.reason == "mfa_required"


def test_denies_untrusted_device():
    engine = ZeroTrustPolicyEngine([make_policy()])

    result = engine.evaluate(
        make_request(device_trust="untrusted")
    )

    assert result.allowed is False
    assert result.reason == "device_trust_not_allowed"


def test_explicit_deny_policy_blocks_access():
    engine = ZeroTrustPolicyEngine([
        make_policy(effect="deny")
    ])

    result = engine.evaluate(make_request())

    assert result.allowed is False
    assert result.reason == "explicitly_denied"


def test_disabled_policy_is_ignored():
    engine = ZeroTrustPolicyEngine([
        make_policy(enabled=False)
    ])

    result = engine.evaluate(make_request())

    assert result.allowed is False
    assert result.reason == "no_matching_policy"


def test_ambiguous_policies_default_to_deny():
    engine = ZeroTrustPolicyEngine([
        make_policy(policy_id="POLICY_A"),
        make_policy(policy_id="POLICY_B"),
    ])

    result = engine.evaluate(make_request())

    assert result.allowed is False
    assert result.reason == "ambiguous_policies"


def test_duplicate_policy_id_is_rejected():
    policy = make_policy()
    engine = ZeroTrustPolicyEngine([policy])

    with pytest.raises(ValueError, match="Duplicate policy ID"):
        engine.add_policy(policy)


def test_remove_policy():
    engine = ZeroTrustPolicyEngine([make_policy()])

    assert engine.remove_policy("POLICY_READ_REPORTS") is True
    assert engine.remove_policy("POLICY_READ_REPORTS") is False

    result = engine.evaluate(make_request())

    assert result.allowed is False
    assert result.reason == "no_matching_policy"


def test_invalid_source_ip_is_rejected():
    with pytest.raises(ValueError):
        make_request(source_ip="not-an-ip")


def test_blank_subject_is_rejected():
    with pytest.raises(ValueError):
        make_request(subject_id="   ")
