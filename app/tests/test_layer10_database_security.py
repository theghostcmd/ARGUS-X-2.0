
import pytest
from pydantic import ValidationError

from app.layers.layer10_database_security.schemas import (
    DatabaseAccessPolicy,
    DatabaseAccessRequest,
    DatabaseDecisionAction,
    DatabaseOperation,
)
from app.layers.layer10_database_security.security_engine import (
    DatabaseSecurityEngine,
)


def make_policy(
    policy_id="read-orders",
    principal="app_service",
    database="sales",
    operations=None,
    tables=None,
    enabled=True,
):
    return DatabaseAccessPolicy(
        policy_id=policy_id,
        principal=principal,
        database=database,
        allowed_operations=operations or [DatabaseOperation.SELECT],
        allowed_tables=tables or ["orders"],
        enabled=enabled,
    )


def make_request(
    request_id="db-req-1",
    principal="app_service",
    database="sales",
    operation=DatabaseOperation.SELECT,
    table="orders",
    query_text="SELECT id FROM orders WHERE id = 10",
):
    return DatabaseAccessRequest(
        request_id=request_id,
        principal=principal,
        database=database,
        operation=operation,
        table=table,
        query_text=query_text,
    )


def test_matching_policy_allows_operation():
    engine = DatabaseSecurityEngine([make_policy()])

    decision = engine.evaluate(make_request())

    assert decision.action == DatabaseDecisionAction.ALLOW
    assert decision.policy_id == "read-orders"


def test_missing_policy_defaults_to_deny():
    engine = DatabaseSecurityEngine()

    decision = engine.evaluate(make_request())

    assert decision.action == DatabaseDecisionAction.DENY
    assert "default deny" in decision.reason.lower()


def test_wrong_principal_is_denied():
    engine = DatabaseSecurityEngine([make_policy()])

    decision = engine.evaluate(make_request(principal="unknown_user"))

    assert decision.action == DatabaseDecisionAction.DENY


def test_wrong_database_is_denied():
    engine = DatabaseSecurityEngine([make_policy()])

    decision = engine.evaluate(make_request(database="finance"))

    assert decision.action == DatabaseDecisionAction.DENY


def test_wrong_table_is_denied():
    engine = DatabaseSecurityEngine([make_policy()])

    decision = engine.evaluate(make_request(table="users"))

    assert decision.action == DatabaseDecisionAction.DENY


def test_wrong_operation_is_denied():
    engine = DatabaseSecurityEngine([make_policy()])

    decision = engine.evaluate(
        make_request(operation=DatabaseOperation.DELETE)
    )

    assert decision.action == DatabaseDecisionAction.DENY


def test_disabled_policy_is_ignored():
    engine = DatabaseSecurityEngine(
        [make_policy(enabled=False)]
    )

    decision = engine.evaluate(make_request())

    assert decision.action == DatabaseDecisionAction.DENY


def test_duplicate_policy_id_is_rejected():
    engine = DatabaseSecurityEngine()
    policy = make_policy()
    engine.add_policy(policy)

    with pytest.raises(ValueError, match="already exists"):
        engine.add_policy(policy)


def test_remove_policy():
    engine = DatabaseSecurityEngine([make_policy()])

    assert engine.remove_policy("read-orders") is True
    assert engine.remove_policy("read-orders") is False


def test_drop_table_query_is_denied():
    engine = DatabaseSecurityEngine([make_policy()])

    decision = engine.evaluate(
        make_request(
            operation=DatabaseOperation.DROP,
            query_text="DROP TABLE orders",
        )
    )

    assert decision.action == DatabaseDecisionAction.DENY
    assert any(
        finding.code == "DESTRUCTIVE_DDL"
        for finding in decision.findings
    )


def test_truncate_query_is_denied():
    engine = DatabaseSecurityEngine([make_policy()])

    decision = engine.evaluate(
        make_request(query_text="TRUNCATE TABLE orders")
    )

    assert decision.action == DatabaseDecisionAction.DENY
    assert any(
        finding.code == "DESTRUCTIVE_DDL"
        for finding in decision.findings
    )


def test_possible_multiple_statements_are_denied():
    engine = DatabaseSecurityEngine([make_policy()])

    decision = engine.evaluate(
        make_request(
            query_text="SELECT id FROM orders; DELETE FROM orders"
        )
    )

    assert decision.action == DatabaseDecisionAction.DENY
    assert any(
        finding.code == "MULTIPLE_STATEMENTS"
        for finding in decision.findings
    )


def test_query_without_where_on_delete_is_flagged():
    engine = DatabaseSecurityEngine([make_policy()])

    decision = engine.evaluate(
        make_request(query_text="DELETE FROM orders")
    )

    assert decision.action == DatabaseDecisionAction.DENY
    assert any(
        finding.code == "BROAD_DELETE_OR_UPDATE"
        for finding in decision.findings
    )


def test_duplicate_matching_policies_are_denied():
    engine = DatabaseSecurityEngine(
        [
            make_policy(policy_id="policy-a"),
            make_policy(policy_id="policy-b"),
        ]
    )

    decision = engine.evaluate(make_request())

    assert decision.action == DatabaseDecisionAction.DENY
    assert any(
        finding.code == "AMBIGUOUS_POLICIES"
        for finding in decision.findings
    )


def test_table_names_are_normalized():
    policy = make_policy(tables=["ORDERS"])
    engine = DatabaseSecurityEngine([policy])

    decision = engine.evaluate(make_request(table="ORDERS"))

    assert decision.action == DatabaseDecisionAction.ALLOW


def test_blank_request_id_is_rejected():
    with pytest.raises(ValidationError):
        make_request(request_id="   ")


def test_blank_table_name_is_rejected():
    with pytest.raises(ValidationError):
        make_request(table="   ")


def test_invalid_operation_is_rejected():
    with pytest.raises(ValidationError):
        DatabaseAccessRequest(
            request_id="db-req-invalid",
            principal="app_service",
            database="sales",
            operation="EXECUTE_ARBITRARY",
            table="orders",
        )


def test_unknown_policy_fields_are_rejected():
    with pytest.raises(ValidationError):
        DatabaseAccessPolicy(
            policy_id="invalid-policy",
            principal="app_service",
            database="sales",
            allowed_operations=[DatabaseOperation.SELECT],
            unexpected_field=True,
        )
