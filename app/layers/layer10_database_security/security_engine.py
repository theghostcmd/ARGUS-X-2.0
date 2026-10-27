
import re

from app.layers.layer10_database_security.schemas import (
    DatabaseAccessDecision,
    DatabaseAccessPolicy,
    DatabaseAccessRequest,
    DatabaseDecisionAction,
    DatabaseOperation,
    DatabaseRiskLevel,
    DatabaseSecurityFinding,
)


class DatabaseSecurityEngine:
    """
    Evaluates database access policies and flags selected query risks.

    This engine does not connect to a database or execute SQL.
    Enforcement must be performed by a trusted database integration.
    """

    DANGEROUS_QUERY_PATTERNS = [
        (
            "MULTIPLE_STATEMENTS",
            re.compile(r";\s*\S", re.IGNORECASE),
            DatabaseRiskLevel.HIGH,
            "Query may contain multiple SQL statements.",
        ),
        (
            "DESTRUCTIVE_DDL",
            re.compile(
                r"\b(DROP|TRUNCATE|ALTER)\s+(TABLE|DATABASE|SCHEMA)\b",
                re.IGNORECASE,
            ),
            DatabaseRiskLevel.CRITICAL,
            "Potentially destructive database DDL detected.",
        ),
        (
            "BROAD_DELETE_OR_UPDATE",
            re.compile(
                r"\b(DELETE\s+FROM|UPDATE)\s+"
                r"[A-Za-z0-9_.\[\]\"`]+\s*;?\s*$",
                re.IGNORECASE,
            ),
            DatabaseRiskLevel.HIGH,
            "UPDATE or DELETE may be missing a WHERE clause.",
        ),
    ]

    def __init__(
        self,
        policies: list[DatabaseAccessPolicy] | None = None,
    ) -> None:
        self._policies: dict[str, DatabaseAccessPolicy] = {}

        for policy in policies or []:
            self.add_policy(policy)

    def add_policy(self, policy: DatabaseAccessPolicy) -> None:
        if policy.policy_id in self._policies:
            raise ValueError(
                f"Database policy already exists: {policy.policy_id}"
            )

        self._policies[policy.policy_id] = policy

    def remove_policy(self, policy_id: str) -> bool:
        return self._policies.pop(policy_id, None) is not None

    def get_policies(self) -> list[DatabaseAccessPolicy]:
        return list(self._policies.values())

    def _find_matching_policies(
        self,
        request: DatabaseAccessRequest,
    ) -> list[DatabaseAccessPolicy]:
        return [
            policy
            for policy in self._policies.values()
            if policy.enabled
            and policy.principal == request.principal
            and policy.database == request.database
            and request.operation in policy.allowed_operations
            and (
                not policy.allowed_tables
                or request.table in policy.allowed_tables
            )
        ]

    @classmethod
    def inspect_query(
        cls,
        query_text: str,
    ) -> list[DatabaseSecurityFinding]:
        """Perform basic heuristic checks on SQL text."""

        findings: list[DatabaseSecurityFinding] = []

        for code, pattern, risk, message in cls.DANGEROUS_QUERY_PATTERNS:
            if pattern.search(query_text):
                findings.append(
                    DatabaseSecurityFinding(
                        code=code,
                        risk=risk,
                        message=message,
                    )
                )

        return findings

    def evaluate(
        self,
        request: DatabaseAccessRequest,
    ) -> DatabaseAccessDecision:
        findings = self.inspect_query(request.query_text)

        if findings:
            return DatabaseAccessDecision(
                request_id=request.request_id,
                action=DatabaseDecisionAction.DENY,
                findings=findings,
                reason="Query risk checks flagged potentially unsafe SQL.",
            )

        matches = self._find_matching_policies(request)

        if len(matches) > 1:
            return DatabaseAccessDecision(
                request_id=request.request_id,
                action=DatabaseDecisionAction.DENY,
                findings=[
                    DatabaseSecurityFinding(
                        code="AMBIGUOUS_POLICIES",
                        risk=DatabaseRiskLevel.HIGH,
                        message="Multiple policies match the same request.",
                    )
                ],
                reason="Access denied due to ambiguous policy configuration.",
            )

        if not matches:
            return DatabaseAccessDecision(
                request_id=request.request_id,
                action=DatabaseDecisionAction.DENY,
                reason="No matching database access policy; default deny.",
            )

        policy = matches[0]

        return DatabaseAccessDecision(
            request_id=request.request_id,
            action=DatabaseDecisionAction.ALLOW,
            policy_id=policy.policy_id,
            reason="Database operation is allowed by the matching policy.",
        )
