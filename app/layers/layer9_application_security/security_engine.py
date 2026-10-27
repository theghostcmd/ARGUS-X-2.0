
import re

from app.layers.layer9_application_security.schemas import (
    ApplicationAction,
    ApplicationCheckType,
    ApplicationRequest,
    ApplicationSecurityConfig,
    ApplicationSecurityDecision,
    ApplicationSecurityFinding,
    ApplicationSeverity,
)


class ApplicationSecurityEngine:
    """Performs basic application-level request security checks."""

    # Selected high-risk patterns only; this is not a complete WAF.
    SUSPICIOUS_PATTERNS = {
        "possible_sql_injection": re.compile(
            r"(?i)(?:\bunion\s+select\b|'\s*(?:or|and)\s+\d+\s*=\s*\d+|--\s*$)"
        ),
        "possible_xss": re.compile(
            r"(?i)<\s*script\b|javascript\s*:|onerror\s*="
        ),
        "possible_path_traversal": re.compile(
            r"(?:\.\./|\.\.\\)"
        ),
    }

    def __init__(self, config: ApplicationSecurityConfig) -> None:
        self.config = config

    @staticmethod
    def _finding(
        check_type: ApplicationCheckType,
        severity: ApplicationSeverity,
        code: str,
        message: str,
    ) -> ApplicationSecurityFinding:
        return ApplicationSecurityFinding(
            check_type=check_type,
            severity=severity,
            action=ApplicationAction.BLOCK,
            code=code,
            message=message,
        )

    def inspect(
        self,
        request: ApplicationRequest,
        *,
        actual_body_size: int | None = None,
    ) -> ApplicationSecurityDecision:
        """
        Inspect normalized request metadata.

        Supply actual_body_size from a trusted server/framework measurement
        whenever the body has been read. Client-supplied Content-Length alone
        must not be treated as authoritative.
        """

        findings: list[ApplicationSecurityFinding] = []

        if not self.config.enabled:
            return ApplicationSecurityDecision(
                request_id=request.request_id,
                allowed=True,
                findings=[],
                reason="Application security checks are disabled.",
            )

        if request.method not in self.config.allowed_methods:
            findings.append(
                self._finding(
                    ApplicationCheckType.HTTP_METHOD,
                    ApplicationSeverity.MEDIUM,
                    "METHOD_NOT_ALLOWED",
                    "HTTP method is not in the configured allowlist.",
                )
            )

        if request.content_type is not None:
            if request.content_type not in self.config.allowed_content_types:
                findings.append(
                    self._finding(
                        ApplicationCheckType.CONTENT_TYPE,
                        ApplicationSeverity.MEDIUM,
                        "CONTENT_TYPE_NOT_ALLOWED",
                        "Content type is not in the configured allowlist.",
                    )
                )

        measured_size = actual_body_size

        if measured_size is not None:
            if measured_size < 0:
                raise ValueError("actual_body_size cannot be negative")
        else:
            measured_size = request.content_length

        if (
            measured_size is not None
            and measured_size > self.config.max_body_size_bytes
        ):
            findings.append(
                self._finding(
                    ApplicationCheckType.BODY_SIZE,
                    ApplicationSeverity.HIGH,
                    "BODY_TOO_LARGE",
                    "Request body exceeds the configured size limit.",
                )
            )

        for required_header in self.config.required_security_headers:
            if required_header not in request.headers:
                findings.append(
                    self._finding(
                        ApplicationCheckType.SECURITY_HEADERS,
                        ApplicationSeverity.MEDIUM,
                        "MISSING_SECURITY_HEADER",
                        f"Required security header is missing: {required_header}",
                    )
                )

        for field_name, field_value in request.input_values.items():
            for code, pattern in self.SUSPICIOUS_PATTERNS.items():
                if pattern.search(field_value):
                    findings.append(
                        self._finding(
                            ApplicationCheckType.INPUT_VALIDATION,
                            ApplicationSeverity.HIGH,
                            code.upper(),
                            f"Suspicious input pattern detected in field: {field_name}",
                        )
                    )
                    break

        blocked = bool(findings)

        return ApplicationSecurityDecision(
            request_id=request.request_id,
            allowed=not blocked,
            findings=findings,
            reason=(
                "Request blocked by application security policy."
                if blocked
                else "Request passed configured application security checks."
            ),
        )
