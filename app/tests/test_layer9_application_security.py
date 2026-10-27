
import pytest
from pydantic import ValidationError

from app.layers.layer9_application_security.schemas import (
    ApplicationRequest,
    ApplicationSecurityConfig,
)
from app.layers.layer9_application_security.security_engine import (
    ApplicationSecurityEngine,
)


@pytest.fixture
def config():
    return ApplicationSecurityConfig(
        config_id="test-config",
        allowed_methods=["GET", "POST"],
        allowed_content_types=["application/json"],
        max_body_size_bytes=1024,
        required_security_headers=["x-content-type-options"],
    )


@pytest.fixture
def engine(config):
    return ApplicationSecurityEngine(config)


def make_request(**overrides):
    values = {
        "request_id": "req-001",
        "method": "GET",
        "path": "/api/items",
        "content_type": "application/json",
        "content_length": 100,
        "headers": {"X-Content-Type-Options": "nosniff"},
        "input_values": {"search": "normal search"},
    }
    values.update(overrides)
    return ApplicationRequest(**values)


def test_safe_request_is_allowed(engine):
    decision = engine.inspect(make_request())

    assert decision.allowed is True
    assert decision.findings == []


def test_disallowed_method_is_blocked(engine):
    decision = engine.inspect(make_request(method="TRACE"))

    assert decision.allowed is False
    assert any(
        finding.code == "METHOD_NOT_ALLOWED"
        for finding in decision.findings
    )


def test_disallowed_content_type_is_blocked(engine):
    decision = engine.inspect(
        make_request(content_type="text/plain")
    )

    assert decision.allowed is False
    assert any(
        finding.code == "CONTENT_TYPE_NOT_ALLOWED"
        for finding in decision.findings
    )


def test_oversized_body_is_blocked(engine):
    decision = engine.inspect(
        make_request(content_length=2048)
    )

    assert decision.allowed is False
    assert any(
        finding.code == "BODY_TOO_LARGE"
        for finding in decision.findings
    )


def test_trusted_measured_body_size_takes_precedence(engine):
    decision = engine.inspect(
        make_request(content_length=100),
        actual_body_size=2048,
    )

    assert decision.allowed is False
    assert any(
        finding.code == "BODY_TOO_LARGE"
        for finding in decision.findings
    )


def test_missing_required_header_is_blocked(engine):
    decision = engine.inspect(make_request(headers={}))

    assert decision.allowed is False
    assert any(
        finding.code == "MISSING_SECURITY_HEADER"
        for finding in decision.findings
    )


def test_sql_injection_pattern_is_flagged(engine):
    decision = engine.inspect(
        make_request(
            input_values={"search": "' OR 1=1 --"}
        )
    )

    assert decision.allowed is False
    assert any(
        finding.code == "POSSIBLE_SQL_INJECTION"
        for finding in decision.findings
    )


def test_xss_pattern_is_flagged(engine):
    decision = engine.inspect(
        make_request(
            input_values={"comment": "<script>alert(1)</script>"}
        )
    )

    assert decision.allowed is False
    assert any(
        finding.code == "POSSIBLE_XSS"
        for finding in decision.findings
    )


def test_path_traversal_pattern_is_flagged(engine):
    decision = engine.inspect(
        make_request(
            input_values={"file": "../../etc/passwd"}
        )
    )

    assert decision.allowed is False
    assert any(
        finding.code == "POSSIBLE_PATH_TRAVERSAL"
        for finding in decision.findings
    )


def test_disabled_security_config_allows_without_inspection():
    config = ApplicationSecurityConfig(
        config_id="disabled-config",
        enabled=False,
    )
    engine = ApplicationSecurityEngine(config)

    decision = engine.inspect(
        make_request(method="TRACE", headers={})
    )

    assert decision.allowed is True
    assert decision.findings == []


def test_negative_actual_body_size_is_rejected(engine):
    with pytest.raises(ValueError, match="cannot be negative"):
        engine.inspect(make_request(), actual_body_size=-1)


def test_invalid_request_method_is_normalized():
    request = make_request(method=" get ")

    assert request.method == "GET"


def test_content_type_parameters_are_removed():
    request = make_request(
        content_type="Application/JSON; charset=utf-8"
    )

    assert request.content_type == "application/json"


def test_negative_content_length_is_rejected():
    with pytest.raises(ValidationError):
        make_request(content_length=-1)


def test_extra_config_fields_are_rejected():
    with pytest.raises(ValidationError):
        ApplicationSecurityConfig(
            config_id="invalid",
            unexpected_field=True,
        )
