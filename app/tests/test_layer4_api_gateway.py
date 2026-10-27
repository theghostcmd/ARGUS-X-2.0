
import pytest

from app.layers.layer4_api_gateway.schemas import (
    GatewayRoute,
    GatewayRequestMetadata,
)
from app.layers.layer4_api_gateway.gateway import APIGateway


def make_route(**overrides):
    data = {
        "route_id": "users_api",
        "path": "/api/users",
        "methods": ["GET"],
        "backend_url": "http://127.0.0.1:9000",
        "auth_mode": "bearer",
        "enabled": True,
        "timeout_seconds": 10,
        "max_request_body_bytes": 1024,
    }
    data.update(overrides)
    return GatewayRoute(**data)


def make_request(**overrides):
    data = {
        "request_id": "test-request-001",
        "method": "GET",
        "path": "/api/users",
        "content_length": 0,
    }
    data.update(overrides)
    return GatewayRequestMetadata(**data)


def test_matching_route_is_allowed():
    gateway = APIGateway([make_route()])

    result = gateway.evaluate(make_request())

    assert result.allowed is True
    assert result.route_id == "users_api"
    assert result.status_code == 200


def test_unknown_route_returns_404():
    gateway = APIGateway([make_route()])

    result = gateway.evaluate(
        make_request(path="/api/unknown")
    )

    assert result.allowed is False
    assert result.status_code == 404
    assert result.reason == "route_not_found"


def test_wrong_method_returns_405():
    gateway = APIGateway([make_route()])

    result = gateway.evaluate(
        make_request(method="POST")
    )

    assert result.allowed is False
    assert result.status_code == 405
    assert result.reason == "method_not_allowed"


def test_disabled_route_returns_403():
    gateway = APIGateway([
        make_route(enabled=False)
    ])

    result = gateway.evaluate(make_request())

    assert result.allowed is False
    assert result.status_code == 403
    assert result.reason == "route_disabled"


def test_large_request_body_returns_413():
    gateway = APIGateway([
        make_route(max_request_body_bytes=100)
    ])

    result = gateway.evaluate(
        make_request(content_length=101)
    )

    assert result.allowed is False
    assert result.status_code == 413
    assert result.reason == "request_body_too_large"


def test_duplicate_route_id_is_rejected():
    route = make_route()
    gateway = APIGateway([route])

    with pytest.raises(ValueError, match="Duplicate route ID"):
        gateway.add_route(route)


def test_duplicate_path_and_method_are_rejected():
    first = make_route(route_id="route_one")
    second = make_route(route_id="route_two")

    with pytest.raises(ValueError, match="Duplicate route"):
        APIGateway([first, second])


def test_invalid_metadata_is_rejected():
    gateway = APIGateway([make_route()])

    result = gateway.evaluate_untrusted({
        "request_id": "test-request-002",
        "method": "INVALID",
        "path": "/api/users",
        "content_length": 0,
    })

    assert result.allowed is False
    assert result.status_code == 400
    assert result.reason == "invalid_request_metadata"


def test_invalid_path_is_rejected():
    gateway = APIGateway([make_route()])

    result = gateway.evaluate(
        make_request(path="/api\\users")
    )

    assert result.allowed is False
    assert result.status_code == 400
    assert result.reason == "invalid_path"


def test_remove_route():
    gateway = APIGateway([make_route()])

    assert gateway.remove_route("users_api") is True

    result = gateway.evaluate(make_request())

    assert result.allowed is False
    assert result.status_code == 404


def test_unknown_route_is_default_denied():
    gateway = APIGateway()

    result = gateway.evaluate(make_request())

    assert result.allowed is False
    assert result.status_code == 404
