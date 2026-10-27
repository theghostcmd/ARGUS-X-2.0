
from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit

from pydantic import ValidationError

from app.layers.layer4_api_gateway.schemas import (
    GatewayDecision,
    GatewayRequestMetadata,
    GatewayRoute,
)

logger = logging.getLogger("argus_x.layer4_api_gateway")


class APIGateway:
    """
    Independent API gateway policy and route-selection engine.

    This class selects a configured route and validates request metadata.
    It does not forward HTTP requests or authenticate credentials yet.
    """

    def __init__(
        self,
        routes: list[GatewayRoute] | None = None,
    ) -> None:
        self._routes: dict[str, GatewayRoute] = {}
        self._path_methods: dict[tuple[str, str], str] = {}

        for route in routes or []:
            self.add_route(route)

    def add_route(self, route: GatewayRoute) -> None:
        """Register a route and reject duplicate route IDs or method/path pairs."""
        if route.route_id in self._routes:
            raise ValueError(
                f"Duplicate route ID: {route.route_id}"
            )

        for method in route.methods:
            key = (route.path, method)

            if key in self._path_methods:
                raise ValueError(
                    f"Duplicate route for {method} {route.path}"
                )

        self._routes[route.route_id] = route

        for method in route.methods:
            self._path_methods[(route.path, method)] = route.route_id

    def remove_route(self, route_id: str) -> bool:
        """Remove a route. Return False if the ID does not exist."""
        route = self._routes.pop(route_id, None)

        if route is None:
            return False

        for method in route.methods:
            self._path_methods.pop((route.path, method), None)

        return True

    def get_route(self, route_id: str) -> GatewayRoute | None:
        """Return a configured route by ID."""
        return self._routes.get(route_id)

    def list_routes(self) -> list[GatewayRoute]:
        """Return a copy of the registered route collection."""
        return list(self._routes.values())

    @staticmethod
    def _valid_path(path: str) -> bool:
        if not path or not path.startswith("/"):
            return False

        if "\\" in path or "?" in path or "#" in path:
            return False

        # Reject control characters and malformed percent escapes.
        if any(ord(char) < 32 or ord(char) == 127 for char in path):
            return False

        if re.search(r"%(?![0-9a-fA-F]{2})", path):
            return False

        return True

    def evaluate(
        self,
        request: GatewayRequestMetadata,
    ) -> GatewayDecision:
        """Evaluate a validated request against configured gateway routes."""
        if not self._valid_path(request.path):
            return GatewayDecision(
                allowed=False,
                reason="invalid_path",
                status_code=400,
            )

        route_id = self._path_methods.get(
            (request.path, request.method)
        )

        if route_id is not None:
            route = self._routes[route_id]

            if not route.enabled:
                return GatewayDecision(
                    allowed=False,
                    route_id=route.route_id,
                    reason="route_disabled",
                    status_code=403,
                )

            if (
                request.content_length
                > route.max_request_body_bytes
            ):
                return GatewayDecision(
                    allowed=False,
                    route_id=route.route_id,
                    reason="request_body_too_large",
                    status_code=413,
                )

            return GatewayDecision(
                allowed=True,
                route_id=route.route_id,
                reason="route_matched",
                status_code=200,
            )

        # If the path exists for another method, return 405.
        path_exists = any(
            configured_path == request.path
            for configured_path, _ in self._path_methods
        )

        if path_exists:
            return GatewayDecision(
                allowed=False,
                reason="method_not_allowed",
                status_code=405,
            )

        return GatewayDecision(
            allowed=False,
            reason="route_not_found",
            status_code=404,
        )

    def evaluate_untrusted(
        self,
        data: dict,
    ) -> GatewayDecision:
        """
        Safely evaluate an untrusted dictionary.

        Invalid metadata is rejected instead of being used for routing.
        """
        try:
            request = GatewayRequestMetadata.model_validate(data)
        except (ValidationError, TypeError, ValueError):
            return GatewayDecision(
                allowed=False,
                reason="invalid_request_metadata",
                status_code=400,
            )

        return self.evaluate(request)
