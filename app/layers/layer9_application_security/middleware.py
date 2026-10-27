import json
import logging
import time
import uuid
from urllib.parse import parse_qsl

from starlette.responses import JSONResponse

from app.layers.layer9_application_security.schemas import (
    ApplicationRequest,
    ApplicationSecurityConfig,
)
from app.layers.layer9_application_security.security_engine import (
    ApplicationSecurityEngine,
)

logger = logging.getLogger("argus_x.layer9_application_security")


class ApplicationSecurityMiddleware:
    """Inspect HTTP requests before they reach application routes."""

    def __init__(
        self,
        app,
        enabled: bool = True,
        max_body_bytes: int = 1_048_576,
        excluded_paths=("/health", "/ready"),
    ):
        self.app = app
        self.enabled = enabled
        self.max_body_bytes = max_body_bytes
        self.excluded_paths = frozenset(excluded_paths)

        # These are request checks, not response-header checks.
        config = ApplicationSecurityConfig(
            config_id="argus-x-http-application-security",
            allowed_methods=[
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
                "HEAD",
            ],
            allowed_content_types=[
                "application/json",
                "application/x-www-form-urlencoded",
                "text/plain",
                "multipart/form-data",
            ],
            max_body_size_bytes=max_body_bytes,
            required_security_headers=[],
            enabled=enabled,
        )
        self.engine = ApplicationSecurityEngine(config)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "/")

        if path in self.excluded_paths:
            await self.app(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        request_id = state.get("request_id") or str(uuid.uuid4())
        state["request_id"] = request_id

        headers = {
            key.decode("latin-1").lower():
            value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }

        content_type = headers.get("content-type")
        if content_type:
            content_type = content_type.split(";", 1)[0].strip().lower()

        raw_length = headers.get("content-length")
        declared_length = None

        if raw_length is not None:
            try:
                declared_length = int(raw_length)
            except (TypeError, ValueError):
                await self._block(
                    scope, receive, send, request_id,
                    "invalid_content_length", 400,
                )
                return

            if declared_length < 0:
                await self._block(
                    scope, receive, send, request_id,
                    "invalid_content_length", 400,
                )
                return

            if declared_length > self.max_body_bytes:
                await self._block(
                    scope, receive, send, request_id,
                    "body_too_large", 413,
                )
                return

        body = bytearray()

        # Buffer the body so the security engine can inspect it.
        # Replay it afterwards so FastAPI can read it normally.
        while True:
            message = await receive()

            if message["type"] == "http.disconnect":
                return

            if message["type"] != "http.request":
                continue

            body.extend(message.get("body", b""))

            if len(body) > self.max_body_bytes:
                await self._block(
                    scope, receive, send, request_id,
                    "body_too_large", 413,
                )
                return

            if not message.get("more_body", False):
                break

        actual_body_size = len(body)
        input_values = self._extract_inputs(
            scope.get("query_string", b""),
            content_type,
            bytes(body),
        )

        request = ApplicationRequest(
            request_id=request_id,
            method=scope.get("method", "GET"),
            path=path,
            content_type=content_type,
            content_length=declared_length,
            headers=headers,
            input_values=input_values,
        )

        decision = self.engine.inspect(
            request,
            actual_body_size=actual_body_size,
        )

        if not decision.allowed:
            finding_codes = [
                finding.code for finding in decision.findings
                if finding.action.value == "block"
            ]
            reason = finding_codes[0] if finding_codes else decision.reason

            await self._block(
                scope, receive, send, request_id, reason, 403,
            )
            return

        replay_body = bytes(body)
        replayed = False

        async def replay_receive():
            nonlocal replayed

            if not replayed:
                replayed = True
                return {
                    "type": "http.request",
                    "body": replay_body,
                    "more_body": False,
                }

            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    def _extract_inputs(query_string, content_type, body):
        """Extract text inputs without logging or returning raw request bodies."""
        inputs = {}

        query = query_string.decode("utf-8", errors="replace")
        for key, value in parse_qsl(
            query, keep_blank_values=True, max_num_fields=1000
        ):
            inputs[f"query:{key}"] = value

        if not body:
            return inputs

        text = body.decode("utf-8", errors="replace")

        if content_type == "application/json":
            try:
                parsed = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                # Let the application framework handle invalid JSON syntax.
                return inputs

            ApplicationSecurityMiddleware._flatten_json(parsed, inputs)
        elif content_type == "application/x-www-form-urlencoded":
            try:
                pairs = parse_qsl(
                    text, keep_blank_values=True, max_num_fields=1000
                )
                for key, value in pairs:
                    inputs[f"body:{key}"] = value
            except ValueError:
                # Avoid turning a malformed form into an unhandled middleware error.
                pass
        elif content_type and content_type.startswith("text/"):
            inputs["body:text"] = text[:8192]

        return inputs

    @staticmethod
    def _flatten_json(value, output, prefix="", depth=0):
        if depth > 8 or len(output) >= 1000:
            return

        if isinstance(value, dict):
            for key, child in value.items():
                name = f"{prefix}.{key}" if prefix else str(key)
                ApplicationSecurityMiddleware._flatten_json(
                    child, output, name, depth + 1
                )
        elif isinstance(value, list):
            for index, child in enumerate(value):
                ApplicationSecurityMiddleware._flatten_json(
                    child, output, f"{prefix}[{index}]", depth + 1
                )
        elif isinstance(value, str):
            output[prefix or "body:value"] = value
        elif value is not None:
            output[prefix or "body:value"] = str(value)

    @staticmethod
    async def _block(
        scope, receive, send, request_id, reason, status_code
    ):
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"

        # Never log raw query parameters, credentials or request bodies.
        logger.warning(json.dumps({
            "event": "application_security_block",
            "request_id": request_id,
            "rule": reason,
            "method": scope.get("method"),
            "path": scope.get("path"),
            "client_ip": client_ip,
            "timestamp": int(time.time()),
        }))

        response = JSONResponse(
            status_code=status_code,
            content={
                "error": "request_blocked",
                "layer": "application_security",
                "rule": reason,
                "request_id": request_id,
            },
            headers={
                "X-Request-ID": request_id,
                "Cache-Control": "no-store",
            },
        )
        await response(scope, receive, send)