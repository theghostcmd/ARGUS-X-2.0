
import json
import logging
import time
import uuid

from starlette.responses import JSONResponse

from app.layers.layer2_waf.inspector import inspect_text

logger = logging.getLogger("argus_x.layer2_waf")


class WAFMiddleware:
    def __init__(
        self,
        app,
        max_body_bytes: int = 1_048_576,
        max_url_length: int = 4096,
        excluded_paths: tuple = ("/health", "/ready"),
    ):
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.max_url_length = max_url_length
        self.excluded_paths = excluded_paths

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = (
            scope.get("state", {}).get("request_id")
            or str(uuid.uuid4())
        )

        path = scope.get("path", "/")
        method = scope.get("method", "GET")
        query = scope.get("query_string", b"").decode(
            "utf-8", errors="replace"
        )

        if path in self.excluded_paths:
            await self.app(scope, receive, send)
            return

        if len(path) > self.max_url_length or len(query) > self.max_url_length:
            await self._block(
                scope, receive, send, request_id,
                "url_too_long", 414,
            )
            return

        # Inspect query string.
        rule = inspect_text(query)
        if rule:
            await self._block(
                scope, receive, send, request_id, rule, 403
            )
            return

        headers = dict(scope.get("headers", []))
        content_type = headers.get(b"content-type", b"").decode(
            "latin-1"
        ).lower()

        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                body_length = int(raw_length)
            except ValueError:
                await self._block(
                    scope, receive, send, request_id,
                    "invalid_content_length", 400,
                )
                return

            if body_length < 0:
                await self._block(
                    scope, receive, send, request_id,
                    "invalid_content_length", 400,
                )
                return

            if body_length > self.max_body_bytes:
                await self._block(
                    scope, receive, send, request_id,
                    "body_too_large", 413,
                )
                return

        inspectable = any(
            kind in content_type
            for kind in (
                "application/json",
                "application/x-www-form-urlencoded",
                "text/",
            )
        )

        if inspectable:
            body = bytearray()
            too_large = False

            # Read incrementally so requests without Content-Length
            # cannot bypass the configured body-size limit.
            while True:
                message = await receive()

                if message["type"] == "http.disconnect":
                    return

                if message["type"] != "http.request":
                    continue

                body.extend(message.get("body", b""))

                if len(body) > self.max_body_bytes:
                    too_large = True
                    break

                if not message.get("more_body", False):
                    break

            if too_large:
                await self._block(
                    scope, receive, send, request_id,
                    "body_too_large", 413,
                )
                return

            rule = inspect_text(
                body.decode("utf-8", errors="replace")
            )
            if rule:
                await self._block(
                    scope, receive, send, request_id, rule, 403
                )
                return

            # Replay the request body to the downstream application.
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

            receive = replay_receive

        await self.app(scope, receive, send)

    async def _block(
        self, scope, receive, send,
        request_id, rule, status_code,
    ):
        headers = dict(scope.get("headers", []))
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"

        # Avoid logging the request body or sensitive query contents.
        logger.warning(json.dumps({
            "event": "waf_block",
            "request_id": request_id,
            "rule": rule,
            "method": scope.get("method"),
            "path": scope.get("path"),
            "client_ip": client_ip,
            "timestamp": int(time.time()),
        }))

        response = JSONResponse(
            status_code=status_code,
            content={
                "error": "request_blocked",
                "rule": rule,
                "request_id": request_id,
            },
            headers={
                "X-Request-ID": request_id,
                "Cache-Control": "no-store",
            },
        )
        await response(scope, receive, send)
