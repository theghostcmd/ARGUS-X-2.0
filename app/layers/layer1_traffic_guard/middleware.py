
import logging
import uuid

from starlette.responses import JSONResponse

from app.config import Settings

logger = logging.getLogger("argus_x.layer1")


class TrafficGuardMiddleware:
    """ASGI middleware for application-level request rate limiting."""

    def __init__(self, app, limiter, settings: Settings):
        self.app = app
        self.limiter = limiter
        self.settings = settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        request_id = str(uuid.uuid4())
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        path = scope.get("path", "/")

        # Keep the health endpoint available for basic monitoring.
        if path == self.settings.health_path:
            await self.app(scope, receive, send)
            return

        try:
            allowed = await self.limiter.allow(
                client_id=client_ip,
                limit=self.settings.rate_limit_requests,
                window=self.settings.rate_limit_window_seconds,
                block_seconds=self.settings.rate_limit_block_seconds,
            )
        except Exception:
            logger.exception(
                "event=rate_limiter_error request_id=%s path=%s",
                request_id,
                path,
            )

            if self.settings.rate_limit_fail_closed:
                response = JSONResponse(
                    status_code=503,
                    content={
                        "error": "security_service_unavailable",
                        "message": "Traffic protection is temporarily unavailable.",
                        "request_id": request_id,
                    },
                    headers={
                        "X-Request-ID": request_id,
                        "Cache-Control": "no-store",
                        "Retry-After": "5",
                    },
                )
                await response(scope, receive, send)
                return

            # Fail-open should be explicitly accepted as a risk.
            await self.app(scope, receive, send)
            return

        if not allowed:
            logger.warning(
                "event=traffic_blocked request_id=%s client_ip=%s path=%s",
                request_id,
                client_ip,
                path,
            )

            response = JSONResponse(
                status_code=429,
                content={
                    "error": "too_many_requests",
                    "message": "Request limit exceeded. Try again later.",
                    "request_id": request_id,
                },
                headers={
                    "X-Request-ID": request_id,
                    "Retry-After": str(
                        self.settings.rate_limit_block_seconds
                    ),
                    "Cache-Control": "no-store",
                },
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
