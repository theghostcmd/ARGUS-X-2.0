from app.layers.layer8_ids_ips.schemas import SecurityEvent
from app.services.security_intelligence_service import (
    SecurityIntelligenceService,
)
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status

from app.config import Settings, get_settings
from app.core.access_controller import IntegratedAccessController
from app.core.auth_dependencies import get_authenticated_user
from app.core.authentication import JWTAuthenticator
from app.core.logging_config import configure_logging
from app.layers.layer1_traffic_guard.limiter import (
    MemoryLimiter,
    RedisLimiter,
)
from app.layers.layer1_traffic_guard.middleware import (
    TrafficGuardMiddleware,
)
from app.layers.layer2_waf.middleware import WAFMiddleware
from app.layers.layer6_iam.access_manager import IAMAccessManager
from app.layers.layer6_iam.schemas import UserIdentity
from app.layers.layer9_application_security.middleware import (
    ApplicationSecurityMiddleware,
)
from app.middleware.request_id import RequestIDMiddleware


DeviceTrustResolver = Callable[[Request, UserIdentity], str]
SecurityEventProvider = Callable[
    [Request, UserIdentity],
    list[SecurityEvent],
] 


def create_app(
    settings: Settings | None = None,
    *,
    jwt_authenticator: JWTAuthenticator | None = None,
    iam_manager: IAMAccessManager | None = None,
    access_controller: IntegratedAccessController | None = None,
    device_trust_resolver: DeviceTrustResolver | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging()

    if settings.rate_limit_backend == "redis":
        limiter = RedisLimiter(settings.redis_url)
    else:
        limiter = MemoryLimiter()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            yield
        finally:
            await limiter.close()

    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        lifespan=lifespan,
    )

    # Security components must be explicitly configured by the application.
    # Never create fake users, placeholder JWT secrets, or trusted devices.
    app.state.jwt_authenticator = jwt_authenticator
    app.state.iam_manager = iam_manager
    app.state.access_controller = access_controller
    app.state.device_trust_resolver = device_trust_resolver

    # Starlette runs the most recently added middleware first.
    # Runtime request order:
    # Request ID -> Application Security -> WAF
    # -> Traffic Guard -> FastAPI routes.
    app.add_middleware(
        TrafficGuardMiddleware,
        limiter=limiter,
        settings=settings,
    )
    app.add_middleware(WAFMiddleware)
    app.add_middleware(
        ApplicationSecurityMiddleware,
        enabled=settings.application_security_enabled,
        max_body_bytes=settings.application_security_max_body_bytes,
    )
    app.add_middleware(RequestIDMiddleware)

    @app.get("/health", tags=["Operations"])
    async def health() -> dict[str, str]:
        return {
            "status": "ok",
            "service": settings.app_name,
            "environment": settings.app_env,
        }

    @app.get("/", tags=["Operations"])
    async def root() -> dict[str, str]:
        return {
            "service": settings.app_name,
            "layer": "layer1_traffic_guard",
            "message": "Traffic guard is running.",
        }

    @app.get("/api/alerts", tags=["Protected API"])
    async def get_alerts(
        request: Request,
        user: UserIdentity = Depends(get_authenticated_user),
    ) -> dict[str, Any]:
        controller: IntegratedAccessController | None = getattr(
            request.app.state,
            "access_controller",
            None,
        )

        if controller is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="authorization_not_configured",
            )

        raw_length = request.headers.get("content-length")
        try:
            content_length = int(raw_length) if raw_length is not None else 0
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_content_length",
            ) from None

        resolver: DeviceTrustResolver | None = getattr(
            request.app.state,
            "device_trust_resolver",
            None,
        )

        # Unknown by default. Never accept device trust from a client header.
        device_trust = (
            resolver(request, user) if resolver is not None else "unknown"
        )

        request_id = getattr(request.state, "request_id", None) or "unknown"

        decision = controller.authorize(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            content_length=content_length,
            user_id=user.user_id,
            device_trust=device_trust,
            source_ip=(
                request.client.host if request.client is not None else None
            ),
        )

        if not decision.allowed:
            raise HTTPException(
                status_code=decision.status_code,
                detail=decision.reason,
            )

        # Replace this demonstration payload with your real alert service.
        return {
            "status": "ok",
            "user_id": user.user_id,
            "data": [],
            "message": "Access authorized; no alert service is connected yet.",
        }

    return app


app = create_app()

