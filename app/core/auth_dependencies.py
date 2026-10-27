
from fastapi import HTTPException, Request, status

from app.core.authentication import (
    AuthenticationError,
    JWTAuthenticator,
)
from app.layers.layer6_iam.access_manager import IAMAccessManager
from app.layers.layer6_iam.schemas import UserIdentity


async def get_authenticated_user(request: Request) -> UserIdentity:
    """
    Authenticate a Bearer JWT and resolve its subject against server-side IAM.

    Never trust roles, MFA status, or device trust supplied as JWT claims.
    Authorization is a separate step.
    """
    authenticator: JWTAuthenticator | None = getattr(
        request.app.state,
        "jwt_authenticator",
        None,
    )
    iam: IAMAccessManager | None = getattr(
        request.app.state,
        "iam_manager",
        None,
    )

    if authenticator is None or iam is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authentication_not_configured",
        )

    try:
        principal = authenticator.authenticate_header(
            request.headers.get("authorization")
        )
    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_or_missing_credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    # The JWT subject must identify an existing server-side IAM user.
    user = iam.get_user(principal.subject)

    if user is None or not user.active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_or_missing_credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
