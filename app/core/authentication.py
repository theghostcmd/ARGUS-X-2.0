
from dataclasses import dataclass
from typing import Any, Mapping

import jwt
from jwt.exceptions import PyJWTError


class AuthenticationError(Exception):
    """Raised when a Bearer access token is missing or invalid."""


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Identity claims extracted from a cryptographically verified token."""

    subject: str
    issuer: str
    audience: str


class JWTAuthenticator:
    """
    Verify HS256 JWT access tokens.

    The signing secret must be supplied by trusted server configuration.
    Never accept a secret, algorithm, issuer, or audience from the request.
    """

    def __init__(
        self,
        *,
        secret: str,
        issuer: str,
        audience: str,
        leeway_seconds: int = 0,
    ) -> None:
        if not isinstance(secret, str) or len(secret.encode("utf-8")) < 32:
            raise ValueError(
                "JWT secret must contain at least 32 UTF-8 bytes"
            )

        if not issuer or not issuer.strip():
            raise ValueError("JWT issuer cannot be blank")

        if not audience or not audience.strip():
            raise ValueError("JWT audience cannot be blank")

        if (
            isinstance(leeway_seconds, bool)
            or not isinstance(leeway_seconds, int)
            or leeway_seconds < 0
            or leeway_seconds > 60
        ):
            raise ValueError("JWT leeway must be between 0 and 60 seconds")

        self._secret = secret
        self._issuer = issuer
        self._audience = audience
        self._leeway_seconds = leeway_seconds

    def authenticate_header(
        self,
        authorization_header: str | None,
    ) -> AuthenticatedPrincipal:
        """Validate an Authorization header and return its verified subject."""

        if not isinstance(authorization_header, str):
            raise AuthenticationError("missing_or_invalid_credentials")

        parts = authorization_header.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise AuthenticationError("missing_or_invalid_credentials")

        token = parts[1]

        try:
            claims: Mapping[str, Any] = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway_seconds,
                options={
                    "require": ["sub", "exp", "iat", "iss", "aud"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except (PyJWTError, TypeError, ValueError, OverflowError):
            raise AuthenticationError(
                "invalid_or_expired_access_token"
            ) from None

        subject = claims.get("sub")

        if not isinstance(subject, str) or not subject.strip():
            raise AuthenticationError("invalid_or_expired_access_token")

        # Audience may be encoded as a string or a list in a JWT.
        # PyJWT has already verified that the configured audience matches.
        return AuthenticatedPrincipal(
            subject=subject,
            issuer=self._issuer,
            audience=self._audience,
        )
