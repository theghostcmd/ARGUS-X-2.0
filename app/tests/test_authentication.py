from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.core.authentication import (
    AuthenticationError,
    JWTAuthenticator,
)


SECRET = "test-only-secret-key-with-at-least-32-bytes"
ISSUER = "argus-x-test"
AUDIENCE = "argus-x-api"


@pytest.fixture
def authenticator():
    return JWTAuthenticator(
        secret=SECRET,
        issuer=ISSUER,
        audience=AUDIENCE,
    )


def create_token(
    *,
    secret=SECRET,
    issuer=ISSUER,
    audience=AUDIENCE,
    subject="user-001",
    expires_in=300,
    include_iat=True,
):
    now = datetime.now(timezone.utc)
    claims = {
        "sub": subject,
        "exp": now + timedelta(seconds=expires_in),
        "iss": issuer,
        "aud": audience,
    }

    if include_iat:
        claims["iat"] = now

    return jwt.encode(claims, secret, algorithm="HS256")


def test_valid_bearer_token_returns_verified_subject(authenticator):
    token = create_token()

    principal = authenticator.authenticate_header(f"Bearer {token}")

    assert principal.subject == "user-001"
    assert principal.issuer == ISSUER
    assert principal.audience == AUDIENCE


def test_bearer_scheme_is_case_insensitive(authenticator):
    token = create_token()

    principal = authenticator.authenticate_header(f"bearer {token}")

    assert principal.subject == "user-001"


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Basic abc",
        "Bearer",
        "Bearer token extra",
        "Bearer ",
    ],
)
def test_missing_or_malformed_authorization_header_is_rejected(
    authenticator, header
):
    with pytest.raises(AuthenticationError):
        authenticator.authenticate_header(header)


def test_invalid_signature_is_rejected(authenticator):
    token = create_token(
        secret="a-different-secret-key-with-at-least-32-bytes"
    )

    with pytest.raises(
        AuthenticationError,
        match="invalid_or_expired_access_token",
    ):
        authenticator.authenticate_header(f"Bearer {token}")


def test_expired_token_is_rejected(authenticator):
    token = create_token(expires_in=-60)

    with pytest.raises(AuthenticationError):
        authenticator.authenticate_header(f"Bearer {token}")


def test_wrong_issuer_is_rejected(authenticator):
    token = create_token(issuer="untrusted-issuer")

    with pytest.raises(AuthenticationError):
        authenticator.authenticate_header(f"Bearer {token}")


def test_wrong_audience_is_rejected(authenticator):
    token = create_token(audience="another-api")

    with pytest.raises(AuthenticationError):
        authenticator.authenticate_header(f"Bearer {token}")


def test_missing_iat_is_rejected(authenticator):
    token = create_token(include_iat=False)

    with pytest.raises(AuthenticationError):
        authenticator.authenticate_header(f"Bearer {token}")


def test_blank_subject_is_rejected(authenticator):
    token = create_token(subject="   ")

    with pytest.raises(AuthenticationError):
        authenticator.authenticate_header(f"Bearer {token}")


def test_invalid_secret_is_rejected():
    with pytest.raises(ValueError):
        JWTAuthenticator(
            secret="too-short",
            issuer=ISSUER,
            audience=AUDIENCE,
        )


def test_blank_issuer_is_rejected():
    with pytest.raises(ValueError):
        JWTAuthenticator(
            secret=SECRET,
            issuer=" ",
            audience=AUDIENCE,
        )


def test_invalid_leeway_is_rejected():
    with pytest.raises(ValueError):
        JWTAuthenticator(
            secret=SECRET,
            issuer=ISSUER,
            audience=AUDIENCE,
            leeway_seconds=-1,
        )