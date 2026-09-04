from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt

from backend.security.authenticated_user import AuthenticatedUser
from backend.security.secrets import SecretConfiguration


JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL = timedelta(minutes=15)

JWT_ISSUER = "eldorado-ai"
JWT_AUDIENCE = "eldorado-api"

_SECRET_KEY_ENV_VAR = "ELDORADO_JWT_SECRET"
_TOKEN_TYPE = "access"


class TokenConfigError(Exception):
    """Raised when JWT configuration is missing or invalid."""


class TokenError(Exception):
    """Raised when an access token is invalid or cannot be trusted."""


@dataclass(frozen=True)
class VerifiedAccessToken:
    """
    Verified access-token result.

    AuthenticatedUser is the trusted application identity.
    token_id is retained separately for the future session/revocation
    layer without changing the existing identity contract.
    """

    user: AuthenticatedUser
    token_id: UUID


def _get_secret_key() -> str:
    try:
        secret_key = SecretConfiguration.get_required(
            _SECRET_KEY_ENV_VAR
        )
    except RuntimeError as exc:
        raise TokenConfigError(
            f"{_SECRET_KEY_ENV_VAR} is not configured"
        ) from exc

    if len(secret_key) < 32:
        raise TokenConfigError(
            f"{_SECRET_KEY_ENV_VAR} must be at least 32 characters"
        )

    return secret_key


def create_access_token(user_id: UUID) -> str:
    """
    Issue a short-lived signed access token for one authenticated user.

    The user identity must already have been established by the
    authentication layer. This function does not authenticate users.
    """
    if not isinstance(user_id, UUID):
        raise TypeError("user_id must be a UUID")

    secret_key = _get_secret_key()

    now = datetime.now(timezone.utc)
    token_id = uuid.uuid4()

    payload = {
        "sub": str(user_id),
        "type": _TOKEN_TYPE,
        "jti": str(token_id),
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }

    return jwt.encode(
        payload,
        secret_key,
        algorithm=JWT_ALGORITHM,
    )


def verify_access_token(token: str) -> VerifiedAccessToken:
    """
    Verify an access token and return its trusted identity.

    Revocation and session-state checks deliberately do not belong
    here. They will be applied by the authentication/session layer
    after cryptographic verification succeeds.
    """
    if not token or not token.strip():
        raise TokenError("token is invalid")

    secret_key = _get_secret_key()

    try:
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={
                "require": [
                    "sub",
                    "type",
                    "jti",
                    "iat",
                    "exp",
                    "iss",
                    "aud",
                ]
            },
        )

    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token has expired") from exc

    except jwt.InvalidTokenError as exc:
        raise TokenError("token is invalid") from exc

    if payload.get("type") != _TOKEN_TYPE:
        raise TokenError("token is not an access token")

    raw_user_id = payload.get("sub")
    raw_token_id = payload.get("jti")

    if not isinstance(raw_user_id, str):
        raise TokenError("token subject is invalid")

    if not isinstance(raw_token_id, str):
        raise TokenError("token id is invalid")

    try:
        user_id = UUID(raw_user_id)
    except ValueError as exc:
        raise TokenError("token subject is invalid") from exc

    try:
        token_id = UUID(raw_token_id)
    except ValueError as exc:
        raise TokenError("token id is invalid") from exc

    return VerifiedAccessToken(
        user=AuthenticatedUser(user_id=user_id),
        token_id=token_id,
    )
