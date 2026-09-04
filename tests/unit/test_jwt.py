"""Tests for Eldorado-AI JWT access-token security."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import jwt
import pytest

from backend.security.authenticated_user import AuthenticatedUser
from backend.security.jwt import (
    ACCESS_TOKEN_TTL,
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_ISSUER,
    TokenConfigError,
    TokenError,
    create_access_token,
    verify_access_token,
)


TEST_SECRET = (
    "test-secret-key-that-is-long-enough-for-jwt-security-123456"
)


@pytest.fixture(autouse=True)
def jwt_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide a valid JWT secret for every test."""
    monkeypatch.setenv("ELDORADO_JWT_SECRET", TEST_SECRET)


def test_create_access_token_returns_jwt() -> None:
    user_id = uuid4()

    token = create_access_token(user_id)

    assert isinstance(token, str)
    assert len(token.split(".")) == 3


def test_access_token_contains_expected_claims() -> None:
    user_id = uuid4()

    token = create_access_token(user_id)

    payload = jwt.decode(
        token,
        TEST_SECRET,
        algorithms=[JWT_ALGORITHM],
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
    )

    assert payload["sub"] == str(user_id)
    assert payload["type"] == "access"
    assert UUID(payload["jti"])
    assert payload["iss"] == JWT_ISSUER
    assert payload["aud"] == JWT_AUDIENCE
    assert "iat" in payload
    assert "exp" in payload


def test_access_token_has_fifteen_minute_ttl() -> None:
    user_id = uuid4()

    token = create_access_token(user_id)

    payload = jwt.decode(
        token,
        TEST_SECRET,
        algorithms=[JWT_ALGORITHM],
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
    )

    issued_at = datetime.fromtimestamp(
        payload["iat"],
        tz=timezone.utc,
    )
    expires_at = datetime.fromtimestamp(
        payload["exp"],
        tz=timezone.utc,
    )

    assert expires_at - issued_at == ACCESS_TOKEN_TTL


def test_each_access_token_has_unique_jti() -> None:
    user_id = uuid4()

    first = create_access_token(user_id)
    second = create_access_token(user_id)

    first_payload = jwt.decode(
        first,
        TEST_SECRET,
        algorithms=[JWT_ALGORITHM],
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
    )
    second_payload = jwt.decode(
        second,
        TEST_SECRET,
        algorithms=[JWT_ALGORITHM],
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
    )

    assert first_payload["jti"] != second_payload["jti"]


def test_verify_access_token_returns_existing_authenticated_user() -> None:
    user_id = uuid4()

    token = create_access_token(user_id)

    result = verify_access_token(token)

    assert isinstance(result.user, AuthenticatedUser)
    assert result.user.user_id == user_id
    assert isinstance(result.token_id, UUID)


def test_wrong_secret_rejects_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = uuid4()

    token = create_access_token(user_id)

    monkeypatch.setenv(
        "ELDORADO_JWT_SECRET",
        "different-secret-key-that-is-also-long-enough-123456",
    )

    with pytest.raises(TokenError, match="token is invalid"):
        verify_access_token(token)


def test_malformed_token_is_rejected() -> None:
    with pytest.raises(TokenError, match="token is invalid"):
        verify_access_token("not.a.valid.jwt")


def test_empty_token_is_rejected() -> None:
    with pytest.raises(TokenError, match="token is invalid"):
        verify_access_token("")


def test_expired_token_is_rejected() -> None:
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "type": "access",
        "jti": str(uuid4()),
        "iat": now - timedelta(minutes=16),
        "exp": now - timedelta(minutes=1),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }

    token = jwt.encode(
        payload,
        TEST_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    with pytest.raises(TokenError, match="token has expired"):
        verify_access_token(token)


def test_wrong_token_type_is_rejected() -> None:
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "jti": str(uuid4()),
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }

    token = jwt.encode(
        payload,
        TEST_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    with pytest.raises(TokenError, match="token is not an access token"):
        verify_access_token(token)


def test_wrong_issuer_is_rejected() -> None:
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "type": "access",
        "jti": str(uuid4()),
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "iss": "wrong-issuer",
        "aud": JWT_AUDIENCE,
    }

    token = jwt.encode(
        payload,
        TEST_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    with pytest.raises(TokenError, match="token is invalid"):
        verify_access_token(token)


def test_wrong_audience_is_rejected() -> None:
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "type": "access",
        "jti": str(uuid4()),
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "iss": JWT_ISSUER,
        "aud": "wrong-audience",
    }

    token = jwt.encode(
        payload,
        TEST_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    with pytest.raises(TokenError, match="token is invalid"):
        verify_access_token(token)


def test_invalid_user_id_is_rejected() -> None:
    now = datetime.now(timezone.utc)

    payload = {
        "sub": "not-a-uuid",
        "type": "access",
        "jti": str(uuid4()),
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }

    token = jwt.encode(
        payload,
        TEST_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    with pytest.raises(TokenError, match="token subject is invalid"):
        verify_access_token(token)


def test_invalid_jti_is_rejected() -> None:
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "type": "access",
        "jti": "not-a-uuid",
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }

    token = jwt.encode(
        payload,
        TEST_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    with pytest.raises(TokenError, match="token id is invalid"):
        verify_access_token(token)


def test_missing_required_claim_is_rejected() -> None:
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "type": "access",
        "jti": str(uuid4()),
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "iss": JWT_ISSUER,
    }

    token = jwt.encode(
        payload,
        TEST_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    with pytest.raises(TokenError, match="token is invalid"):
        verify_access_token(token)


def test_non_uuid_user_id_cannot_create_access_token() -> None:
    with pytest.raises(TypeError, match="user_id must be a UUID"):
        create_access_token("not-a-uuid")  # type: ignore[arg-type]


def test_missing_jwt_secret_is_configuration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ELDORADO_JWT_SECRET", raising=False)

    with pytest.raises(
        TokenConfigError,
        match="ELDORADO_JWT_SECRET",
    ):
        create_access_token(uuid4())


def test_short_jwt_secret_is_configuration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ELDORADO_JWT_SECRET",
        "too-short",
    )

    with pytest.raises(
        TokenConfigError,
        match="at least 32 characters",
    ):
        create_access_token(uuid4())