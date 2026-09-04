from __future__ import annotations

from uuid import UUID

import pytest
from fastapi import HTTPException

from backend.api.auth import require_authenticated_user
from backend.security.authenticated_user import AuthenticatedUser
from backend.security.jwt import TokenError, VerifiedAccessToken


USER_ID = UUID("11111111-1111-1111-1111-111111111111")
TOKEN_ID = UUID("22222222-2222-2222-2222-222222222222")
TOKEN = "valid.jwt.token"


def test_missing_authorization_header_is_rejected() -> None:
    with pytest.raises(HTTPException) as exc_info:
        require_authenticated_user(None)

    assert exc_info.value.status_code == 401
    assert exc_info.value.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "authorization",
    [
        "",
        "Basic credentials",
        "Bearer",
        "Bearer ",
        "Token something",
    ],
)
def test_malformed_authorization_header_is_rejected(
    authorization: str,
) -> None:
    with pytest.raises(HTTPException) as exc_info:
        require_authenticated_user(authorization)

    assert exc_info.value.status_code == 401


def test_invalid_access_token_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(_: str) -> VerifiedAccessToken:
        raise TokenError("token is invalid")

    monkeypatch.setattr(
        "backend.api.auth.verify_access_token",
        reject,
    )

    with pytest.raises(HTTPException) as exc_info:
        require_authenticated_user(f"Bearer {TOKEN}")

    assert exc_info.value.status_code == 401


def test_valid_access_token_returns_authenticated_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = VerifiedAccessToken(
        user=AuthenticatedUser(user_id=USER_ID),
        token_id=TOKEN_ID,
    )

    def verify(token: str) -> VerifiedAccessToken:
        assert token == TOKEN
        return expected

    monkeypatch.setattr(
        "backend.api.auth.verify_access_token",
        verify,
    )

    result = require_authenticated_user(f"Bearer {TOKEN}")

    assert result == AuthenticatedUser(user_id=USER_ID)


def test_bearer_scheme_is_case_insensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = VerifiedAccessToken(
        user=AuthenticatedUser(user_id=USER_ID),
        token_id=TOKEN_ID,
    )

    monkeypatch.setattr(
        "backend.api.auth.verify_access_token",
        lambda token: expected,
    )

    result = require_authenticated_user(f"bEaReR {TOKEN}")

    assert result == expected.user


def test_identity_comes_from_verified_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = VerifiedAccessToken(
        user=AuthenticatedUser(user_id=USER_ID),
        token_id=TOKEN_ID,
    )

    monkeypatch.setattr(
        "backend.api.auth.verify_access_token",
        lambda token: expected,
    )

    # There is deliberately no user_id parameter accepted by the
    # authentication boundary.
    result = require_authenticated_user(f"Bearer {TOKEN}")

    assert result.user_id == USER_ID