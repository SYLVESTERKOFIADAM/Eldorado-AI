from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from backend.repositories.refresh_authentication_repository import (
    RefreshAuthenticationRepository,
    RefreshAuthenticationResult,
    RefreshAuthenticationState,
)


USER_ID = UUID("76bab0d0-94f5-4925-a729-62e31726456f")
SESSION_ID = uuid4()
FAMILY_ID = uuid4()
TOKEN_ID = uuid4()


def test_repository_contract_is_abstract():
    assert RefreshAuthenticationRepository.__abstractmethods__ == {
        "refresh_transaction"
    }


def test_valid_result_requires_complete_identity():
    result = RefreshAuthenticationResult(
        state=RefreshAuthenticationState.VALID,
        user_id=USER_ID,
        session_id=SESSION_ID,
        token_family_id=FAMILY_ID,
        refresh_token_id=TOKEN_ID,
    )

    assert result.state is RefreshAuthenticationState.VALID
    assert result.user_id == USER_ID


def test_replay_result_requires_complete_identity():
    result = RefreshAuthenticationResult(
        state=RefreshAuthenticationState.REPLAY,
        user_id=USER_ID,
        session_id=SESSION_ID,
        token_family_id=FAMILY_ID,
        refresh_token_id=TOKEN_ID,
    )

    assert result.state is RefreshAuthenticationState.REPLAY


def test_invalid_result_cannot_expose_identity():
    result = RefreshAuthenticationResult(
        state=RefreshAuthenticationState.INVALID,
    )

    assert result.state is RefreshAuthenticationState.INVALID
    assert result.user_id is None
    assert result.session_id is None
    assert result.token_family_id is None
    assert result.refresh_token_id is None


@pytest.mark.parametrize(
    "state",
    [
        RefreshAuthenticationState.VALID,
        RefreshAuthenticationState.REPLAY,
    ],
)
def test_authenticated_result_requires_all_identity_fields(state):
    with pytest.raises(ValueError):
        RefreshAuthenticationResult(
            state=state,
            user_id=USER_ID,
        )


def test_invalid_result_rejects_identity():
    with pytest.raises(ValueError):
        RefreshAuthenticationResult(
            state=RefreshAuthenticationState.INVALID,
            user_id=USER_ID,
        )
