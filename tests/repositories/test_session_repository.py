import inspect

from backend.repositories.session_repository import SessionRepository


EXPECTED_METHODS = {
    "create_session",
    "get_session",
    "touch_session",
    "revoke_session",
    "revoke_token_family",
    "create_refresh_token",
    "get_refresh_token_by_hash",
    "rotate_refresh_token",
}


def test_session_repository_defines_expected_contract():
    assert EXPECTED_METHODS.issubset(
        set(SessionRepository.__abstractmethods__)
    )


def test_session_repository_is_abstract():
    assert inspect.isabstract(SessionRepository)


def test_session_repository_cannot_be_instantiated():
    try:
        SessionRepository()
    except TypeError:
        pass
    else:
        raise AssertionError(
            "SessionRepository must not be directly instantiable."
        )
