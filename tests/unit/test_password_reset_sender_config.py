from __future__ import annotations

import pytest

from backend.api.password_routes import get_password_reset_sender
from backend.services.password_reset_email import (
    ConsolePasswordResetEmailSender,
)


def test_sender_fails_closed_when_environment_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ELDORADO_ENV", raising=False)
    monkeypatch.delenv("ELDORADO_ENABLE_CONSOLE_RESET_EMAIL", raising=False)

    with pytest.raises(RuntimeError):
        get_password_reset_sender()


def test_sender_rejects_console_delivery_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ELDORADO_ENV", "production")
    monkeypatch.setenv("ELDORADO_ENABLE_CONSOLE_RESET_EMAIL", "true")

    with pytest.raises(RuntimeError):
        get_password_reset_sender()


def test_sender_requires_explicit_development_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ELDORADO_ENV", "development")
    monkeypatch.setenv("ELDORADO_ENABLE_CONSOLE_RESET_EMAIL", "false")

    with pytest.raises(RuntimeError):
        get_password_reset_sender()


def test_sender_allows_explicit_development_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ELDORADO_ENV", "development")
    monkeypatch.setenv("ELDORADO_ENABLE_CONSOLE_RESET_EMAIL", "true")

    sender = get_password_reset_sender()

    assert isinstance(sender, ConsolePasswordResetEmailSender)