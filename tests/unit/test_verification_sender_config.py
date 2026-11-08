from __future__ import annotations

import pytest

from backend.api.auth_routes import get_email_sender
from backend.services.verification_email import (
    ConsoleVerificationEmailSender,
)


def test_sender_fails_closed_when_environment_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ELDORADO_ENV", raising=False)
    monkeypatch.delenv(
        "ELDORADO_ENABLE_CONSOLE_VERIFICATION_EMAIL", raising=False
    )

    with pytest.raises(RuntimeError):
        get_email_sender()


def test_sender_rejects_console_delivery_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ELDORADO_ENV", "production")
    monkeypatch.setenv("ELDORADO_ENABLE_CONSOLE_VERIFICATION_EMAIL", "true")

    with pytest.raises(RuntimeError):
        get_email_sender()


def test_sender_requires_explicit_development_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ELDORADO_ENV", "development")
    monkeypatch.setenv("ELDORADO_ENABLE_CONSOLE_VERIFICATION_EMAIL", "false")

    with pytest.raises(RuntimeError):
        get_email_sender()


def test_sender_allows_explicit_development_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ELDORADO_ENV", "development")
    monkeypatch.setenv("ELDORADO_ENABLE_CONSOLE_VERIFICATION_EMAIL", "true")

    sender = get_email_sender()

    assert isinstance(sender, ConsoleVerificationEmailSender)