from __future__ import annotations

from collections.abc import Callable

import pytest

from backend.api.auth_routes import get_email_sender
from backend.api.password_routes import get_password_reset_sender
from backend.services.smtp_email import SmtpEmailSender

SMTP_ENV = {
    "ELDORADO_SMTP_HOST": "smtp.example.com",
    "ELDORADO_SMTP_USER": "mailer",
    "ELDORADO_SMTP_PASSWORD": "s3cret-pass",
    "ELDORADO_SMTP_FROM": "noreply@example.com",
    "ELDORADO_PUBLIC_BASE_URL": "https://app.example.com",
}

FACTORIES = [get_email_sender, get_password_reset_sender]


def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ELDORADO_ENV",
        "ELDORADO_EMAIL_BACKEND",
        "ELDORADO_ENABLE_CONSOLE_VERIFICATION_EMAIL",
        "ELDORADO_ENABLE_CONSOLE_RESET_EMAIL",
        "ELDORADO_SMTP_PORT",
        "ELDORADO_SMTP_SECURITY",
        *SMTP_ENV,
    ):
        monkeypatch.delenv(name, raising=False)


def _smtp(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in SMTP_ENV.items():
        monkeypatch.setenv(name, value)

    monkeypatch.setenv("ELDORADO_EMAIL_BACKEND", "smtp")


@pytest.mark.parametrize("factory", FACTORIES)
def test_smtp_backend_is_allowed_in_production(
    monkeypatch: pytest.MonkeyPatch,
    factory: Callable[[], object],
) -> None:
    _clean(monkeypatch)
    _smtp(monkeypatch)
    monkeypatch.setenv("ELDORADO_ENV", "production")

    assert isinstance(factory(), SmtpEmailSender)


@pytest.mark.parametrize("factory", FACTORIES)
def test_production_without_backend_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    factory: Callable[[], object],
) -> None:
    _clean(monkeypatch)
    monkeypatch.setenv("ELDORADO_ENV", "production")
    monkeypatch.setenv("ELDORADO_ENABLE_CONSOLE_VERIFICATION_EMAIL", "true")
    monkeypatch.setenv("ELDORADO_ENABLE_CONSOLE_RESET_EMAIL", "true")

    with pytest.raises(RuntimeError):
        factory()


@pytest.mark.parametrize("factory", FACTORIES)
def test_unknown_backend_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    factory: Callable[[], object],
) -> None:
    _clean(monkeypatch)
    monkeypatch.setenv("ELDORADO_ENV", "production")
    monkeypatch.setenv("ELDORADO_EMAIL_BACKEND", "carrier-pigeon")

    with pytest.raises(RuntimeError):
        factory()


@pytest.mark.parametrize("factory", FACTORIES)
def test_smtp_backend_fails_closed_when_misconfigured(
    monkeypatch: pytest.MonkeyPatch,
    factory: Callable[[], object],
) -> None:
    _clean(monkeypatch)
    _smtp(monkeypatch)
    monkeypatch.setenv("ELDORADO_ENV", "production")
    monkeypatch.delenv("ELDORADO_SMTP_HOST", raising=False)

    with pytest.raises(RuntimeError):
        factory()