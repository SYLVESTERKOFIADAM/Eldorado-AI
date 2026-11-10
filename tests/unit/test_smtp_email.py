from __future__ import annotations

import smtplib
import ssl

import pytest

from backend.services.smtp_email import (
    EmailConfigurationError,
    SmtpEmailSender,
    SmtpSettings,
)

TOKEN = "A" * 43

SMTP_ENV = {
    "ELDORADO_SMTP_HOST": "smtp.example.com",
    "ELDORADO_SMTP_USER": "mailer",
    "ELDORADO_SMTP_PASSWORD": "s3cret-pass",
    "ELDORADO_SMTP_FROM": "noreply@example.com",
    "ELDORADO_PUBLIC_BASE_URL": "https://app.example.com",
}


def _settings(**overrides: object) -> SmtpSettings:
    values: dict[str, object] = {
        "host": "smtp.example.com",
        "port": 587,
        "username": "mailer",
        "password": "s3cret-pass",
        "sender": "noreply@example.com",
        "security": "starttls",
        "base_url": "https://app.example.com",
    }
    values.update(overrides)
    return SmtpSettings(**values)  # type: ignore[arg-type]


class FakeSmtp:
    def __init__(
        self,
        fail_login: bool = False,
        fail_quit: bool = False,
    ) -> None:
        self.logged_in_as: tuple[str, str] | None = None
        self.sent: list = []
        self.quit_called = False
        self.closed = False
        self._fail_login = fail_login
        self._fail_quit = fail_quit

    def login(self, user: str, password: str) -> None:
        if self._fail_login:
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")
        self.logged_in_as = (user, password)

    def send_message(self, message: object) -> None:
        self.sent.append(message)

    def quit(self) -> None:
        self.quit_called = True
        if self._fail_quit:
            raise smtplib.SMTPServerDisconnected("connection lost")

    def close(self) -> None:
        self.closed = True


def _sender(fake: FakeSmtp) -> SmtpEmailSender:
    return SmtpEmailSender(_settings(), connect=lambda settings: fake)


def _sender_that_must_not_connect() -> SmtpEmailSender:
    def connect(settings: SmtpSettings) -> FakeSmtp:
        raise AssertionError("must not connect")

    return SmtpEmailSender(_settings(), connect=connect)


# --- settings validation ----------------------------------------------------


def test_settings_accept_valid_values() -> None:
    settings = _settings()

    assert settings.host == "smtp.example.com"
    assert settings.base_url == "https://app.example.com"


@pytest.mark.parametrize(
    "overrides",
    [
        {"host": "bad host"},
        {"host": ""},
        {"port": 0},
        {"port": 70000},
        {"security": "plain"},
        {"sender": "noreply@example.com\nBcc: evil@example.com"},
        {"sender": "no-at-sign"},
        {"username": ""},
        {"password": ""},
        {"timeout_seconds": 0},
    ],
)
def test_settings_reject_invalid_values(overrides: dict) -> None:
    with pytest.raises(EmailConfigurationError):
        _settings(**overrides)


@pytest.mark.parametrize(
    "base_url",
    [
        "",
        "http://app.example.com",
        "ftp://app.example.com",
        "https://user:pw@app.example.com",
        "https://app.example.com/?a=1",
        "https://app.example.com/#frag",
        "https://app.example.com/ x",
    ],
)
def test_settings_reject_unsafe_base_url(base_url: str) -> None:
    with pytest.raises(EmailConfigurationError):
        _settings(base_url=base_url)


def test_base_url_is_normalised() -> None:
    assert _settings(base_url="https://app.example.com/base/").base_url == (
        "https://app.example.com/base"
    )


@pytest.mark.parametrize(
    "base_url",
    ["http://localhost:8000", "http://127.0.0.1:8000"],
)
def test_http_is_allowed_only_for_localhost(base_url: str) -> None:
    assert _settings(base_url=base_url).base_url == base_url


def test_settings_repr_hides_credentials() -> None:
    text = repr(_settings())

    assert "s3cret-pass" not in text
    assert "mailer" not in text


# --- settings from environment ----------------------------------------------


def _set_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in SMTP_ENV.items():
        monkeypatch.setenv(name, value)

    monkeypatch.delenv("ELDORADO_SMTP_PORT", raising=False)
    monkeypatch.delenv("ELDORADO_SMTP_SECURITY", raising=False)


def test_from_environment_applies_starttls_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_env(monkeypatch)

    settings = SmtpSettings.from_environment()

    assert settings.port == 587
    assert settings.security == "starttls"


def test_from_environment_defaults_port_for_implicit_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_env(monkeypatch)
    monkeypatch.setenv("ELDORADO_SMTP_SECURITY", "ssl")

    assert SmtpSettings.from_environment().port == 465


@pytest.mark.parametrize("name", sorted(SMTP_ENV))
def test_from_environment_fails_closed_when_setting_missing(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    _set_env(monkeypatch)
    monkeypatch.delenv(name, raising=False)

    with pytest.raises(RuntimeError):
        SmtpSettings.from_environment()


def test_from_environment_rejects_non_numeric_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_env(monkeypatch)
    monkeypatch.setenv("ELDORADO_SMTP_PORT", "abc")

    with pytest.raises(EmailConfigurationError):
        SmtpSettings.from_environment()


# --- sending ----------------------------------------------------------------


def test_send_verification_delivers_link_in_body_only() -> None:
    fake = FakeSmtp()

    _sender(fake).send_verification("person@example.com", TOKEN)

    assert fake.logged_in_as == ("mailer", "s3cret-pass")
    assert len(fake.sent) == 1

    message = fake.sent[0]
    assert message["To"] == "person@example.com"
    assert "noreply@example.com" in message["From"]
    assert message["Subject"] == "Verify your Eldorado-AI email address"
    assert (
        "https://app.example.com/verify-email#token=" + TOKEN
        in message.get_content()
    )

    for header in ("From", "To", "Subject", "Message-ID"):
        assert TOKEN not in message[header]

    assert fake.quit_called is True


def test_send_password_reset_delivers_reset_link() -> None:
    fake = FakeSmtp()

    _sender(fake).send_password_reset("person@example.com", TOKEN)

    message = fake.sent[0]
    assert message["Subject"] == "Reset your Eldorado-AI password"
    assert (
        "https://app.example.com/reset-password#token=" + TOKEN
        in message.get_content()
    )


@pytest.mark.parametrize(
    "recipient",
    [
        "person@example.com\nBcc: evil@example.com",
        "person@example.com\r\nBcc: evil@example.com",
        "not-an-address",
        "",
        "a b@example.com",
    ],
)
def test_invalid_recipient_is_rejected_before_connecting(
    recipient: str,
) -> None:
    with pytest.raises(ValueError):
        _sender_that_must_not_connect().send_verification(recipient, TOKEN)


@pytest.mark.parametrize(
    "token",
    ["", "abc\nxyz", "a b", "x" * 300, "tok/en", "tok?en"],
)
def test_invalid_token_is_rejected_before_connecting(token: str) -> None:
    sender = _sender_that_must_not_connect()

    with pytest.raises(ValueError):
        sender.send_password_reset("person@example.com", token)


def test_login_failure_propagates_and_closes_session() -> None:
    fake = FakeSmtp(fail_login=True)

    with pytest.raises(smtplib.SMTPAuthenticationError):
        _sender(fake).send_verification("person@example.com", TOKEN)

    assert fake.sent == []
    assert fake.quit_called is True


def test_quit_failure_falls_back_to_close() -> None:
    fake = FakeSmtp(fail_quit=True)

    _sender(fake).send_verification("person@example.com", TOKEN)

    assert len(fake.sent) == 1
    assert fake.closed is True


# --- default connection factory ----------------------------------------------


class FakeStartTlsClient:
    instances: list = []

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context: ssl.SSLContext | None = None
        self.closed = False
        self.fail_starttls = False
        FakeStartTlsClient.instances.append(self)

    def starttls(self, context: ssl.SSLContext) -> None:
        if self.fail_starttls:
            raise smtplib.SMTPException("starttls refused")

        self.context = context

    def close(self) -> None:
        self.closed = True


class FakeImplicitTlsClient:
    instances: list = []

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        FakeImplicitTlsClient.instances.append(self)


def test_default_connection_verifies_certificates_with_starttls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from backend.services.smtp_email import _connect

    FakeStartTlsClient.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeStartTlsClient)

    client = _connect(_settings())

    assert client is FakeStartTlsClient.instances[0]
    assert client.timeout == 10.0
    assert client.context is not None
    assert client.context.verify_mode == ssl.CERT_REQUIRED
    assert client.context.check_hostname is True


def test_default_connection_closes_when_starttls_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from backend.services.smtp_email import _connect

    FakeStartTlsClient.instances = []

    class Failing(FakeStartTlsClient):
        def __init__(self, host: str, port: int, timeout: float) -> None:
            super().__init__(host, port, timeout)
            self.fail_starttls = True

    monkeypatch.setattr(smtplib, "SMTP", Failing)

    with pytest.raises(smtplib.SMTPException):
        _connect(_settings())

    assert FakeStartTlsClient.instances[0].closed is True


def test_default_connection_supports_implicit_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from backend.services.smtp_email import _connect

    FakeImplicitTlsClient.instances = []
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeImplicitTlsClient)

    client = _connect(_settings(security="ssl", port=465))

    assert client is FakeImplicitTlsClient.instances[0]
    assert client.port == 465
    assert client.context.verify_mode == ssl.CERT_REQUIRED
    assert client.context.check_hostname is True