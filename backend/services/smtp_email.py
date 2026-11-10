from __future__ import annotations

import os
import re
import smtplib
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from urllib.parse import urlsplit

from backend.security.secrets import SecretConfiguration

_ADDRESS = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")
_HOST = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{1,256}")
_WHITESPACE = re.compile(r"\s")
_SECURITY_MODES = ("starttls", "ssl")
_LOCAL_HOSTS = ("localhost", "127.0.0.1")


class EmailConfigurationError(RuntimeError):
    """Raised when SMTP delivery is misconfigured. Delivery fails closed."""


def _normalise_base_url(url: str) -> str:
    if not url or _WHITESPACE.search(url):
        raise EmailConfigurationError("Public base URL is invalid.")

    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise EmailConfigurationError("Public base URL is invalid.") from None

    if parts.scheme not in ("https", "http") or not host:
        raise EmailConfigurationError("Public base URL is invalid.")

    if parts.username or parts.password or parts.query or parts.fragment:
        raise EmailConfigurationError("Public base URL is invalid.")

    if parts.scheme == "http" and host not in _LOCAL_HOSTS:
        raise EmailConfigurationError(
            "Public base URL must use https outside localhost."
        )

    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"


@dataclass(frozen=True)
class SmtpSettings:
    """
    Validated SMTP delivery settings.

    Credentials are excluded from repr so they cannot leak into logs or
    tracebacks.
    """

    host: str
    port: int
    username: str = field(repr=False)
    password: str = field(repr=False)
    sender: str
    security: str
    base_url: str
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        if _HOST.fullmatch(self.host) is None:
            raise EmailConfigurationError("SMTP host is invalid.")

        if not 1 <= self.port <= 65535:
            raise EmailConfigurationError("SMTP port is invalid.")

        if self.security not in _SECURITY_MODES:
            raise EmailConfigurationError(
                "SMTP security must be 'starttls' or 'ssl'."
            )

        if not self.username or not self.password:
            raise EmailConfigurationError("SMTP credentials are required.")

        if _ADDRESS.fullmatch(self.sender) is None:
            raise EmailConfigurationError("SMTP sender address is invalid.")

        if not 1 <= self.timeout_seconds <= 60:
            raise EmailConfigurationError("SMTP timeout is invalid.")

        object.__setattr__(
            self,
            "base_url",
            _normalise_base_url(self.base_url),
        )

    @classmethod
    def from_environment(cls) -> "SmtpSettings":
        security = (
            os.environ.get("ELDORADO_SMTP_SECURITY") or "starttls"
        ).strip().lower()
        default_port = "465" if security == "ssl" else "587"
        raw_port = (
            os.environ.get("ELDORADO_SMTP_PORT") or default_port
        ).strip()

        try:
            port = int(raw_port)
        except ValueError:
            raise EmailConfigurationError(
                "ELDORADO_SMTP_PORT must be a number."
            ) from None

        return cls(
            host=SecretConfiguration.get_required("ELDORADO_SMTP_HOST").strip(),
            port=port,
            username=SecretConfiguration.get_required("ELDORADO_SMTP_USER"),
            password=SecretConfiguration.get_required("ELDORADO_SMTP_PASSWORD"),
            sender=SecretConfiguration.get_required("ELDORADO_SMTP_FROM").strip(),
            security=security,
            base_url=SecretConfiguration.get_required(
                "ELDORADO_PUBLIC_BASE_URL"
            ),
        )


SmtpFactory = Callable[[SmtpSettings], smtplib.SMTP]


def _connect(settings: SmtpSettings) -> smtplib.SMTP:
    # The default context verifies certificates and hostnames.
    context = ssl.create_default_context()

    if settings.security == "ssl":
        return smtplib.SMTP_SSL(
            settings.host,
            settings.port,
            timeout=settings.timeout_seconds,
            context=context,
        )

    client = smtplib.SMTP(
        settings.host,
        settings.port,
        timeout=settings.timeout_seconds,
    )

    try:
        client.starttls(context=context)
    except Exception:
        client.close()
        raise

    return client


class SmtpEmailSender:
    """
    Delivers verification and password reset emails over authenticated,
    TLS-protected SMTP. Satisfies both VerificationEmailSender and
    PasswordResetEmailSender.

    Tokens appear only in the link inside the message body, in the URL
    fragment, and are never logged or placed in headers.
    """

    def __init__(
        self,
        settings: SmtpSettings,
        connect: SmtpFactory | None = None,
    ) -> None:
        self._settings = settings
        self._connect = connect or _connect

    @classmethod
    def from_environment(cls) -> "SmtpEmailSender":
        return cls(SmtpSettings.from_environment())

    def send_verification(self, email: str, raw_token: str) -> None:
        link = self._link("/verify-email", raw_token)

        self._send(
            email,
            "Verify your Eldorado-AI email address",
            "Verify your email address for Eldorado-AI by opening "
            "this link:\n\n"
            f"{link}\n\n"
            "If you did not create an account, you can ignore this "
            "email.\n",
        )

    def send_password_reset(self, email: str, raw_token: str) -> None:
        link = self._link("/reset-password", raw_token)

        self._send(
            email,
            "Reset your Eldorado-AI password",
            "A password reset was requested for your Eldorado-AI "
            "account. Open this link to choose a new password:\n\n"
            f"{link}\n\n"
            "If you did not request this, ignore this email. Your "
            "password will not change.\n",
        )

    def _link(self, path: str, raw_token: str) -> str:
        if _TOKEN.fullmatch(raw_token) is None:
            raise ValueError("Invalid token format.")

        return f"{self._settings.base_url}{path}#token={raw_token}"

    def _send(self, recipient: str, subject: str, body: str) -> None:
        if _ADDRESS.fullmatch(recipient) is None:
            raise ValueError("Invalid recipient address.")

        settings = self._settings
        message = EmailMessage()
        message["From"] = f"Eldorado-AI <{settings.sender}>"
        message["To"] = recipient
        message["Subject"] = subject
        message["Date"] = formatdate(usegmt=True)
        message["Message-ID"] = make_msgid(
            domain=settings.sender.rsplit("@", 1)[1]
        )
        message.set_content(body)

        client = self._connect(settings)

        try:
            client.login(settings.username, settings.password)
            client.send_message(message)
        finally:
            try:
                client.quit()
            except (smtplib.SMTPException, OSError):
                client.close()