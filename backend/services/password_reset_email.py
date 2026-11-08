from __future__ import annotations

import os
from typing import Protocol


class PasswordResetEmailSender(Protocol):
    def send_password_reset(self, email: str, raw_token: str) -> None:
        """Deliver a password reset token to the account owner."""


class ConsolePasswordResetEmailSender:
    """
    DEVELOPMENT ONLY. Prints the reset link to the server console.

    The raw token appears in the process output, so this must never be
    used in production. Replace it with a real provider behind the same
    interface.
    """

    def __init__(self, base_url: str | None = None) -> None:
        self._base_url = (
            base_url
            or os.getenv("ELDORADO_PUBLIC_BASE_URL")
            or "http://localhost:8000"
        ).rstrip("/")

    def send_password_reset(self, email: str, raw_token: str) -> None:
        print(
            f"[DEV ONLY] Password reset email for {email}: "
            f"{self._base_url}/reset-password#token={raw_token}",
            flush=True,
        )