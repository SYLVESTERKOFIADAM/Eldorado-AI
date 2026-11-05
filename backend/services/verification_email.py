from __future__ import annotations

import os
from typing import Protocol


class VerificationEmailSender(Protocol):
    def send_verification(self, email: str, raw_token: str) -> None:
        """Deliver a verification token to the account owner."""


class ConsoleVerificationEmailSender:
    """
    DEVELOPMENT ONLY. Prints the verification link to the server console.

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

    def send_verification(self, email: str, raw_token: str) -> None:
        print(
            f"[DEV ONLY] Verification email for {email}: "
            f"{self._base_url}/verify-email#token={raw_token}",
            flush=True,
        )