from __future__ import annotations

import os


class SecretConfiguration:
    """
    Controlled access to Eldorado secrets.

    Secrets must originate from the application environment or an
    approved secret-management system. They must never come from:
    - user input,
    - memory,
    - AI-generated content,
    - translated content,
    - external webpages.

    This class does not log or expose secret values.
    """

    @staticmethod
    def get_required(name: str) -> str:
        if not name.strip():
            raise ValueError("Secret name cannot be empty.")

        value = os.getenv(name)

        if value is None or not value.strip():
            raise RuntimeError(
                f"Required secret '{name}' is not configured."
            )

        return value

    @staticmethod
    def get_optional(name: str) -> str | None:
        if not name.strip():
            raise ValueError("Secret name cannot be empty.")

        value = os.getenv(name)

        if value is None or not value.strip():
            return None

        return value
