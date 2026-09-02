from __future__ import annotations

from abc import ABC, abstractmethod

from backend.models.translation import TranslationRequest, TranslationResult


class TranslationProvider(ABC):
    """
    Security boundary for external or local translation providers.

    Providers transform content only. They must never:
    - authenticate users,
    - authorize tools,
    - grant permissions,
    - modify memory,
    - modify security policy,
    - execute arbitrary commands.
    """

    @abstractmethod
    def translate(self, request: TranslationRequest) -> TranslationResult:
        """
        Translate validated input into the requested target language.
        """
        raise NotImplementedError

    @abstractmethod
    def detect_language(self, text: str) -> str:
        """
        Detect the language of supplied text.

        The result is informational and must not be used as an
        authentication or authorization signal.
        """
        raise NotImplementedError
