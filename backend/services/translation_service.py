from __future__ import annotations

from backend.models.translation import TranslationRequest, TranslationResult
from backend.security.authenticated_user import AuthenticatedUser
from backend.services.translation_provider import TranslationProvider


class TranslationService:
    """
    Application service for secure language translation.

    Translation is a content transformation capability. Neither the
    source text nor translated text is an authorization signal.

    Provider output must remain untrusted data until explicitly processed
    by another security-controlled subsystem.
    """

    def __init__(
        self,
        authenticated_user: AuthenticatedUser,
        provider: TranslationProvider,
    ) -> None:
        self._authenticated_user = authenticated_user
        self._provider = provider

    def translate(self, request: TranslationRequest) -> TranslationResult:
        """
        Translate text using the configured provider.
        """
        if not self._authenticated_user.user_id:
            raise PermissionError("Authenticated user is required.")

        return self._provider.translate(request)

    def detect_language(self, text: str) -> str:
        """
        Detect the language of text using the configured provider.
        """
        if not self._authenticated_user.user_id:
            raise PermissionError("Authenticated user is required.")

        if not text.strip():
            raise ValueError("Text cannot be empty.")

        return self._provider.detect_language(text)

    def translate_auto(
        self,
        text: str,
        target_language: str,
    ) -> TranslationResult:
        """
        Detect the source language and translate to the target language.
        """
        source_language = self.detect_language(text)

        request = TranslationRequest(
            text=text,
            source_language=source_language,
            target_language=target_language,
        )

        return self.translate(request)
