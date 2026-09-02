from __future__ import annotations

import pytest

from backend.models.translation import TranslationRequest, TranslationResult
from backend.services.translation_provider import TranslationProvider


class StubTranslationProvider(TranslationProvider):
    def translate(self, request: TranslationRequest) -> TranslationResult:
        return TranslationResult(
            original_text=request.text,
            translated_text="translated",
            source_language=request.source_language or "en",
            target_language=request.target_language,
            confidence=0.95,
        )

    def detect_language(self, text: str) -> str:
        if not text.strip():
            raise ValueError("Text cannot be empty.")
        return "en"


def test_translation_request_accepts_valid_input() -> None:
    request = TranslationRequest(
        text="Hello, how are you?",
        target_language="fr",
        source_language="en",
    )

    assert request.text == "Hello, how are you?"
    assert request.target_language == "fr"
    assert request.source_language == "en"


def test_translation_request_rejects_empty_text() -> None:
    with pytest.raises(ValueError):
        TranslationRequest(
            text="   ",
            target_language="fr",
        )


def test_translation_request_rejects_empty_target_language() -> None:
    with pytest.raises(ValueError):
        TranslationRequest(
            text="Hello",
            target_language="   ",
        )


def test_translation_request_rejects_empty_source_language() -> None:
    with pytest.raises(ValueError):
        TranslationRequest(
            text="Hello",
            target_language="fr",
            source_language="   ",
        )


def test_translation_result_accepts_valid_result() -> None:
    result = TranslationResult(
        original_text="Hello",
        translated_text="Bonjour",
        source_language="en",
        target_language="fr",
        confidence=0.98,
    )

    assert result.translated_text == "Bonjour"
    assert result.confidence == 0.98


def test_translation_result_rejects_invalid_confidence() -> None:
    with pytest.raises(ValueError):
        TranslationResult(
            original_text="Hello",
            translated_text="Bonjour",
            source_language="en",
            target_language="fr",
            confidence=1.5,
        )


def test_provider_translation_contract() -> None:
    provider = StubTranslationProvider()

    result = provider.translate(
        TranslationRequest(
            text="Hello",
            target_language="fr",
            source_language="en",
        )
    )

    assert result.original_text == "Hello"
    assert result.translated_text == "translated"
    assert result.target_language == "fr"


def test_provider_language_detection_contract() -> None:
    provider = StubTranslationProvider()

    assert provider.detect_language("Hello world") == "en"


def test_provider_language_detection_rejects_empty_text() -> None:
    provider = StubTranslationProvider()

    with pytest.raises(ValueError):
        provider.detect_language("   ")
