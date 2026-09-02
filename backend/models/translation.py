from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class TranslationRequest:
    """
    Immutable request for a translation operation.

    Translation is a content transformation capability. It does not
    authenticate users, authorize tools, or grant permissions.
    """

    text: str
    target_language: str
    source_language: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.text.strip():
            raise ValueError("Translation text cannot be empty.")

        if not self.target_language.strip():
            raise ValueError("Target language cannot be empty.")

        if self.source_language is not None and not self.source_language.strip():
            raise ValueError("Source language cannot be empty when provided.")


@dataclass(frozen=True)
class TranslationResult:
    """
    Result returned by a translation provider.

    The translated content remains untrusted application data.
    """

    original_text: str
    translated_text: str
    source_language: Optional[str]
    target_language: str
    confidence: Optional[float] = None

    def __post_init__(self) -> None:
        if not self.original_text.strip():
            raise ValueError("Original text cannot be empty.")

        if not self.translated_text.strip():
            raise ValueError("Translated text cannot be empty.")

        if not self.target_language.strip():
            raise ValueError("Target language cannot be empty.")

        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Translation confidence must be between 0.0 and 1.0.")
