from __future__ import annotations

from typing import Any

import requests

from backend.models.translation import TranslationRequest, TranslationResult
from backend.security.secrets import SecretConfiguration
from backend.services.translation_provider import TranslationProvider


class AzureTranslationProvider(TranslationProvider):
    """
    Azure Translator implementation of the translation boundary.

    Security properties:
    - Credentials come only from SecretConfiguration.
    - The endpoint is configured by the application, not user input.
    - HTTP requests use an explicit timeout.
    - Secret values are never included in raised errors.
    - Provider output remains untrusted application data.
    """

    API_VERSION = "2026-06-06"

    def __init__(
        self,
        endpoint: str | None = None,
        api_key: str | None = None,
        region: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._endpoint = (
            endpoint
            or SecretConfiguration.get_required(
                "AZURE_TRANSLATOR_ENDPOINT"
            )
        ).rstrip("/")

        self._api_key = (
            api_key
            or SecretConfiguration.get_required(
                "AZURE_TRANSLATOR_KEY"
            )
        )

        self._region = region or SecretConfiguration.get_optional(
            "AZURE_TRANSLATOR_REGION"
        )

        if timeout_seconds <= 0:
            raise ValueError("Timeout must be greater than zero.")

        self._timeout_seconds = timeout_seconds

    def translate(
        self,
        request: TranslationRequest,
    ) -> TranslationResult:
        url = f"{self._endpoint}/translate"

        params = {
            "api-version": self.API_VERSION,
        }

        headers = {
            "Ocp-Apim-Subscription-Key": self._api_key,
            "Content-Type": "application/json",
        }

        if self._region:
            headers["Ocp-Apim-Subscription-Region"] = self._region

        payload: dict[str, Any] = {
            "inputs": [
                {
                    "text": request.text,
                    "targets": [
                        {
                            "language": request.target_language,
                        }
                    ],
                }
            ]
        }

        if request.source_language:
            payload["inputs"][0]["language"] = request.source_language

        try:
            response = requests.post(
                url,
                params=params,
                headers=headers,
                json=payload,
                timeout=self._timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(
                "Azure translation request failed."
            ) from exc

        try:
            data = response.json()
            translation = data["value"][0]["translations"][0]

            translated_text = translation["text"]
            target_language = translation["language"]

        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(
                "Azure translation returned an invalid response."
            ) from exc

        if not isinstance(translated_text, str) or not translated_text.strip():
            raise RuntimeError(
                "Azure translation returned empty translated text."
            )

        if not isinstance(target_language, str) or not target_language.strip():
            raise RuntimeError(
                "Azure translation returned an invalid target language."
            )

        return TranslationResult(
            original_text=request.text,
            translated_text=translated_text,
            source_language=request.source_language,
            target_language=target_language,
        )

    def detect_language(self, text: str) -> str:
        if not text.strip():
            raise ValueError("Text cannot be empty.")

        url = f"{self._endpoint}/detect"

        params = {
            "api-version": self.API_VERSION,
        }

        headers = {
            "Ocp-Apim-Subscription-Key": self._api_key,
            "Content-Type": "application/json",
        }

        if self._region:
            headers["Ocp-Apim-Subscription-Region"] = self._region

        payload: dict[str, Any] = {
            "inputs": [
                {
                    "text": text,
                }
            ]
        }

        try:
            response = requests.post(
                url,
                params=params,
                headers=headers,
                json=payload,
                timeout=self._timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(
                "Azure language detection request failed."
            ) from exc

        try:
            data = response.json()
            detected_language = data["value"][0]["language"]

        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(
                "Azure language detection returned an invalid response."
            ) from exc

        if (
            not isinstance(detected_language, str)
            or not detected_language.strip()
        ):
            raise RuntimeError(
                "Azure language detection returned an invalid language."
            )

        return detected_language
