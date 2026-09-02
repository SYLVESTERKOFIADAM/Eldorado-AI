from __future__ import annotations

from uuid import uuid4

import pytest
import requests

from backend.models.translation import TranslationRequest
from backend.services.providers.azure_translation import AzureTranslationProvider


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


def test_azure_provider_translates_successfully(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_post(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs

        return FakeResponse(
            {
                "value": [
                    {
                        "translations": [
                            {
                                "text": "Bonjour",
                                "language": "fr",
                            }
                        ]
                    }
                ]
            }
        )

    monkeypatch.setattr(
        "backend.services.providers.azure_translation.requests.post",
        fake_post,
    )

    provider = AzureTranslationProvider(
        endpoint="https://example.cognitiveservices.azure.com",
        api_key="test-secret",
        region="global",
    )

    result = provider.translate(
        TranslationRequest(
            text="Hello",
            source_language="en",
            target_language="fr",
        )
    )

    assert result.translated_text == "Bonjour"
    assert result.target_language == "fr"

    assert captured["kwargs"]["headers"][
        "Ocp-Apim-Subscription-Key"
    ] == "test-secret"


def test_azure_provider_uses_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_post(*args, **kwargs):
        captured["timeout"] = kwargs["timeout"]

        return FakeResponse(
            {
                "value": [
                    {
                        "translations": [
                            {
                                "text": "Bonjour",
                                "language": "fr",
                            }
                        ]
                    }
                ]
            }
        )

    monkeypatch.setattr(
        "backend.services.providers.azure_translation.requests.post",
        fake_post,
    )

    provider = AzureTranslationProvider(
        endpoint="https://example.cognitiveservices.azure.com",
        api_key="test-secret",
        timeout_seconds=7.5,
    )

    provider.translate(
        TranslationRequest(
            text="Hello",
            target_language="fr",
        )
    )

    assert captured["timeout"] == 7.5


def test_azure_provider_rejects_empty_translation_input() -> None:
    provider = AzureTranslationProvider(
        endpoint="https://example.cognitiveservices.azure.com",
        api_key="test-secret",
    )

    with pytest.raises(ValueError):
        provider.translate(
            TranslationRequest(
                text="   ",
                target_language="fr",
            )
        )


def test_azure_provider_handles_network_failure_without_leaking_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "SUPER-SECRET-KEY"

    def fake_post(*args, **kwargs):
        raise requests.RequestException(
            f"network failure involving {secret}"
        )

    monkeypatch.setattr(
        "backend.services.providers.azure_translation.requests.post",
        fake_post,
    )

    provider = AzureTranslationProvider(
        endpoint="https://example.cognitiveservices.azure.com",
        api_key=secret,
    )

    with pytest.raises(RuntimeError) as exc_info:
        provider.translate(
            TranslationRequest(
                text="Hello",
                target_language="fr",
            )
        )

    assert str(exc_info.value) == "Azure translation request failed."
    assert secret not in str(exc_info.value)


def test_azure_provider_rejects_invalid_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "backend.services.providers.azure_translation.requests.post",
        lambda *args, **kwargs: FakeResponse({"invalid": True}),
    )

    provider = AzureTranslationProvider(
        endpoint="https://example.cognitiveservices.azure.com",
        api_key="test-secret",
    )

    with pytest.raises(RuntimeError, match="invalid response"):
        provider.translate(
            TranslationRequest(
                text="Hello",
                target_language="fr",
            )
        )


def test_azure_provider_detects_language(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "backend.services.providers.azure_translation.requests.post",
        lambda *args, **kwargs: FakeResponse(
            {
                "value": [
                    {
                        "language": "en",
                    }
                ]
            }
        ),
    )

    provider = AzureTranslationProvider(
        endpoint="https://example.cognitiveservices.azure.com",
        api_key="test-secret",
    )

    assert provider.detect_language("Hello world") == "en"


def test_azure_provider_rejects_empty_language_detection() -> None:
    provider = AzureTranslationProvider(
        endpoint="https://example.cognitiveservices.azure.com",
        api_key="test-secret",
    )

    with pytest.raises(ValueError):
        provider.detect_language("   ")


def test_azure_provider_rejects_invalid_timeout() -> None:
    with pytest.raises(ValueError):
        AzureTranslationProvider(
            endpoint="https://example.cognitiveservices.azure.com",
            api_key="test-secret",
            timeout_seconds=0,
        )
