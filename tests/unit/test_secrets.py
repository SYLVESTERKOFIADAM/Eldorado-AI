from __future__ import annotations

import pytest

from backend.security.secrets import SecretConfiguration


def test_required_secret_returns_environment_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ELDORADO_TEST_SECRET", "test-value")

    assert (
        SecretConfiguration.get_required("ELDORADO_TEST_SECRET")
        == "test-value"
    )


def test_required_secret_rejects_missing_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ELDORADO_TEST_SECRET", raising=False)

    with pytest.raises(RuntimeError):
        SecretConfiguration.get_required("ELDORADO_TEST_SECRET")


def test_required_secret_rejects_blank_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ELDORADO_TEST_SECRET", "   ")

    with pytest.raises(RuntimeError):
        SecretConfiguration.get_required("ELDORADO_TEST_SECRET")


def test_optional_secret_returns_none_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ELDORADO_TEST_SECRET", raising=False)

    assert SecretConfiguration.get_optional("ELDORADO_TEST_SECRET") is None


def test_optional_secret_returns_value_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ELDORADO_TEST_SECRET", "test-value")

    assert (
        SecretConfiguration.get_optional("ELDORADO_TEST_SECRET")
        == "test-value"
    )


def test_secret_name_cannot_be_empty() -> None:
    with pytest.raises(ValueError):
        SecretConfiguration.get_required("   ")


def test_optional_secret_name_cannot_be_empty() -> None:
    with pytest.raises(ValueError):
        SecretConfiguration.get_optional("   ")
