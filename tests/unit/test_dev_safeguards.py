from __future__ import annotations

import pytest

from backend.security.dev_safeguards import purge_refusal


def test_allows_development_with_matching_database_name() -> None:
    assert purge_refusal("development", "postgres", "postgres") is None


def test_environment_value_is_normalised() -> None:
    assert purge_refusal("  Development ", "postgres", "postgres") is None


@pytest.mark.parametrize(
    "environment",
    [None, "", "production", "staging", "dev"],
)
def test_refuses_outside_development(environment: str | None) -> None:
    reason = purge_refusal(environment, "postgres", "postgres")

    assert reason is not None
    assert "ELDORADO_ENV" in reason


def test_refuses_when_typed_name_differs() -> None:
    assert purge_refusal("development", "postgres", "podtgres") is not None


def test_name_comparison_is_exact() -> None:
    assert purge_refusal("development", "postgres", "Postgres") is not None


def test_refuses_when_typed_name_is_empty() -> None:
    assert purge_refusal("development", "postgres", "") is not None


def test_refuses_when_database_name_is_empty() -> None:
    assert purge_refusal("development", "", "") is not None