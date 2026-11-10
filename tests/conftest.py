from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _enable_registration_for_existing_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Public registration is closed by default in production code.

    The pre-existing registration tests exercise the open path, so they
    run with it enabled. tests/unit/test_registration_gate.py overrides
    this to verify the closed default.
    """
    monkeypatch.setenv("ELDORADO_ENABLE_REGISTRATION", "true")