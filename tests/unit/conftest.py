"""Unit tests run with no ARGUS_* environment and no registered secrets leaking between tests."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from argus.observability.redaction import clear_registered_secrets


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    for key in list(os.environ):
        if key.upper().startswith("ARGUS_"):
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)  # no accidental pickup of the repo's .env / config
    clear_registered_secrets()
    yield
    clear_registered_secrets()


@pytest.fixture
def write_config(tmp_path: Path):  # type: ignore[no-untyped-def]
    """Write a YAML config file and return its path."""

    def _write(text: str, name: str = "argus.yaml") -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    return _write
