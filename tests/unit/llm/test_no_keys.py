"""D-298: an installation without LLM keys. ``keys_file: null`` (written by ``argus init`` into
config/llm.local.yaml, the one overlay the LLM configuration takes) means no model is called:
the agent, the tuning suggestions and the incident prose are off, nothing waits on a call that
cannot be made, and doctor says ARGUS investigates deterministically."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from argus.llm import doctor as llm_doctor
from argus.llm.providers import callable_providers, load_config, load_keys

pytestmark = pytest.mark.unit

CONFIG = {
    "keys_file": "keys.env",
    "providers": [
        {"name": "a", "base_url": "https://a.example/v1", "keys": ["A_KEY"],
         "models": {"small": {"name": "m"}}},
        {"name": "b", "base_url": "https://b.example/v1", "keys": ["B_KEY"],
         "models": {"small": {"name": "m"}}, "enabled": False},
    ],
}  # fmt: skip


def _config(tmp_path: Path, overlay: object = None) -> Path:
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(CONFIG))
    if overlay is not None:
        (tmp_path / "llm.local.yaml").write_text(yaml.safe_dump(overlay))
    return path


def test_the_overlay_sets_the_keys_file(tmp_path: Path) -> None:
    assert load_config(_config(tmp_path)).keys_file == Path("keys.env")
    assert load_config(_config(tmp_path, {"keys_file": None})).keys_file is None
    assert load_config(_config(tmp_path, {"keys_file": "/x/k.env"})).keys_file == Path("/x/k.env")


def test_the_overlay_may_set_nothing_else(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="may set keys_file only"):
        load_config(_config(tmp_path, {"monthly_cap_usd": 1000}))


def test_no_keys_file_gives_no_key_and_no_callable_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    config = load_config(_config(tmp_path, {"keys_file": None}))
    assert load_keys(None, {"A_KEY"}) == {}
    assert callable_providers(config) == []
    found = llm_doctor.keys_file_check(config)
    assert found.ok
    assert "ARGUS investigates deterministically" in found.detail


def test_only_an_enabled_provider_with_a_key_can_be_called(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    keys = tmp_path / "keys.env"
    keys.write_text("A_KEY=\nB_KEY=b-value\n")
    config = load_config(_config(tmp_path, {"keys_file": str(keys)}))
    assert callable_providers(config) == []  # a has an empty key, b is disabled
    keys.write_text("A_KEY=a-value\n")
    assert callable_providers(config) == ["a"]


def test_assess_switches_the_model_features_off_without_a_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from argus.assess import cli as assess_cli
    from argus.llm import providers

    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    path = _config(tmp_path, {"keys_file": None})
    monkeypatch.setattr(providers, "DEFAULT_PATH", path)
    monkeypatch.setattr(providers.load_config, "__defaults__", (path,))
    why = assess_cli._no_model()
    assert why is not None
    assert "ARGUS investigates deterministically" in why
    keys = tmp_path / "keys.env"
    keys.write_text("A_KEY=a-value\n")
    (tmp_path / "llm.local.yaml").write_text(yaml.safe_dump({"keys_file": str(keys)}))
    assert assess_cli._no_model() is None
    (tmp_path / "llm.local.yaml").write_text(yaml.safe_dump({"keys_file": str(tmp_path / "x")}))
    assert assess_cli._no_model() == f"no enabled provider has a key in {tmp_path / 'x'}"
