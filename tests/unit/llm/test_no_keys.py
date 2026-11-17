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


def test_the_overlay_sets_the_budget_and_nothing_else(tmp_path: Path) -> None:
    config = load_config(_config(tmp_path, {"monthly_cap_usd": 80, "daily_cap_usd": 2.6}))
    assert (config.monthly_cap_usd, config.daily_cap_usd) == (80, 2.6)
    said = "may set daily_cap_usd, keys_file, monthly_cap_usd, provider_caps, provider_enabled"
    with pytest.raises(ValueError, match=said + ", purposes only"):
        load_config(_config(tmp_path, {"margin": 1.0}))


def _priced(tmp_path: Path, caps: object) -> Path:
    priced = {**CONFIG, "monthly_cap_usd": 80, "daily_cap_usd": 2.6, "providers": [
        {**CONFIG["providers"][0], "models": {"small": {"name": "m", "input_per_m": 1.0}}},
        CONFIG["providers"][1]]}  # fmt: skip
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(priced))
    (tmp_path / "llm.local.yaml").write_text(yaml.safe_dump({"provider_caps": caps}))
    return path


def test_the_overlay_sets_a_providers_own_caps(tmp_path: Path) -> None:
    config = load_config(_priced(tmp_path, {"a": {"monthly_cap_usd": 40, "daily_cap_usd": 1.3}}))
    a, b = config.providers
    assert (a.monthly_cap_usd, a.daily_cap_usd) == (40, 1.3)
    assert (b.monthly_cap_usd, b.daily_cap_usd) == (None, None)


@pytest.mark.parametrize(
    ("caps", "why"),
    [
        ({"nope": {"monthly_cap_usd": 1}}, "names no such provider: nope"),
        ({"a": {"margin": 1}}, "provider_caps.a sets daily_cap_usd, monthly_cap_usd only"),
        ({"a": 5}, "provider_caps.a sets"),
        (["a"], "maps a provider's name to its caps"),
        ({"a": {"monthly_cap_usd": 100}}, "monthly"),  # above the overall cap
    ],
)
def test_the_overlays_provider_caps_are_checked(tmp_path: Path, caps: object, why: str) -> None:
    with pytest.raises(ValueError, match=why):
        load_config(_priced(tmp_path, caps))


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


def test_the_apps_overlay_lies_over_the_local_one(tmp_path: Path) -> None:
    path = _config(tmp_path, {"monthly_cap_usd": 80, "daily_cap_usd": 2.6})
    (tmp_path / "llm.admin.yaml").write_text(yaml.safe_dump({"monthly_cap_usd": 20}))
    config = load_config(path)
    assert (config.monthly_cap_usd, config.daily_cap_usd) == (20, 2.6)


def test_the_apps_overlay_switches_a_provider_and_sets_a_tasks_own(tmp_path: Path) -> None:
    path = _config(tmp_path)
    first = CONFIG["providers"][0]["name"]
    admin = {
        "provider_enabled": {first: False},
        "purposes": {"story": {"calls_per_day": 4}, "opinion": {"tier": "large"}},
    }
    (tmp_path / "llm.admin.yaml").write_text(yaml.safe_dump(admin))
    config = load_config(path)
    assert not next(p for p in config.providers if p.name == first).enabled
    assert config.purposes["story"].calls_per_day == 4
    assert config.purposes["opinion"].tier == "large"
    for bad, why in (
        ({"provider_enabled": {"nope": False}}, "no such provider"),
        ({"provider_enabled": {first: "yes"}}, "true or false"),
        ({"purposes": {"story": {"margin": 1}}}, "purposes.story sets"),
    ):
        (tmp_path / "llm.admin.yaml").write_text(yaml.safe_dump(bad))
        with pytest.raises(ValueError, match=why):
            load_config(path)
