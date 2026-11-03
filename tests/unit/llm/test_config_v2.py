"""The gateway v2 configuration (Q-G1): the campus provider's rules, task allowlists, the
models' context and output, pinning one provider, and the shipped, disabled ``local`` entry."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from argus.llm.providers import (
    DEFAULT_PATH,
    ROOT,
    LlmConfig,
    ModelConfig,
    Tier,
    Trust,
    load_config,
    models_of,
    pinned,
)

pytestmark = pytest.mark.unit


def campus(**over: Any) -> dict[str, Any]:
    return {"name": "local", "trust": "campus", "base_url": "https://127.0.0.1:18443/v1",
            "keys": ["LOCAL_LLM_API_KEY"], "ca_file": "data/tls/local-llm.crt",
            "tasks": ["evaluate"], "models": {"small": {"name": "cp"}},
            "limits": {"rpd": 300}, **over}  # fmt: skip


def cloud(**over: Any) -> dict[str, Any]:
    return {"name": "c", "base_url": "https://c.example/v1", "keys": ["K"],
            "models": {"small": {"name": "m"}}, **over}  # fmt: skip


def cfg(*providers: dict[str, Any]) -> LlmConfig:
    return LlmConfig.model_validate({"providers": list(providers)})


@pytest.mark.parametrize(
    ("over", "message"),
    [
        ({"base_url": "https://llm.example.edu/v1"}, "on this machine"),
        ({"base_url": "https://10.13.171.247:18443/v1"}, "on this machine"),
        ({"ca_file": None}, "own certificate"),
        ({"tasks": None}, "task allowlist"),
        ({"limits": None}, "daily cap"),
        ({"limits": {"rpm": 2}}, "daily cap"),
        ({"tasks": []}, "tasks must be"),
        ({"tasks": ["assess", "exfiltrate"]}, "tasks must be"),
        ({"timeout_s": 0}, "greater than 0"),
        ({"timeout_s": 901}, "less than or equal to 900"),
        ({"concurrency": 0}, "greater than or equal to 1"),
        ({"trust": "friendly"}, "trust"),
    ],
)
def test_a_campus_provider_must_be_local_pinned_limited_and_capped(
    over: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        cfg(campus(**over))


def test_a_campus_provider_capped_per_model_and_a_cloud_one_with_tasks() -> None:
    per_model = campus(
        limits=None,
        models={
            "small": {"name": "cp", "limits": {"rpd": 9}},
            "medium": {"name": "cp", "limits": {"rpd": 9}},
        },
    )
    assert cfg(per_model).providers[0].trust is Trust.CAMPUS
    half = campus(limits=None, models={"small": {"name": "cp", "limits": {"rpd": 9}},
                                       "medium": {"name": "cp"}})  # fmt: skip
    with pytest.raises(ValidationError, match="daily cap"):
        cfg(half)
    p = cfg(cloud(tasks=["assess", "tune"])).providers[0]
    assert (p.serves("assess"), p.serves("evaluate")) == (True, False)
    assert cfg(cloud()).providers[0].serves("anything")
    with pytest.raises(ValidationError, match="tasks must be"):
        cfg(cloud(tasks=["nope"]))
    ipv6 = cfg(campus(base_url="https://[::1]:18443/v1")).providers[0]
    assert ipv6.trust is Trust.CAMPUS


def test_the_defaults_keep_phase_2s_behaviour() -> None:
    p = cfg(cloud()).providers[0]
    assert (p.trust, p.ca_file, p.timeout_s, p.concurrency, p.tasks, p.probe) == (
        Trust.CLOUD, None, 60.0, None, None, False)  # fmt: skip
    assert (p.schema_output, p.slow_s) == (False, 120.0)
    m = p.models[Tier.SMALL]
    assert (m.context_tokens, m.thinking_tokens, m.max_output) == (None, 0, None)
    assert m.output_cap(1000) == 1000
    assert m.fits(10**9, 10**9)
    assert p.ca_path() is None
    assert cfg(cloud()).evaluation.opens(__import__("datetime").datetime.now()) is None


def test_output_cap_and_context() -> None:
    m = ModelConfig(name="cp", context_tokens=1000, thinking_tokens=300, max_output=700)
    assert m.output_cap(100) == 400
    assert m.output_cap(500) == 700
    assert m.fits(2 * (1000 - 64 - 400), 400)
    assert not m.fits(2 * (1000 - 64 - 400) + 1, 400)
    with pytest.raises(ValidationError):
        ModelConfig(name="cp", thinking_tokens=-1)
    with pytest.raises(ValidationError):
        ModelConfig(name="cp", context_tokens=10)


def test_the_certificate_path_is_relative_to_the_repository(tmp_path: Path) -> None:
    p = cfg(campus()).providers[0]
    assert p.ca_path() == ROOT / "data" / "tls" / "local-llm.crt"
    absolute = cfg(campus(ca_file=str(tmp_path / "x.crt"))).providers[0]
    assert absolute.ca_path() == tmp_path / "x.crt"
    assert p.lease_for(600).total_seconds() == 660


def test_pinning_one_provider() -> None:
    both = cfg(cloud(), campus(enabled=False))
    assert [p.name for p in pinned(both, "c").providers] == ["c"]
    with pytest.raises(ValueError, match="no provider 'x'"):
        pinned(both, "x")
    with pytest.raises(ValueError, match="local is disabled"):
        pinned(both, "local")
    on = pinned(both, "local", allow_disabled=True).providers[0]
    assert (on.name, on.enabled) == ("local", True)
    assert both.providers[1].enabled is False  # the original is unchanged
    assert models_of(both) == "c/small=m;local/small=cp"


def test_the_shipped_local_entry_is_disabled_campus_and_pinned() -> None:
    llm = load_config(DEFAULT_PATH)
    (local,) = [p for p in llm.providers if p.name == "local"]
    assert local.enabled is False
    assert local.trust is Trust.CAMPUS
    assert local.base_url == "https://127.0.0.1:18443/v1"
    assert local.keys == ("LOCAL_LLM_API_KEY",)
    assert local.ca_file == Path("data/tls/local-llm.crt")  # where the import stores it
    assert local.tasks == ("evaluate", "ping")
    assert local.probe
    assert local.concurrency == 1
    assert local.timeout_s >= 300  # minutes on a CPU, thinking included
    assert local.limits is not None
    assert local.limits.rpd is not None
    for model in local.models.values():
        assert model.name == "cyber-prime-1.2"
        assert model.context_tokens == 16384  # llama-server --ctx-size 16384
        assert model.thinking_tokens >= 1024  # the hand-over's test ran out at 1024
        assert model.output_cap(1500) <= (model.max_output or 10**9)
    assert local.models[Tier.SMALL].fits(20_000, local.models[Tier.SMALL].output_cap(1500))
    assert llm.evaluation.window_utc is not None
    assert llm.evaluation.calls_per_day is not None
    for p in llm.providers:
        if p.trust is Trust.CLOUD:
            assert p.ca_file is None  # the default trust store
