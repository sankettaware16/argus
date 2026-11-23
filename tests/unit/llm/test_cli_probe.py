"""``argus llm probe`` (Q-G1) against the TLS stand-in: the named provider's state, a disabled
one only when named, exit 1 unless every one asked is up; a provider found up has its alarm
cleared (the review's F4). No database (a fake store), no prompt."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from argus.cli import app
from argus.llm import budget
from argus.llm import cli as llm_cli
from argus.llm.cli import _record_up as record_up  # the real one (the fixture replaces it)
from argus.llm.providers import LlmConfig
from tests.unit.llm import local_server as ls

pytestmark = pytest.mark.unit


class Recorder:
    """Stands in for the shared state: which providers `llm probe` found up."""

    def __init__(self) -> None:
        self.names: list[str] = []

    async def __call__(self, settings: object, names: list[str]) -> list[str]:
        self.names += names
        return []


@pytest.fixture(autouse=True)
def recorder(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    found = Recorder()
    monkeypatch.setattr("argus.llm.cli._record_up", found)
    monkeypatch.setattr("argus.llm.cli.load", lambda config: None)
    return found


@pytest.fixture(scope="module")
def cert(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return ls.make_certificate(tmp_path_factory.mktemp("cli") / "run")


@pytest.fixture
def machine() -> ls.Machine:
    return ls.Machine()


@pytest.fixture
def port(cert: Path, machine: ls.Machine) -> Iterator[int]:
    with ls.serving(cert, machine) as p:
        yield p


def setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, port: int, cert: Path,
          key: str = ls.KEY, **over: Any) -> None:  # fmt: skip
    keys = tmp_path / "keys.env"
    keys.write_text(f"LOCAL_LLM_API_KEY={key}\n", encoding="utf-8")
    llm = LlmConfig.model_validate({"keys_file": str(keys), "providers": [
        {"name": "cloud", "base_url": "https://cloud.example/v1", "keys": ["CLOUD_KEY"],
         "models": {"small": {"name": "c"}}},
        {"name": "local", "trust": "self_hosted", "enabled": False, "probe": True,
         "base_url": f"https://127.0.0.1:{port}/v1", "keys": ["LOCAL_LLM_API_KEY"],
         "ca_file": str(cert), "tasks": ["evaluate", "ping"], "limits": {"rpd": 9},
         "models": {"small": {"name": ls.MODEL}}, **over},
    ]})  # fmt: skip
    monkeypatch.setattr("argus.llm.cli.load_config", lambda: llm)


def run(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(app, ["llm", "probe", *args])
    return result.exit_code, result.output + result.stderr


def test_probe_a_disabled_provider_by_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, port: int, cert: Path, machine: ls.Machine
) -> None:
    setup(monkeypatch, tmp_path, port, cert)
    code, out = run("--provider", "local")
    assert code == 0, out
    assert "note: local is disabled for ARGUS's own work; used because you named it" in out
    assert f"local: up: {ls.MODEL} listed (" in out
    assert [s["method"] for s in machine.seen] == ["GET"]
    assert ls.KEY not in out


def test_probe_says_what_is_wrong(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, port: int, cert: Path, machine: ls.Machine
) -> None:
    setup(monkeypatch, tmp_path, port, cert, key="old-run-key-0000")
    code, out = run("--provider", "local")
    assert code == 1
    assert "local: unauthorized: the key was refused (401)" in out
    machine.mode = "loading"
    setup(monkeypatch, tmp_path, port, cert)
    assert "local: loading: loading the model (503)" in run("--provider", "local")[1]


def test_probe_without_a_name_asks_only_enabled_providers_with_a_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, port: int, cert: Path, machine: ls.Machine
) -> None:
    setup(monkeypatch, tmp_path, port, cert)  # local is disabled: not asked unless named
    code, out = run()
    assert (code, out.strip()) == (1, "no enabled provider has a probe (probe: true in"
                                      " config/llm.yaml); name one")  # fmt: skip
    assert machine.seen == []
    setup(monkeypatch, tmp_path, port, cert, enabled=True)
    code, out = run()
    assert code == 0, out
    (line,) = out.strip().splitlines()
    assert line.startswith("local: up")
    setup(monkeypatch, tmp_path, port, cert, enabled=True, probe=False)
    assert run()[0] == 1
    code, out = run("--provider", "nobody")
    assert code == 1
    assert "error: no provider 'nobody'" in out
    code, out = run("--provider", "cloud")
    assert (code, out.strip()) == (1, "cloud: no key")


def test_an_up_provider_is_recorded_and_a_down_one_is_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, port: int, cert: Path, recorder: Recorder
) -> None:
    setup(monkeypatch, tmp_path, port, cert)
    assert run("--provider", "local")[0] == 0
    assert recorder.names == ["local"]
    setup(monkeypatch, tmp_path, port, cert, key="old-run-key-0000")
    assert run("--provider", "local")[0] == 1
    assert recorder.names == ["local"]  # unauthorized: nothing cleared


class Store:
    def __init__(self, state: budget.State) -> None:
        self.state = state

    async def probe_up(self, provider: str, now: datetime, *, actor: str) -> budget.Alarm | None:
        assert actor == "cli"
        cleared, self.state = budget.probe_up(self.state, provider, now)
        return cleared


class Engine:
    async def dispose(self) -> None:
        return None


async def test_recording_clears_the_alarm_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    at = datetime(2026, 10, 16, 12, tzinfo=UTC)
    state = budget.raise_alarm(budget.State(), "local", "tls_failed", "not the pinned one", at)
    store = Store(budget.cool_down(state, "local", datetime.now(UTC) + timedelta(hours=1), at))
    monkeypatch.setattr(llm_cli, "engine_for", lambda settings: Engine())
    monkeypatch.setattr(llm_cli, "PgLlmStore", lambda db: store)
    lines = await record_up(None, ["local", "other"])
    assert lines == ["local: alarm cleared (tls_failed since 2026-10-16 12:00 UTC); calls may go"
                     " now"]  # fmt: skip
    assert store.state.alarms == {}
    assert "local" not in store.state.cooldowns
    assert await record_up(None, ["local"]) == []
