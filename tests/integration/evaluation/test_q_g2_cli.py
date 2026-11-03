"""Q-G2's commands end to end: ``argus llm drill`` against the stand-in for the model machine
(never 18443), ``argus gold ladder``, ``argus gold task`` and ``argus llm shadow`` against a
throwaway database; the licence before any evaluation call to the campus model."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from argus.llm.privacy import Privacy
from argus.llm.providers import LlmConfig
from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401 - the fixture
from tests.unit.evaluation.test_robustness import BENIGN_ANSWER
from tests.unit.llm import local_server as ls

pytestmark = pytest.mark.integration


@pytest.fixture
def machine() -> ls.Machine:
    return ls.Machine(answer=BENIGN_ANSWER, delay_s=1.5)  # slower than the drill's deadline


@pytest.fixture
def stand_in(tmp_path_factory: pytest.TempPathFactory, machine: ls.Machine
             ) -> Iterator[tuple[int, Path]]:  # fmt: skip
    cert = ls.make_certificate(tmp_path_factory.mktemp("certs") / "run1")
    with ls.serving(cert, machine) as p:
        yield p, cert


def configure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, privacy: Privacy,
              stand_in: tuple[int, Path], **over: Any) -> LlmConfig:  # fmt: skip
    port, cert = stand_in
    keys = tmp_path / "keys.env"
    keys.write_text(f"LOCAL_LLM_API_KEY={ls.KEY}\n", encoding="utf-8")
    model = {"name": ls.MODEL, "context_tokens": 16384, "thinking_tokens": 2048,
             "max_output": 6144, "max_prompt_tokens": 12000}  # fmt: skip
    provider = {"name": "local", "enabled": False, "trust": "campus",
                "base_url": f"https://127.0.0.1:{port}/v1", "keys": ["LOCAL_LLM_API_KEY"],
                "ca_file": str(cert), "timeout_s": 30, "concurrency": 1,
                "tasks": ["evaluate", "ping"], "probe": True, "schema_output": True,
                "schema_required": True, "models": {"small": model, "medium": model},
                "limits": {"rpm": 100, "rpd": 375}, **over}  # fmt: skip
    cfg = LlmConfig.model_validate({"keys_file": str(keys), "providers": [provider]})
    for where in ("argus.llm.cli.load_config", "argus.llm.providers.load_config"):
        monkeypatch.setattr(where, lambda *a: cfg)
    for where in ("argus.llm.cli._privacy", "argus.assess.cli._privacy"):
        monkeypatch.setattr(where, lambda settings: privacy)
    return cfg


def test_the_drill_and_the_ladder_from_the_command_line(
    cli_env: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    privacy: Privacy,
    stand_in: tuple[int, Path],
    machine: ls.Machine,
) -> None:
    configure(monkeypatch, tmp_path, privacy, stand_in)
    out = tmp_path / "q-g2"
    code, text = _invoke("llm", "drill", "--measures", str(out), "-c", str(cli_env))
    assert code == 0, text
    assert "note: local is disabled for ARGUS's own work; used because you named it" in text
    assert "control: answered" in text
    assert "wrong_key: deferred" in text
    assert "loading: skipped" in text
    assert "hardening slots_refused: ok" in text
    drill = json.loads((out / "local" / "drill.json").read_text(encoding="utf-8"))
    assert drill["cases"]["overflow"]["outcome"] == "no_proposal"
    assert ls.KEY not in (out / "local" / "drill.json").read_text(encoding="utf-8")
    assert _invoke("db", "upgrade", "-c", str(cli_env))[0] == 0
    code, text = _invoke("gold", "ladder", "--cloud", "", "--measures", str(out),
                         "-c", str(cli_env))  # fmt: skip
    assert code == 0, text
    lines = text.splitlines()
    assert lines[0] == "extract on local/cyber-prime-1.2: not promoted: stops at setup (fail)"
    assert "    - the licence's confirmation is not recorded (licence: D-NNN)" in lines
    assert "  robustness: pass" in lines
    assert "assess on local/cyber-prime-1.2: not promoted: stops at allowed (not allowed)" in lines
    assert (out / "local" / "ladder.json").is_file()
    machine.exposed = frozenset({"/metrics"})
    code, text = _invoke("llm", "drill", "--measures", str(out), "-c", str(cli_env))
    assert code == 1
    assert "hardening metrics_refused: FAILED" in text


def test_evaluation_calls_wait_for_the_licence(
    cli_env: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    privacy: Privacy,
    stand_in: tuple[int, Path],
    machine: ls.Machine,
) -> None:
    configure(monkeypatch, tmp_path, privacy, stand_in)
    assert _invoke("db", "upgrade", "-c", str(cli_env))[0] == 0
    for args in (("gold", "task", "--task", "triage", "--allow-disabled"),
                 ("llm", "shadow", "--task", "triage", "--allow-disabled"),
                 ("gold", "agent", "--provider", "local", "--allow-disabled")):  # fmt: skip
        code, text = _invoke(*args, "--measures", str(tmp_path), "-c", str(cli_env)) if (
            args[1] == "task") else _invoke(*args, "-c", str(cli_env))  # fmt: skip
        assert code == 1, (args, text)
        assert "licence confirmation is not recorded" in text
    assert [s for s in machine.seen if s["method"] == "POST"] == []  # nothing was asked
    configure(monkeypatch, tmp_path, privacy, stand_in, licence="D-121")
    code, text = _invoke("gold", "task", "--task", "triage", "--measures", str(tmp_path),
                         "-c", str(cli_env))  # fmt: skip
    assert code == 1  # campus data to a disabled provider: only when asked by name
    assert "disabled in config/llm.yaml (--allow-disabled to use it)" in text
    code, text = _invoke("gold", "task", "--task", "triage", "--allow-disabled", "--measures",
                         str(tmp_path), "-c", str(cli_env))  # fmt: skip
    assert code == 0, text
    assert "triage on local: 0 items, 0 calls" in text  # no gold set here: nothing to measure
    code, text = _invoke("llm", "shadow", "--task", "summary", "-c", str(cli_env))
    assert code == 1
    assert "--allow-disabled" in text
    code, text = _invoke("llm", "shadow", "--task", "summary", "--allow-disabled",
                         "-c", str(cli_env))  # fmt: skip
    assert code == 1  # F8: the web still logs in as the runtime login, which may read it
    assert "web.database_role: api" in text
    monkeypatch.setenv("ARGUS_WEB__DATABASE_ROLE", "api")
    code, text = _invoke("llm", "shadow", "--task", "summary", "--allow-disabled",
                         "-c", str(cli_env))  # fmt: skip
    assert code == 0, text
    assert "summary in shadow on local/cyber-prime-1.2: 0 stored" in text
    code, text = _invoke("gold", "task", "--task", "assess", "-c", str(cli_env))
    assert code == 1
    assert "no task 'assess'" in text
