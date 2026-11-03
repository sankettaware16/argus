"""The robustness drill and the hardening check (Q-G2, plan §7.4) against the stand-in for the
model machine (tests/unit/llm/local_server.py: Caddy and llama-server as ARGUS sees them, with
the setup script's own certificate, on a free loopback port, never 18443).

Each fault defers within an hour (overflow: no proposal), never an answer, never benign; the
same faults through the investigation agent end in a deferral or "no usable answer", never a
verdict. A weaker setup than D-108's fails the hardening check."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from argus.agent.agent import Agent
from argus.assess.runner import Defer
from argus.evaluation import ladder, robustness
from argus.llm import budget
from argus.llm.gateway import LlmGateway, MemoryLlmStore, NoCapacity
from argus.llm.privacy import Privacy
from argus.llm.providers import LlmConfig
from argus.llm.wire import HttpxLlmTransport
from tests.unit.agent.test_agent import CLASSIFIER, INV, PACKS, Siem, body
from tests.unit.llm import local_server as ls

pytestmark = pytest.mark.unit
KEYS = {"LOCAL_LLM_API_KEY": SecretStr(ls.KEY)}
BENIGN_ANSWER = json.dumps({"outcome": "benign_expected", "confidence": 0.9, "reason": "routine",
                            "missing": []})  # fmt: skip


@pytest.fixture(scope="module")
def cert(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return ls.make_certificate(tmp_path_factory.mktemp("certs") / "run1")


def config(port: int, ca: Path, **over: Any) -> LlmConfig:
    model = {"name": ls.MODEL, "context_tokens": 16384, "thinking_tokens": 2048,
             "max_output": 6144, "max_prompt_tokens": 12000}  # fmt: skip
    provider: dict[str, Any] = {
        "name": "local", "trust": "campus", "base_url": f"https://127.0.0.1:{port}/v1",
        "keys": ["LOCAL_LLM_API_KEY"], "ca_file": str(ca), "timeout_s": 30, "concurrency": 1,
        "tasks": ["evaluate", "ping"], "probe": True, "max_tokens_field": "max_tokens",
        "schema_output": True, "schema_required": True, "licence": "D-990",
        "models": {"small": model, "medium": model}, "limits": {"rpm": 100, "rpd": 300},
    }  # fmt: skip
    provider.update(over)
    return LlmConfig.model_validate({"providers": [provider]})


@pytest.fixture
def machine() -> ls.Machine:
    return ls.Machine(answer=BENIGN_ANSWER)


@pytest.fixture
def port(cert: Path, machine: ls.Machine) -> Iterator[int]:
    with ls.serving(cert, machine) as p:
        yield p


def faults(machine: ls.Machine) -> robustness.Hook:
    """What the machine itself does in each case (the drill changes only ARGUS's side)."""

    @asynccontextmanager
    async def hook(case: str) -> AsyncIterator[None]:
        machine.mode = "loading" if case == "loading" else "ok"
        machine.delay_s = 3.0 if case == "slow" else 0.0
        try:
            yield
        finally:
            machine.mode, machine.delay_s = "ok", 0.0

    return hook


async def test_the_drill_on_the_stand_in_defers_every_fault(
    cert: Path, port: int, machine: ls.Machine, privacy: Privacy
) -> None:
    cfg = config(port, cert)
    before = datetime.now(UTC)
    result = await robustness.drill(cfg, KEYS, privacy.campus, HttpxLlmTransport,
                                    robustness.CASES, faults(machine))  # fmt: skip
    cases = result.cases
    assert cases["control"].outcome == "answered"  # the healthy machine answers
    for name, want in ladder.CASES.items():
        assert cases[name].outcome == want, (name, cases[name])
        if want == "deferred":
            assert cases[name].wait_s is not None
            assert cases[name].wait_s <= 3600 + 5, name
    assert "tls_failed" in cases["changed_certificate"].detail
    assert "unauthorized" in cases["wrong_key"].detail
    assert "model_mismatch" in cases["wrong_model"].detail
    assert "too_large" in cases["overflow"].detail
    assert "busy" in cases["crashed_lease"].detail
    assert "down" in cases["off"].detail
    assert "loading" in cases["loading"].detail
    assert all(v for v in result.hardening.values()), result.hardening
    assert set(result.hardening) == set(ladder.HARDENING)
    # nothing reached the machine with another key, and no fault's call was answered
    chats = [s for s in machine.seen if s["method"] == "POST" and s["path"].endswith("completions")]
    assert all(s["headers"]["Authorization"] == f"Bearer {ls.KEY}" for s in chats
               if s["body"] != {})  # fmt: skip
    measures = ladder.Measures(provider="local", model=ls.MODEL, trust="campus",
                               licence="D-990", hardening=result.hardening,
                               robustness=result.cases)  # fmt: skip
    rung = ladder.judge("triage", measures).rungs[1]
    assert (rung.name, rung.state) == ("robustness", ladder.State.PASS), rung.lines
    assert rung.state is ladder.State.PASS
    assert json.loads(json.dumps(result.as_json(before)))["cases"]["off"]["outcome"] == "deferred"


async def test_on_the_machine_loading_is_left_to_the_stand_in(
    cert: Path, port: int, privacy: Privacy
) -> None:
    result = await robustness.drill(config(port, cert), KEYS, privacy.campus, HttpxLlmTransport,
                                    ("wrong_key",), check_hardening=False)  # fmt: skip
    assert result.cases["loading"].outcome == "skipped"
    assert result.cases["slow"].outcome == "skipped"  # not run: the ladder says so
    assert result.hardening == {}
    measured = ladder.Measures(provider="local", model="m", trust="campus",
                               robustness=result.cases)  # fmt: skip
    rung = ladder.robustness_rung(measured)
    assert rung.state is ladder.State.FAIL
    assert any(line.startswith("slow: skipped") for line in rung.lines)
    assert any("loading: covered by the stand-in" in line for line in rung.lines)


async def test_the_drill_never_touches_the_shared_state(
    cert: Path, port: int, privacy: Privacy
) -> None:
    """A wrong key or certificate raises an alarm only in the drill's own store."""
    result = await robustness.drill(config(port, cert), KEYS, privacy.campus, HttpxLlmTransport,
                                    ("wrong_key", "changed_certificate"))  # fmt: skip
    assert {e["case"] for e in result.ledger} >= {"control", "wrong_key"}
    # the drill builds its own stores: nothing to inspect in a shared one but its outcome
    assert result.cases["wrong_key"].outcome == "deferred"


async def test_a_control_that_does_not_answer_makes_the_drill_prove_nothing(
    cert: Path, privacy: Privacy
) -> None:
    cfg = config(ls.free_port(), cert)
    result = await robustness.drill(cfg, KEYS, privacy.campus, HttpxLlmTransport, ("wrong_key",),
                                    check_hardening=False)  # fmt: skip
    assert result.cases["control"].outcome == "deferred"
    measured = ladder.Measures(provider="local", model="m", trust="campus",
                               robustness=result.cases)  # fmt: skip
    rung = ladder.robustness_rung(measured)
    assert rung.state is ladder.State.FAIL
    assert rung.lines[0].startswith("control: deferred")


@pytest.mark.parametrize(
    ("change", "failed"),
    [({"exposed": frozenset({"/slots", "/metrics"})}, {"slots_refused", "metrics_refused"}),
     ({"keyless": True}, {"models_without_key", "chat_without_key"}),
     ({"model": "another-model"}, {"models_with_key"})],
)  # fmt: skip
async def test_a_weaker_setup_fails_the_hardening_check(
    cert: Path, port: int, machine: ls.Machine, change: dict[str, Any], failed: set[str]
) -> None:
    for name, value in change.items():
        setattr(machine, name, value)
    cfg = config(port, cert)
    transport = HttpxLlmTransport(cfg)
    try:
        checks = await robustness.hardening(cfg.providers[0], KEYS["LOCAL_LLM_API_KEY"], transport)
    finally:
        await transport.aclose()
    assert {k for k, ok in checks.items() if not ok} == failed
    paths = [s["path"] for s in machine.seen]
    assert {"/slots", "/props", "/health", "/metrics"} <= set(paths)
    no_key = [s for s in machine.seen if s["headers"].get("Authorization") != f"Bearer {ls.KEY}"]
    assert {s["path"] for s in no_key} == {"/v1/models", "/v1/chat/completions"}


async def test_an_off_machine_fails_the_hardening_check(cert: Path) -> None:
    cfg = config(ls.free_port(), cert)
    transport = HttpxLlmTransport(cfg)
    try:
        checks = await robustness.hardening(cfg.providers[0], KEYS["LOCAL_LLM_API_KEY"], transport)
    finally:
        await transport.aclose()
    assert not any(checks.values())  # no answer: cannot tell, so every check fails


# -- the same faults through the investigation agent -------------------------------------------


def coordinator_benign() -> str:
    return json.dumps({"outcome": "benign_expected", "confidence": 0.9, "reason": "routine",
                       "cites": ["severity low"], "consult": [], "ask": []})  # fmt: skip


@asynccontextmanager
async def agent_on(cfg: LlmConfig, store: MemoryLlmStore, keys: dict[str, SecretStr],
                   privacy: Privacy) -> AsyncIterator[Agent]:  # fmt: skip
    transport = HttpxLlmTransport(cfg)
    gateway = LlmGateway(cfg, keys, transport, store)
    siem = Siem()
    try:
        yield Agent(privacy, gateway.complete, PACKS, siem.fetch, siem.snapshots, CLASSIFIER,
                    purpose="evaluate", priority=budget.Priority.LOW)  # fmt: skip
    finally:
        await transport.aclose()


@pytest.mark.parametrize("case", ["off", "loading", "overflow", "slow", "wrong_model",
                                  "changed_certificate", "wrong_key", "crashed_lease"])  # fmt: skip
async def test_every_fault_through_the_agent_defers_or_gives_no_verdict(
    cert: Path, port: int, machine: ls.Machine, privacy: Privacy, tmp_path: Path, case: str
) -> None:
    machine.answer = coordinator_benign()
    cfg = config(port, cert, timeout_s=1.0) if case == "slow" else config(port, cert)
    if case not in ("loading", "slow"):
        cfg = robustness._case_config(cfg, cfg.providers[0], tmp_path, case)
    machine.mode = {"loading": "loading", "overflow": "overflow"}.get(case, "ok")
    machine.delay_s = 2.0 if case == "slow" else 0.0
    keys = {"LOCAL_LLM_API_KEY": robustness.WRONG_KEY} if case == "wrong_key" else KEYS
    store = MemoryLlmStore()
    if case == "crashed_lease":
        now = datetime.now(UTC)
        await store.change(lambda s: budget.lease(s, "local", "crashed", 1, now,
                                                  now + timedelta(minutes=16)))  # fmt: skip
    async with agent_on(cfg, store, keys, privacy) as agent:
        if case != "overflow":  # an overflow never waits: it cannot fit later either
            with pytest.raises(Defer) as wait:
                await agent.run(INV, body(), False, False)
            assert wait.value.until <= datetime.now(UTC) + timedelta(hours=1, seconds=5)
            return
        verdict = await agent.run(INV, body(), False, False)
    assert "too_large" in [e.outcome for e in store.ledger]  # the machine's own 400
    assert verdict.outcome is None
    assert verdict.reasons[0] == "no usable answer from the model"


async def test_the_healthy_machine_answers_the_agent(
    cert: Path, port: int, machine: ls.Machine, privacy: Privacy
) -> None:
    """The control: the stand-in's answer reaches the agent (the faults above are faults)."""
    machine.answer = coordinator_benign()
    async with agent_on(config(port, cert), MemoryLlmStore(), KEYS, privacy) as agent:
        verdict = await agent.run(INV, body(), False, False)
    assert agent.last is not None
    assert agent.last.calls >= 1
    assert verdict.reasons[0] == "routine"  # the model's answer was read (the floor decides)


async def test_a_no_capacity_is_what_the_agent_defers_on(privacy: Privacy) -> None:
    """The agent's Defer comes from the gateway's NoCapacity (assumed by the drill)."""

    async def busy(call: Any) -> Any:
        raise NoCapacity(datetime.now(UTC) + timedelta(minutes=5), "busy")

    siem = Siem()
    agent = Agent(privacy, busy, PACKS, siem.fetch, siem.snapshots, CLASSIFIER)
    with pytest.raises(Defer):
        await agent.run(INV, body(), False, False)


async def test_without_the_licence_only_the_connection_test_reaches_the_machine(
    cert: Path, port: int, machine: ls.Machine, privacy: Privacy
) -> None:
    """Q-G2: no call with campus data goes to the campus model before its licence is
    recorded, whatever path sends it (the gateway refuses it); the drill's ping still goes."""
    cfg = config(port, cert, licence=None)
    machine.answer = coordinator_benign()
    async with agent_on(cfg, MemoryLlmStore(), KEYS, privacy) as agent:
        verdict = await agent.run(INV, body(), False, False)
    assert verdict.outcome is None
    assert [s for s in machine.seen if s["method"] == "POST"] == []
    result = await robustness.drill(cfg, KEYS, privacy.campus, HttpxLlmTransport, ("wrong_key",),
                                    check_hardening=False)  # fmt: skip
    assert result.cases["control"].outcome == "answered"
