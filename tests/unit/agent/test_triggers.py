"""Q-H1: what may start the investigator is its file's triggers, within code's binding. The
assess service queues the engine's undecided items only when the file takes
``engine_no_decision``; a person's request (D-095) only when it takes ``person_request`` (the
web route, tested with the Inbox). A refused file turns the agent off, never the decision
engine: the service checks the files every pass."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from argus import raising
from argus.agent import loader
from argus.agent.registry import ENABLED, PINS, Pin, Trigger
from argus.assess import cli as assess_cli
from argus.assess import patterns
from argus.config.settings import NotifiedSettings, SigninsSettings
from argus.signins import run as signins_run
from tests.unit.agent.test_loader import FILES, copy, header


@pytest.fixture(autouse=True)
def no_wave(monkeypatch: pytest.MonkeyPatch) -> None:
    """These tests run the assess service on stand-ins for its settings and database; the
    deterministic wave (Q-F3) is not theirs: the SIEM is not set up here."""

    async def none(*_: Any) -> None:
        return None

    monkeypatch.setattr(assess_cli, "_investigation", none)


def pinned_narrowing(tmp_path: Path, triggers: str) -> tuple[Path, Any, Any]:
    """A directory whose investigator takes only ``triggers``, as coordinator@4, with the
    pins and enabled versions that make it load."""
    d = copy(tmp_path / "agents")
    text = header(header(FILES["investigator"], "triggers", triggers), "version", "coordinator@4")
    (d / "investigator.md").write_text(text)
    got = loader.read(d / "investigator.md")
    pins = {**PINS, "investigator": {"coordinator@4": Pin(got.file_sha256, got.prompt_sha256,
                                                          "test")}}  # fmt: skip
    return d, pins, {**ENABLED, "investigator": "coordinator@4"}


def test_allows_follows_the_files_triggers(tmp_path: Path) -> None:
    assert loader.allows(Trigger.ENGINE_NO_DECISION)
    assert loader.allows(Trigger.PERSON_REQUEST)
    assert not loader.allows(Trigger.COORDINATOR_CONSULT)  # a specialist's, not the lead's
    d, pins, enabled = pinned_narrowing(tmp_path, "[engine_no_decision]")
    assert loader.allows(Trigger.ENGINE_NO_DECISION, d, pins=pins, enabled=enabled)
    assert not loader.allows(Trigger.PERSON_REQUEST, d, pins=pins, enabled=enabled)
    assert not loader.allows(Trigger.ENGINE_NO_DECISION, d)  # not pinned in code: refused
    assert not loader.allows(Trigger.ENGINE_NO_DECISION, tmp_path / "nowhere")


def test_a_refused_file_is_why_the_agent_is_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = copy(tmp_path / "agents")
    (d / "intel.md").write_text(header(FILES["intel"], "tier", "medium"))
    monkeypatch.setattr(loader, "DIRECTORY", d)
    agents, why = assess_cli._agents()
    assert agents is None
    assert type(why) is loader.AgentError
    assert str(why) == "intel.md: tier medium is above what code allows intel (small)"
    monkeypatch.setattr(loader, "DIRECTORY", loader.ROOT / "config" / "agents")
    agents, why = assess_cli._agents()
    assert (agents.coordinator.version, why) == ("coordinator@4", None)

    def broken(*a: Any, **kw: Any) -> Any:
        raise OSError(5, "Input/output error\r", "/x\udce9")  # a library's own text

    monkeypatch.setattr(loader, "load", broken)
    agents, why = assess_cli._agents()
    assert agents is None
    assert type(why) is loader.AgentError
    assert str(why) == "[Errno 5] Input/output error\\x0d: '/x\\udce9'"


class _Db:
    @contextlib.asynccontextmanager
    async def begin(self) -> AsyncIterator[Any]:
        yield object()

    async def dispose(self) -> None:
        return None


class _Learned:
    def fingerprint(self) -> str:
        return "f"


class _Investigator:
    name = "agent@1"

    def __init__(self, takes: bool) -> None:
        self._takes = takes

    def takes(self, trigger: Trigger) -> bool:
        assert trigger is Trigger.ENGINE_NO_DECISION
        return self._takes


SETTINGS = SimpleNamespace(
    cases=SimpleNamespace(suggest=True, offers_per_hour=30, retitle=False),
    history=SimpleNamespace(window=timedelta(days=5)),
    campaigns=SimpleNamespace(resolvers=()),
    notified=NotifiedSettings(),
    incident=SimpleNamespace(enabled=False, prose=False),  # AR7's pass, off here
    signins=SigninsSettings(),  # AR6's pass, off by default
    risk=SimpleNamespace(present=False, shown_per_day=10, reading=False),  # E5, Track 4: off
)  # all the pass reads of them


class StopError(Exception):
    """Ends the service's loop in a test."""


def seams(monkeypatch: pytest.MonkeyPatch, scheduled: list[str] | None = None) -> None:
    """The pass's newer steps, stood in for: AR2b's raising step does nothing, and the pattern
    picker (AR2) queues one run and says which assessor it was asked for."""

    async def raise_nothing(*a: Any, **kw: Any) -> raising.Done:
        return raising.Done()

    async def pick(conn: Any, privacy: Any, assessor: str, now: Any, **kw: Any) -> Any:
        if scheduled is not None:
            scheduled.append(assessor)
        return patterns.Scheduled(1 if scheduled is not None else 0, 0)

    async def no_close() -> None:
        return None

    async def prune_nothing(*a: Any, **kw: Any) -> list[str]:
        return []

    monkeypatch.setattr(assess_cli.raising, "run", raise_nothing)
    monkeypatch.setattr(assess_cli.patterns, "schedule", pick)
    monkeypatch.setattr(assess_cli, "_no_model", lambda: None)  # a provider has a key (D-298)
    monkeypatch.setattr(signins_run, "prune", prune_nothing)  # AR6's retention: not these tests'
    # AR3's outside lookups (D-165) are not part of what these tests are about
    monkeypatch.setattr(
        assess_cli.raising, "outside_for", lambda *a: (SimpleNamespace(view=None), None, no_close)
    )


@pytest.mark.parametrize("stray", ["investigator.md~", "investigator.md.orig", "README.md",
                                   "web.md as a directory"])  # fmt: skip
def test_a_refused_file_turns_the_agent_off_and_the_engine_keeps_running(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stray: str,
) -> None:
    """A stray file beside the agents (an editor's backup, a merge tool's .orig) refuses
    them: the agent is off, with one warning, while the decision engine and the weekly
    tuning keep running every pass; once the file is gone the agent starts at the next pass
    (found in review: `argus assess run --agent` exited 1 before the engine's first pass, and
    the unit's Restart=always looped on it)."""
    d = copy(tmp_path / "agents")
    if stray == "web.md as a directory":
        (d / "web.md").unlink()
        (d / "web.md").mkdir()
    else:
        (d / stray).write_text("backup\n")
    monkeypatch.setattr(loader, "DIRECTORY", d)
    ran: list[str] = []
    built: list[Any] = []
    passes = iter(range(5))

    async def learn(conn: Any) -> _Learned:
        return _Learned()

    async def zero(*a: Any, **kw: Any) -> int:
        return 0

    async def run_once(db: Any, assessor: Any, *a: Any) -> dict[str, int]:
        ran.append(getattr(assessor, "name", "engine@1"))
        return {}

    async def close() -> None:
        return None

    def agent(settings: Any, privacy: Any, db: Any, agents: Any, outside: Any = None) -> Any:
        built.append(agents)
        return _Investigator(True), close

    async def sleep(seconds: float) -> None:
        n = next(passes)
        ran.append(f"pass {n}")
        if n == 1:  # the file is fixed between the second and the third pass
            if stray == "web.md as a directory":
                (d / "web.md").rmdir()
                (d / "web.md").write_text(FILES["web"])
            else:
                (d / stray).unlink()
        if n == 3:
            raise StopError

    seams(monkeypatch)
    monkeypatch.setattr(assess_cli, "load", lambda config: SETTINGS)
    monkeypatch.setattr(assess_cli, "_privacy", lambda settings: object())
    monkeypatch.setattr(assess_cli, "_agent", agent)
    monkeypatch.setattr(assess_cli, "engine_for", lambda settings: _Db())
    monkeypatch.setattr(assess_cli.decision, "learn", learn)
    monkeypatch.setattr(assess_cli.queue, "requeue", zero)
    monkeypatch.setattr(assess_cli.runner, "schedule", zero)
    monkeypatch.setattr(assess_cli.runner, "run_once", run_once)
    monkeypatch.setattr(assess_cli.asyncio, "sleep", sleep)
    with pytest.raises(StopError):
        assess_cli.assess_run(once=False, agent=True, every=1, agent_per_day=5,
                              agent_batch=2, tuning=False, config=None)  # fmt: skip
    assert ran == ["engine@1", "pass 0", "engine@1", "pass 1", "engine@1", "agent@1", "pass 2",
                   "engine@1", "agent@1", "pass 3"]  # fmt: skip
    assert len(built) == 1  # built once
    assert built[0].coordinator.version == "coordinator@4"
    out = capsys.readouterr()
    assert out.out.splitlines()[1:4] == [
        "agent: off (its files are refused)", "queued 0 requeued 0",
        "agent: off (its files are refused)"]  # fmt: skip
    assert out.out.splitlines()[-1] == "agent: queued 0 patterns, shared 0"
    (warning, again) = out.err.splitlines()
    assert warning.startswith("warning: the investigation agent is off: ")
    assert warning.endswith(". The decision engine runs without it; what waits for the agent"
                            " stays queued.")  # fmt: skip
    assert again == "the investigation agent is on again: its files load"


def test_without_agent_the_files_are_never_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def never() -> Any:
        raise AssertionError("read the agent's files")

    async def learn(conn: Any) -> _Learned:
        return _Learned()

    async def zero(*a: Any, **kw: Any) -> int:
        return 0

    async def run_once(db: Any, assessor: Any, *a: Any) -> dict[str, int]:
        return {}

    seams(monkeypatch)
    monkeypatch.setattr(assess_cli, "load", lambda config: SETTINGS)
    monkeypatch.setattr(assess_cli, "_privacy", lambda settings: object())
    monkeypatch.setattr(assess_cli, "_agents", never)
    monkeypatch.setattr(assess_cli, "engine_for", lambda settings: _Db())
    monkeypatch.setattr(assess_cli.decision, "learn", learn)
    monkeypatch.setattr(assess_cli.queue, "requeue", zero)
    monkeypatch.setattr(assess_cli.runner, "schedule", zero)
    monkeypatch.setattr(assess_cli.runner, "run_once", run_once)
    assess_cli.assess_run(once=True, agent=False, every=1, agent_per_day=5, agent_batch=2,
                          tuning=False, config=None)  # fmt: skip


@pytest.mark.parametrize("takes", [True, False])
def test_the_service_queues_the_engines_undecided_only_when_the_file_takes_them(
    monkeypatch: pytest.MonkeyPatch, takes: bool
) -> None:
    scheduled: list[str] = []
    ran: list[str] = []

    async def learn(conn: Any) -> _Learned:
        return _Learned()

    async def requeue(*a: Any) -> int:
        return 0

    async def schedule(conn: Any, privacy: Any, assessor: str, now: Any, **kw: Any) -> int:
        scheduled.append(assessor)
        return 1

    async def run_once(db: Any, assessor: Any, *a: Any) -> dict[str, int]:
        ran.append(getattr(assessor, "name", "engine"))
        return {}

    async def close() -> None:
        return None

    monkeypatch.setattr(assess_cli, "load", lambda config: SETTINGS)
    monkeypatch.setattr(assess_cli, "_privacy", lambda settings: object())
    seams(monkeypatch, scheduled)  # the picker records the agent's turn after the engine's
    monkeypatch.setattr(assess_cli, "_agents", lambda: (object(), None))
    monkeypatch.setattr(assess_cli, "_agent", lambda *a: (_Investigator(takes), close))
    monkeypatch.setattr(assess_cli, "engine_for", lambda settings: _Db())
    monkeypatch.setattr(assess_cli.decision, "learn", learn)
    monkeypatch.setattr(assess_cli.queue, "requeue", requeue)
    monkeypatch.setattr(assess_cli.runner, "schedule", schedule)
    monkeypatch.setattr(assess_cli.runner, "run_once", run_once)
    assess_cli.assess_run(once=True, agent=True, every=1, agent_per_day=5, agent_batch=2,
                          tuning=False, config=None)  # fmt: skip
    assert scheduled == ["engine@1", *(["agent@1"] if takes else [])]
    assert "agent@1" in ran  # what is already queued (a person's request) still runs


async def test_the_queue_itself_refuses_a_persons_request_the_file_does_not_take(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Whatever route a person's request comes by (the Inbox today, /api/v1 tomorrow), the
    queue refuses it for agent@1 when its file does not take person_request (found in
    review, Q-H1); other assessors are not the agent's file's to decide."""
    from argus.assess import runner

    seen: list[str] = []

    class Conn:
        async def execute(self, *a: Any, **kw: Any) -> Any:
            seen.append("read")
            raise AssertionError("nothing is read for a refused request")

    monkeypatch.setattr(loader, "allows", lambda trigger, *a, **kw: False)
    got = await runner.request(Conn(), None, None, "agent@1", None)  # type: ignore[arg-type]
    assert got == "refused"
    assert seen == []
    with pytest.raises(AssertionError, match="nothing is read"):
        await runner.request(Conn(), None, None, "engine@1", None)  # type: ignore[arg-type]


def test_the_health_pages_view_of_the_investigator(monkeypatch: pytest.MonkeyPatch) -> None:
    from argus.web import app

    assert app._investigator_state() == {
        "ready": True,
        "state": "ready",
        "detail": "investigator coordinator@4; web, proxy specialist@1; intel specialist@2",
    }

    def broken(*a: Any, **kw: Any) -> Any:
        raise PermissionError(13, "Permission denied\r", "/x\udce9\r")

    monkeypatch.setattr(loader, "load", broken)
    assert app._investigator_state() == {
        "ready": False, "state": "refused",
        "detail": "[Errno 13] Permission denied\\x0d: '/x\\udce9\\r'",
    }  # fmt: skip

    def off(*a: Any, **kw: Any) -> Any:
        raise loader.AgentOffError("web.md: holds specialist@1, but web is off")

    monkeypatch.setattr(loader, "load", off)
    assert app._investigator_state() == {
        "ready": False, "state": "off", "detail": "web.md: holds specialist@1, but web is off"
    }  # fmt: skip


def test_the_service_says_when_the_agent_is_switched_off_in_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R2 (second review): an agent switched off in code is not a file to fix; each pass
    says which kind of off it is, as the health page does."""

    async def learn(conn: Any) -> _Learned:
        return _Learned()

    async def zero(*a: Any, **kw: Any) -> int:
        return 0

    async def run_once(db: Any, assessor: Any, *a: Any) -> dict[str, int]:
        return {}

    real = loader.load
    monkeypatch.setattr(loader, "load", lambda directory=None, **kw: real(
        directory, enabled={**ENABLED, "investigator": None}))  # fmt: skip
    seams(monkeypatch)
    monkeypatch.setattr(assess_cli, "load", lambda config: SETTINGS)
    monkeypatch.setattr(assess_cli, "_privacy", lambda settings: object())
    monkeypatch.setattr(assess_cli, "engine_for", lambda settings: _Db())
    monkeypatch.setattr(assess_cli.decision, "learn", learn)
    monkeypatch.setattr(assess_cli.queue, "requeue", zero)
    monkeypatch.setattr(assess_cli.runner, "schedule", zero)
    monkeypatch.setattr(assess_cli.runner, "run_once", run_once)
    assess_cli.assess_run(once=True, agent=True, every=1, agent_per_day=5, agent_batch=2,
                          tuning=False, config=None)  # fmt: skip
    out = capsys.readouterr()
    assert out.out.splitlines()[-1] == "agent: off (switched off in code)"
    assert out.err == (
        "warning: the investigation agent is off: investigator.md: holds coordinator@4, but"
        " investigator is off (argus.agent.registry.ENABLED). The decision engine runs"
        " without it; what waits for the agent stays queued.\n"
    )


def test_without_a_model_key_the_agent_is_off_and_its_work_stays_queued(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D-298: no keys file (or no enabled provider with a key): the agent is never built, the
    patterns are not handed to it, and the engine runs every pass."""
    monkeypatch.setattr(loader, "DIRECTORY", copy(tmp_path / "agents"))
    ran: list[str] = []
    scheduled: list[str] = []
    passes = iter(range(3))

    async def learn(conn: Any) -> _Learned:
        return _Learned()

    async def zero(*a: Any, **kw: Any) -> int:
        return 0

    async def run_once(db: Any, assessor: Any, *a: Any) -> dict[str, int]:
        ran.append(getattr(assessor, "name", "engine@1"))
        return {}

    def agent(*a: Any, **kw: Any) -> Any:
        raise AssertionError("no agent is built without a model key")

    async def sleep(seconds: float) -> None:
        if next(passes) == 1:
            raise StopError

    seams(monkeypatch, scheduled)
    monkeypatch.setattr(assess_cli, "_no_model", lambda: "no model key (llm keys_file: none)")
    monkeypatch.setattr(assess_cli, "load", lambda config: SETTINGS)
    monkeypatch.setattr(assess_cli, "_privacy", lambda settings: object())
    monkeypatch.setattr(assess_cli, "_agent", agent)
    monkeypatch.setattr(assess_cli, "engine_for", lambda settings: _Db())
    monkeypatch.setattr(assess_cli.decision, "learn", learn)
    monkeypatch.setattr(assess_cli.queue, "requeue", zero)
    monkeypatch.setattr(assess_cli.runner, "schedule", zero)
    monkeypatch.setattr(assess_cli.runner, "run_once", run_once)
    monkeypatch.setattr(assess_cli.asyncio, "sleep", sleep)
    with pytest.raises(StopError):
        assess_cli.assess_run(once=False, agent=True, every=1, agent_per_day=5,
                              agent_batch=2, tuning=False, config=None)  # fmt: skip
    assert ran == ["engine@1", "engine@1"]
    assert scheduled == []  # nothing handed to an agent that cannot answer
    out = capsys.readouterr()
    assert out.out.count("agent: off (no model key)") == 2
    assert out.err.count("the investigation agent is off: no model key") == 1  # said once
