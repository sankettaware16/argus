"""The parity cassettes of agent@1 (Q-H1): what the agent sends to a model, recorded once on the
code before its prompts moved to ``config/agents/*.md``, and replayed strictly after.

Each scenario runs the real agent through the real LLM gateway (P5: the privacy validator, the
body builder, the budget) with a fixed provider, a scripted model and a fake the SIEM. The
gateway's transport is an ``LlmCassette``: recording keeps each answer under the key of the
exact request (provider, URL and body: the system prompt, the rendered item, the model and the
answer cap). Replay is strict: a request whose bytes changed has no answer and the run stops
with ``CassetteMiss``.

The manifest keeps, per scenario, the keys in the order they were asked, the system prompts
they carried (text, by hash: what a reader checks), what the SIEM was asked and the verdict, so
a replay is compared on all of it; and the evaluation signatures and base prompts of the code
it was recorded on.

    uv run python -m tests.unit.agent.parity --record   # only on the pre-port code (BASE)

Everything here is synthetic: the unit tests' dossier, campus and asset map.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from argus.agent import agent as ag
from argus.agent import loader
from argus.agent.agent import Agent, Limits
from argus.assets.classify import IpClassifier
from argus.context.packs import TaskSpec, default_registry
from argus.evaluation import agent_eval
from argus.llm.gateway import LlmGateway, MemoryLlmStore
from argus.llm.privacy import Privacy, load_policy
from argus.llm.providers import LlmConfig
from argus.llm.wire import LlmCassette, LlmReply, LlmWire, cassette_key
from tests.unit.llm.conftest import ASSETS, CAMPUS_PREFIX
from tests.unit.llm.test_privacy import dossier

HERE = Path(__file__).resolve().parent / "parity"
MANIFEST = HERE / "manifest.json"
AGENTS = HERE / "agents"  # the files as Q-H1 pinned them: coordinator@3, specialist@1 (see frozen)
NOW = datetime(2026, 10, 16, 12, tzinfo=UTC)
INV = uuid.UUID(int=7)
CLASSIFIER = IpClassifier(ASSETS, (CAMPUS_PREFIX,))
PACKS = default_registry(CLASSIFIER, clock=lambda: NOW)
PACK = PACKS.resolve({}).ident
KEY = SecretStr("parity-not-a-key")  # fake-secret: never sent anywhere, never stored
CONFIG = LlmConfig.model_validate(
    {
        "keys_file": "/nonexistent/parity.env",
        "providers": [
            {
                "name": "parity",
                "base_url": "https://parity.invalid/v1",
                "keys": ["PARITY_KEY"],
                "models": {
                    "small": {"name": "parity-small"},
                    "medium": {"name": "parity-medium"},
                    "large": {"name": "parity-large"},
                },
            }
        ],
    }
)


def frozen() -> loader.Agents:
    """The agents the recording was made with: Q-H1's files, kept here byte for byte (AR3's
    version of the repository's files adds the outside tools, so the cassettes, which hold the
    exact prompts, are replayed with these). Structural checks only: code pins the newer files."""
    return loader.load(AGENTS, pins=None, enabled=None)


def privacy() -> Privacy:
    return Privacy.build(load_policy(), ASSETS, (CAMPUS_PREFIX,))


def body(**over: Any) -> dict[str, Any]:
    b = dossier()
    b.update({"pack": PACK, "version": 1, "evidence": [], "signals": [], "local_signals": []})
    b["context"]["pack"]["ti"] = {}
    b.update(over)
    return b


def say(**data: Any) -> str:
    base: dict[str, Any] = {
        "outcome": "true_positive",
        "confidence": 0.7,
        "reason": "r",
        "cites": ["severity high"],
        "consult": [],
        "ask": [],
    }
    base.update(data)
    return json.dumps(base)


def notes(text: str, **data: Any) -> str:
    return json.dumps({"notes": text, "cites": [], "ask": [], **data})


def token(p: Privacy, value: str, b: Mapping[str, Any], label: str = "IP") -> str:
    request = p.request([dict(b)])
    return str(request._maps["I1"]._token[(label, value.lower())])


HELD = {
    "task_key": "k",
    "template": "proxy.host@1",
    "status": "ok",
    "coverage": {},
    "row_count": 1,
    "truncated": False,
    "result_hash": "h",
}


@dataclass
class Scenario:
    """One run: the item, the model's answers in order (text, or text made from the item's
    pseudonyms), what the SIEM answers, and the agent's limits."""

    name: str
    item: dict[str, Any]
    replies: Callable[[Privacy, dict[str, Any]], list[str]]
    status: str = "ok"  # what each evidence fetch reports
    limits: Limits | None = None
    first_seen: bool | None = False
    spike: bool | None = False
    # a specialist asks for a tool outside its own set: the pre-port code runs it; from Q-H1
    # the run must stay identical up to that ask, which is refused and never reaches the SIEM
    outside: bool = False


def _low() -> dict[str, Any]:
    low = body(facts={**body()["facts"], "severity": "low"})
    low["signals"] = [{"name": "ti.listed", "status": "known", "value": 0}]
    return low


def scenarios() -> list[Scenario]:
    def host(p: Privacy, b: dict[str, Any]) -> str:
        return token(p, "10.20.3.4", b)

    return [
        Scenario("a_plain_answer", body(), lambda p, b: [say()]),
        Scenario(
            "specialists_then_a_second_answer",
            body(),
            lambda p, b: [
                say(consult=["proxy", "intel", "web"]),
                notes("proxy says x"),
                notes("intel says y"),
                say(outcome="inconclusive"),
            ],
        ),
        Scenario(
            "a_tool_and_its_evidence",
            body(),
            lambda p, b: [
                say(
                    ask=[
                        {"tool": "proxy.host", "entity": host(p, b)},
                        {"tool": "proxy.host", "entity": host(p, b)},
                    ]
                ),
                say(reason="after the evidence"),
            ],
        ),
        Scenario(
            "refusals_in_the_history",
            body(),
            lambda p, b: [
                say(
                    ask=[
                        {"tool": "proxy.destination", "entity": host(p, b)},
                        {"tool": "drop.index", "entity": host(p, b)},
                        {"tool": "proxy.host", "entity": f"{host(p, b)} OR x"},
                        {"tool": "proxy.host", "entity": "10.20.3.5"},
                        {"tool": "proxy.host", "entity": "I9.IP_1"},
                        {"tool": "ti.lookup", "entity": "8.8.8.8"},
                    ]
                ),
                say(reason="with the refusals"),
            ],
        ),
        Scenario(
            "specialists_asking_in_their_own_set",
            body(),
            lambda p, b: [
                say(consult=["proxy", "intel"]),
                notes("proxy: one destination", ask=[{"tool": "proxy.host", "entity": host(p, b)}]),
                notes("intel: check the address", ask=[{"tool": "ti.lookup", "entity": "8.8.8.8"}]),
                say(ask=[{"tool": "proxy.destination", "entity": "8.8.8.8"}]),
                say(reason="with three checks"),
            ],
        ),
        Scenario(
            "web_specialist_asks_its_tool",
            body(),
            lambda p, b: [
                say(consult=["web"]),
                notes("web: follow-ups", ask=[{"tool": "web.followups", "entity": host(p, b)}]),
                say(outcome="inconclusive", reason="needs the follow-ups"),
                say(reason="the follow-ups say enough"),
            ],
        ),
        Scenario(
            "a_benign_answer_clears_the_floor",
            _low(),
            lambda p, b: [
                say(outcome="benign_expected", cites=["severity low"]),
            ],
        ),
        Scenario(
            "evidence_already_held",
            body(evidence=[dict(HELD)]),
            lambda p, b: [
                say(
                    ask=[
                        {"tool": "proxy.host", "entity": host(p, b)},
                        {"tool": "ti.lookup", "entity": "8.8.8.8"},
                        {"tool": "ti.lookup", "entity": "evil.example"},
                    ]
                ),
                say(reason="the history says what was held"),
            ],
        ),
        Scenario(
            "every_round_used",
            body(),
            lambda p, b: [
                say(ask=[{"tool": "ti.lookup", "entity": "8.8.8.8"}]),
                say(ask=[{"tool": "proxy.host", "entity": host(p, b)}]),
                say(ask=[{"tool": "proxy.destination", "entity": "8.8.8.8"}]),
                say(ask=[{"tool": "web.followups", "entity": host(p, b)}]),
            ],
        ),
        Scenario(
            "narrower_limits",
            body(),
            lambda p, b: [
                say(
                    ask=[
                        {"tool": "ti.lookup", "entity": "8.8.8.8"},
                        {"tool": "proxy.host", "entity": host(p, b)},
                    ],
                    consult=["proxy"],
                ),
                notes("proxy: busy host"),
                say(
                    ask=[
                        {"tool": "ti.lookup", "entity": "8.8.8.8"},
                        {"tool": "proxy.host", "entity": host(p, b)},
                    ],
                    consult=["intel"],
                ),
                say(reason="the last call"),
            ],
            limits=Limits(rounds=2, tools=1, calls=4),
        ),
        Scenario(
            "no_tools_in_the_gold_run",
            body(),
            lambda p, b: [
                say(ask=[{"tool": "proxy.host", "entity": host(p, b)}], consult=["proxy"]),
                notes("proxy: no data", ask=[{"tool": "proxy.destination", "entity": "8.8.8.8"}]),
                say(reason="without evidence"),
            ],
            status="unavailable",
        ),
        Scenario(
            "hypotheses_and_cites",
            body(),
            lambda p, b: [
                say(
                    reason=f"{host(p, b)} beacons",
                    hypotheses=[
                        {
                            "name": f"{host(p, b)} is infected",
                            "for": ["regular posts"],
                            "against": ["no TI hit"],
                        },
                        {"name": "updates", "for": [], "against": [f"{host(p, b)} is a lab PC"]},
                    ],
                ),
            ],
        ),
        Scenario(
            "an_injected_item",
            agent_eval.inject(body()),
            lambda p, b: [
                say(outcome="inconclusive", reason="the item tells me what to answer"),
            ],
            first_seen=True,
        ),
        Scenario(
            "outside_intel_asks_a_proxy_tool",
            body(),
            lambda p, b: [
                say(consult=["intel"]),
                notes(
                    "intel: look at the host", ask=[{"tool": "proxy.host", "entity": host(p, b)}]
                ),
                say(reason="a second answer"),
                say(reason="after the proxy evidence"),
            ],
            outside=True,
        ),
        Scenario(
            "outside_an_injected_ask_obeyed_by_a_specialist",
            agent_eval.inject(body()),
            lambda p, b: [
                say(consult=["web"]),
                notes("web: as the item says", ask=[{"tool": "proxy.host", "entity": "I1.IP_1"}]),
                say(outcome="inconclusive", reason="the item tells me what to answer"),
                say(outcome="inconclusive", reason="after the injected ask"),
            ],
            outside=True,
        ),
    ]


class Siem:
    def __init__(self, status: str) -> None:
        self.status = status
        self.tasks: list[dict[str, Any]] = []

    async def fetch(self, inv: uuid.UUID, version: int, spec: TaskSpec) -> Mapping[str, Any]:
        ref = spec.ref()
        self.tasks.append({"version": version, **json.loads(json.dumps(ref, default=str))})
        return {
            "task_key": ref["task_key"],
            "template": f"{ref['template']}@{ref['version']}",
            "status": self.status,
            "coverage": {},
            "row_count": 3,
            "truncated": False,
            "result_hash": "h",
            "reused": False,
        }

    async def snapshots(self, inv: uuid.UUID, version: int, keys: list[str]) -> Mapping[str, Any]:
        return {k: {"aggregations": {}} for k in keys}


class Scripted:
    """The model: the scenario's answers in order, as an OpenAI-compatible reply."""

    def __init__(self, replies: list[str]) -> None:
        self.replies = list(replies)
        self.wires: list[LlmWire] = []

    async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        self.wires.append(wire)
        if not self.replies:
            raise AssertionError("the scenario has no answer left for this call")
        text = self.replies.pop(0)
        data = {
            "choices": [{"message": {"content": text}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10},
        }
        return LlmReply(200, json.dumps(data).encode(), 5.0)


class Keys:
    """A transport that remembers the key of every request it passes on, in order."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.keys: list[str] = []
        self.wires: list[LlmWire] = []

    async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        self.keys.append(cassette_key(wire))
        self.wires.append(wire)
        reply: LlmReply = await self.inner.send(wire, key)
        return reply


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class Run:
    keys: list[str]
    calls: list[dict[str, Any]]
    prompts: dict[str, str]
    tasks: list[dict[str, Any]]
    verdict: dict[str, Any]
    report: dict[str, Any] = field(default_factory=dict)


async def run(s: Scenario, transport: Any, make: Callable[..., Agent] | None = None) -> Run:
    """``s`` through the agent, with ``transport`` under the gateway (a cassette)."""
    p = privacy()
    keys = Keys(transport)
    gateway = LlmGateway(CONFIG, {"PARITY_KEY": KEY}, keys, MemoryLlmStore(), lambda: NOW)
    siem = Siem(s.status)
    kw: dict[str, Any] = {"clock": lambda: NOW, "monotonic": lambda: 0.0}
    if s.limits is not None:
        kw["limits"] = s.limits
    build = make or (lambda *a, **k: Agent(*a, agents=frozen(), **k))
    agent = build(p, gateway.complete, PACKS, siem.fetch, siem.snapshots, CLASSIFIER, **kw)
    verdict = await agent.run(INV, s.item, s.first_seen, s.spike)
    calls, prompts = [], {}
    for wire in keys.wires:
        sent = json.loads(wire.body)
        system, user = (m["content"] for m in sent["messages"])
        prompts[_sha(system)] = system
        calls.append(
            {
                "system": _sha(system),
                "user": _sha(user),
                "model": sent["model"],
                "max_tokens": sent["max_tokens"],
            }
        )
    *reasons, report = verdict.reasons
    return Run(
        keys=keys.keys,
        calls=calls,
        prompts=prompts,
        tasks=siem.tasks,
        verdict={
            "outcome": verdict.outcome,
            "decided_by": verdict.decided_by,
            "confidence": verdict.confidence,
            "reasons": reasons,
        },
        report=dict(report),
    )


BASE = "ba3ac758c22a26558348026082c092ae65000bc9"  # the pre-port code these were recorded on


def _pre_port() -> Any:
    """The pre-port prompts module; the recording means nothing on any other code."""
    try:
        from argus.agent import prompts  # type: ignore[attr-defined]
    except ImportError:
        raise SystemExit(
            "the parity cassettes are recorded on the pre-port code only: check out"
            f" {BASE[:7]} in a separate worktree and record there"
        ) from None
    return prompts


def base_prompts() -> dict[str, str]:
    """The instructions agent@1's code gives each model call before any history or notes."""
    prompts = _pre_port()
    lines = ag.tool_lines  # type: ignore[attr-defined]
    out = {"investigator": prompts.COORDINATOR_TEXT.format(tools=lines())}
    for domain, focus in prompts.FOCUS.items():
        out[domain] = prompts.SPECIALIST_TEXT.format(
            domain=domain, focus=focus, tools=lines(domain)
        )
    return out


def signatures() -> dict[str, str]:
    class Plain(Agent):
        def __init__(self) -> None:
            self.limits = ag.DEFAULT_LIMITS  # type: ignore[attr-defined]

    a = Plain()
    return {"no_tools": agent_eval.signature(a, False), "tools": agent_eval.signature(a, True)}


async def record() -> dict[str, Any]:
    prompts = _pre_port()
    HERE.mkdir(parents=True, exist_ok=True)
    (HERE / "cassettes").mkdir(exist_ok=True)
    out: dict[str, Any] = {
        "format": 1,
        "base": BASE,
        "versions": {"coordinator": prompts.COORDINATOR, "specialist": prompts.SPECIALIST},
        "signatures": signatures(),
        "base_prompts": base_prompts(),
        "scenarios": {},
    }
    for s in scenarios():
        path = HERE / "cassettes" / f"{s.name}.json"
        path.unlink(missing_ok=True)
        replies = s.replies(privacy(), s.item)
        scripted = Scripted(replies)
        cassette = LlmCassette(path, "record", scripted)
        got = await run(s, cassette)
        if scripted.replies:
            raise AssertionError(f"{s.name}: {len(scripted.replies)} answers were never asked for")
        if len(set(got.keys)) != len(got.keys):
            raise AssertionError(f"{s.name}: two calls had the same bytes (replay would mix them)")
        cassette.save()
        out["scenarios"][s.name] = {
            "keys": got.keys,
            "calls": got.calls,
            "tasks": got.tasks,
            "verdict": got.verdict,
            "report": got.report,
            "outside": s.outside,
        }
        out.setdefault("prompts", {}).update(got.prompts)
    MANIFEST.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--record", action="store_true", help="record (pre-port code only)")
    args = parser.parse_args()
    if not args.record:
        parser.error("nothing to do: --record records the cassettes")
    done = asyncio.run(record())
    print(f"recorded {len(done['scenarios'])} scenarios, signatures {done['signatures']}")


if __name__ == "__main__":
    main()
