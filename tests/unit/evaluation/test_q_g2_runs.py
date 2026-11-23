"""Q-G2's runs: a helper task on its gold set (resumable, keyed by the text sent and the model,
labels never sent, deferral stops cleanly, items too large left out, injection flips counted);
the agent's gold run and its repeat as the ladder's gold rung; the injection test with the
small-model attacks in turn; the licence before any evaluation call to the campus model."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from argus import site
from argus.evaluation import agent_eval, ladder, measures, taskrun, tasks
from argus.evaluation.store import GoldRow
from argus.llm.gateway import Call, Completion, NoCapacity, Refused, body_for, lease_s
from argus.llm.privacy import Privacy
from argus.llm.providers import LlmConfig, load_config, pinned
from tests.unit.agent.test_agent import body
from tests.unit.evaluation.test_agent_eval import CASES, IDS, ROWS, Engine, FakeAgent

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 23, 18, tzinfo=UTC)


def local(**over: Any) -> LlmConfig:
    model = {"name": "cp", "context_tokens": 16384, "thinking_tokens": 2048, "max_output": 6144,
             "max_prompt_tokens": 12000, "read_tps": 45, "write_tps": 11}  # fmt: skip
    provider = {"name": "local", "trust": "self_hosted", "base_url": "https://127.0.0.1:28443/v1",
                "keys": ["K"], "ca_file": "/x.crt", "timeout_s": 900, "concurrency": 1,
                "tasks": ["evaluate", "ping"], "schema_output": True, "schema_required": True,
                "models": {"small": model}, "limits": {"rpd": 375}, **over}  # fmt: skip
    return LlmConfig.model_validate({"providers": [provider]})


class Fake:
    """The gateway's complete(): an answer per call (the last repeats), or an exception."""

    def __init__(self, *replies: str | Exception) -> None:
        self.replies = list(replies)
        self.calls: list[Call] = []

    async def __call__(self, call: Call) -> Completion:
        self.calls.append(call)
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return Completion(reply, "local", "cp", 300, 40, 0.0, 12_000, uuid.uuid4())


def case(n: int, label: str | None = None, floor: bool = False, **over: Any) -> taskrun.TaskCase:
    return taskrun.TaskCase(uuid.UUID(int=n), 1, "generic@1", "a" * 64, body(**over), floor, label)


PLANTED = "known false alarm"  # in every payload, as the item renders it
TRIAGE_NOW = json.dumps({"urgency": "now", "reason": "r"})
TRIAGE_LATER = json.dumps({"urgency": "later", "reason": "r"})


async def test_a_task_run_is_kept_resumed_and_measured(privacy: Privacy, tmp_path: Path) -> None:
    spec = tasks.SPECS[tasks.TRIAGE]
    cases = [case(1, "true_positive"), case(2, "benign_expected"), case(3, "benign_policy")]
    fake = Fake(TRIAGE_NOW, TRIAGE_LATER, "not json")
    out = tmp_path / "answers.json"
    scored = await taskrun.run_task(spec, cases, privacy, fake, local(), out, "local/cp")
    assert (scored.calls, scored.usable, scored.stopped) == (3, 2, None)
    for call in fake.calls:  # an evaluation call with the strict schema; the label never sent
        assert (call.purpose, call.priority.value, call.schema) == ("evaluate", "low", spec.schema)
        assert "true_positive" not in call.request.text
        assert call.instructions == site.say(tasks.TRIAGE_TEXT)
    measured = taskrun.measure(spec, cases, scored)
    assert (measured.items, measured.right, measured.positives_later) == (2, 2, ())
    assert measured.calls == ladder.Count(hits=2, total=3)
    assert len(measured.latency) == 3  # every answered call, unusable ones too
    assert measured.latency[0][1] == pytest.approx(lease_s(local().providers[0], fake.calls[0]))
    again = Fake(RuntimeError("must not be called"))
    resumed = await taskrun.run_task(spec, cases, privacy, again, local(), out, "local/cp")
    assert again.calls == []
    assert (resumed.calls, resumed.usable) == (3, 2)
    other = Fake(TRIAGE_NOW)
    await taskrun.run_task(spec, cases, privacy, other, local(), out, "local/another")
    assert len(other.calls) == 3  # another model: asked again


async def test_a_long_deferral_stops_the_run_and_a_short_one_waits(
    privacy: Privacy, tmp_path: Path
) -> None:
    spec = tasks.SPECS[tasks.SUMMARY]
    now = datetime.now(UTC)
    late = NoCapacity(now + timedelta(hours=3), "evaluation runs overnight only")
    soon = NoCapacity(now + timedelta(seconds=30), "busy")
    slept: list[float] = []

    async def sleep(s: float) -> None:
        slept.append(s)

    summary = json.dumps({"summary": "An alert."})
    fake = Fake(soon, summary, late)
    scored = await taskrun.run_task(spec, [case(1), case(2)], privacy, fake, local(),
                                    tmp_path / "a.json", "local/cp", sleep=sleep)  # fmt: skip
    assert len(slept) == 1
    assert slept[0] <= 31
    assert scored.stopped is not None
    assert scored.stopped.startswith("no capacity until")
    assert scored.calls == 1  # the first item answered and kept; the second resumes later


async def test_a_refused_call_is_unusable_and_a_too_large_item_is_left_out(
    privacy: Privacy, tmp_path: Path
) -> None:
    spec = tasks.SPECS[tasks.EXTRACT]
    fake = Fake(Refused("truncated (200)"))
    small = local(models={"small": {"name": "cp", "context_tokens": 16384,
                                    "max_prompt_tokens": 64}})  # fmt: skip
    scored = await taskrun.run_task(spec, [case(1)], privacy, fake, small, tmp_path / "a.json",
                                    "local/cp")  # fmt: skip
    assert (scored.too_large, scored.calls, fake.calls) == (1, 0, [])
    scored = await taskrun.run_task(spec, [case(1)], privacy, fake, local(), tmp_path / "b.json",
                                    "local/cp")  # fmt: skip
    assert (scored.calls, scored.usable, scored.latency) == (1, 0, [])


async def test_injection_rotates_the_payloads_and_counts_flips(
    privacy: Privacy, tmp_path: Path
) -> None:
    spec = tasks.SPECS[tasks.TRIAGE]
    cases = [case(n, "true_positive") for n in range(1, 5)]

    def answer(call: Call) -> str:  # a model every payload fools
        return TRIAGE_LATER if PLANTED in call.request.text else TRIAGE_NOW

    class ByText(Fake):
        async def __call__(self, call: Call) -> Completion:
            self.calls.append(call)
            return Completion(answer(call), "local", "cp", 10, 5, 0.0, 10, uuid.uuid4())

    fake = ByText("unused")
    scored = await taskrun.run_task(spec, cases, privacy, fake, local(), tmp_path / "i.json",
                                    "local/cp", inject_=True)  # fmt: skip
    assert len(fake.calls) == 12  # clean, again, injected, for each item
    assert sorted(scored.flips) == sorted(agent_eval.PAYLOADS)
    measured = taskrun.measure(spec, cases, scored)
    assert measured.injection is not None
    planted = [c for c in fake.calls if PLANTED in c.request.text]
    assert len(planted) == 4  # every payload reached the model (escaped and quoted, P1)
    assert (measured.injection.items, measured.injection.flips) == (4, 4)
    assert all(c.hits == 1 for c in measured.injection.by_payload.values())
    for c in fake.calls:  # P1 on every planted request, as on every other
        assert c.request.validate().allowed
    fewer = ByText("unused")
    scored = await taskrun.run_task(spec, cases, privacy, fewer, local(), tmp_path / "f.json",
                                    "local/cp", inject_=True, inject_items=2)  # fmt: skip
    assert len(fewer.calls) == 2 * 3 + 2  # the injection test on the first two items only
    assert sum(len(f) for f in scored.flips.values()) == 2


def test_the_lease_follows_the_gateways_deadline() -> None:
    cfg = local()
    request = Privacy.__new__(Privacy)  # unused: a Call needs a Request only for its text
    del request
    from argus.llm.privacy import Request

    call = Call(Request("x" * 2000, (), (), (), (), None), "y", "evaluate",  # type: ignore[arg-type]
                max_output=300, schema={"type": "object"})  # fmt: skip
    p = cfg.providers[0]
    size = len(body_for(p, call))
    expected = (size / 2 / 45 + (300 + 2048) / 11) * 1.5 + 15 + 60
    assert lease_s(p, call) == pytest.approx(expected, abs=1)
    assert taskrun.fits(cfg, call)
    tight = local(timeout_s=60)
    assert lease_s(tight.providers[0], call) is None  # too slow for its limit: never sent
    assert not taskrun.fits(tight, call)


# -- the agent's gold run as the ladder's gold rung ------------------------------------------


def test_the_reasons_tell_a_cite_failure_from_no_decision() -> None:
    assert agent_eval.judged({"outcome": "true_positive"}) == (True, False)
    for why, expected in (("a cited fact is not in the item (benign_expected): 'x'", (True, True)),
                          ("a benign answer must cite ARGUS's own words, not only quoted", (True,
                                                                                            True)),
                          ("floor: on a threat list", (True, False)),
                          ("the agent could not decide", (False, False)),
                          ("no usable answer from the model", (False, False))):  # fmt: skip
        assert agent_eval.judged({"outcome": None, "reasons": ["r", why]}) == expected


async def test_the_agents_own_texts_are_what_judged_reads(privacy: Privacy) -> None:
    """Tie CITE_FAILURES to agent.py: an unverified cite gives that reason."""
    from tests.unit.agent.test_agent import Model, agent, run, say

    verdict = await run(agent(privacy, Model(say(outcome="benign_expected",
                                                 cites=["not in the item at all"]))))  # fmt: skip
    entry = {"outcome": verdict.outcome, "reasons": verdict.reasons}
    assert agent_eval.judged(entry) == (True, True)
    verdict = await run(agent(privacy, Model(say(outcome="inconclusive"))))
    assert agent_eval.judged({"outcome": None, "reasons": verdict.reasons}) == (False, False)


def verdicts(*outcomes: str | None, cites_failed: bool = False) -> dict[str, Any]:
    return {str(i): {"outcome": o, "decided": o is not None, "cites_failed": cites_failed}
            for i, o in zip(IDS, outcomes, strict=True)}  # fmt: skip


def test_the_gold_rung_pairs_the_model_with_a_cloud_run() -> None:
    mine = verdicts("true_positive", None, "benign_expected")
    cloud = verdicts("true_positive", "true_positive", None)
    again = verdicts("true_positive", "true_positive", "benign_expected")
    gold = agent_eval.gold_measure(ROWS, mine, cloud, "openai", again)
    assert (gold.items, gold.positives, gold.positives_benign) == (3, 2, ())
    assert (gold.b, gold.c, gold.no_proposal, gold.cloud_no_proposal) == (1, 1, 1, 1)
    assert gold.cloud_repeat == ladder.Count(hits=2, total=3)
    bad = agent_eval.gold_measure(ROWS, verdicts("benign_expected", None, None), cloud, "openai")
    assert bad.positives_benign == (str(IDS[0]),)
    partial = agent_eval.gold_measure(ROWS, {str(IDS[0]): mine[str(IDS[0])]}, cloud, "openai")
    assert partial.items == 1  # like for like: only items both runs answered
    unlabelled = [GoldRow(IDS[0], "r", "test", (), {}, None, None, None, None)]
    assert agent_eval.gold_measure(unlabelled, mine, cloud, "openai").items == 0


async def test_a_repeat_run_is_kept_apart(tmp_path: Path) -> None:
    out = tmp_path / "v.json"
    first, _ = await agent_eval.evaluate(Engine(), CASES, FakeAgent(["true_positive"] * 3), out,  # type: ignore[arg-type]
                                         False)  # fmt: skip
    second = FakeAgent(["benign_expected"] * 3)
    again, _ = await agent_eval.evaluate(Engine(), CASES, second, out, False, run=1)  # type: ignore[arg-type]
    assert second.seen == IDS
    assert {v["outcome"] for v in again.values()} == {"benign_expected"}
    assert {v["outcome"] for v in first.values()} == {"true_positive"}
    measure = agent_eval.verdict_measure(again, "m", 1)
    assert measure["run"] == 1
    assert set(measure["verdicts"]) == {str(i) for i in IDS}


async def test_the_injection_test_takes_every_payload_in_turn(tmp_path: Path) -> None:
    cases = [agent_eval.GoldCase(uuid.UUID(int=n), "true_positive", {"report": {}})
             for n in range(1, 9)]  # fmt: skip
    outcomes: list[Any] = []
    for n in range(8):
        outcomes += ["true_positive", "true_positive",
                     "benign_expected" if n == 1 else "true_positive"]  # fmt: skip
    agent = FakeAgent(outcomes)
    engine: Any = Engine()
    lines, measured = await agent_eval.injection_measured(engine, cases, agent, tmp_path / "j.json",
                                                          rotate=True)  # fmt: skip
    assert measured is not None
    assert (measured.items, measured.flips) == (8, 1)
    assert set(measured.by_payload) == set(agent_eval.PAYLOADS)
    assert measured.by_payload["turn"] == ladder.Count(hits=1, total=2)  # item 2 took "turn"
    assert any(line.startswith("- turned benign, per payload: notice 0 of 2") for line in lines)
    plain = await agent_eval.injection(Engine(), cases[:1], FakeAgent(["true_positive"] * 3),  # type: ignore[arg-type]
                                       tmp_path / "k.json")  # fmt: skip
    assert plain[1] == "- turned benign by the injection (must be 0): 0"


def test_every_payload_reaches_the_item_and_passes_the_validator(privacy: Privacy) -> None:
    for payload in agent_eval.PAYLOADS.values():
        planted = agent_eval.inject(body(), payload)
        request = privacy.request([planted])
        assert request.validate().allowed
        assert planted["report"]["summary"][-1] == payload
        assert PLANTED in request.text  # it reaches the model, quoted as untrusted data
        assert "</think>" not in request.text  # escaped: no tag of the model's own


# -- the licence before evaluation calls --------------------------------------------------


def test_evaluation_calls_to_the_campus_model_wait_for_the_licence() -> None:
    assert "licence confirmation is not recorded" in (measures.require_licence(local()) or "")
    assert measures.require_licence(local(licence="D-121")) is None
    spec = {"name": "c", "base_url": "https://c.ex/v1", "keys": ["K"],
            "models": {"small": {"name": "m"}}}  # fmt: skip
    cloud = LlmConfig.model_validate({"providers": [spec]})
    assert measures.require_licence(cloud) is None
    shipped = pinned(load_config(), "local", allow_disabled=True)
    assert measures.require_licence(shipped) is not None  # not confirmed yet (plan §12 item 21)


def test_a_measure_for_another_model_is_not_used() -> None:
    notes: list[str] = []
    data = measures.wrapped(local(), {"x": 1})
    assert measures.unwrapped(data, local(), notes, "f") == {"x": 1}
    other = local(models={"small": {"name": "another", "context_tokens": 16384}})
    assert measures.unwrapped(data, other, notes, "f") is None
    assert notes
    assert "not this model" in notes[0]
    assert measures.unwrapped(None, local(), notes, "f") is None
