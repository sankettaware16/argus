"""The privacy comparison runner (P2/D-078 through P5): every arm, one model, resumable,
labels never sent, A-real refused."""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from argus.evaluation import comparison
from argus.llm import arms, budget, compare, prompts
from argus.llm.gateway import Call, Completion, NoCapacity, Refused
from argus.llm.privacy import Privacy
from argus.llm.providers import Tier
from tests.unit.llm.test_privacy import dossier

LOW = {**dossier(), "facts": {**dossier()["facts"], "severity": "low"}}
CASES = [
    comparison.GoldCase(uuid.UUID(int=1), "true_positive", dossier()),
    comparison.GoldCase(uuid.UUID(int=2), "benign_expected", LOW),
]


def reply(outcome: str) -> str:
    return json.dumps({"outcome": outcome, "confidence": 0.9, "reason": "r", "missing": []})


class Model:
    """Answers by a rule over the call; records every call."""

    def __init__(self, decide: Callable[[Call], str] | None = None) -> None:
        self.calls: list[Call] = []
        self.decide = decide or (lambda call: reply("true_positive"))

    async def __call__(self, call: Call) -> Completion:
        self.calls.append(call)
        if len(self.calls) > 100:
            raise AssertionError("asked again and again")
        out = self.decide(call)
        return Completion(out, "p", "m", 100, 20, 0.001, 5, uuid.uuid4())


async def test_every_arm_once_per_item_then_from_the_cache(
    privacy: Privacy, tmp_path: Path
) -> None:
    model = Model()
    path = tmp_path / "answers.json"
    result = await comparison.run(CASES, privacy, model, path)
    sent = [a for a in comparison.DEFAULT_ARMS if a != "C-counts"]
    # an exact count here reads as an internal address in decimal: the validator refuses it
    assert result.blocked["C-counts"] == [str(c.investigation_id) for c in CASES]
    assert len(model.calls) == 2 * len(sent)
    assert result.calls == len(model.calls)
    assert result.cost_usd == pytest.approx(0.001 * len(model.calls))
    for call in model.calls:
        assert call.purpose == "evaluate"
        assert call.priority is budget.Priority.LOW
        assert call.tier is Tier.SMALL
        assert call.instructions == prompts.PROMPTS[prompts.ASSESS_V1]
        assert call.max_output == 800
        for label in ("true_positive", "benign_expected"):  # the labels are never sent
            assert label not in call.request.text
    assert [c.request.text for c in model.calls[: len(sent)]] == [
        arms.render(privacy, a, [CASES[0].body]).text for a in sent
    ]  # item by item, every arm
    again = await comparison.run(CASES, privacy, Model(), path)
    assert again.calls == 0
    assert again.answers == result.answers
    assert stat_mode(path) == 0o600


def stat_mode(path: Path) -> int:
    import stat

    return stat.S_IMODE(path.stat().st_mode)


async def test_a_changed_prompt_or_text_is_asked_again(privacy: Privacy, tmp_path: Path) -> None:
    path = tmp_path / "answers.json"
    await comparison.run(CASES[:1], privacy, Model(), path, ["B"])
    cache = json.loads(path.read_text(encoding="utf-8"))
    (key,) = cache
    assert key.startswith(f"B|{CASES[0].investigation_id}|{prompts.ASSESS_V1}|small|")
    assert cache[key]["model"] == "p/m"
    assert cache[key]["tokens"] == 120
    medium = Model()
    await comparison.run(CASES[:1], privacy, medium, path, ["B"], Tier.MEDIUM)
    assert len(medium.calls) == 1  # another model: asked again
    other = comparison.GoldCase(CASES[0].investigation_id, "true_positive", LOW)
    model = Model()
    await comparison.run([other], privacy, model, path, ["B"])
    assert len(model.calls) == 1


async def test_a_real_is_refused(privacy: Privacy, tmp_path: Path) -> None:
    model = Model()
    with pytest.raises(ValueError, match="A-real sends real campus data"):
        await comparison.run(CASES, privacy, model, tmp_path / "a.json", ["B", "A-real"])
    assert model.calls == []
    assert "A-real" not in comparison.DEFAULT_ARMS


async def test_scores_and_the_decision(privacy: Privacy, tmp_path: Path) -> None:
    def decide(call: Call) -> str:  # B misses the true positive the fake arm catches
        is_b = "10.200." not in call.request.text and "host-" not in call.request.text
        if "severity high" in call.request.text:
            return reply("benign_expected" if is_b else "true_positive")
        return reply("benign_expected")

    arms_ = ["B", "A-fake", "C-ips"]
    result = await comparison.run(CASES, privacy, Model(decide), tmp_path / "a.json", arms_)
    lines = comparison.report(CASES, result)
    assert lines[0] == f"items with a person's answer: 2; calls this run: 6 (${0.006:.4f})"
    table = {line.split()[0]: line.split() for line in lines if line.split()[0] in arms_}
    assert table["A-fake"][2] == "100%"
    assert table["B"][2] == "50%"
    assert table["B"][4] == "1"  # one true positive missed
    assert lines[-1].startswith("decision (D-078): LOOSEN C-ips")


async def test_capacity_waits_briefly_then_stops_resumably(
    privacy: Privacy, tmp_path: Path
) -> None:
    now = datetime(2026, 10, 16, 12, tzinfo=UTC)
    slept: list[float] = []
    state = {"n": 0}

    async def model(call: Call) -> Completion:
        state["n"] += 1
        if state["n"] == 1:
            raise NoCapacity(now + timedelta(seconds=30), "minute")
        if state["n"] == 3:
            raise NoCapacity(now + timedelta(hours=2), "day")
        return Completion(reply("true_positive"), "p", "m", 1, 1, 0.0, 1, uuid.uuid4())

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    path = tmp_path / "a.json"
    result = await comparison.run(CASES, privacy, model, path, ["B", "A-fake"], sleep=sleep,
                                  clock=now.timestamp)  # fmt: skip
    assert slept == [30.0]
    assert result.stopped == "no capacity until 2026-10-16 14:00 UTC"
    assert result.calls == 1
    assert len(json.loads(path.read_text(encoding="utf-8"))) == 1
    assert "stopped early: no capacity until 2026-10-16 14:00 UTC (run again to resume)" in (
        comparison.report(CASES, result)
    )


async def test_a_past_capacity_time_still_sleeps_a_second(privacy: Privacy, tmp_path: Path) -> None:
    now = datetime(2026, 10, 16, 12, tzinfo=UTC)
    slept: list[float] = []
    seen = {"n": 0}

    async def model(call: Call) -> Completion:
        seen["n"] += 1
        if seen["n"] == 1:
            raise NoCapacity(now - timedelta(seconds=5), "past")
        return Completion(reply("true_positive"), "p", "m", 1, 1, 0.0, 1, uuid.uuid4())

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    await comparison.run(CASES[:1], privacy, model, tmp_path / "a.json", ["B"], sleep=sleep,
                         clock=now.timestamp)  # fmt: skip
    assert slept == [1.0]


async def test_refused_blocked_and_unusable_are_counted(
    privacy: Privacy, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Call] = []

    async def model(call: Call) -> Completion:
        seen.append(call)
        if len(seen) > 100:
            raise AssertionError("asked again and again")
        if "10.200." in call.request.text:
            raise Refused("no")
        return Completion("not json", "p", "m", 1, 1, 0.0, 1, uuid.uuid4())

    result = await comparison.run(CASES, privacy, model, tmp_path / "a.json", ["B", "C-ips"])
    assert result.blocked["C-ips"] == [str(c.investigation_id) for c in CASES]
    assert result.unusable["B"] == [str(c.investigation_id) for c in CASES]
    lines = comparison.report(CASES, result)
    assert "  B: 2 unusable answers" in lines
    assert "  C-ips: 2 blocked by the validator" in lines
    assert lines[-1] == "not enough answers to compare yet"
    real = arms.render

    def leaky(p: Any, name: str, bodies: Any, max_chars: int = 60_000) -> Any:
        r = real(p, name, bodies, max_chars)
        r.text += "\n10.20.3.4"
        return r

    monkeypatch.setattr("argus.llm.arms.render", leaky)
    model2: list[Call] = []

    async def never(call: Call) -> Completion:
        model2.append(call)
        raise AssertionError("a blocked request reached the model")

    result = await comparison.run(CASES, privacy, never, tmp_path / "b.json", ["B"])
    assert result.blocked["B"] == [str(c.investigation_id) for c in CASES]
    assert model2 == []


def test_report_without_a_reference_or_common_items() -> None:
    run = comparison.Run({"B": {"x": comparison.compare.Answer("true_positive")}})
    assert comparison.report(CASES, run)[-1] == "not enough answers to compare yet"
    run = comparison.Run(
        {"B": {"x": comparison.compare.Answer("true_positive")},
         "A-fake": {"y": comparison.compare.Answer("true_positive")}}
    )  # fmt: skip
    assert comparison.report(CASES, run)[-1].startswith("cannot score:")


def test_the_cache_survives_a_failed_save(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "a.json"
    comparison._save(path, {"k": 1})

    def boom(*a: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("argus.evaluation.comparison.os.replace", boom)
    with pytest.raises(OSError, match="disk full"):
        comparison._save(path, {"k": 2})
    assert json.loads(path.read_text(encoding="utf-8")) == {"k": 1}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.json"]
    assert comparison._load(tmp_path / "none.json") == {}


# -- the exact values and edges (mutation testing, P5) --------------------------------------

I1, I2 = (str(c.investigation_id) for c in CASES)


def test_a_gold_case_is_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        CASES[0].label = "x"  # type: ignore[misc]


async def test_the_key_holds_a_16_character_digest_of_the_text(
    privacy: Privacy, tmp_path: Path
) -> None:
    path = tmp_path / "answers.json"
    await comparison.run(CASES[:1], privacy, Model(), path, ["B"])
    (key,) = json.loads(path.read_text(encoding="utf-8"))
    sent = arms.render(privacy, "B", [CASES[0].body]).text
    assert key.split("|")[-1] == hashlib.sha256(sent.encode()).hexdigest()[:16]


def test_the_cache_file_format_and_its_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a" / "b" / "answers.json"
    seen: list[str] = []
    real = os.replace

    def replace(src: str, dst: Path) -> None:
        seen.append(Path(src).name)
        real(src, dst)

    monkeypatch.setattr("argus.evaluation.comparison.os.replace", replace)
    comparison._save(path, {"b": 1, "a": {"y": 2, "x": 3}})
    assert path.read_text(encoding="utf-8") == '{\n "a": {\n  "x": 3,\n  "y": 2\n },\n "b": 1\n}'
    assert stat_mode(path.parent) == 0o700
    (temp,) = seen
    assert temp.startswith(".answers-")


def test_a_failed_save_whose_temporary_file_is_gone_raises_the_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def gone(src: str, dst: Path) -> None:
        Path(src).unlink()
        raise OSError("disk full")

    monkeypatch.setattr("argus.evaluation.comparison.os.replace", gone)
    with pytest.raises(OSError, match="disk full"):
        comparison._save(tmp_path / "a.json", {"k": 1})


async def test_every_real_data_arm_is_named(
    privacy: Privacy, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(arms, "REAL_DATA", frozenset({"A-real", "B"}))
    with pytest.raises(ValueError, match=r"^A-real, B sends real campus data"):
        await comparison.run(CASES, privacy, Model(), tmp_path / "a.json", ["B", "A-real"])


async def test_a_wait_of_exactly_the_limit_is_waited_and_longer_stops(
    privacy: Privacy, tmp_path: Path
) -> None:
    now = datetime(2026, 10, 16, 12, tzinfo=UTC)
    waits = [timedelta(seconds=120), timedelta(seconds=120.5)]
    slept: list[float] = []

    async def model(call: Call) -> Completion:
        raise NoCapacity(now + waits.pop(0), "minute")

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    result = await comparison.run(CASES, privacy, model, tmp_path / "a.json", ["B"],
                                  sleep=sleep, clock=now.timestamp)  # fmt: skip
    assert slept == [120.0]
    assert result.stopped == "no capacity until 2026-10-16 12:02 UTC"


async def test_the_default_sleep_is_asyncios(
    privacy: Privacy, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 10, 16, 12, tzinfo=UTC)
    slept: list[float] = []
    seen = {"n": 0}

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    async def model(call: Call) -> Completion:
        seen["n"] += 1
        if seen["n"] == 1:
            raise NoCapacity(now + timedelta(seconds=3), "minute")
        return Completion(reply("true_positive"), "p", "m", 1, 1, 0.0, 1, uuid.uuid4())

    monkeypatch.setattr(asyncio, "sleep", sleep)
    await comparison.run(CASES[:1], privacy, model, tmp_path / "a.json", ["B"],
                         clock=now.timestamp)  # fmt: skip
    assert slept == [3.0]


async def test_the_seconds_an_answer_took(privacy: Privacy, tmp_path: Path) -> None:
    ticks = iter([100.0, 101.23456])
    path = tmp_path / "a.json"
    result = await comparison.run(CASES[:1], privacy, Model(), path, ["B"],
                                  clock=lambda: next(ticks))  # fmt: skip
    (entry,) = json.loads(path.read_text(encoding="utf-8")).values()
    assert entry["seconds"] == 1.235
    assert result.answers["B"][I1].seconds == 1.235


async def test_an_unusable_answer_is_no_answer(privacy: Privacy, tmp_path: Path) -> None:
    model = Model(lambda call: "not json")
    result = await comparison.run(CASES, privacy, model, tmp_path / "a.json", ["B"])
    assert result.unusable["B"] == [I1, I2]
    assert result.answers["B"] == {}


async def test_a_refused_call_is_not_asked_again(privacy: Privacy, tmp_path: Path) -> None:
    calls: list[Call] = []

    async def model(call: Call) -> Completion:
        calls.append(call)
        if len(calls) > 10:
            raise AssertionError("asked again and again")
        raise Refused("no")

    result = await comparison.run(CASES, privacy, model, tmp_path / "a.json", ["B"])
    assert len(calls) == 2
    assert result.blocked["B"] == [I1, I2]


async def test_a_completed_call_is_not_asked_again(privacy: Privacy, tmp_path: Path) -> None:
    calls: list[Call] = []

    async def model(call: Call) -> Completion:
        calls.append(call)
        if len(calls) > 10:
            raise AssertionError("asked again and again")
        return Completion(reply("true_positive"), "p", "m", 1, 1, 0.0, 1, uuid.uuid4())

    await comparison.run(CASES, privacy, model, tmp_path / "a.json", ["B"])
    assert len(calls) == 2


def answers(**by_arm: tuple[str, str]) -> comparison.Run:
    return comparison.Run({arm: {I1: compare.Answer(v1), I2: compare.Answer(v2)}
                           for arm, (v1, v2) in by_arm.items()})  # fmt: skip


HEADER = (
    "arm        items  accuracy  TP recall  missed TP  agree w/ ref  McNemar p"
    "  asks withheld  tokens"
)


def test_the_report_table_and_keeping_the_policy() -> None:
    right = ("true_positive", "benign_expected")
    lines = comparison.report(CASES, answers(B=right, **{"A-fake": right}))
    assert HEADER in lines
    assert lines[-1] == "decision (D-078): KEEP the policy: within 3% of A-fake (gap +0.0%)"


def test_the_report_names_every_rule_to_loosen() -> None:
    right = ("true_positive", "benign_expected")
    run = answers(B=("benign_expected", "benign_expected"), **{"A-fake": right,
                  "C-ips": right, "C-hosts": right})  # fmt: skip
    assert comparison.report(CASES, run)[-1].startswith(
        "decision (D-078): LOOSEN C-hosts, C-ips: gap"
    )


def test_the_report_asks_the_user_when_no_rule_closes_the_gap() -> None:
    right = ("true_positive", "benign_expected")
    run = answers(B=("benign_expected", "benign_expected"), **{"A-fake": right})
    assert comparison.report(CASES, run)[-1].startswith("decision (D-078): ASK THE USER: gap")


def test_the_report_without_true_positives_shows_no_recall() -> None:
    cases = [comparison.GoldCase(c.investigation_id, "benign_expected", c.body) for c in CASES]
    benign = ("benign_expected", "benign_expected")
    lines = comparison.report(cases, answers(B=benign, **{"A-fake": benign}))
    rows = {line.split()[0]: line.split() for line in lines if line.split()[0] in ("B", "A-fake")}
    assert rows["B"][3] == "-"
    assert rows["A-fake"][3] == "-"
    right = ("true_positive", "benign_expected")
    lines = comparison.report(CASES, answers(B=right, **{"A-fake": right}))
    rows = {line.split()[0]: line.split() for line in lines}
    assert rows["B"][3] == "100%"


def test_the_report_lists_both_problems_of_an_arm() -> None:
    run = comparison.Run({"B": {}}, {"B": [I1]}, {"B": [I2]})
    assert "  B: 1 blocked by the validator, 1 unusable answers" in comparison.report(CASES, run)
