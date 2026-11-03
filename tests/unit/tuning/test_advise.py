"""Drafted tuning suggestions (P7): the report through the privacy layer, and a suggestion
kept only with evidence (quotes in what the model read; an exception's value is the report's,
with enough benign verdicts and no true positive)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, date, datetime
from typing import Any

import pytest

from argus import site
from argus.llm.gateway import Call, Completion, NoCapacity, Refused
from argus.llm.privacy import Privacy
from argus.llm.providers import Tier
from argus.tuning import advise
from argus.tuning.report import RuleReport, ValueStat, label_support

NOW = datetime(2026, 10, 16, 12, tzinfo=UTC)
REP = RuleReport(
    rule="Proxy: tunnel", start=NOW, end=NOW, alerts=900,
    per_day=((date(2026, 10, 15), 400), (date(2026, 10, 16), 500)), investigations=40,
    runs=120, runs_at_limit=12, max_signals=100, labels={"rule_false_positive": 5},
    proposals={"true_positive": 1},
    values=(
        ValueStat("entity.ip", "8.8.8.8", 30, 700, {"rule_false_positive": 4}),
        ValueStat("source.ip", "10.20.3.4", 9, 150, {"rule_false_positive": 1,
                                                     "true_positive": 1}),
        ValueStat("entity.ip", "8.8.4.4", 3, 50, {"benign_expected": 2}),
        ValueStat("entity.ip", "8.8.8.8", 1, 1, {}),  # a repeat is shown once
    ),
)  # fmt: skip


def reply(*suggestions: dict[str, Any]) -> str:
    return json.dumps({"suggestions": list(suggestions)})


def ok(**over: Any) -> dict[str, Any]:
    base = {"kind": "threshold", "path": "", "value": "", "change": "raise the limit",
            "why": "runs hit it", "evidence": ["runs that hit the alert limit (100): 12"],
            "risk": "more alerts"}  # fmt: skip
    base.update(over)
    return base


class Model:
    def __init__(self, reply: str | Exception) -> None:
        self.reply = reply
        self.calls: list[Call] = []

    async def __call__(self, call: Call) -> Completion:
        self.calls.append(call)
        if isinstance(self.reply, Exception):
            raise self.reply
        return Completion(self.reply, "p", "m", 10, 10, 0.003, 5, uuid.uuid4())


def shown(privacy: Privacy, value: str) -> str:
    item, _ = advise.body(REP)
    request = privacy.request([item])
    return request._maps["I1"]._token.get(("IP", value), value)


def test_the_body_and_the_numbers(privacy: Privacy) -> None:
    item, slots = advise.body(REP)
    assert item["facts"] == {"rule_name": "Proxy: tunnel", "alert_count": 900}
    fields = item["context"]["pack"]["fields"]
    assert fields["entity.ip"] == {"distinct": 2, "alerts": 750,
                                   "top": [["8.8.8.8", 700], ["8.8.4.4", 50]]}  # fmt: skip
    assert fields["source.ip"]["top"] == [["10.20.3.4", 150]]
    assert list(slots) == [("entity.ip", "8.8.8.8"), ("entity.ip", "8.8.4.4"),
                           ("source.ip", "10.20.3.4")]  # fmt: skip
    request = privacy.request([item])
    assert request.validate().allowed
    assert "10.20.3.4" not in request.text
    assert "8.8.8.8" in request.text
    lines = advise.numbers(REP, slots).splitlines()
    assert lines[0] == "- alerts this week: 900 (per day: Thu 400, Fri 500)"
    assert lines[2] == "- rule runs: 120; runs that hit the alert limit (100): 12"
    assert lines[3] == "- people's verdicts (last 30 days): rule_false_positive 5"
    assert lines[4] == "- current proposals: true_positive 1"
    assert lines[5] == ("- entity.ip value 1 (in the order shown): 30 investigations, 700"
                        " alerts; people's verdicts: rule_false_positive 4")  # fmt: skip
    assert lines[6].startswith("- entity.ip value 2 (in the order shown): 3 investigations")
    assert lines[7].startswith("- source.ip value 1 (in the order shown): 9 investigations")
    empty = RuleReport("r", NOW, NOW, 0, (), 0, 0, 0, None, {}, {}, ())
    assert advise.numbers(empty, {}).splitlines()[0] == "- alerts this week: 0 (per day: none)"
    assert "(unknown)" in advise.numbers(empty, {})


async def test_a_supported_exception_and_a_threshold_are_kept(privacy: Privacy) -> None:
    model = Model(reply(
        ok(),
        ok(kind="exception", path="entity.ip", value="8.8.8.8", change="exclude it",
           evidence=["entity.ip value 1 (in the order shown): 30 investigations"]),
        ok(kind="none"),
    ))  # fmt: skip
    got = await advise.advise(REP, privacy, model)
    assert [s.kind for s in got.suggestions] == ["threshold", "exception"]
    assert got.suggestions[1].value == "8.8.8.8"
    assert got.suggestions[1].path == "entity.ip"
    assert got.dropped == []
    assert (got.model, got.cost_usd) == ("p/m", 0.003)
    (call,) = model.calls
    assert (call.purpose, call.tier, call.priority.value) == ("tune", Tier.MEDIUM, "low")
    assert "runs that hit the alert limit (100): 12" in call.instructions


@pytest.mark.parametrize(
    ("suggestion", "why"),
    [
        (ok(evidence=["the rule fires 9000 times"]), "threshold: evidence not in the report"),
        (ok(evidence=[]), "threshold: evidence not in the report"),
        (ok(kind="delete"), "unknown kind 'delete'"),
        (
            ok(kind="exception", path="entity.ip", value="9.9.9.9"),
            "exception: not one of the report's values",
        ),
        (
            ok(kind="exception", path="entity.ip", value="8.8.4.4"),
            "exception: 2 benign and 0 true-positive verdicts (needs 3 and 0)",
        ),
        (
            ok(kind="exception", path="source.ip", value="TOKEN"),
            "exception: 1 benign and 1 true-positive verdicts (needs 3 and 0)",
        ),
        (
            ok(kind="exception", path="source.ip", value="8.8.8.8"),
            "exception: not one of the report's values",
        ),
        (
            ok(kind="exception", path="entity.ip", value="I7.IP_1"),
            "exception: not one of the report's values",
        ),
    ],
)
async def test_unsupported_suggestions_are_dropped_with_a_reason(
    privacy: Privacy, suggestion: dict[str, Any], why: str
) -> None:
    if suggestion.get("value") == "TOKEN":
        suggestion["value"] = shown(privacy, "10.20.3.4")
    got = await advise.advise(REP, privacy, Model(reply(suggestion)))
    assert got.suggestions == []
    assert got.dropped == [why]


async def test_a_pseudonymous_value_is_revealed_for_the_person(privacy: Privacy) -> None:
    rich = RuleReport(**{**REP.__dict__, "values": (
        ValueStat("source.ip", "10.20.3.4", 9, 150, {"rule_false_positive": 3}),)})  # fmt: skip
    token = privacy.request([advise.body(rich)[0]])._maps["I1"]._token[("IP", "10.20.3.4")]
    said = ok(kind="exception", path="source.ip", value=token, change=f"exclude {token}",
              why=f"{token} is benign", evidence=[f"source.ip (1): {token}"],
              risk=f"{token} changes")  # fmt: skip
    model = Model(reply(said))
    got = await advise.advise(rich, privacy, model)
    (s,) = got.suggestions
    assert s.value == "10.20.3.4"
    assert s.change == "exclude 10.20.3.4"
    assert s.why == "10.20.3.4 is benign"
    assert s.risk == "10.20.3.4 changes"
    assert s.evidence == ("source.ip (1): 10.20.3.4",)
    assert s.as_dict()["value"] == "10.20.3.4"


@pytest.mark.parametrize("text", ["no", "[]", json.dumps({"suggestions": "x"})])
async def test_an_unusable_answer(privacy: Privacy, text: str) -> None:
    got = await advise.advise(REP, privacy, Model(text))
    assert got.dropped == ["no usable answer from the model"]


async def test_at_most_three_and_junk_skipped(privacy: Privacy) -> None:
    got = await advise.advise(REP, privacy, Model(reply(ok(), "x", ok(), ok(), ok())))  # type: ignore[arg-type]
    assert len(got.suggestions) == 2  # the first three: two kept, one junk
    junk = await advise.advise(REP, privacy, Model(reply(ok(change=5, why=None))))
    assert (junk.suggestions[0].change, junk.suggestions[0].why) == ("", "")


async def test_refusal_and_capacity(privacy: Privacy) -> None:
    got = await advise.advise(REP, privacy, Model(Refused("blocked by the validator")))
    assert got.dropped == ["refused: blocked by the validator"]
    with pytest.raises(NoCapacity):
        await advise.advise(REP, privacy, Model(NoCapacity(NOW, "day")))


async def test_a_report_that_cannot_be_sent(
    privacy: Privacy, monkeypatch: pytest.MonkeyPatch
) -> None:
    from argus.llm.privacy import Request

    monkeypatch.setattr(privacy, "request", lambda bodies, max_chars=60_000: Request(
        "", (), (), ("I1",), (), privacy.campus))  # fmt: skip
    model = Model(reply(ok()))
    got = await advise.advise(REP, privacy, model)
    assert got.dropped == ["the report could not be sent"]
    assert model.calls == []


def test_label_support() -> None:
    assert label_support(REP.values[0]) == (4, 0)
    assert label_support(REP.values[1]) == (1, 1)
    assert label_support({"labels": {"benign_policy": 2, "inconclusive": 4}}) == (2, 0)
    assert label_support({}) == (0, 0)


# -- exactness (mutation work, 2026-10-21) ---------------------------------------------------


def test_the_constants_and_the_prompt_text() -> None:
    import hashlib

    assert advise.PROMPT == "tune@1"
    assert advise.KINDS == ("exception", "threshold", "scope")
    assert advise.MIN_LABELS == 3
    assert advise.PER_FIELD == 5
    # a changed prompt must get a new name: tune@1 is this exact text
    text = site.say(advise.INSTRUCTIONS)  # the template read through ACME's words
    digest = hashlib.sha256(text.encode()).hexdigest()
    assert text.startswith("You help a university security team tune one SIEM")
    assert digest == DIGEST


DIGEST = "6dd74975655a55668a258bf0197c2d6e3e716eef4aa73a470710c6d1dabc7fe1"  # tune@1


def test_records_exactly() -> None:
    s = advise.Suggestion("scope", "p", "v", "c", "w", ("e1", "e2"), "r")
    assert s.as_dict() == {"kind": "scope", "path": "p", "value": "v", "change": "c",
                           "why": "w", "evidence": ["e1", "e2"], "risk": "r"}  # fmt: skip
    a = advise.Advice()
    assert (a.suggestions, a.dropped, a.model, a.cost_usd) == ([], [], "-", 0.0)


def test_the_body_exactly_and_five_values_per_field() -> None:
    values = tuple(ValueStat("user_agent.original", f"agent {k}", 1, k + 1, {}) for k in range(7))
    many = RuleReport(**{**REP.__dict__, "values": values})
    item, slots = advise.body(many)
    assert item == {
        "facts": {"rule_name": "Proxy: tunnel", "alert_count": 900},
        "context": {"pack": {"fields": {"user_agent.original": {
            "distinct": 5, "alerts": 15,
            "top": [[f"agent {k}", k + 1] for k in range(5)]}},
            "complete": True, "alerts_read": 900}},
        "report": {"steps": [], "summary": []},
        "signals": [], "local_signals": [], "evidence": [],
    }  # fmt: skip
    assert len(slots) == 5


def test_numbers_join_several_and_say_none() -> None:
    rep = RuleReport(**{**REP.__dict__, "labels": {"true_positive": 1, "benign_policy": 2},
                        "proposals": {"true_positive": 3, "rule_false_positive": 1},
                        "values": (ValueStat("source.ip", "10.20.3.4", 1, 1,
                                             {"benign_policy": 1, "true_positive": 2}),
                                   ValueStat("entity.ip", "8.8.8.8", 1, 1, {}))})  # fmt: skip
    _, slots = advise.body(rep)
    lines = advise.numbers(rep, slots).splitlines()
    assert lines[3] == "- people's verdicts (last 30 days): benign_policy 2, true_positive 1"
    assert lines[4] == "- current proposals: rule_false_positive 1, true_positive 3"
    assert lines[5].endswith("people's verdicts: benign_policy 1, true_positive 2")
    assert lines[6].endswith("people's verdicts: none")
    bare = RuleReport(**{**REP.__dict__, "labels": {}, "proposals": {}})
    shown = advise.numbers(bare, {}).splitlines()
    assert shown[3] == "- people's verdicts (last 30 days): none"
    assert shown[4] == "- current proposals: none"


async def test_the_call_and_the_refusal_message_cut(privacy: Privacy) -> None:
    model = Model(reply(ok()))
    await advise.advise(REP, privacy, model)
    (call,) = model.calls
    assert (call.max_output, call.timeout_s) == (2000, 120.0)
    got = await advise.advise(REP, privacy, Model(Refused("x" * 200)))
    assert got.dropped == ["refused: " + "x" * 120]


async def test_cuts_and_defaults_of_a_suggestion(privacy: Privacy) -> None:
    long_kind = await advise.advise(REP, privacy, Model(reply(ok(kind="k" * 30))))
    assert long_kind.dropped == [f"unknown kind {'k' * 20!r}"]
    fact = "runs that hit the alert limit (100): 12"
    seven = await advise.advise(REP, privacy, Model(reply(ok(evidence=[fact] * 7))))
    assert len(seven.suggestions[0].evidence) == 6
    padded = fact + " " * (300 - len(fact)) + "Qzz"  # the cut at 300 leaves only the fact
    cut = await advise.advise(REP, privacy, Model(reply(ok(evidence=[padded]))))
    assert cut.dropped == []
    assert cut.suggestions[0].evidence == (fact + " " * (300 - len(fact)),)
    no_path = ok()
    del no_path["path"]
    got = await advise.advise(REP, privacy, Model(reply(no_path, ok(path="p" * 90))))
    assert [s.path for s in got.suggestions] == ["", "p" * 80]
    assert [s.value for s in got.suggestions] == ["", ""]
    wordy = await advise.advise(REP, privacy, Model(reply(ok(change="c" * 500))))
    assert wordy.suggestions[0].change == "c" * 400
    foreign = await advise.advise(REP, privacy, Model(reply(ok(why="see I9.IP_1"))))
    assert foreign.suggestions[0].why == "see I9.IP_1"


async def test_an_exception_without_a_value_is_never_one_of_the_reports(
    privacy: Privacy,
) -> None:
    rep = RuleReport(**{**REP.__dict__, "values": (
        ValueStat("user_agent.original", "XXXX", 9, 9, {"rule_false_positive": 4}),)})  # fmt: skip
    no_value = ok(kind="exception", path="user_agent.original")
    del no_value["value"]
    got = await advise.advise(rep, privacy, Model(reply(no_value)))
    assert got.dropped == ["exception: not one of the report's values"]


def test_a_suggestion_is_frozen() -> None:
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        advise.Suggestion("k", "p", "v", "c", "w", (), "r").kind = "x"  # type: ignore[misc]


async def test_a_suggestion_without_a_kind_is_dropped(privacy: Privacy) -> None:
    kindless = ok()
    del kindless["kind"]
    got = await advise.advise(REP, privacy, Model(reply(kindless)))
    assert got.dropped == ["unknown kind ''"]
