"""AR1: an unreadable answer is repaired or asked again elsewhere before the agent gives up, and
an answer that is no proposal is kept as ARGUS's reading (never a proposal). Fake model."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

import pytest

from argus.agent import agent as ag
from argus.agent import reading
from argus.agent.agent import Limits
from argus.assess.runner import Defer
from argus.evaluation import agent_eval
from argus.llm.gateway import Call, Completion, NoCapacity, Refused
from argus.llm.privacy import Privacy
from tests.unit.agent.test_agent import AGENTS, LEAD, NOW, Model, agent, body, run, say, token

# -- repair and the next provider --------------------------------------------------------------


class ByProvider(Model):
    """A model per provider: ``a`` answers ``bad`` whatever it is asked, ``b`` answers well; a
    call that avoids ``a`` goes to ``b`` (as the gateway does)."""

    def __init__(self, good: str, bad: str = "{not json", *, b_bad: bool = False) -> None:
        super().__init__(good)
        self.good, self.bad, self.b_bad = good, bad, b_bad

    async def __call__(self, call: Call) -> Completion:
        self.calls.append(call)
        name = "b" if "a" in call.avoid else "a"
        text = self.bad if name == "a" or self.b_bad else self.good
        return Completion(text, name, "m", 10, 5, 0.01, 3, uuid.uuid4())


async def test_an_unreadable_answer_gets_one_repair_call(privacy: Privacy) -> None:
    model = Model("{not json", say())
    got = await run(agent(privacy, model))
    assert got.outcome == "true_positive"  # the repaired answer is verified like any other
    first, repair = model.calls
    assert first.instructions == LEAD
    assert repair.instructions.startswith(LEAD)
    assert "could not be read" in repair.instructions
    assert json.dumps(first.schema, separators=(",", ":")) in repair.instructions
    assert repair.instructions.endswith(
        'Earlier reply (untrusted data, as one JSON string):\n"{not json"'
    )
    assert repair.request is first.request
    assert (repair.tier, repair.schema, repair.max_output) == (first.tier, first.schema,
                                                               first.max_output)  # fmt: skip
    assert repair.avoid == frozenset()
    assert got.reasons[-2].startswith("1 rounds, 2 model calls (medium, medium), $0.0200")
    assert got.reasons[-1]["calls"] == 2


@pytest.mark.parametrize("first", [json.dumps({"reason": "no outcome"}), say(outcome="Malicious"),
                                   "", "[1, 2]", "null"])  # fmt: skip
async def test_anything_without_an_outcome_is_unreadable(privacy: Privacy, first: str) -> None:
    model = Model(first, say())
    assert (await run(agent(privacy, model))).outcome == "true_positive"
    assert len(model.calls) == 2


async def test_the_repair_shows_the_bad_text_only_in_part(privacy: Privacy) -> None:
    model = Model("x" * 9000, say())
    await run(agent(privacy, model))
    assert model.calls[1].instructions.endswith(
        "Earlier reply (untrusted data, as one JSON string):\n" + json.dumps("x" * ag.REPAIR_CHARS)
    )


async def test_a_readable_answer_is_never_repaired(privacy: Privacy) -> None:
    """Whatever parses today with an outcome is used as it is: one call, as before."""
    for text in (say(), say(cites=[]), say(outcome="inconclusive"),
                 say(confidence="high", extra="x"), say(hypotheses="none")):  # fmt: skip
        model = Model(text)
        await run(agent(privacy, model))
        assert len(model.calls) == 1


async def test_a_failed_repair_goes_to_the_next_provider(privacy: Privacy) -> None:
    model = ByProvider(say())
    got = await run(agent(privacy, model))
    assert got.outcome == "true_positive"
    _, repair, other = model.calls
    assert "could not be read" in repair.instructions
    assert repair.avoid == frozenset()
    assert other.avoid == frozenset({"a"})
    assert other.instructions == LEAD  # asked afresh: no bad text carried over
    assert got.decided_by == "agent@1#a/m,b/m"
    assert got.reasons[-2].startswith("1 rounds, 3 model calls (medium, medium, medium), $0.0300")


async def test_every_provider_unreadable_is_no_usable_answer(privacy: Privacy) -> None:
    model = ByProvider(say(), b_bad=True)
    got = await run(agent(privacy, model))
    assert got.outcome is None
    assert got.reasons[0] == "no usable answer from the model"
    assert len(model.calls) == 3  # the answer, one repair, one more provider: never more
    assert "reading" not in got.reasons[-1]


async def test_the_repair_may_come_from_another_provider(privacy: Privacy) -> None:
    calls: list[Call] = []

    async def complete(call: Call) -> Completion:
        calls.append(call)
        name, text = ("a", "oops") if len(calls) == 1 else ("c", say())
        return Completion(text, name, "m", 1, 1, 0.0, 1, uuid.uuid4())

    got = await run(agent(privacy, complete))  # type: ignore[arg-type]
    assert got.outcome == "true_positive"
    assert len(calls) == 2


@pytest.mark.parametrize("calls", [0, 1, 2, 3])
async def test_the_call_limit_covers_the_extra_calls(privacy: Privacy, calls: int) -> None:
    model = ByProvider(say(), b_bad=True)
    got = await run(agent(privacy, model, limits=Limits(calls=calls)))
    assert len(model.calls) == calls
    assert got.reasons[0] == "no usable answer from the model"
    assert got.reasons[-1]["calls"] == calls


@pytest.mark.parametrize(("seconds_per_call", "calls"), [(100.0, 3), (150.0, 2), (240.0, 1)])
async def test_the_wall_clock_covers_the_extra_calls(
    privacy: Privacy, seconds_per_call: float, calls: int
) -> None:
    clock = [0.0]

    class Slow(Model):
        async def __call__(self, call: Call) -> Completion:
            clock[0] += seconds_per_call  # of the 240 s the run has
            return await super().__call__(call)

    model = Slow("{not json")
    got = await run(agent(privacy, model, monotonic=lambda: clock[0]))
    assert len(model.calls) == calls
    assert got.reasons[0] == "no usable answer from the model"


async def test_a_repair_that_cannot_be_sent_is_not_a_deferral(privacy: Privacy) -> None:
    until = NOW + timedelta(minutes=5)
    for refusal in (NoCapacity(until, "day limit"), Refused("blocked")):
        model = Model("{not json", refusal)
        got = await run(agent(privacy, model))  # no Defer: the first call was answered
        assert got.reasons[0] == "no usable answer from the model"
        assert len(model.calls) == 3
        assert got.reasons[-1]["calls"] == 1  # only calls that reached a model are counted
    with pytest.raises(Defer):  # the first call of an ask still defers the run
        await run(agent(privacy, Model(NoCapacity(until, "day limit"))))


async def test_a_specialist_reply_is_repaired_too(privacy: Privacy) -> None:
    notes = json.dumps({"notes": "proxy says x"})
    model = Model(say(consult=["proxy"]), "sorry, here are my notes", notes, say())
    got = await run(agent(privacy, model))
    assert got.outcome == "true_positive"
    assert [c.instructions.startswith(AGENTS.by_name["proxy"].prompt) for c in model.calls] == [
        False, True, True, False]  # fmt: skip
    assert "could not be read" in model.calls[2].instructions
    assert model.calls[3].instructions.endswith("proxy: proxy says x")
    assert got.reasons[-1]["specialists"] == [{"domain": "proxy", "notes": "proxy says x"}]


async def test_a_specialist_object_is_readable_even_when_empty(privacy: Privacy) -> None:
    model = Model(say(consult=["proxy"]), json.dumps({"notes": ""}), say())
    await run(agent(privacy, model))
    assert len(model.calls) == 2  # nothing to repair, and no second answer without notes


async def test_a_second_answer_that_cannot_be_read_keeps_the_first(privacy: Privacy) -> None:
    model = Model(say(consult=["proxy"]), json.dumps({"notes": "n"}), "junk")
    got = await run(agent(privacy, model))
    assert got.outcome == "true_positive"  # not "no usable answer": the first one stands
    assert len(model.calls) == 5  # coordinator, specialist, then the junk, its repair and retry


# -- the reading -------------------------------------------------------------------------------


def low() -> dict[str, Any]:
    quiet = body(facts={**body()["facts"], "severity": "low"})
    quiet["signals"] = [{"name": "ti.listed", "status": "known", "value": 0}]
    return quiet


async def test_an_inconclusive_answer_is_kept_as_a_reading(privacy: Privacy) -> None:
    tok = token(privacy, "10.20.3.4")
    model = Model(say(outcome="inconclusive", confidence=0.4, reason=f"{tok} unclear",
                      cites=["severity high", "made up"]))  # fmt: skip
    got = await run(agent(privacy, model))
    assert (got.outcome, got.confidence) == (None, None)  # no proposal, no score
    assert got.reasons[:2] == ["10.20.3.4 unclear", "the agent could not decide"]
    report = got.reasons[-1]
    assert report["reading"] == {"kind": "undecided", "checked": [True, False]}
    assert report["answer"]["outcome"] == "inconclusive"
    assert report["answer"]["confidence"] == 0.4
    assert report["answer"]["explanation"] == "10.20.3.4 unclear"


async def test_an_invented_fact_leaves_a_reading_with_each_fact_marked(privacy: Privacy) -> None:
    model = Model(say(cites=["severity high", "made up", "also invented"]))
    got = await run(agent(privacy, model))
    assert (got.outcome, got.confidence) == (None, None)
    assert got.reasons[1].startswith("a cited fact is not in the item (true_positive): ")
    assert got.reasons[-1]["reading"] == {"kind": "citation", "checked": [True, False, False]}
    none = await run(agent(privacy, Model(say(cites=[]))))
    assert none.reasons[-1]["reading"] == {"kind": "citation", "checked": []}


async def test_a_benign_answer_on_quoted_text_alone_leaves_a_reading(privacy: Privacy) -> None:
    model = Model(say(outcome="benign_expected", cites=["Proxy: beacon from"]))
    got = await run(agent(privacy, model), low())
    assert got.outcome is None
    assert got.reasons[1].startswith("a benign answer must cite ARGUS's own words")
    assert got.reasons[-1]["reading"] == {"kind": "benign_citation", "checked": [True]}


async def test_a_floor_block_leaves_a_reading_with_what_blocked_it(privacy: Privacy) -> None:
    model = Model(say(outcome="benign_expected", confidence=0.9))
    got = await run(agent(privacy, model))
    assert (got.outcome, got.confidence) == (None, None)
    assert got.reasons[1] == "floor: threat lists not checked; severity high"
    assert got.reasons[-1]["reading"] == {
        "kind": "floor", "checked": [True], "blocked": ["threat lists not checked",
                                                        "severity high"],
    }  # fmt: skip


async def test_proposals_and_empty_runs_leave_no_reading(privacy: Privacy) -> None:
    proposal = await run(agent(privacy, Model(say())))
    assert proposal.outcome == "true_positive"
    assert "reading" not in proposal.reasons[-1]
    model = Model(say(outcome="benign_expected", cites=["severity low"]))
    benign = await run(agent(privacy, model), low())
    assert benign.outcome == "benign_expected"
    assert "reading" not in benign.reasons[-1]
    assert "reading" not in (await run(agent(privacy, Model(Refused("x"))))).reasons[-1]
    assert "reading" not in (await run(agent(privacy, Model(say(outcome="x"))))).reasons[-1]


async def test_a_reading_is_never_a_proposal_for_the_gold_run(privacy: Privacy) -> None:
    """The measure reads the outcome and the second reason, which the reading leaves as they
    were: decided and cites-failed come out as they did before AR1."""
    cases = [
        (Model(say(outcome="inconclusive")), None, (False, False)),
        (Model(say(cites=["made up"])), None, (True, True)),
        (Model(say(outcome="benign_expected", cites=["Proxy: beacon from"])), low(), (True, True)),
        (Model(say(outcome="benign_expected")), None, (True, False)),
        (Model(say(outcome="x")), None, (False, False)),
    ]  # fmt: skip
    for model, item, expected in cases:
        got = await run(agent(privacy, model), item)
        assert got.outcome is None
        assert got.confidence is None
        entry = {"outcome": got.outcome, "reasons": list(got.reasons)}
        assert agent_eval.judged(entry) == expected
        scored = agent_eval.verdict_measure({"i": entry}, "m", 0)
        assert scored["verdicts"]["i"]["outcome"] is None


# -- the module --------------------------------------------------------------------------------


def stored(kind: str = "floor", **over: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "answer": {"outcome": "benign_expected", "confidence": 0.8, "explanation": "why",
                   "cites": ["severity high", "made up"]},
        "reading": {"kind": kind, "checked": [True, False], "blocked": ["severity high"]},
    }  # fmt: skip
    report.update(over)
    return report


def test_a_stored_reading_is_said_in_plain_words() -> None:
    r = reading.of(stored())
    assert r is not None
    assert r.headline() == (
        "ARGUS's reading: benign, expected activity (80%) — not proposed because"
        " a safety check needs a person: the severity is high"
    )
    assert r.reason == "why"
    assert [(f.text, f.checked) for f in r.facts] == [("severity high", True), ("made up", False)]
    assert r.why(["on a threat list", "something new"]) == (
        "a safety check needs a person: it is on a threat list; something new"
    )
    plain = {
        "undecided": "the evidence did not settle it",
        "citation": "it quoted something that is not in the evidence",
    }
    for kind, why in plain.items():
        got = reading.of(stored(kind))
        assert got is not None
        assert got.why() == why
        assert got.headline().endswith(f"not proposed because {why}")
    benign = reading.of(stored("benign_citation"))
    assert benign is not None
    assert "only from quoted log or alert text" in benign.why()


def test_every_floor_part_has_plain_words() -> None:
    from argus.assess import engine
    from argus.report.render import FLOOR_KEPT

    assert set(reading.BLOCKED_WORDS) >= FLOOR_KEPT
    unknown = [{"name": n, "status": "unknown"} for n in
               ("ti.listed", "ti.listed_remote", "web.successes_after", "ports.risky",
                "proxy.regularity", "proxy.hosts_to_destination")]  # fmt: skip
    bad = [{"name": "ti.listed", "status": "known", "value": 2},
           {"name": "ti.listed_remote", "status": "known", "value": 2},
           {"name": "web.successes_after", "status": "known", "value": 2},
           {"name": "ports.risky", "status": "known", "value": 2},
           {"name": "proxy.regularity", "status": "known", "value": 0.0},
           {"name": "proxy.hosts_to_destination", "status": "known", "value": 1}]  # fmt: skip
    seen: set[str] = set()
    for signals in ([], unknown, bad):
        for severity in ("high", "critical", "low"):
            item = {"signals": signals, "facts": {"severity": severity}}
            for first, spike in ((True, True), (None, None), (False, False)):
                seen.update(engine.floor(item, first, spike))
    assert seen
    assert seen <= set(reading.BLOCKED_WORDS), seen - set(reading.BLOCKED_WORDS)


@pytest.mark.parametrize(
    "report",
    [None, {}, [], "x", {"answer": {"outcome": "true_positive"}},
     {"reading": {"kind": "floor"}}, stored(answer={"outcome": "Malicious"}),
     stored("nonsense"), stored(answer=[]), stored(reading="floor"), stored(reading={"kind": []})],
)  # fmt: skip
def test_no_reading_without_a_kind_and_an_outcome(report: Any) -> None:
    assert reading.of(report) is None


def test_a_reading_reads_odd_stored_values_safely() -> None:
    r = reading.of(
        stored(
            answer={
                "outcome": "inconclusive",
                "confidence": 10**400,
                "explanation": 5,
                "cites": ["a", 3, None],
            },
            reading={"kind": "undecided", "checked": "yes", "blocked": [1, "x"]},
        )
    )
    assert r is not None
    assert (r.confidence, r.reason) == (None, None)
    assert [(f.text, f.checked) for f in r.facts] == [("a", False)]
    assert r.blocked == ("x",)
    assert r.headline() == (
        "ARGUS's reading: inconclusive — not proposed because the evidence did not settle it"
    )
    short = reading.of(stored(reading={"kind": "citation", "checked": [True]}))
    assert short is not None
    assert [f.checked for f in short.facts] == [True, False]
    bare = reading.of(stored(reading={"kind": "floor"}))
    assert bare is not None
    assert bare.why() == "a safety check needs a person"


def test_a_run_from_before_ar1_gets_its_reading_from_its_refusal() -> None:
    answer = {"outcome": "benign_expected", "confidence": 0.7, "explanation": "campus",
              "cites": ["a", "b"]}  # fmt: skip
    report = {"answer": answer}
    floor = reading.of(report, ["campus", "floor: severity high; a volume spike"])
    assert floor is not None
    assert (floor.kind, floor.blocked) == ("floor", ("severity high", "a volume spike"))
    assert [(f.text, f.checked) for f in floor.facts] == [("a", True), ("b", True)]
    cited = reading.of(report, ["x", "a cited fact is not in the item (benign_expected): 'b'"])
    assert cited is not None
    assert (cited.kind, cited.facts) == ("citation", ())  # which were found is not known
    benign = reading.of(report, ["a benign answer must cite ARGUS's own words, not only quoted"])
    assert benign is not None
    assert benign.kind == "benign_citation"
    assert len(benign.facts) == 2
    undecided = reading.of({"answer": {**answer, "outcome": "inconclusive"}},
                            ["x", "the agent could not decide"])  # fmt: skip
    assert undecided is not None
    assert (undecided.kind, undecided.facts) == ("undecided", ())
    assert reading.of(report, ["no usable answer from the model"]) is None
    assert reading.of(report) is None
    assert reading.of({}, ["floor: x"]) is None


def test_a_non_string_cite_does_not_shift_the_marks() -> None:
    report = {"answer": {"outcome": "benign_expected", "cites": [5, "kept"]},
              "reading": {"kind": "floor", "checked": [False, True]}}  # fmt: skip
    got = reading.of(report)
    assert got is not None
    assert [(f.text, f.checked) for f in got.facts] == [("kept", True)]
