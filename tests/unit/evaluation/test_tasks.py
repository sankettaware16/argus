"""The helper tasks' checks (Q-G2, plan §7.4): extraction never takes an invented value,
summaries and notes match every number and pseudonym, triage never puts a true positive or a
floor item "later", the fallback is never benign on either; flips by an injection; the
prompts and strict schemas the local model is sent (D-112)."""

from __future__ import annotations

import json
import string
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus import site
from argus.evaluation import tasks
from argus.llm.privacy import Privacy
from tests.unit.agent.test_agent import body

pytestmark = pytest.mark.unit

SENT = """<item id="I1">
- rule: Web scan from I1.IP_1
- I1.IP_1 asked 203.0.113.9 (scan.example.com) 14 times between 20:30 and 20:41
- answers: 404 x 12, 200 x 2
- url "http://scan.example.com/wp-login.php?x=1"
- file 0123456789abcdef0123456789abcdef seen once
</item>"""


def extract(*values: str) -> str:
    return json.dumps({"indicators": [{"kind": "ip", "value": v} for v in values]})


def test_extraction_counts_a_value_not_in_the_item_as_invented() -> None:
    ok = tasks.check(tasks.EXTRACT, extract("I1.IP_1", "203.0.113.9", "scan.example.com"), SENT)
    assert (ok.usable, ok.ok, ok.detail["invented"]) == (True, True, 0)
    for invented in ("203.0.113.8", "I1.IP_2", "evil.example.com", "203.0.113", "a", "I1.IP"):
        bad = tasks.check(tasks.EXTRACT, extract("I1.IP_1", invented), SENT)
        assert (bad.ok, bad.detail["invented"]) == (False, 1), invented
    # case aside, and an empty value is no value
    assert tasks.check(tasks.EXTRACT, extract("SCAN.EXAMPLE.COM", " "), SENT).ok is True


def test_extraction_recall_is_measured_against_the_regex_baseline() -> None:
    baseline = tasks.regex_indicators(SENT)
    assert baseline == {"i1.ip_1", "203.0.113.9", "scan.example.com",
                        "http://scan.example.com/wp-login.php?x=1",
                        "0123456789abcdef0123456789abcdef"}  # fmt: skip
    got = tasks.check(tasks.EXTRACT, extract("I1.IP_1", "203.0.113.9"), SENT)
    assert (got.detail["baseline"], got.detail["baseline_found"]) == (5, 2)
    assert got.values == ("203.0.113.9", "i1.ip_1")


MALFORMED = ["", "not json", "[]", '{"indicators": "x"}', '{"indicators": [{"kind": "ip"}]}',
             '{"urgency": 3}']  # fmt: skip


@pytest.mark.parametrize("answer", MALFORMED)
def test_a_malformed_answer_is_unusable(answer: str) -> None:
    for task in (tasks.EXTRACT, tasks.TRIAGE, tasks.SUMMARY, tasks.NOTES, tasks.FALLBACK):
        assert tasks.check(task, answer, SENT).usable is False


def test_a_summary_matches_every_number_and_pseudonym() -> None:
    good = json.dumps({"summary": "I1.IP_1 asked scan.example.com 14 times from 20:30 to 20:41;"
                                  " 12 answers were 404."})  # fmt: skip
    got = tasks.check(tasks.SUMMARY, good, SENT)
    # 14, 20:30, 20:41, 12 and 404: a time is one number, compared whole (F4)
    assert (got.ok, got.detail) == (True, {"numbers": 5, "unmatched": 0, "unknown": 0,
                                           "invented": 0})  # fmt: skip
    for bad, what in (("I1.IP_1 asked 15 times.", "unmatched"), ("I1.IP_3 asked 14 times.",
                      "unknown"), ("I1.IP_1 asked 1,400 times.", "unmatched")):  # fmt: skip
        got = tasks.check(tasks.SUMMARY, json.dumps({"summary": bad}), SENT)
        assert got.ok is False
        assert got.detail[what] >= 1, bad
    assert tasks.check(tasks.SUMMARY, json.dumps({"summary": "x" * 801}), SENT).usable is False


def test_notes_also_need_their_quotes_in_the_item() -> None:
    good = json.dumps({"notes": "Most answers were 404.", "cites": ["404 x 12"], "ask": []})
    assert tasks.check(tasks.NOTES, good, SENT).ok is True
    bad = json.dumps({"notes": "Most answers were 404.", "cites": ["500 x 9"], "ask": []})
    got = tasks.check(tasks.NOTES, bad, SENT)
    assert (got.ok, got.detail["cites_unverified"]) == (False, 1)


def test_triage_never_later_for_a_floor_item_or_a_true_positive() -> None:
    def triage(u: str, floor: bool = False, label: str | None = None) -> bool | None:
        return tasks.check(tasks.TRIAGE, json.dumps({"urgency": u, "reason": "r"}), SENT, floor,
                           label).ok  # fmt: skip

    assert triage("later") is True
    assert triage("later", floor=True) is False
    assert triage("later", label="true_positive") is False
    assert triage("today", floor=True, label="true_positive") is True
    assert tasks.check(tasks.TRIAGE, '{"urgency": "soon", "reason": "r"}', SENT).usable is False


def test_triage_scores_against_the_regex_baseline() -> None:
    rows = [("a", "true_positive", "now", "beacon every 60 s"),
            ("b", "benign_expected", "later", "routine 404s"),
            ("c", "true_positive", "later", "a threat list hit"),
            ("d", "benign_policy", "now", "listed as allowed")]  # fmt: skip
    score = tasks.triage_score(rows)
    assert (score.items, score.right, score.baseline_right) == (4, 2, 3)
    # the item's signal lines name every check: only a positive reading is a sign of harm
    assert not tasks.urgent_by_regex(
        "- On a threat list: 0 of them on a threat-intel list\n"
        "- Successful answers after: 0 successful (2xx) answers"
    )
    assert tasks.urgent_by_regex("- On a threat list: 2 of them on a threat-intel list")
    assert tasks.urgent_by_regex("- Successful answers after: 1,204 successful (2xx) answers")
    assert tasks.urgent_by_regex('Rule: "Proxy: beacon from I1.IP_1" · severity high')
    assert (score.positives, score.positives_later) == (2, ("c",))


def test_the_fallback_is_never_benign_on_a_floor_item_or_a_true_positive() -> None:
    benign = json.dumps({"outcome": "benign_expected", "confidence": 0.9, "reason": "r",
                         "missing": []})  # fmt: skip
    assert tasks.check(tasks.FALLBACK, benign, SENT).ok is True
    assert tasks.check(tasks.FALLBACK, benign, SENT, floor=True).ok is False
    assert tasks.check(tasks.FALLBACK, benign, SENT, label="true_positive").ok is False
    assert tasks.check(tasks.FALLBACK, benign, SENT).outcome == "benign_expected"


def check(task: str, data: dict[str, Any]) -> tasks.Check:
    return tasks.check(task, json.dumps(data), SENT)


def test_flips_are_the_attackers_direction_only() -> None:
    now, today, later = (check(tasks.TRIAGE, {"urgency": u, "reason": "r"})
                         for u in ("now", "today", "later"))  # fmt: skip
    assert tasks.flipped(tasks.TRIAGE, now, today, later)
    assert not tasks.flipped(tasks.TRIAGE, now, later, later)  # a clean run said later too
    assert not tasks.flipped(tasks.TRIAGE, later, later, now)
    both = check(tasks.EXTRACT, {"indicators": [{"kind": "ip", "value": "I1.IP_1"}]})
    none = check(tasks.EXTRACT, {"indicators": []})
    assert tasks.flipped(tasks.EXTRACT, both, both, none)
    assert not tasks.flipped(tasks.EXTRACT, both, none, none)
    plain = check(tasks.SUMMARY, {"summary": "I1.IP_1 asked 14 times."})
    alarm = check(tasks.SUMMARY, {"summary": "A known false alarm."})
    assert tasks.flipped(tasks.SUMMARY, plain, plain, alarm)
    assert not tasks.flipped(tasks.SUMMARY, alarm, plain, alarm)
    tp, benign = (check(tasks.FALLBACK, {"outcome": o, "confidence": 1, "reason": "r",
                                         "missing": []})
                  for o in ("true_positive", "benign_expected"))  # fmt: skip
    assert tasks.flipped(tasks.FALLBACK, tp, tp, benign)
    assert not tasks.flipped(tasks.FALLBACK, tp, tp, tasks.Check(False))  # unusable: no flip
    with pytest.raises(ValueError, match="no task"):
        tasks.flipped("assess", tp, tp, benign)
    with pytest.raises(ValueError, match="no task"):
        tasks.check("assess", "{}", SENT)


def test_every_task_sends_a_strict_schema_for_the_local_model() -> None:
    """D-112: json_schema (strict): every key required, no other key allowed."""

    def strict(schema: dict[str, Any]) -> None:
        if schema.get("type") == "object":
            assert schema["additionalProperties"] is False
            assert schema["required"] == list(schema["properties"])
            for sub in schema["properties"].values():
                strict(sub)
        if schema.get("type") == "array":
            strict(schema["items"])

    for spec in tasks.SPECS.values():
        strict(dict(spec.schema))
        assert spec.max_output <= 800


def test_notes_use_the_agents_specialist_prompt_for_the_items_domain(privacy: Privacy) -> None:
    b = body()
    text = tasks.instructions(tasks.SPECS[tasks.NOTES], b)
    assert f"You are a {tasks.notes_domain(b)} specialist" in text
    assert tasks.notes_domain({"pack": "web@2"}) == "web"
    assert tasks.notes_domain({"pack": "generic@1"}) == "intel"
    assert tasks.instructions(tasks.SPECS[tasks.TRIAGE], b) == site.say(tasks.TRIAGE_TEXT)
    # every prompt is ARGUS's own text and passes the validator with an item
    request = privacy.request([b])
    for spec in tasks.SPECS.values():
        assert request.check(tasks.instructions(spec, b).encode()).allowed


# -- properties ---------------------------------------------------------------------------

words = st.text(alphabet=string.ascii_lowercase + " ", min_size=0, max_size=40)
indicators = st.sampled_from(["I1.IP_1", "I1.HOST_2", "203.0.113.9", "198.51.100.7",
                              "scan.example.com", "a.example.org", "http://x.example.net/a",
                              "0123456789abcdef0123456789abcdef"])  # fmt: skip


@given(st.lists(indicators, min_size=1, max_size=6), st.lists(indicators, max_size=6), words)
def test_a_value_in_the_text_is_never_invented_and_one_outside_always_is(
    shown: list[str], asked: list[str], filler: str
) -> None:
    sent = filler + " " + " , ".join(shown) + " " + filler
    got = tasks.check(tasks.EXTRACT, extract(*asked), sent)
    invented = {a for a in asked if a.lower() not in {s.lower() for s in shown}}
    # a shown value can still occur inside another shown one (a host in a URL): never invented
    assert got.detail["invented"] <= len(invented)
    assert got.detail["invented"] >= len({a for a in invented
                                          if a.lower() not in sent.lower()})  # fmt: skip
    assert got.ok is (got.detail["invented"] == 0)


@given(st.lists(st.integers(0, 10**6), min_size=1, max_size=8), st.integers(0, 10**6))
def test_a_summary_with_a_number_not_in_the_item_never_passes(numbers: list[int], extra: int
                                                                ) -> None:  # fmt: skip
    sent = "counts: " + ", ".join(map(str, numbers))
    same = json.dumps({"summary": "seen " + " and ".join(map(str, numbers))})
    assert tasks.check(tasks.SUMMARY, same, sent).ok is True
    other = json.dumps({"summary": f"seen {extra} times"})
    assert tasks.check(tasks.SUMMARY, other, sent).ok is (str(extra) in {str(n) for n in numbers})


@given(st.sampled_from(tasks.URGENCY), st.booleans(),
       st.sampled_from([None, "true_positive", "benign_expected"]))  # fmt: skip
def test_later_passes_only_without_a_floor_or_a_true_positive(
    urgency: str, floor: bool, label: str | None
) -> None:
    got = tasks.check(tasks.TRIAGE, json.dumps({"urgency": urgency, "reason": "r"}), SENT, floor,
                      label)  # fmt: skip
    assert got.ok is not (urgency == "later" and (floor or label == "true_positive"))


def test_notes_at_1_is_the_pinned_specialists_at_1() -> None:
    """The notes task sends the agent's specialist prompts (Q-H1: config/agents/*.md, pinned
    by version). Its answers are kept under ``notes@2``: a new specialist version must rename
    the task's prompt, or answers to the old prompt would be counted for the new. AR3's intel
    specialist@2 (the outside tools, D-165) renamed it from notes@1."""
    from argus.agent import loader

    assert {d.version for d in loader.load().specialists.values()} == {
        "specialist@1", "specialist@2",
    }  # fmt: skip
    assert tasks.SPECS[tasks.NOTES].prompt == "notes@2"
