"""P2: the gold set's selection and pre-filled suggestions (D-080)."""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest

from argus.evaluation import gold
from argus.evaluation.gold import Candidate, flags, manifest, select, split, suggest

pytestmark = pytest.mark.unit


def body(
    signals: dict[str, Any] | None = None, unknown: tuple[str, ...] = (), steps: str = "a"
) -> dict[str, Any]:
    sig = [{"name": n, "status": "known", "value": v} for n, v in (signals or {}).items()]
    sig += [{"name": n, "status": "unknown", "value": None} for n in unknown]
    return {"signals": sig, "report": {"steps": [{"number": 1, "status": steps}]},
            "facts": {"group_key": '[["source.ip", "1.2.3.4"]]'}}  # fmt: skip


def cand(
    n: int, rule: str = "r", day: int = 14, labels: tuple[Any, ...] = (), **kw: Any
) -> Candidate:
    given = kw.pop("b", None)
    content = given if given is not None else body(**kw)
    return Candidate(f"id{n}", 1, "generic@12", "h" * 64, rule + "-id", rule,
                     date(2026, 10, day), content, labels)  # fmt: skip


def test_flags() -> None:
    assert flags(body({"ti.listed": 1})) == ("on a threat list",)
    assert flags(body({"ti.listed_remote": 2, "web.successes_after": 3})) == (
        "on a threat list", "successful answers after the alert",
    )  # fmt: skip
    assert flags(body({"proxy.regularity": 0.29, "ports.risky": 1})) == (
        "regular traffic, like a beacon", "remote-admin, P2P or anonymizer ports",
    )  # fmt: skip
    assert flags(body({"proxy.regularity": 0.3, "ti.listed": 0, "ports.risky": True})) == ()
    assert flags(body(unknown=("ti.listed",))) == ()


@pytest.mark.parametrize(("day", "part"), [(11, "dev"), (12, "test"), (15, "test"), (7, "dev")])
def test_split(day: int, part: str) -> None:
    assert split(date(2026, 10, day)) == part


def test_people_and_true_positives_are_always_chosen() -> None:
    pool = [cand(n, steps=str(n % 3)) for n in range(40)]
    pool[7] = cand(7, labels=(("devuser", "benign_expected", None),))
    pool[9] = cand(9, labels=((gold.ASSISTANT, "true_positive", "c2"),))
    chosen = {i.candidate.investigation_id: i.why for i in select(pool)}
    assert chosen["id7"] == ("labelled by a person",)
    assert chosen["id9"] == ("labelled a true positive",)
    assert len(chosen) == 5


def test_quotas_are_per_rule_name_and_small_rules_go_whole() -> None:
    pool = [cand(n, rule="big", steps=str(n % 4)) for n in range(30)]
    pool += [cand(100 + n, rule="small") for n in range(2)]
    twin = [Candidate(f"t{n}", 1, "p", "h", "other-id", "big", date(2026, 10, 14), body(), ())
            for n in range(5)]  # fmt: skip
    items = select(pool + twin)
    per_rule: dict[str, int] = {}
    for item in items:
        per_rule[item.candidate.rule_name] = per_rule.get(item.candidate.rule_name, 0) + 1
    assert per_rule == {"big": 5, "small": 2}


def test_kinds_and_flags_come_first_and_the_choice_is_stable() -> None:
    pool = [cand(n, steps="same") for n in range(20)]
    pool += [cand(50, steps="rare"), cand(51, signals={"ti.listed": 1})]
    first = [i.candidate.investigation_id for i in select(pool)]
    again = [i.candidate.investigation_id for i in select(list(reversed(pool)))]
    assert first == again
    assert "id50" in first
    assert "id51" in first
    why = {i.candidate.investigation_id: i.why for i in select(pool)}
    assert why["id51"] == ("signals: on a threat list",)
    assert why["id50"][0].startswith("a kind of this rule")


def test_days_alternate_within_a_kind() -> None:
    pool = [cand(n, day=7 + n) for n in range(9)]
    days = sorted(i.candidate.day.day for i in select(pool))
    assert days[0] == 7
    assert days[-1] == 15


@pytest.mark.parametrize(
    ("signals", "unknown", "assistant", "outcome", "source"),
    [
        ({}, (), ("benign_policy", "approved scan"), "benign_policy", "assistant label"),
        ({"ti.listed": 1}, (), None, "true_positive", "signals"),
        ({"web.successes_after": 2}, (), None, "inconclusive", "signals"),
        ({}, ("ti.listed",), None, "inconclusive", "signals"),
        ({}, (), None, "benign_expected", "signals"),
    ],
)
def test_suggestions(signals: dict[str, Any], unknown: tuple[str, ...], assistant: Any,
                     outcome: str, source: str) -> None:  # fmt: skip
    s = suggest(body(signals, unknown), assistant)
    assert (s.outcome, s.source) == (outcome, source)
    assert s.reasons


def test_suggestion_reasons() -> None:
    assert suggest(body({"ti.listed": 1}), ("true_positive", " c2 seen ")).reasons == (
        "c2 seen", "on a threat list",
    )  # fmt: skip
    assert suggest(body(), ("inconclusive", None)).reasons == ()
    assert suggest(body(unknown=("b", "a", "c", "d", "e")), None).reasons == (
        "could not be told: a, b, c, d",
    )  # fmt: skip


def test_the_manifest_holds_no_dossier_text() -> None:
    c = cand(1, signals={"ti.listed": 1}, labels=(("devuser", "true_positive", "seen"),))
    record = manifest(select([c]))[0]
    assert record == {
        "investigation_id": "id1", "version": 1, "pack": "generic@12", "dossier_hash": "h" * 64,
        "rule_id": "r-id", "rule_name": "r", "day": "2026-10-14", "split": "test",
        "why": ["labelled by a person", "labelled a true positive"],
        "suggestion": {"outcome": "true_positive", "reasons": ["on a threat list"],
                       "source": "signals"},
        "person": "true_positive",
    }  # fmt: skip


def test_constants() -> None:
    assert (gold.SEED, gold.ASSISTANT, gold.PER_RULE, gold.POSITIVE) == (
        "gold-v1", "argus-assistant", 5, "true_positive",
    )  # fmt: skip
    with pytest.raises(AttributeError):
        cand(1).version = 2  # type: ignore[misc]


def test_the_newest_label_of_each_kind() -> None:
    c = cand(1, labels=((gold.ASSISTANT, "a", "n1"), ("devuser", "b", None),
                        (gold.ASSISTANT, "c", "n3"), ("ravi", "d", "n4")))  # fmt: skip
    assert c.assistant == ("c", "n3")
    assert c.human == ("d", "n4")
    assert cand(2).assistant is None


def test_local_signals_and_unknown_values_count_as_written() -> None:
    local = {"local_signals": [{"name": "ti.listed", "status": "known", "value": 1}]}
    assert flags(local) == ("on a threat list",)
    unknown = {"signals": [{"name": "ti.listed", "status": "unknown", "value": 5}]}
    assert flags(unknown) == ()
    assert flags({"signals": ["x", {"name": 3}]}) == ()


def stepped(value: str, key: str = '[["source.ip", "1.2.3.4"]]') -> dict[str, Any]:
    return {
        "report": {"steps": [{"number": 1, "status": "answered", "fields": ["source.ip", "url"]}]},
        "context": {"pack": {"fields": {"source.ip": {"distinct": 1, "top": [[value, 1]]},
                                        "url": {"distinct": 1, "top": [["/a", 1]]}}}},
        "facts": {"group_key": key},
    }  # fmt: skip


def test_the_kind_leaves_out_the_grouping_key() -> None:
    a, b = cand(1, b=stepped("1.1.1.1")), cand(2, b=stepped("2.2.2.2"))
    assert gold._signature(a) == gold._signature(b)  # source.ip is the key: not a kind
    c = cand(3, b=stepped("1.1.1.1", key="not json ["))
    d = cand(4, b=stepped("2.2.2.2", key='["x"'))
    assert gold._signature(c) != gold._signature(d)  # no readable key: source.ip counts
    e = cand(5, b=stepped("1.1.1.1", key='[["source.ip", "x"], "y", []]'))
    assert gold._signature(e) == gold._signature(a)


def test_threat_list_hits_take_half_the_quota() -> None:
    pool = [cand(n, signals={"ti.listed": 1}) for n in range(6)] + [cand(9, steps="b")]
    why = [i.why for i in select(pool)]
    assert sum(w[0].startswith("signals: ") for w in why) == 2
    assert len(why) == 5
    one = [i.why for i in select(pool, per_rule=1)]
    assert one == [("signals: on a threat list",)]


def test_the_choice_within_a_kind_alternates_early_and_late() -> None:
    pool = [cand(n, day=7 + n) for n in range(9)]
    chosen = sorted(i.candidate.day.day for i in select(pool, per_rule=4))
    assert chosen == [7, 8, 14, 15]
    why = {i.candidate.day.day: i.why for i in select(pool, per_rule=4)}
    assert why[7] == ("a kind of this rule (9 alike)",)
    assert why[15] == ("a kind of this rule (8 alike)",)


def test_kinds_are_taken_round_robin_largest_first() -> None:
    pool = [cand(n, steps="big") for n in range(6)] + [
        cand(10 + n, steps="small") for n in range(2)
    ]
    small = {"id10", "id11"}
    kinds = [i.candidate.investigation_id in small for i in select(pool, per_rule=4)]
    assert sum(kinds) == 2  # two of each kind, not four of the largest


def test_suggestion_texts() -> None:
    assert suggest(body({"web.successes_after": 1}), None).reasons == (
        "successful answers after the alert", "needs a person's look",
    )  # fmt: skip
    assert suggest(body(), None).reasons == ("no threat-list hit, success or beacon seen",)
    assert suggest({"signals": [{"name": "z", "status": "unknown"}]}, None).reasons == (
        "could not be told: z",
    )  # fmt: skip


def test_the_body_is_left_out_of_equality_and_repr_and_items_are_frozen() -> None:
    import dataclasses

    a = cand(1, b={"secret": "s3cr3t-text"})
    b = cand(1, b={"other": 1})
    assert a == b
    assert "s3cr3t-text" not in repr(a)
    (item,) = select([a])
    with pytest.raises(dataclasses.FrozenInstanceError):
        item.split = "x"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        suggest(body(), None).outcome = "x"  # type: ignore[misc]


def test_a_missing_grouping_key_is_no_key() -> None:
    plain = cand(1, b={**stepped("1.1.1.1"), "facts": {}})
    other = cand(2, b={**stepped("2.2.2.2"), "facts": {}})
    assert gold._signature(plain) != gold._signature(other)  # no key: source.ip counts


def test_flags_are_joined_in_why() -> None:
    c = cand(1, signals={"ti.listed": 1, "web.successes_after": 2})
    assert select([c])[0].why == ("signals: on a threat list, successful answers after the alert",)


def test_the_quota_stops_in_the_middle_of_a_round() -> None:
    pool = [cand(n, steps=f"kind{n % 3}") for n in range(9)]  # three kinds of three
    assert len(select(pool, per_rule=4)) == 4


def test_the_early_late_order_within_a_kind() -> None:
    pool = [cand(n, day=7 + n) for n in range(9)]
    picked = [i.candidate.day.day for i in select(pool, per_rule=3)]
    assert sorted(picked) == [7, 8, 15]  # first, last, first again


def test_known_signals_that_flag_nothing_suggest_benign() -> None:
    s = suggest(body({"proxy.regularity": 0.9}), None)
    assert (s.outcome, s.source) == ("benign_expected", "signals")


def test_extend_takes_benign_suggestions_rule_by_rule_then_the_short_rule() -> None:
    hit = {"ti.listed": 1}
    pool = [
        *(cand(n, rule="a") for n in range(5)),
        *(cand(10 + n, rule="b") for n in range(2)),
        cand(20, rule="c", signals=hit),  # suggested true positive: not benign
        *(cand(30 + n, rule="dns", signals=hit) for n in range(4)),
    ]
    items = gold.extend(pool, exclude={"id0"}, benign=5, rule="dns", rule_count=3)
    ids = [i.candidate.investigation_id for i in items]
    benign = [i for i in items if i.why == ("suggested benign (criterion 3)",)]
    assert len(benign) == 5
    assert "id0" not in ids
    assert "id20" not in ids
    assert sorted(i.candidate.rule_name for i in benign) == ["a", "a", "a", "b", "b"]
    assert [i.why for i in items if i.candidate.rule_name == "dns"] == [
        ("a rule short of labels (D-080)",)
    ] * 3
    assert items == gold.extend(list(reversed(pool)), {"id0"}, 5, "dns", 3)  # stable
    assert [i.split for i in items] == ["test"] * 8
    assert gold.extend(pool, set(), benign=0) == []


def test_extend_stops_when_the_benign_pool_runs_out() -> None:
    items = gold.extend([cand(1), cand(2, rule="x")], exclude=(), benign=40)
    assert len(items) == 2
