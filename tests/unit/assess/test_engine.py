"""P4 (D-085): keys, their qualification, the floor, and decisions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from argus.assess import engine
from argus.assess.engine import Label, Learned, decide, floor, keys, qualified

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 16, tzinfo=UTC)


def body(
    statuses: str = "answered", value: str = "/x", distinct: int = 1, **signals: Any
) -> dict[str, Any]:
    sig = [
        {"name": n, "status": "unknown" if v == "?" else "known", "value": None if v == "?" else v}
        for n, v in signals.items()
    ]
    return {
        "facts": {"rule_name": "R", "severity": "low", "group_key": '[["source.ip", "1.2.3.4"]]'},
        "report": {"steps": [{"number": 1, "status": statuses, "fields": ["url", "source.ip"]}]},
        "context": {"pack": {"fields": {
            "url": {"distinct": distinct, "top": [[value, 3]]},
            "source.ip": {"distinct": 1, "top": [["1.2.3.4", 3]]}}}},
        "signals": sig,
    }  # fmt: skip


CLEAR = {"ti.listed": 0}


def labels(outcome: str, n: int, age: int = 1, other: str | None = None) -> list[Label]:
    out = [Label(outcome, NOW - timedelta(days=age)) for _ in range(n)]
    return out + ([Label(other, NOW)] if other else [])


def test_keys() -> None:
    assert keys(body()) == [("steps", "R", "1:answered"), ("field", "R", "url", "/x")]
    assert keys(body(distinct=4)) == [("steps", "R", "1:answered")]  # too many values
    assert keys({"facts": {"rule_id": "r1"}}) == []
    bad_key = body()
    bad_key["facts"]["group_key"] = "not json"
    assert ("field", "R", "source.ip", "1.2.3.4") in keys(bad_key)


@pytest.mark.parametrize(
    ("given", "decides"),
    [
        (labels("benign_expected", 5), "benign_expected"),
        (labels("benign_expected", 4), None),  # support
        (labels("benign_expected", 5, age=31), None),  # too old
        (labels("benign_expected", 19, other="inconclusive"), "benign_expected"),  # 95%
        (labels("benign_expected", 18, other="inconclusive"), None),  # 94.7%
        (labels("benign_expected", 30, other="true_positive"), None),  # a TP vetoes benign
        (labels("true_positive", 30, other="benign_expected"), "true_positive"),
    ],
)
def test_qualification(given: list[Label], decides: str | None) -> None:
    assert qualified(given, NOW) == decides


@pytest.mark.parametrize(
    ("signals", "severity", "first", "spike", "blocked"),
    [
        (CLEAR, "low", False, False, []),
        ({}, "low", False, False, ["threat lists not checked"]),
        ({"ti.listed": 1}, "low", False, False, ["on a threat list"]),
        ({"ti.listed": "?"}, "low", False, False, ["ti.listed not known"]),
        ({**CLEAR, "ti.listed_remote": 2}, "low", False, False, ["on a threat list"]),
        ({**CLEAR, "web.successes_after": 1}, "low", False, False,
         ["successful answers after the alert"]),
        ({**CLEAR, "web.successes_after": "?"}, "low", False, False,
         ["web.successes_after not known"]),
        ({**CLEAR, "ports.risky": 1}, "low", False, False,
         ["remote-admin, P2P or anonymizer ports"]),
        ({**CLEAR, "proxy.regularity": 0.29}, "low", False, False, ["regular like a beacon"]),
        ({**CLEAR, "proxy.regularity": 0.3}, "low", False, False, []),
        ({**CLEAR, "proxy.regularity": "?"}, "low", False, False, ["proxy.regularity not known"]),
        ({**CLEAR, "proxy.hosts_to_destination": 1}, "low", False, False,
         ["a destination few campus hosts reach"]),
        ({**CLEAR, "proxy.hosts_to_destination": 2}, "low", False, False, []),
        ({**CLEAR, "proxy.hosts_to_destination": "?"}, "low", False, False,
         ["destinations not known"]),
        (CLEAR, "High", False, False, ["severity high"]),
        (CLEAR, "critical", False, False, ["severity critical"]),
        (CLEAR, "low", True, False, ["an entity seen for the first time"]),
        (CLEAR, "low", None, False, ["first-seen not known"]),
        (CLEAR, "low", False, True, ["a volume spike"]),
        (CLEAR, "low", False, None, ["volume baseline not known"]),
    ],
)  # fmt: skip
def test_the_floor(signals: dict[str, Any], severity: str, first: bool | None,
                   spike: bool | None, blocked: list[str]) -> None:  # fmt: skip
    b = body(**signals)
    b["facts"]["severity"] = severity
    assert floor(b, first, spike) == blocked


def learned(**by_key: list[Label]) -> Learned:
    out = Learned()
    for name, given in by_key.items():
        out.by_key[("steps", "R", "1:answered") if name == "steps" else
                   ("field", "R", "url", "/x")] = given  # fmt: skip
    return out


def test_decisions() -> None:
    assert decide(body(**CLEAR), Learned(), NOW, False, False).reasons == [
        "no key with enough consistent human labels"]  # fmt: skip
    benign = decide(body(**CLEAR), learned(steps=labels("benign_expected", 5)), NOW, False, False)
    assert benign.outcome == "benign_expected"
    assert benign.key == ("steps", "R", "1:answered")
    assert benign.reasons == ["key steps / R / 1:answered: 5 human labels, all or nearly all"
                              " benign_expected"]  # fmt: skip
    blocked = decide(body(**{"ti.listed": 1}), learned(steps=labels("benign_expected", 5)), NOW,
                     False, False)  # fmt: skip
    assert blocked.outcome is None
    assert blocked.reasons[1] == "floor: on a threat list"
    tp = decide(body(**{"ti.listed": 1}), learned(steps=labels("true_positive", 5)), NOW, True,
                True)  # fmt: skip
    assert tp.outcome == "true_positive"  # the floor never stops a true positive
    both = learned(steps=labels("benign_expected", 5), field=labels("rule_false_positive", 5))
    assert decide(body(**CLEAR), both, NOW, False, False).reasons == [
        "keys disagree: benign_expected, rule_false_positive"]  # fmt: skip


def test_the_fingerprint_follows_the_labels() -> None:
    a = learned(steps=labels("benign_expected", 5))
    b = learned(steps=labels("benign_expected", 5))
    c = learned(steps=labels("benign_expected", 6))
    assert a.fingerprint() == b.fingerprint() != c.fingerprint()
    assert len(a.fingerprint()) == 12
    assert engine.MIN_SUPPORT == 5
    assert engine.MIN_AGREEMENT == 0.95
    assert timedelta(days=30) == engine.MAX_AGE
    assert engine.NAME == "engine@1"


def steps_body(facts: dict[str, Any], *statuses: str) -> dict[str, Any]:
    steps = [{"number": n, "status": s} for n, s in enumerate(statuses, 1)]
    return {"facts": facts, "report": {"steps": steps}}


def test_the_rule_names_a_key() -> None:
    assert keys(steps_body({"rule_id": "r1"}, "answered")) == [("steps", "r1", "1:answered")]
    assert keys(steps_body({}, "answered")) == [("steps", "?", "1:answered")]
    assert keys(steps_body({"rule_name": "R", "rule_id": "r1"}, "answered", "empty")) == [
        ("steps", "R", "1:answered,2:empty")]  # fmt: skip


def test_odd_group_keys_and_values() -> None:
    odd = body()
    odd["facts"]["group_key"] = '[[], 5, ["source.ip", "1.2.3.4"]]'  # junk pairs are skipped
    assert keys(odd) == keys(body())
    assert keys(body(distinct=3)) == [("steps", "R", "1:answered"), ("field", "R", "url", "/x")]
    no_count = body()
    del no_count["context"]["pack"]["fields"]["url"]["distinct"]
    assert keys(no_count) == keys(body())


def test_signals_come_from_both_lists_and_junk_is_ignored() -> None:
    b = body(**CLEAR)
    b["local_signals"] = ["junk", None, {"name": 7}, {"status": "known"},
                          {"name": "ports.risky", "status": "known", "value": 2}]  # fmt: skip
    assert floor(b, False, False) == ["remote-admin, P2P or anonymizer ports"]
    b["signals"] = []
    assert "threat lists not checked" in floor(b, False, False)


@pytest.mark.parametrize("name", ["ports.risky", "web.successes_after", "ti.listed_remote"])
@pytest.mark.parametrize("value", [0, None])
def test_a_known_zero_is_clear(name: str, value: Any) -> None:
    b = body(**CLEAR)
    b["signals"].append({"name": name, "status": "known", "value": value})
    assert floor(b, False, False) == []


def test_a_key_of_exactly_the_maximum_age_still_decides() -> None:
    assert qualified(labels("benign_expected", 5, age=30), NOW) == "benign_expected"


def test_the_floor_names_every_reason() -> None:
    b = body(**{"ti.listed": 1})
    d = decide(b, learned(steps=labels("benign_expected", 5)), NOW, True, False)
    assert d.reasons[1] == "floor: on a threat list; an entity seen for the first time"
    assert d.key == ("steps", "R", "1:answered")


def test_labels_and_decisions_are_values() -> None:
    from dataclasses import FrozenInstanceError

    with pytest.raises(FrozenInstanceError):
        Label("x", NOW).outcome = "y"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        engine.Decision(None, []).outcome = "y"  # type: ignore[misc]


def test_describe() -> None:
    given = learned(steps=labels("benign_expected", 5), field=labels("true_positive", 2))
    assert list(engine.describe(given, NOW)) == [
        (("field", "R", "url", "/x"), 2, None),
        (("steps", "R", "1:answered"), 5, "benign_expected"),
    ]
