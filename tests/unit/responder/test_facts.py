"""What a case shows (Q-H2): the facts, and which families they make apply."""

from __future__ import annotations

from typing import Any

import pytest

from argus.responder import catalogue as cat
from argus.responder import facts as fct
from argus.responder.facts import FACTS, Facts

C = cat.load()
BEACON = [("ip", "10.8.235.157", "actor"), ("ip", "77.221.155.150", "c2")]


def keys(facts: Facts) -> list[str]:
    return [f.key for f in fct.match(C, facts)]


def test_a_c2_indicator_is_the_ps1bot_family() -> None:
    facts = fct.from_parts(BEACON, [], [])
    assert facts.present == {"c2_indicator"}
    assert keys(facts) == ["c2_beacon"]
    assert keys(fct.from_parts([("ip", "10.8.235.157", "actor")], [], [])) == []
    assert keys(fct.from_parts([("ip", "77.221.155.150", "indicator")], [], [])) == []


@pytest.mark.parametrize(
    ("path", "fact", "other"),
    [
        ("/.env", "sensitive_file_served", "attack_path_served"),
        ("/%2eenv", "sensitive_file_served", "attack_path_served"),
        ("//.git/config", "sensitive_file_served", "attack_path_served"),
        ("/static/../../etc/passwd", "attack_path_served", "sensitive_file_served"),
        ("/wp-admin/setup.php", "attack_path_served", "sensitive_file_served"),
    ],
)
def test_a_served_path_makes_the_family_of_its_kind(path: str, fact: str, other: str) -> None:
    facts = fct.from_parts([], [], [path])
    assert fact in facts.present
    assert path in facts.paths[fact]
    assert other not in facts.present or path.endswith("config")


def test_a_path_nobody_attacks_with_is_no_fact() -> None:
    assert fct.from_parts([], [], ["/index.html", "/static/app.js"]).present == frozenset()


def doc(category: str, outcome: str) -> dict[str, Any]:
    return {"event.category": [category], "event.outcome": outcome}


def test_a_failed_authentication_in_an_alert_is_brute_force() -> None:
    assert keys(fct.from_parts([], [doc("authentication", "failure")], [])) == ["brute_force"]
    nested = {"event": {"category": ["authentication"], "outcome": "failure"}}
    assert keys(fct.from_parts([], [nested], [])) == ["brute_force"]
    for not_one in (doc("authentication", "success"), doc("network", "failure"), {}):
        assert keys(fct.from_parts([], [not_one], [])) == []


@pytest.mark.parametrize(
    ("value", "yes"),
    [("asha@example.edu", True), ("a.b+c@dept.univ.example", True), ("asha", False),
     ("@example.edu", False), ("asha@localhost", False), ("a b@c.in", False)],
)  # fmt: skip
def test_an_email_address_user_is_a_mail_account(value: str, yes: bool) -> None:
    facts = fct.from_parts([("user", value, "actor")], [], [])
    assert ("mail_user" in facts.present) is yes
    assert keys(fct.from_parts([("host", value, "actor")], [], [])) == []


def test_families_come_in_the_catalogues_order_and_a_case_can_show_several() -> None:
    facts = fct.from_parts(
        [*BEACON, ("user", "asha@example.edu", "actor")], [doc("authentication", "failure")],
        ["/.env"],
    )  # fmt: skip
    assert keys(facts) == ["c2_beacon", "exposed_file", "brute_force", "account_compromise"]
    assert fct.required_paths(facts, C.family("exposed_file")) == {"/.env"}
    assert fct.required_paths(facts, C.family("c2_beacon")) == frozenset()


def test_an_unknown_fact_is_a_bug_not_a_family() -> None:
    with pytest.raises(ValueError, match="no fact telepathy"):
        Facts(frozenset({"telepathy"}))
    assert set(FACTS) == {f for fam in C.families for f in fam.when}


def threat(technique: str, *subs: str) -> list[dict[str, Any]]:
    entry: dict[str, Any] = {"id": technique, "name": "x"}
    if subs:
        entry["subtechnique"] = [{"id": sub} for sub in subs]
    return [{"framework": "MITRE ATT&CK", "tactic": {"id": "TA0006"}, "technique": [entry]}]


def test_a_rule_tagged_t1110_is_brute_force_even_without_event_fields() -> None:
    """Threshold and sequence alerts copy no ``event.*`` fields; the rule's tag still says it."""
    flat = {"kibana.alert.rule.threat": threat("T1110")}
    nested = {"kibana": {"alert": {"rule": {"threat": threat("T1110")}}}}
    sub = {"kibana.alert.rule.threat": threat("T1078", "T1110.003")}
    for doc_ in (flat, nested, sub, {"kibana.alert.rule.threat": threat(" t1110 ")}):
        assert keys(fct.from_parts([], [doc_], [])) == ["brute_force"], doc_
    for other in (threat("T1111"), threat("T11101"), threat("T1078", "T1078.002"), "T1110", None):
        assert keys(fct.from_parts([], [{"kibana.alert.rule.threat": other}], [])) == [], other
    assert keys(fct.from_parts([], [{"rule.name": "T1110 in the name"}], [])) == []


def test_a_mail_shaped_user_alone_is_no_account_compromise() -> None:
    """Any e-mail-shaped username (sign-ins at ACME are) would otherwise advise a reset on every
    case; the catalogue asks for failed sign-ins as well."""
    alone = fct.from_parts([("user", "asha@example.edu", "actor")], [], [])
    assert keys(alone) == []
    both = fct.from_parts(
        [("user", "asha@example.edu", "actor")], [doc("authentication", "failure")], []
    )
    assert keys(both) == ["brute_force", "account_compromise"]
    assert keys(fct.from_parts([*BEACON, ("user", "asha@example.edu", "actor")], [], [])) == [
        "c2_beacon"
    ]  # a C2 case with a mail-shaped user is not an account case


def test_a_stored_answer_of_any_odd_shape_is_no_outcome_and_never_raises() -> None:
    good = {"aggregations": {"paths": {"buckets": []}}}
    assert fct.outcomes_of(good, ["/.env"])[0].path == "/.env"
    for snapshot in (
        None, [], "x", 5, {}, {"aggregations": None}, {"aggregations": [1]}, {"aggregations": "x"},
        {"aggregations": {"paths": {"buckets": 5}}}, {"aggregations": {"paths": 7}},
        {"aggregations": {"paths": {"buckets": [None, 1, {"key": []}]}, "ok_0": []}},
    ):  # fmt: skip
        assert isinstance(fct.outcomes_of(snapshot, ["/.env"]), list), snapshot
    for asked in (None, "x", 5, {}, [None], [[]]):
        assert isinstance(fct.outcomes_of(good, asked), list), asked
