"""Q-F3: from gaps to checks. Which requests a wave would send and why, within its caps; never a
tool the rule's own indices do not allow; the same plan every time; a plan made from the
wave's own results asks nothing more."""

from __future__ import annotations

import json
import random
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.context import batch1
from argus.context.packs import TaskSpec
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.state import MemoryStore
from argus.investigation import catalogue, gaps
from argus.investigation.catalogue import Switches
from argus.investigation.gaps import Assessed, Profile
from argus.investigation.plan import Caps, Seen, candidates, choose, priority, task_key
from tests.unit.investigation.kit import (
    ALL_ON,
    DNS,
    NGINX,
    NOW,
    SQUID,
    TI_UNANSWERED,
    body,
    ref,
    step,
    unknown,
)
from tests.unit.report.kit import signal

pytestmark = pytest.mark.unit
TARGETS = Targets(log_sources=frozenset({"squid", "dns", "nginx", "postfix"}))
GATEWAY = Gateway(object(), MemoryStore(), targets=TARGETS)  # type: ignore[arg-type]
THRESHOLD_ALERT = {"rule_type": "threshold", "kibana.alert.rule.indices": list(SQUID)}


def plan_for(
    dossier: dict[str, Any],
    indices: tuple[str, ...] = SQUID,
    switches: Switches = ALL_ON,
    caps: Caps | None = None,
    admission: dict[str, Any] | None = None,
    seen: dict[str, Seen] | None = None,
    assessed: Assessed | None = None,
    rule_type: str | None = "query",
):  # type: ignore[no-untyped-def]
    caps = caps or Caps()
    found = gaps.find(dossier, Profile(rule_type, indices), assessed)
    mat = catalogue.Material(dossier["facts"], dossier["context"]["pack"], NOW, rule_type, None)
    cands = candidates(found, mat, switches)
    return choose(found, cands, admission or {}, seen or {}, caps, NOW), found, cands


# ----------------------------------------------------------------------------- the choice


def test_the_best_closer_of_a_gap_is_asked() -> None:
    plan, _, _ = plan_for(body(steps=[step(2, "deferred", ["timeline"])]))
    assert [(p.template, p.mode) for p in plan.checks] == [("proxy.host", "send")]
    (check,) = plan.sends
    assert check.rank == 1
    assert check.heavy
    assert check.keys == ("step:2",)
    assert check.reason.startswith("the host's proxy traffic — for: Step 2 of the rule's note")
    assert len(check.reason) <= 200


def test_a_closer_that_is_switched_off_gives_way_to_the_next() -> None:
    off = Switches(templates=frozenset({"proxy.pair"}), proxy_aggregations=False)
    plan, _, _ = plan_for(body(steps=[step(2, "deferred", ["timeline"])]), switches=off)
    assert [(p.template, p.mode) for p in plan.checks] == [("proxy.pair", "send")]


def test_a_check_nobody_may_ask_is_left_with_its_reason() -> None:
    nothing = Switches()
    plan, _, _ = plan_for(body(steps=[step(2, "deferred", ["timeline"])]), switches=nothing)
    assert plan.sends == ()
    assert plan.left[0][0] == "step:2"
    assert "switched off" in plan.left[0][1]
    assert {p.mode for p in plan.checks} == {"skip"}


def test_one_check_answers_every_gap_it_closes() -> None:
    steps = [step(2, "deferred", ["timeline"]), step(3, "deferred", ["log_pivot"])]
    dossier = body([unknown("proxy.regularity", "timeout")], steps)
    plan, found, _ = plan_for(dossier)
    assert [p.template for p in plan.sends] == ["proxy.host"]
    assert plan.sends[0].keys == ("signal:proxy.regularity", "step:2", "step:3")
    assert plan.left == ()
    assert [g.key for g in found][:3] == ["signal:proxy.regularity", "step:2", "step:3"]


def test_checks_go_in_the_order_of_the_gaps_they_close() -> None:
    dossier = body(
        [
            unknown("ti.listed", "source_not_checked"),
            unknown("proxy.hosts_to_destination", "failed"),
        ],
        [step(1, "deferred", ["timeline"])],
        ti=TI_UNANSWERED,
    )
    plan, _, _ = plan_for(dossier)
    assert [p.template for p in plan.sends] == ["ti.lookup", "proxy.destination", "proxy.host"]
    assert [p.rank for p in plan.sends] == [1, 2, 3]  # the floor, then the deferred step


def test_the_caps_hold_in_rank_order() -> None:
    dossier = body(
        [
            unknown("ti.listed", "source_not_checked"),
            unknown("proxy.hosts_to_destination", "failed"),
            unknown("web.successes_after", "failed"),
        ],
        [step(1, "deferred", ["timeline"])],
        ti=TI_UNANSWERED,
    )
    plan, _, _ = plan_for(dossier, indices=SQUID + NGINX, caps=Caps(requests=4, heavy=1))
    # the floor's own order: ti.lookup, web.followups (medium), proxy.destination (heavy 1);
    # the deferred step's proxy.host would be the second heavy request
    assert [p.template for p in plan.sends] == ["ti.lookup", "web.followups", "proxy.destination"]
    skipped = {p.template: p.why_not for p in plan.checks if p.mode == "skip"}
    assert skipped["proxy.host"] == "the host's proxy traffic: this wave's limit of heavy requests"
    one = plan_for(dossier, indices=SQUID + NGINX, caps=Caps(requests=1, heavy=1))[0]
    assert [p.template for p in one.sends] == ["ti.lookup"]
    assert any("request limit" in why for _, why in one.left)


def test_a_stored_answer_is_reused_not_asked_again() -> None:
    dossier = body(steps=[step(2, "deferred", ["timeline"])])
    first, _, _ = plan_for(dossier)
    key = first.sends[0].task_key
    plan, _, _ = plan_for(dossier, seen={str(key): Seen("ok", NOW)})
    assert plan.sends == ()
    assert [(p.template, p.mode) for p in plan.checks] == [("proxy.host", "reuse")]
    assert plan.reuses[0].task_key == key


def test_a_failed_check_waits_before_it_is_asked_again() -> None:
    dossier = body(steps=[step(2, "deferred", ["timeline"])])
    key = str(plan_for(dossier)[0].sends[0].task_key)
    host_only = Switches(proxy_aggregations=True)
    soon = {key: Seen("timeout", NOW - timedelta(minutes=5))}
    plan, _, _ = plan_for(dossier, seen=soon, switches=host_only)
    assert plan.sends == ()
    assert "the host's proxy traffic: tried a moment ago and failed" in plan.left[0][1]
    later = {key: Seen("timeout", NOW - timedelta(minutes=31))}
    assert [p.template for p in plan_for(dossier, seen=later, switches=host_only)[0].sends] == [
        "proxy.host"
    ]
    # with the next closer on, the wave goes on to it meanwhile
    assert [p.template for p in plan_for(dossier, seen=soon)[0].sends] == ["proxy.pair"]


def test_a_rule_the_database_refuses_leaves_the_check_out() -> None:
    dossier = body(steps=[step(2, "deferred", ["timeline"])])
    key = str(plan_for(dossier)[0].sends[0].task_key)
    refused = {key: batch1.Refusal("too_common", "host")}
    plan, _, _ = plan_for(dossier, admission=refused)
    # proxy.host is the only closer the pack's builder made a request for; pair is next
    assert [p.template for p in plan.sends] == ["proxy.pair"]


def test_a_gap_nothing_can_close_is_not_in_the_plan() -> None:
    dossier = body([unknown("web.successes_after", "ingest_not_verified"),
                    unknown("alerts.cadence_cv", "too_few_alerts")])  # fmt: skip
    plan, found, cands = plan_for(dossier)
    assert plan.checks == ()
    assert cands == []
    assert not any(g.closable for g in found)


def test_pair_and_contact_wait_for_their_subjects() -> None:
    dossier = body(steps=[step(2, "deferred", ["timeline"])], fields={}, ips={})
    plan, _, _ = plan_for(dossier)
    assert plan.sends == ()
    assert plan.left[0][1].count("no window or subject") + plan.left[0][1].count("nothing") >= 1


# ----------------------------------------------------------------------------- never refused


EVERY = [
    unknown(n.removeprefix("signal:"), "timeout")
    for c in catalogue.CHECKS.values()
    for n in sorted(c.closes)
    if n.startswith("signal:")
]
NEEDS = [step(i, "deferred", [n]) for i, n in
         enumerate(("reputation", "prevalence", "timeline", "log_pivot"), start=1)]  # fmt: skip
INDEX_SETS = [SQUID, NGINX, DNS, SQUID + NGINX, SQUID + DNS, NGINX + DNS, SQUID + NGINX + DNS, ()]


@settings(max_examples=60, deadline=None)
@given(
    indices=st.sampled_from(INDEX_SETS),
    rule_type=st.sampled_from(["threshold", "esql", "query", "eql", None]),
    on=st.sets(st.sampled_from(sorted(catalogue.CHECKS)), max_size=9),
    assessed=st.sampled_from(
        [None, Assessed("true_positive", 0.9), Assessed("benign_expected", 0.3)]
    ),
    heavy=st.integers(0, 4),
    requests=st.integers(1, 6),
)
def test_every_planned_request_is_one_the_rule_may_have_and_the_validator_accepts(
    indices: tuple[str, ...], rule_type: str | None, on: set[str], assessed: Assessed | None,
    heavy: int, requests: int,
) -> None:  # fmt: skip
    """Whatever the rule reads, the switches and the caps: each request of a plan is a
    catalogue template whose log source the rule's own indices name, it builds, and the
    gateway's validator accepts the final request (never a refused tool)."""
    switches = Switches(
        templates=frozenset(on & set(batch1.TEMPLATES)),
        proxy_aggregations="proxy.host" in on, log_queries="web.followups" in on,
        ti_sync="ti.lookup" in on,
    )  # fmt: skip
    dossier = body(EVERY, NEEDS, indices=indices)
    plan, _, _ = plan_for(dossier, indices, switches, Caps(requests, heavy), assessed=assessed,
                          rule_type=rule_type)  # fmt: skip
    sources = catalogue.sources_of(indices)
    assert len(plan.sends) <= requests
    assert sum(p.heavy for p in plan.sends) <= heavy
    for p in plan.checks:
        spec = catalogue.CHECKS[p.template]
        assert catalogue.reads_needed(spec, sources)
        if p.mode == "send":
            assert switches.on(p.template)
            assert isinstance(p.task, TaskSpec)
            assert type(p.task.template).name == p.template
            if p.template in batch1.TEMPLATES:
                batch1.final_request(p.task, TARGETS, NOW)  # raises if the validator refuses
            # and the gateway's own final request, for every template: the validator accepts it
            GATEWAY.preview(p.task.template, p.task.params, deadline=NOW + timedelta(hours=1),
                            now=NOW)  # fmt: skip


def test_no_two_requests_of_a_plan_are_the_same() -> None:
    dossier = body(EVERY, NEEDS, indices=SQUID + NGINX + DNS)
    plan, _, _ = plan_for(
        dossier, SQUID + NGINX + DNS, caps=Caps(12, 12), rule_type="threshold",
        assessed=Assessed("true_positive", 0.9),
    )  # fmt: skip
    keys = [p.task_key for p in plan.checks if p.task_key]
    assert len(keys) == len(set(keys))
    assert len({p.template for p in plan.checks}) == len(plan.checks)


# ----------------------------------------------------------------------------- determinism


@given(st.randoms(use_true_random=False))
def test_the_same_dossier_gives_the_same_plan_whatever_order_it_is_listed_in(
    rng: random.Random,
) -> None:
    base = body(EVERY, NEEDS, indices=SQUID + NGINX)
    mixed = {**base, "signals": list(base["signals"]), "report": dict(base["report"])}
    rng.shuffle(mixed["signals"])
    mixed["report"]["steps"] = list(base["report"]["steps"])
    rng.shuffle(mixed["report"]["steps"])
    one = plan_for(base, SQUID + NGINX, caps=Caps(8, 8))[0]
    two = plan_for(mixed, SQUID + NGINX, caps=Caps(8, 8))[0]
    assert [(p.template, p.mode, p.task_key, p.keys, p.reason) for p in one.checks] == [
        (p.template, p.mode, p.task_key, p.keys, p.reason) for p in two.checks
    ]
    assert one.left == two.left


def test_a_second_wave_over_the_first_ones_results_asks_nothing() -> None:
    """Idempotence: the plan's own requests, once their answers are stored, are all reused."""
    dossier = body(EVERY, NEEDS, indices=SQUID + NGINX)
    first, _, _ = plan_for(dossier, SQUID + NGINX, caps=Caps(8, 8))
    assert first.sends
    stored = {str(p.task_key): Seen("ok", NOW) for p in first.sends}
    again, _, _ = plan_for(dossier, SQUID + NGINX, caps=Caps(8, 8), seen=stored)
    assert again.sends == ()
    assert {p.task_key for p in again.reuses} == set(stored)
    assert [p.template for p in again.reuses] == [p.template for p in first.sends]


def test_a_rule_name_changes_no_plan() -> None:
    a = body(EVERY, NEEDS)
    b = body(EVERY, NEEDS)
    b["facts"] = {**b["facts"], "rule_name": "Anything", "rule_id": "other"}
    pa, pb = plan_for(a)[0], plan_for(b)[0]
    assert [(p.template, p.reason) for p in pa.checks] == [
        (p.template, p.reason) for p in pb.checks
    ]


# ----------------------------------------------------------------------------- which item first


def test_the_item_order() -> None:
    def prio(dossier: dict[str, Any], severity: str = "medium") -> Any:
        return priority(gaps.find(dossier, Profile("query", SQUID + NGINX)), severity)

    floor = prio(body([unknown("proxy.regularity", "timeout")]))
    step_only = prio(body(steps=[step(1, "deferred", ["timeline"])]))
    none = prio(body())
    assert floor < step_only
    assert prio(body([unknown("ti.listed", "timeout")]), "critical") < prio(
        body([unknown("ti.listed", "timeout")]), "low")  # fmt: skip
    ti = prio(body([unknown("ti.listed", "timeout")]))
    beacon = prio(body([unknown("proxy.regularity", "timeout")]))
    success = prio(body([unknown("web.successes_after", "timeout")]))
    assert ti < beacon < success
    assert prio(body([unknown("ti.listed", "ingest_not_verified")])) == none  # not closable


def test_the_signals_of_a_dossier_do_not_move_the_plan_when_known() -> None:
    dossier = body([signal("proxy.regularity", 0.8), signal("ti.listed", 0)])
    plan, found, _ = plan_for(dossier)
    assert found == ()
    assert plan.checks == ()


def test_keys_are_the_requests_content_addresses() -> None:
    plan = plan_for(body(steps=[step(2, "deferred", ["timeline"])]))[0]
    task = plan.sends[0].task
    assert task is not None
    assert plan.sends[0].task_key == task_key(task)
    assert len(str(plan.sends[0].task_key)) == 64


def test_an_asked_template_is_not_asked_again_for_the_same_gap() -> None:
    dossier = body(steps=[step(2, "deferred", ["timeline"])],
                   evidence=[ref("proxy.host", "ok")])  # fmt: skip
    plan, found, _ = plan_for(dossier)
    assert found[0].exhausted == ("proxy.host",)
    assert [p.template for p in plan.sends] == ["proxy.pair"]


# ----------------------------------------------------------------------------- source events

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "normalized"


def alert(name: str) -> dict[str, Any]:
    return dict(json.loads((FIXTURES / name).read_text()))


@pytest.mark.parametrize(
    ("name", "rule_type", "indices", "source"),
    [
        ("threshold__proxy_excessive_blocked_requests_from_single_host.json", "threshold",
         ("acme-logs-squid*",), "squid"),
        ("esql__sensitive_path_enumeration.json", "esql", ("acme-logs-nginx-*",), "nginx"),
    ],
)  # fmt: skip
def test_the_rows_behind_an_aggregated_alert_close_its_unknown_step(
    name: str, rule_type: str, indices: tuple[str, ...], source: str
) -> None:  # fmt: skip
    dossier = body(steps=[step(1, "unknown")], indices=indices)
    found = gaps.find(dossier, Profile(rule_type, indices))
    assert [(g.kind.value, g.closers) for g in found] == [
        ("unknown_step", ("logs.source_events",))
    ]  # fmt: skip
    mat = catalogue.Material(dossier["facts"], dossier["context"]["pack"], NOW, rule_type,
                             alert(name))  # fmt: skip
    plan = choose(found, candidates(found, mat, ALL_ON), {}, {}, Caps(), NOW)
    (check,) = plan.sends
    assert check.template == "logs.source_events"
    assert not check.heavy  # rows, not an aggregation
    assert check.task is not None
    assert check.task.params.source == source  # type: ignore[attr-defined]
    batch1.final_request(check.task, TARGETS, NOW)
    GATEWAY.preview(check.task.template, check.task.params, deadline=NOW + timedelta(hours=1),
                    now=NOW)  # fmt: skip


def test_an_event_alert_has_no_rows_behind_it_to_ask_for() -> None:
    query = alert("query__proxy_plain_http_post_to_raw_ip_address_possible_c2_beacon.json")
    dossier = body(steps=[step(1, "unknown")])
    found = gaps.find(dossier, Profile("query", SQUID))
    assert not found[0].closable
    mat = catalogue.Material(dossier["facts"], dossier["context"]["pack"], NOW, "query", query)
    assert isinstance(catalogue.build("logs.source_events", mat), batch1.Refusal)
    assert choose(found, candidates(found, mat, ALL_ON), {}, {}, Caps(), NOW).checks == ()
