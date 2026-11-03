"""Q-D4's planner (pure): people's tags are kept, edited fields left alone, Kibana ends equal to
ARGUS on what ARGUS manages, representative alerts are few and deterministic."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.cases import kibana as intent
from argus.gateway.kibana import models
from argus.writer import plan, render

pytestmark = pytest.mark.unit

CASE = uuid.UUID("3f2a9c1e-5b7d-4e86-9a10-c4d2e8f61b73")
BASE = "https://argus.example"
CTX = render.Context(BASE, reference="k")
MANAGED = [
    "argus",
    f"argus:case:{CASE}",
    "argus:owner:argus",
    "argus:owner:user-4",
    "argus:state:open",
    "argus:state:assigned",
    "argus:state:closed",
    "argus:closed",
    "argus:reason:benign_policy",
]


def row(op: str, payload: dict[str, Any], *, from_state: str = "open", to_state: str = "assigned"):  # type: ignore[no-untyped-def]
    return plan.Row(
        1, CASE, 1, 0, "W2" if op != "close" else "W3", op, payload,
        intent.payload_hash(payload), f"{CASE}:v2:0", None, "approved", 0, from_state, to_state,
    )  # fmt: skip


def live(**over: Any) -> dict[str, Any]:
    case: dict[str, Any] = {
        "id": "kid-1", "version": "WzEsMV0=", "status": "open", "severity": "high",
        "tags": ["argus", f"argus:case:{CASE}", "argus:owner:argus", "argus:state:open"],
        "settings": {"syncAlerts": False}, "created_by": {"username": "argus"},
    }  # fmt: skip
    case.update(over)
    return case


TAKE = {
    "status": "in-progress",
    "argus_tags": sorted(
        ["argus", f"argus:case:{CASE}", "argus:owner:user-4", "argus:state:assigned"]
    ),
}  # fmt: skip


def test_is_managed_names_exactly_the_tags_argus_writes() -> None:
    for tag in MANAGED:
        assert plan.is_managed(tag), tag
    for tag in [
        "argus:custom",
        "argus-x",
        "Argus",
        "argus:",
        "argus:owner:",
        "team-blue",
        "",
        "argusX",
    ]:
        assert not plan.is_managed(tag), tag


@given(
    st.lists(
        st.sampled_from([*MANAGED, "team-blue", "argus:custom", "ioc", "x" * 40]), max_size=12
    ),
    st.lists(st.sampled_from(MANAGED), min_size=1, max_size=6),
)
def test_merge_tags_keeps_every_persons_tag_and_sets_arguss_exactly(
    seen: list[str], wanted: list[str]
) -> None:
    merged = plan.merge_tags(seen, wanted)
    assert len(set(merged)) == len(merged)
    assert {t for t in merged if plan.is_managed(t)} == set(wanted)
    assert {t for t in seen if not plan.is_managed(t)} <= set(merged)  # people's tags stay
    assert plan.merge_tags(merged, wanted) == merged  # and nothing moves a second time


def test_a_take_sets_status_and_owner_tag_and_keeps_a_persons_tag() -> None:
    seen = live(tags=[*live()["tags"], "team-blue"])
    verdict = plan.plan_change(row("update", TAKE), seen, plan.MirrorFacts(), CTX, "argus")
    assert isinstance(verdict, plan.Send)
    change = verdict.params.cases[0]  # type: ignore[attr-defined]
    assert (change.status, change.id, change.version) == ("in-progress", "kid-1", "WzEsMV0=")
    assert "team-blue" in change.tags
    assert "argus:owner:user-4" in change.tags
    assert "argus:owner:argus" not in change.tags
    assert change.severity is None


def test_what_is_already_so_is_not_sent_again() -> None:
    done = live(status="in-progress", tags=[*TAKE["argus_tags"], "team-blue"])
    verdict = plan.plan_change(row("update", TAKE), done, plan.MirrorFacts(), CTX, "argus")
    assert isinstance(verdict, plan.Skip)


def test_a_status_a_person_changed_is_never_reverted() -> None:
    closed = live(status="closed")  # neither what ARGUS expects (open) nor what it sets
    verdict = plan.plan_change(row("update", TAKE), closed, plan.MirrorFacts(), CTX, "argus")
    assert isinstance(verdict, plan.Send)
    assert verdict.params.cases[0].status is None  # type: ignore[attr-defined]
    assert verdict.kept == ("status (a person changed it in Kibana)",)
    only_status = row("update", {"status": "in-progress"})
    skipped = plan.plan_change(only_status, closed, plan.MirrorFacts(), CTX, "argus")
    assert isinstance(skipped, plan.Skip)
    assert "a person changed it" in skipped.reason


def test_a_severity_a_person_edited_is_left_alone() -> None:
    payload = {"severity": "critical"}
    edited = plan.MirrorFacts(unmanaged=frozenset({"severity"}))
    assert isinstance(
        plan.plan_change(row("update", payload), live(), edited, CTX, "argus"), plan.Skip
    )
    sent = plan.plan_change(row("update", payload), live(), plan.MirrorFacts(), CTX, "argus")
    assert isinstance(sent, plan.Send)
    assert sent.params.cases[0].severity == "critical"


@pytest.mark.parametrize(
    ("seen", "mirror", "action"),
    [
        (live(settings={"syncAlerts": True}), plan.MirrorFacts(), "sync_on"),
        (live(created_by={"username": "someone"}), plan.MirrorFacts(), "pause"),
        (None, plan.MirrorFacts(), "pause"),
        (live(), plan.MirrorFacts(deleted=True), "pause"),
        (live(), plan.MirrorFacts(paused="a person changed ARGUS's tags"), "wait"),
    ],
)
def test_nothing_is_sent_to_a_case_that_is_not_safe_to_write_to(
    seen: dict[str, Any] | None, mirror: plan.MirrorFacts, action: str
) -> None:
    verdict = plan.plan_change(row("update", TAKE), seen, mirror, CTX, "argus")
    assert isinstance(verdict, plan.Hold)
    assert verdict.action == action


def test_sync_alerts_matters_only_to_a_status_change_or_an_attach() -> None:
    on = live(settings={"syncAlerts": True})
    tags_only = {"argus_tags": TAKE["argus_tags"]}
    assert isinstance(
        plan.plan_change(row("update", tags_only), on, plan.MirrorFacts(), CTX, "argus"), plan.Send
    )
    comment = row("comment", {"template": "new_activity", "params": {}})
    assert isinstance(plan.plan_change(comment, on, plan.MirrorFacts(), CTX, "argus"), plan.Send)
    assert isinstance(plan.plan_attach("kid-1", [("a", "i")], on), plan.Hold)


def test_a_payload_that_no_longer_has_its_hash_is_tampering() -> None:
    forged = row("update", TAKE)
    bad = plan.Row(
        forged.id, forged.case_id, forged.case_event_id, forged.position, forged.write_class,
        forged.op, {**TAKE, "status": "closed"}, forged.payload_hash, forged.idempotency_key,
        None, "approved", 0, "open", "assigned",
    )  # fmt: skip
    verdict = plan.plan_change(bad, live(), plan.MirrorFacts(), CTX, "argus")
    assert isinstance(verdict, plan.Hold)
    assert verdict.action == "tamper"


def test_a_closure_closes_with_the_reason_tags_and_keeps_a_persons_tag() -> None:
    tags = sorted(
        [
            "argus",
            f"argus:case:{CASE}",
            "argus:state:closed",
            "argus:closed",
            "argus:reason:benign_policy",
        ]
    )
    payload = {"status": "closed", "severity": "high", "argus_tags": tags}
    seen = live(tags=[*live()["tags"], "team-blue"])
    verdict = plan.plan_change(row("close", payload), seen, plan.MirrorFacts(), CTX, "argus")
    assert isinstance(verdict, plan.Send)
    change = verdict.params.cases[0]  # type: ignore[attr-defined]
    assert change.status == "closed"
    assert "team-blue" in change.tags
    assert change.severity is None  # a closure changes status and tags only
    assert models.closing_tags(change.tags) == "benign_policy"
    already = live(status="closed", tags=list(change.tags))
    assert isinstance(
        plan.plan_change(row("close", payload), already, plan.MirrorFacts(), CTX, "argus"),
        plan.Skip,
    )


def test_a_comment_is_skipped_when_the_change_it_explains_was_not_made() -> None:
    comment = row("comment", {"template": "new_activity", "params": {}})
    skipped = plan.plan_change(
        comment, live(), plan.MirrorFacts(), CTX, "argus", explained="severity edited"
    )
    assert isinstance(skipped, plan.Skip)
    assert "was not made" in skipped.reason
    sent = plan.plan_change(comment, live(), plan.MirrorFacts(), CTX, "argus")
    assert isinstance(sent, plan.Send)
    assert "reference" in sent.params.comment


def test_an_unrenderable_payload_pauses_the_row_instead_of_sending_text() -> None:
    bad = row("comment", {"template": "written_by_a_model", "params": {}})
    verdict = plan.plan_change(bad, live(), plan.MirrorFacts(), CTX, "argus")
    assert isinstance(verdict, plan.Hold)
    assert verdict.action == "pause"


@given(
    st.lists(st.sampled_from(["team-blue", "ioc", "argus:custom", *MANAGED]), max_size=10),
    st.sampled_from(["open", "in-progress", "closed"]),
    st.sampled_from(["low", "medium", "high", "critical"]),
    st.sampled_from(["open", "in-progress"]),
    st.sampled_from(["low", "medium", "high", "critical"]),
    st.sets(st.sampled_from(["severity", "title"])),
)
def test_after_the_change_kibana_equals_arguss_on_what_arguss_manages(
    seen_tags: list[str], seen_status: str, seen_severity: str, status: str, severity: str,
    unmanaged: set[str],
) -> None:  # fmt: skip
    """Whatever Kibana held, applying the planned PATCH (Kibana replaces the fields it is sent)
    leaves ARGUS's tags exactly as planned, a person's tags and edited severity untouched, the
    status as planned unless a person moved it, and a second plan has nothing left to send."""
    mine = sorted(
        [
            "argus",
            f"argus:case:{CASE}",
            "argus:owner:argus",
            f"argus:state:{'open' if status == 'open' else 'assigned'}",
        ]
    )
    payload = {"status": status, "severity": severity, "argus_tags": mine}
    before = "open"
    state = live(
        tags=sorted({*seen_tags, "argus", f"argus:case:{CASE}"}),
        status=seen_status,
        severity=seen_severity,
    )
    facts = plan.MirrorFacts(unmanaged=frozenset(unmanaged))
    r = row("update", payload, from_state=before, to_state="assigned")
    verdict = plan.plan_change(r, state, facts, CTX, "argus")
    after = dict(state)
    if isinstance(verdict, plan.Send):
        change = verdict.params.cases[0]  # type: ignore[attr-defined]
        for name in ("status", "severity", "tags"):
            if getattr(change, name) is not None:
                after[name] = list(change.tags) if name == "tags" else getattr(change, name)
    assert {t for t in after["tags"] if plan.is_managed(t)} == set(mine)
    assert {t for t in state["tags"] if not plan.is_managed(t)} <= set(after["tags"])
    if "severity" in unmanaged:
        assert after["severity"] == state["severity"]
    else:
        assert after["severity"] == severity
    if seen_status in (before, status):
        assert after["status"] == status
    else:
        assert after["status"] == seen_status  # a person moved it: it stays
    again = plan.plan_change(r, after, facts, CTX, "argus")
    assert isinstance(again, plan.Skip)


# --------------------------------------------------------------------------- attachments

INDEX = ".internal.alerts-security.alerts-acme-soc-000001"
T0 = datetime(2026, 10, 20, 3, 0, tzinfo=UTC)


def alert(n: int, minutes: int, index: str = INDEX) -> plan.AlertRef:
    return plan.AlertRef(T0 + timedelta(minutes=minutes), f"alert-{n:05d}", index)


def test_the_first_and_latest_alert_of_each_investigation_are_attached_in_order() -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    groups = {
        b: [alert(5, 50), alert(6, 40), alert(7, 45)],
        a: [alert(1, 10), alert(2, 30), alert(3, 20)],
    }
    reps = plan.representatives(groups)
    assert [r.alert_id for r in reps] == [
        "alert-00001",
        "alert-00002",
        "alert-00006",
        "alert-00005",
    ]
    assert plan.representatives({a: [alert(1, 10)]}) == [alert(1, 10)]  # one alert: once


def test_an_alert_without_a_usable_index_is_left_out() -> None:
    group = {uuid.uuid4(): [alert(1, 1, "alerts"), alert(2, 2), alert(3, 3, "../x")]}
    assert [r.alert_id for r in plan.representatives(group)] == ["alert-00002"]


@given(st.lists(st.lists(st.integers(0, 10**5), min_size=1, max_size=6), max_size=130))
def test_at_most_200_deterministic_unique_representatives(raw: list[list[int]]) -> None:
    counter = iter(range(10**6))  # an alert is in exactly one investigation
    groups = {uuid.uuid4(): [alert(next(counter), m) for m in minutes] for minutes in raw}
    reps = plan.representatives(groups)
    assert len(reps) <= plan.MAX_ATTACHED == 200
    assert len({r.alert_id for r in reps}) == len(reps)
    shuffled = {k: list(reversed(v)) for k, v in reversed(list(groups.items()))}
    assert plan.representatives(shuffled) == reps  # the order of the input changes nothing
    for group in groups.values():  # while there is room, the first and the latest of each are in
        if len(reps) < 200:
            assert min(group).alert_id in {r.alert_id for r in reps}
            assert max(group).alert_id in {r.alert_id for r in reps}


def test_batches_hold_at_most_five_and_lose_nothing() -> None:
    refs = [alert(n, n) for n in range(12)]
    parts = plan.batches(refs)
    assert [len(p) for p in parts] == [5, 5, 2]
    assert [r for p in parts for r in p] == refs
    assert plan.batches([]) == []
