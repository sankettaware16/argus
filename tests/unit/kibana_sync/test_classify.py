"""The classifier (plan §7.1, DQ7 (a)), pure: units and Hypothesis properties.

Properties: reading the same user actions in any split (cycle boundaries) gives the same
mirror and the same findings (order-free and idempotent); an action of ARGUS's is an alarm
exactly when its kind's count passes what the sent writes explain; no person's action ever
pauses a write class; a pause is never lifted by the classifier."""

from __future__ import annotations

import itertools
import uuid
from datetime import UTC, datetime, timedelta

from hypothesis import given
from hypothesis import strategies as st

from argus.gateway.health import HealthState
from argus.kibana_sync import classify
from argus.kibana_sync.classify import Intervals
from argus.kibana_sync.model import (
    AlertLink,
    AlertState,
    KAction,
    KCase,
    Kind,
    Mirror,
    SentWrite,
    parse_case,
)

T0 = datetime(2026, 10, 26, 9, 0, tzinfo=UTC)
CASE = uuid.UUID(int=7)
KID = "k-1"


def kcase(**kw: object) -> KCase:
    base = {
        "id": KID,
        "version": "v9",
        "status": "open",
        "title": "[ARGUS 1] t",
        "severity": "medium",
        "tags": ("argus", f"argus:case:{CASE}"),
        "created_by": "argus",
        "sync_alerts": False,
        "created_at": T0,
        "updated_at": T0,
    }
    base.update(kw)
    return KCase(**base)  # type: ignore[arg-type]


def mirror(**kw: object) -> Mirror:
    base = {
        "case_id": CASE,
        "kibana_case_id": KID,
        "kibana_version": "v1",
        "status": "open",
        "title": "[ARGUS 1] t",
        "severity": "medium",
        "tags": (),
        "created_by": "argus",
        "sync_alerts": False,
        "kibana_created_at": T0,
        "kibana_updated_at": None,
        "read_at": T0,
    }
    base.update(kw)
    return Mirror(**base)  # type: ignore[arg-type]


def action(n: int, kind: str, by: str = "ra", verb: str = "update", **payload: object) -> KAction:
    return KAction(f"a{n}", kind, verb, T0 + timedelta(seconds=n), by, payload)


def run(
    actions: list[KAction],
    sent: tuple[SentWrite, ...] = (),
    m: Mirror | None = None,
    case: KCase | None = None,
) -> classify.CaseOutcome:
    return classify.classify_case(
        m or mirror(),
        case or kcase(),
        actions,
        sent,
        author="argus",
        now=T0,
        kibana_now=T0 + timedelta(minutes=5),
        complete=True,
    )


def test_each_kind_of_persons_action() -> None:
    out = run(
        [
            action(1, "comment", verb="create", comment={"type": "user", "comment": "hi"}),
            action(2, "status", status="closed"),
            action(3, "status", status="open"),
            action(4, "status", status="in-progress"),
            action(5, "tags", verb="add", tags=["mine"]),
            action(6, "tags", verb="delete", tags=["argus:state:open"]),
            action(7, "settings", settings={"syncAlerts": True}),
            action(8, "title", title="x"),
            action(9, "connector", connector={}),
            action(10, "comment", verb="create", comment={"type": "alert", "alertId": ["a"]}),
            action(11, "something_new"),
        ]
    )
    assert [f.kind for f in out.findings] == [
        Kind.PERSON_COMMENTED,
        Kind.CLOSED_IN_KIBANA,
        Kind.REOPENED_IN_KIBANA,
        Kind.STATUS_CHANGED_IN_KIBANA,
        Kind.PERSON_EDITED,
        Kind.ARGUS_TAGS_CHANGED,
        Kind.SETTINGS_CHANGED,
        Kind.PERSON_EDITED,
        Kind.PERSON_EDITED,
        Kind.PERSON_EDITED,
        Kind.PERSON_EDITED,
    ]
    assert out.mirror.unmanaged == {"title", "connector", "alerts", "something_new"}
    assert out.mirror.paused_reason == "a person changed ARGUS's tags in Kibana"
    assert not out.pause_all
    assert all(f.lag_s == 300 - n for f, n in zip(out.findings, range(1, 12), strict=True))


def test_the_case_itself_not_made_by_argus_or_sync_on_without_an_action() -> None:
    out = run([], case=kcase(created_by="someone"))
    assert [f.kind for f in out.findings] == [Kind.NOT_ARGUS_CASE]
    assert out.pause_all
    out = run([], case=kcase(sync_alerts=True))
    assert [f.kind for f in out.findings] == [Kind.SETTINGS_CHANGED]
    assert out.mirror.paused_reason == "Sync alerts is on for the case"
    assert not out.pause_all


def test_with_pausing_off_a_persons_change_is_a_finding_and_argus_keeps_writing() -> None:
    """D-333 (``kibana.sync.pause_on_change: false``): the same findings, no pause; a pause from
    before stays until the owner lifts it; a case ARGUS did not make still stops everything."""

    def off(actions: list[KAction], **more: object) -> classify.CaseOutcome:
        return classify.classify_case(
            more.get("m") or mirror(),  # type: ignore[arg-type]
            more.get("case") or kcase(),  # type: ignore[arg-type]
            actions, (), author="argus", now=T0, kibana_now=T0 + timedelta(minutes=5),
            complete=True, pause_people=False,
        )  # fmt: skip

    changes = [action(1, "tags", tags=["verdict:benign"]),
               action(2, "settings", settings={"syncAlerts": True})]  # fmt: skip
    on = run(changes)
    out = off(changes)
    assert [f.kind for f in out.findings] == [f.kind for f in on.findings]
    assert on.mirror.paused_reason is not None
    assert out.mirror.paused_reason is None
    synced = off([], case=kcase(sync_alerts=True))
    assert [f.kind for f in synced.findings] == [Kind.SETTINGS_CHANGED]
    assert synced.mirror.paused_reason is None
    assert off(changes, m=mirror(paused_reason="earlier")).mirror.paused_reason == "earlier"
    foreign = off([], case=kcase(created_by="someone"))
    assert foreign.pause_all
    assert foreign.mirror.paused_reason == "the case was not made by ARGUS"


def test_a_pause_is_never_lifted_by_the_classifier() -> None:
    out = run([action(1, "title", title="x")], m=mirror(paused_reason="earlier"))
    assert out.mirror.paused_reason == "earlier"


def test_capacity_of_sent_writes() -> None:
    room = classify.capacity(
        [
            SentWrite("create", frozenset(), 1),
            SentWrite("comment", frozenset(), 2),
            SentWrite("update", frozenset({"status", "argus_tags"}), 1),
            SentWrite("close", frozenset({"status", "argus_tags"}), 1),
        ]
    )
    assert room == {"create": 1, "comment": 2, "status": 2, "tags": 4}


def test_adoption_rules() -> None:
    case = kcase(id="k-9")
    assert classify.adopt(case, known={CASE: 1}, mirrored={}).case_id == CASE
    refused = classify.adopt(case, known={CASE: 0}, mirrored={})
    assert refused.case_id is None
    assert refused.pause_all
    assert [f.kind for f in refused.findings] == [Kind.UNEXPLAINED_ARGUS_CASE]
    two_tags = kcase(tags=("argus", f"argus:case:{CASE}", f"argus:case:{uuid.UUID(int=8)}"))
    assert classify.adopt(two_tags, known={CASE: 1}, mirrored={}).case_id is None
    dup = classify.adopt(case, known={CASE: 1}, mirrored={CASE: "k-1"})
    assert dup.case_id is None
    assert not dup.pause_all
    assert [f.kind for f in dup.findings] == [Kind.DUPLICATE_CASE]


def test_alert_changes_are_found_by_diffing_statuses() -> None:
    later = T0 + timedelta(minutes=1)
    before = {a: AlertState(a, "open", None, None, T0) for a in ("a1", "a2", "a3", "a4", "a6")}
    links = [
        AlertLink("a1", ("k-1",), "closed", "ra", later),  # a person in Kibana's UI
        AlertLink("a2", ("k-1",), "closed", None, None),  # RAC: no user, no time (Q-D1 #7)
        AlertLink("a3", ("k-1",), "acknowledged", None, None),  # ARGUS's write-back
        AlertLink("a4", ("k-1",), "open", None, None),  # unchanged
        AlertLink("a5", ("k-1",), "closed", None, None),  # first seen: its baseline only
        AlertLink("a6", ("k-1",), "closed", "ra", None),  # a user but no newer time: RAC-like
    ]
    out = classify.classify_alerts(
        links,
        previous=before,
        explained=frozenset({"a3"}),
        author="argus",
        case_of={"k-1": ("k-1", CASE)},
        now=later,
    )
    assert [(f.kind, f.details["alert"]) for f in out.findings] == [
        (Kind.ALERT_STATUS_BY_PERSON, "a1"),
        (Kind.ALERT_CHANGE_UNEXPLAINED, "a2"),
        (Kind.ALERT_CHANGE_UNEXPLAINED, "a6"),
    ]
    assert out.pause_all
    assert out.findings[1].case_id == CASE
    assert {s.alert_id: s.status for s in out.states} == {
        "a1": "closed",
        "a2": "closed",
        "a3": "acknowledged",
        "a4": "open",
        "a5": "closed",
        "a6": "closed",
    }


def test_intervals_clock_and_staleness() -> None:
    i = Intervals()
    assert [classify.interval(s, i) for s in HealthState] == [
        timedelta(minutes=10),
        timedelta(minutes=20),
        timedelta(hours=1),
        None,
    ]
    assert classify.clock_offset_ms("Mon, 26 Oct 2026 09:00:31 GMT", T0, T0) == 31_000
    assert classify.clock_offset_ms("garbage", T0, T0) is None
    assert classify.clock_offset_ms(None, T0, T0) is None
    assert classify.clock_alarm(31_000, timedelta(seconds=30))
    assert classify.clock_alarm(-31_000, timedelta(seconds=30))
    assert not classify.clock_alarm(30_000, timedelta(seconds=30))
    bound = classify.staleness_bound(timedelta(minutes=10), timedelta(minutes=2))
    assert bound == timedelta(minutes=22)
    old = mirror(read_at=T0 - timedelta(minutes=23))
    assert classify.staleness([old], T0, bound).stale
    assert not classify.staleness([mirror()], T0, bound).stale
    assert classify.staleness([], T0, bound).oldest_s is None


def test_a_case_answer_is_held_to_the_strict_model() -> None:
    good = {
        "id": "k",
        "version": "v",
        "owner": "securitySolution",
        "status": "open",
        "tags": [],
        "settings": {"syncAlerts": False},
        "created_by": {"username": "argus"},
        "title": "t",
        "severity": "low",
        "created_at": "2026-10-26T09:00:00.000Z",
        "updated_at": None,
    }
    assert parse_case(good).created_at == T0
    import pytest

    from argus.gateway.kibana.errors import AnswerMismatchError

    for broken in (
        {**good, "severity": "urgent"},
        {**good, "created_at": "yesterday"},
        {**good, "created_at": "2026-10-26T09:00:00"},
        {**good, "title": 3},
    ):
        with pytest.raises(AnswerMismatchError):
            parse_case(broken)


# --------------------------------------------------------------------------- properties

PEOPLE = st.sampled_from(["ra", "ta", ""])
ACTIONS = st.lists(
    st.one_of(
        st.builds(lambda: ("comment", "create", {"comment": {"type": "user", "comment": "c"}})),
        st.builds(lambda: ("comment", "create", {"comment": {"type": "alert", "alertId": ["x"]}})),
        st.sampled_from(["open", "in-progress", "closed"]).map(
            lambda s: ("status", "update", {"status": s})
        ),
        st.sampled_from([["mine"], ["argus:owner:argus"], ["argus"]]).map(
            lambda t: ("tags", "add", {"tags": t})
        ),
        st.just(("settings", "update", {"settings": {"syncAlerts": True}})),
        st.sampled_from(["title", "description", "severity", "category"]).map(
            lambda f: (f, "update", {f: "x"})
        ),
        st.just(("create_case", "create", {})),
    ).flatmap(lambda a: st.tuples(st.just(a), st.sampled_from(["argus", "ra", "ta"]))),
    max_size=25,
)
SENT = st.lists(
    st.builds(
        SentWrite,
        st.sampled_from(["create", "comment", "attach", "update", "close"]),
        st.frozensets(st.sampled_from(["status", "severity", "argus_tags"])),
        st.integers(0, 2),
    ),
    max_size=5,
)


def _actions(spec: list[tuple[tuple[str, str, dict[str, object]], str]]) -> list[KAction]:
    return [
        action(n, kind, by, verb, **payload) for n, ((kind, verb, payload), by) in enumerate(spec)
    ]


@given(ACTIONS, SENT, st.lists(st.integers(0, 25), max_size=4))
def test_any_split_of_the_actions_gives_the_same_result(
    spec: list[tuple[tuple[str, str, dict[str, object]], str]],
    sent: list[SentWrite],
    cuts: list[int],
) -> None:
    acts = _actions(spec)
    # the case as Kibana shows it once every action is read: a part that leaves another status
    # holds the version back (review D3-R3), the last one takes it
    case = kcase(status=run(acts, tuple(sent)).mirror.status)
    whole = run(acts, tuple(sent), case=case)
    m, findings, pause = mirror(), [], False
    points = sorted({0, len(acts), *(c for c in cuts if c <= len(acts))})
    for a, b in itertools.pairwise(points):
        out = run(acts[a:b], tuple(sent), m=m, case=case)
        m, pause = out.mirror, pause or out.pause_all
        findings += out.findings
    if not acts:
        out = run([], tuple(sent), m=m, case=case)
        m, findings, pause = out.mirror, list(out.findings), out.pause_all
    assert m == whole.mirror
    assert [f.dedupe_key for f in findings] == [f.dedupe_key for f in whole.findings]
    assert pause == whole.pause_all


@given(ACTIONS, SENT)
def test_an_argus_action_is_an_alarm_exactly_past_what_was_sent(
    spec: list[tuple[tuple[str, str, dict[str, object]], str]], sent: list[SentWrite]
) -> None:
    acts = _actions(spec)
    out = run(acts, tuple(sent))
    room = classify.capacity(sent)
    counts: dict[str, int] = {}
    over = 0
    for a in acts:
        if a.by == "argus":
            kind = classify.action_kind(a)
            counts[kind] = counts.get(kind, 0) + 1
            over += counts[kind] > room.get(kind, 0)
    alarms = [f for f in out.findings if f.kind is Kind.UNEXPLAINED_ARGUS_ACTION]
    assert len(alarms) == over
    assert out.pause_all == (over > 0)
    assert dict(out.mirror.argus_actions) == counts
    assert out.mirror.actions_seen == len(acts)


@given(ACTIONS.map(lambda s: [(a, by) for a, by in s if by != "argus"]), st.text(max_size=5))
def test_no_persons_action_pauses_a_write_class_or_lifts_a_pause(
    spec: list[tuple[tuple[str, str, dict[str, object]], str]], earlier: str
) -> None:
    paused = earlier or None
    out = run(_actions(spec), (), m=mirror(paused_reason=paused))
    assert not out.pause_all
    if paused is not None:
        assert out.mirror.paused_reason == paused
    assert all(f.kind is not Kind.UNEXPLAINED_ARGUS_ACTION for f in out.findings)
