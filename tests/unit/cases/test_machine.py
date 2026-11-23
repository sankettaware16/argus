"""The case lifecycle as a pure function (Q-C1's gate): over random command sequences nothing
closes without a reason and a valid approval, versions only rise by one, every move is an
edge of the lifecycle, and replaying the events rebuilds the case."""

from __future__ import annotations

import re
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.cases import kibana, machine
from argus.cases.machine import (
    EDGES,
    AfterClosure,
    Assign,
    CaseRefused,
    Close,
    Confirm,
    ConfirmByVerdict,
    Contain,
    Dismiss,
    EventRecord,
    Link,
    MergedIn,
    MergeInto,
    NewActivity,
    Open,
    Publish,
    Release,
    Reopen,
    RequestClosure,
    RequestMerge,
    Step,
    Take,
    TeamOpened,
    Unlink,
    event_details,
    replay,
)
from argus.cases.model import (
    KIBANA_TO_OPEN,
    LOCAL_CAPABILITIES,
    NO_QUIET_WINDOW,
    REASONS,
    STATES,
    WAITING_FOR_KIBANA,
    Actor,
    ApprovalFacts,
    Capability,
    Case,
    Indicator,
    Member,
    QuietWindow,
)
from argus.db import models

NOW = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "src/argus/db/migrations/versions/0026_cases_outbox_approvals_chain.py"
)
ALL = frozenset(c.value for c in Capability)
CASE_ID = uuid.UUID(int=1)
TARGET = uuid.UUID(int=2)
INVESTIGATIONS = [uuid.UUID(int=100 + n) for n in range(6)]


def person(user_id: int = 7, caps: frozenset[str] = ALL, kibana_ok: bool = False) -> Actor:
    return Actor.person(
        user_id, caps, via="test",
        kibana=KIBANA_TO_OPEN if kibana_ok else frozenset(),
        kibana_checked_at=NOW - timedelta(seconds=30) if kibana_ok else None,
    )  # fmt: skip


ARGUS = Actor.argus("opener")


def opened(*, suspected: bool = False, actor: Actor | None = None) -> Step:
    command = Open(
        "Regular beaconing from 10.0.0.1", "medium",
        "proposal" if suspected else "person",
        (Member(INVESTIGATIONS[0], "verdict"),),
        (Indicator("ip", "10.0.0.1", "actor"),),
        suspected=suspected,
        cause_assessment_id=5 if suspected else None,
    )  # fmt: skip
    return machine.create(CASE_ID, 1, command, actor or (ARGUS if suspected else person()), NOW)


def approval(
    case: Case, *, kind: str = "closure", reason: str = "benign_expected", **kw: Any
) -> ApprovalFacts:
    values: dict[str, Any] = {
        "request_id": 9, "case_id": case.id, "case_version": case.version, "kind": kind,
        "reason": reason, "target_case_id": TARGET if kind == "merge" else None, "required": 1,
        "approved": 1, "rejected": 0, "expires_at": NOW + timedelta(hours=1),
        "requested_by_user_id": 3,
    }  # fmt: skip
    values.update(kw)
    return ApprovalFacts(**values)


# --------------------------------------------------------------------------- the database's lists


def _sql_pairs(block: str) -> set[tuple[str, str]]:
    return set(re.findall(r"\('([a-z-]+)', '([a-z-]+)'\)", block))


def _edge_list(source: str, function: str) -> str:
    body = source[source.index(f"CREATE FUNCTION {function}()") :]
    start = body.index("NOT (OLD.state, NEW.state) IN (")
    return body[start : body.index("THEN", start)]


def test_the_database_guards_the_same_lifecycle_edges() -> None:
    source = MIGRATION.read_text()
    assert _sql_pairs(_edge_list(source, "argus_case_guard")) == set(EDGES)


def test_the_database_guards_the_same_outbox_moves() -> None:
    from argus.cases.outbox import MOVES

    source = MIGRATION.read_text()
    pairs = _sql_pairs(_edge_list(source, "argus_outbox_guard"))
    assert pairs == {(a, b) for a, moves in MOVES.items() for b in moves}


def test_the_types_match_the_schema() -> None:
    assert set(STATES) == set(models.CASE_STATES)
    assert set(REASONS) == set(models.CLOSURE_REASONS)
    assert set(machine.EVENT_KINDS) == set(models.CASE_EVENT_KINDS)
    from argus.cases.outbox import OUTBOX_STATES

    assert set(OUTBOX_STATES) == set(models.OUTBOX_STATES)


# --------------------------------------------------------------------------- single moves


def test_a_person_opens_a_case_that_waits_without_a_live_kibana_check() -> None:
    step = opened()
    assert (step.kind, step.after.state, step.after.version, step.writes) == (
        "opened",
        "open",
        1,
        (),
    )
    assert step.after.kibana_wait == "Waiting for someone who may open cases in Kibana"
    assert step.after.opened_at == NOW


def test_a_fresh_kibana_check_plans_the_create() -> None:
    step = opened(actor=person(kibana_ok=True))
    assert [(w.write_class, w.op) for w in step.writes] == [("W1", "create")]
    assert step.after.mirrored
    payload = step.writes[0].payload
    assert payload["title"] == "[ARGUS 1] Regular beaconing from 10.0.0.1"
    assert payload["status"] == "open"
    assert payload["argus_tags"] == [
        "argus",
        f"argus:case:{CASE_ID}",
        "argus:owner:argus",
        "argus:state:open",
    ]
    assert payload["description"]["params"]["link"] == f"/go/case/{CASE_ID}"


@pytest.mark.parametrize(
    "checked",
    [None, NOW - timedelta(minutes=5, seconds=1), NOW + timedelta(seconds=1)],
    ids=["never", "stale", "future"],
)
def test_only_a_fresh_check_counts(checked: datetime | None) -> None:
    actor = Actor.person(7, ALL, via="test", kibana=KIBANA_TO_OPEN, kibana_checked_at=checked)
    assert not actor.may_open_in_kibana(NOW)
    edge = Actor.person(7, ALL, via="test", kibana=KIBANA_TO_OPEN,
                        kibana_checked_at=NOW - timedelta(minutes=5))  # fmt: skip
    assert edge.may_open_in_kibana(NOW)
    half = Actor.person(7, ALL, via="test", kibana=frozenset({"createCase"}),
                        kibana_checked_at=NOW)  # fmt: skip
    assert not half.may_open_in_kibana(NOW)


def test_argus_opens_only_suspected_cases_or_from_a_verdict() -> None:
    with pytest.raises(CaseRefused, match="only from a person's verdict"):
        machine.create(CASE_ID, 1, Open("t", "low", "person", (Member(INVESTIGATIONS[0], "v"),)),
                       ARGUS, NOW)  # fmt: skip
    with pytest.raises(CaseRefused, match="ARGUS's own move"):
        opened(suspected=True, actor=person())
    verdict = machine.create(
        CASE_ID, 1,
        Open("t", "low", "verdict", (Member(INVESTIGATIONS[0], "verdict"),), cause_review_id=4),
        ARGUS, NOW,
    )  # fmt: skip
    assert verdict.after.state == "open"


@pytest.mark.parametrize(
    ("command", "message"),
    [
        (Open("", "low", "person", (Member(INVESTIGATIONS[0], "person"),)), "a title is required"),
        (Open("x" * 201, "low", "person", (Member(INVESTIGATIONS[0], "person"),)), "at most 200"),
        (Open("t", "low", "person", ()), "at least one investigation"),
        (Open("t", "low", "verdict", (Member(INVESTIGATIONS[0], "verdict"),)), "cause does not"),
        (Open("t", "low", "person", (Member(INVESTIGATIONS[0], "person"),), suspected=True),
         "ARGUS's own move"),
    ],
)  # fmt: skip
def test_a_bad_open_is_refused(command: Open, message: str) -> None:
    with pytest.raises(CaseRefused, match=message):
        machine.create(CASE_ID, 1, command, person(), NOW)


def test_closing_a_confirmed_case_needs_a_complete_matching_approval() -> None:
    case = opened().after
    for facts, message in [
        (approval(case, approved=0), "has 0 of 1 approvals"),
        (approval(case, rejected=1), "was rejected"),
        (approval(case, case_version=0), "changed after the approval"),
        (approval(case, case_id=TARGET), "not for this case"),
        (approval(case, kind="merge"), "not for this case"),
        (approval(case, expires_at=NOW - timedelta(seconds=1)), "expired"),
        (approval(case, required=2), "has 1 of 2 approvals"),
    ]:
        with pytest.raises(CaseRefused, match=message):
            machine.decide(case, Close(facts), person(), NOW)
    with pytest.raises(CaseRefused, match="the approve capability"):
        machine.decide(case, Close(approval(case)), person(caps=LOCAL_CAPABILITIES), NOW)
    step = machine.decide(case, Close(approval(case)), person(), NOW)
    assert (step.after.state, step.after.closure_reason, step.after.closure_request_id) == (
        "closed", "benign_expected", 9,
    )  # fmt: skip
    assert step.writes == ()  # never mirrored: nothing to close in Kibana


def test_a_mirrored_closure_plans_the_patch_then_the_comment() -> None:
    case = opened(actor=person(kibana_ok=True)).after
    step = machine.decide(case, Close(approval(case, reason="rule_false_positive")), person(), NOW)
    assert [(w.write_class, w.op) for w in step.writes] == [("W3", "close"), ("W3", "comment")]
    assert step.writes[0].payload["argus_tags"] == sorted([
        "argus", f"argus:case:{CASE_ID}", "argus:state:closed", "argus:closed",
        "argus:reason:rule_false_positive",
    ])  # fmt: skip
    assert step.writes[0].payload["status"] == "closed"
    assert step.writes[1].payload == {"template": "closed",
                                      "params": {"reason": "rule_false_positive"}}  # fmt: skip


def test_positive_evidence_is_needed_before_a_closure_is_asked() -> None:
    case = opened().after
    for reason in ("remediated_verified", "attempt_no_impact"):
        with pytest.raises(CaseRefused, match="needs verified evidence") as refused:
            machine.decide(case, RequestClosure(reason, "fixed", NO_QUIET_WINDOW), person(), NOW)  # type: ignore[arg-type]
        assert refused.value.code == "unavailable"
    ok = machine.decide(
        case, RequestClosure("remediated_verified", None, QuietWindow(True, "72 h quiet")),
        person(), NOW,
    )  # fmt: skip
    assert ok.kind == "closure_requested"
    with pytest.raises(CaseRefused, match="not a closure a person requests"):
        machine.decide(case, RequestClosure("duplicate"), person(), NOW)
    for reason in ("remediated_unverified", "risk_accepted", "created_in_error"):
        with pytest.raises(CaseRefused, match="is required"):
            machine.decide(case, RequestClosure(reason, "  "), person(), NOW)  # type: ignore[arg-type]


def test_contain_needs_a_verified_window_and_an_attestation() -> None:
    case = opened().after
    with pytest.raises(CaseRefused, match="not contained"):
        machine.decide(case, Contain("blocked at the firewall", NO_QUIET_WINDOW), person(), NOW)
    with pytest.raises(CaseRefused, match="an attestation is required"):
        machine.decide(case, Contain(" ", QuietWindow(True, "quiet")), person(), NOW)
    step = machine.decide(case, Contain("blocked", QuietWindow(True, "72 h quiet")), person(), NOW)
    assert step.after.state == "contained"
    back = machine.decide(step.after, NewActivity("a new beacon at 13:52 IST"), ARGUS, NOW)
    assert (back.after.state, back.after.attention) == ("open", "New activity after containment")
    with pytest.raises(CaseRefused, match="ARGUS's own move"):
        machine.decide(step.after, NewActivity("x"), person(), NOW)


def test_merges() -> None:
    case = opened().after
    with pytest.raises(CaseRefused, match="needs an approval"):
        machine.decide(case, MergeInto(TARGET, "open", None), person(), NOW)
    facts = approval(case, kind="merge", reason="duplicate", target_case_id=uuid.UUID(int=3))
    with pytest.raises(CaseRefused, match="another target"):
        machine.decide(case, MergeInto(TARGET, "open", facts), person(), NOW)
    with pytest.raises(CaseRefused, match="into a confirmed one"):
        machine.decide(case, MergeInto(TARGET, "suspected", None), person(), NOW)
    with pytest.raises(CaseRefused, match="target case is closed"):
        machine.decide(case, RequestMerge(TARGET, "closed"), person(), NOW)
    with pytest.raises(CaseRefused, match="into itself"):
        machine.decide(case, RequestMerge(CASE_ID, "open"), person(), NOW)
    facts = approval(case, kind="merge", reason="duplicate")
    step = machine.decide(case, MergeInto(TARGET, "open", facts), person(), NOW)
    assert (step.after.state, step.after.closure_reason, step.after.merged_into_id) == (
        "closed", "duplicate", TARGET,
    )  # fmt: skip
    assert step.members_removed == (INVESTIGATIONS[0],)
    assert step.after.members == frozenset()
    with pytest.raises(CaseRefused, match="through the case it joined"):
        machine.decide(step.after, Reopen("wrong merge"), person(), NOW)
    suspected = opened(suspected=True).after
    merged = machine.decide(suspected, MergeInto(TARGET, "open", None), person(), NOW)
    assert merged.after.closure_request_id is None


def test_a_persons_verdict_confirms_a_suspected_case_as_arguss_own_move() -> None:
    suspected = opened(suspected=True).after
    command = ConfirmByVerdict(12, 7, (Member(INVESTIGATIONS[1], "actor", "10.0.0.1"),))
    with pytest.raises(CaseRefused, match="ARGUS's own move"):
        machine.decide(suspected, command, person(), NOW)
    with pytest.raises(CaseRefused, match="names its review"):
        machine.decide(suspected, ConfirmByVerdict(0, 7), ARGUS, NOW)
    step = machine.decide(suspected, command, ARGUS, NOW)
    assert (step.kind, step.after.state, step.after.opened_at, step.writes) == (
        "confirmed", "open", NOW, (),
    )  # fmt: skip
    assert step.after.kibana_wait == "Waiting for someone who may open cases in Kibana"
    assert step.details == {"review": 12, "verdict_by": "user:7"}
    assert step.after.members == {INVESTIGATIONS[0], INVESTIGATIONS[1]}
    with pytest.raises(CaseRefused, match="cannot confirm a open case"):
        machine.decide(step.after, command, ARGUS, NOW)


@pytest.mark.parametrize("bad", ["a\x1b]0;x\x07b", "line\nbreak", "tab\there", "c1\x9bcsi"])
def test_a_title_cannot_hold_control_characters(bad: str) -> None:
    with pytest.raises(CaseRefused, match="control characters"):
        machine.create(CASE_ID, 1, Open(bad, "low", "person", (Member(INVESTIGATIONS[0], "p"),)),
                       person(), NOW)  # fmt: skip


def test_text_limits() -> None:
    case = opened(suspected=True).after
    with pytest.raises(CaseRefused, match="at most 4000"):
        machine.decide(case, Dismiss("benign_expected", "x" * 4001), person(), NOW)
    with pytest.raises(CaseRefused, match="NUL"):
        machine.decide(case, Dismiss("benign_expected", "a\x00b"), person(), NOW)
    with pytest.raises(CaseRefused, match="is not dismissed as"):
        machine.decide(case, Dismiss("risk_accepted"), person(), NOW)


def test_a_case_the_case_team_posted_to_kibana_is_not_dismissed() -> None:
    """A dismissal closes the case at once with no Kibana write: one the case team posted would
    leave its Kibana case open for good, so it is confirmed and its closure asked for instead."""
    case = opened(suspected=True).after
    posted = Dismiss("rule_false_positive", posted="ACME-IR-2026-1106-02")
    with pytest.raises(CaseRefused, match="posted it to Kibana as ACME-IR-2026-1106-02") as no:
        machine.decide(case, posted, person(), NOW)
    assert no.value.code == "conflict"
    assert "ask for its closure" in no.value.message
    assert machine.decide(case, Dismiss("rule_false_positive"), person(), NOW).after.state == (
        "closed"
    )


def test_a_dismissal_keeps_its_reason_on_the_event() -> None:
    """The history says why a possible incident was dismissed: the reason is on the event."""
    case = opened(suspected=True).after
    step = machine.decide(case, Dismiss("benign_expected", "a lab's backup"), person(), NOW)
    assert step.details == {"reason": "benign_expected", "note": "a lab's backup"}
    assert machine.decide(case, Dismiss("benign_policy"), person(), NOW).details == {
        "reason": "benign_policy"
    }


# --------------------------------------------------------------------------- properties

_ACTORS = st.sampled_from(
    [
        ARGUS,
        person(),
        person(8),
        person(9, LOCAL_CAPABILITIES),
        person(10, frozenset({Capability.VIEW.value})),
        person(11, ALL, kibana_ok=True),
    ]
)
_WINDOWS = st.sampled_from([NO_QUIET_WINDOW, QuietWindow(True, "72 h quiet")])
_REASONS = st.sampled_from(REASONS)
_MEMBERS = st.lists(
    st.builds(Member, st.sampled_from(INVESTIGATIONS), st.sampled_from(["actor", "c2", "person"])),
    max_size=3,
).map(tuple)
_INDICATORS = st.lists(
    st.builds(Indicator, st.sampled_from(["ip", "domain"]), st.sampled_from(["a", "b", "10.0.0.1"]),
              st.sampled_from(["actor", "c2", "indicator"])),
    max_size=2,
).map(tuple)  # fmt: skip


@st.composite
def _approvals(draw: st.DrawFn, case: Case, kind: str) -> ApprovalFacts:
    return approval(
        case,
        kind=draw(st.sampled_from([kind, kind, "closure", "merge"])),
        reason=draw(_REASONS) if kind == "closure" else "duplicate",
        case_version=draw(st.sampled_from([case.version, case.version, case.version - 1])),
        approved=draw(st.integers(0, 2)),
        rejected=draw(st.sampled_from([0, 0, 1])),
        required=draw(st.integers(1, 2)),
        expires_at=NOW + draw(st.sampled_from([timedelta(hours=1), timedelta(seconds=-1)])),
    )


@st.composite
def _command(draw: st.DrawFn, case: Case) -> Any:
    choice = draw(st.integers(0, 18))
    if choice == 0:
        return Confirm(draw(st.none() | st.text(max_size=5)))
    if choice == 1:
        return Dismiss(draw(_REASONS), None)
    if choice == 2:
        return Take()
    if choice == 3:
        return Assign(draw(st.integers(1, 12)), draw(st.booleans()))
    if choice == 4:
        return Release()
    if choice == 5:
        return Contain(draw(st.sampled_from(["", "isolated"])), draw(_WINDOWS))
    if choice == 6:
        return NewActivity("beacon", draw(_MEMBERS), draw(_INDICATORS))
    if choice == 7:
        return AfterClosure(draw(st.sampled_from([TARGET, CASE_ID])))
    if choice == 8:
        return Link(
            draw(_MEMBERS),
            draw(_INDICATORS),
            draw(st.none() | st.sampled_from(["high", "critical"])),
        )
    if choice == 9:
        return Publish()
    if choice == 10:
        return RequestClosure(draw(_REASONS), draw(st.sampled_from([None, "why"])), draw(_WINDOWS))
    if choice == 11:
        return RequestMerge(draw(st.sampled_from([TARGET, CASE_ID])), draw(st.sampled_from(STATES)))
    if choice == 12:
        return Close(draw(_approvals(case, "closure")))
    if choice == 13:
        facts = draw(st.none() | _approvals(case, "merge"))
        return MergeInto(TARGET, draw(st.sampled_from(STATES)), facts)
    if choice == 14:
        return MergedIn(TARGET, draw(_MEMBERS), draw(_INDICATORS), "high")
    if choice == 17:
        held = sorted(case.members)
        moving = draw(st.lists(st.sampled_from(held), max_size=len(held))) if held else []
        actors = sorted(i for i in case.indicators if i.role == "actor")
        leaving = draw(st.lists(st.sampled_from(actors), max_size=len(actors))) if actors else []
        return Unlink(tuple(moving), draw(st.sampled_from(["", "two devices"])), TARGET,
                      tuple(leaving))  # fmt: skip
    if choice == 18:
        return TeamOpened(draw(st.sampled_from(["IR-2026-1107-01", " "])), "k-team")
    if choice == 15:
        return ConfirmByVerdict(draw(st.integers(0, 3)), draw(st.integers(0, 3)), draw(_MEMBERS),
                                draw(_INDICATORS))  # fmt: skip
    return Reopen(draw(st.sampled_from(["", "a second look"])))


def _record(step: Step) -> EventRecord:
    return EventRecord(
        step.after.id, step.after.version, step.kind,
        None if step.before is None else step.before.state, step.after.state,
        event_details(step),
    )  # fmt: skip


@settings()  # the profile sets the count: 100 dev, 1,000 ci, 10,000 gate
@given(st.data(), st.booleans(), st.booleans())
def test_random_histories_keep_every_rule(
    data: st.DataObject, suspected: bool, mirrored: bool
) -> None:
    first = opened(suspected=suspected, actor=None if suspected else person(kibana_ok=mirrored))
    case, events = first.after, [_record(first)]
    for _ in range(data.draw(st.integers(1, 25))):
        command = data.draw(_command(case))
        actor = data.draw(_ACTORS)
        try:
            step = machine.decide(case, command, actor, NOW)
        except CaseRefused:
            continue
        before, after = case, step.after
        assert after.version == before.version + 1  # versions only rise, by one
        assert after.state == before.state or (before.state, after.state) in EDGES
        assert after.id == before.id
        assert after.opened_at == before.opened_at or before.opened_at is None
        if after.state == "closed" and before.state != "closed":
            assert after.closure_reason is not None
            assert after.closed_at is not None
            if before.confirmed:  # nothing confirmed closes without a complete approval
                assert isinstance(command, Close | MergeInto)
                facts = command.approval
                assert facts is not None
                assert facts.complete(NOW)
                assert (facts.case_id, facts.case_version) == (before.id, before.version)
                assert after.closure_request_id == facts.request_id
                assert actor.may(Capability.APPROVE)
            else:
                assert isinstance(command, Dismiss | MergeInto)
                # ARGUS merges only a suspected case it raised (the incident engine's)
                assert actor.is_person or (isinstance(command, MergeInto)
                                           and before.cause == "raised")  # fmt: skip
        if after.state == "suspected":
            assert not after.confirmed
        for write in step.writes:  # Kibana only for mirrored cases, W3 only by approval
            assert before.mirrored or write.op == "create"
            if write.write_class == "W3":
                assert after.closure_request_id is not None
            else:  # nothing else closes the Kibana case (the database refuses it too)
                assert not kibana.closes_case(write)
        if not actor.is_person:
            assert isinstance(command, NewActivity | AfterClosure | Link | ConfirmByVerdict
                              | MergeInto | MergedIn | TeamOpened)  # fmt: skip
        if isinstance(command, TeamOpened):  # the wait ends; nothing else changes
            assert after == replace(before, kibana_wait=None, version=before.version + 1)
            assert before.kibana_wait is not None
        case = after
        events.append(_record(step))
        assert replay(events) == case


@settings()  # the profile sets the count: 100 dev, 1,000 ci, 10,000 gate
@given(
    st.lists(
        st.sampled_from(sorted(__import__("argus.cases.outbox", fromlist=["x"]).OUTBOX_STATES)),
        max_size=30,
    ),
    st.data(),
)
def test_an_outbox_row_is_sent_again_only_after_an_approved_resend(
    moves: list[str], data: st.DataObject
) -> None:
    from argus.cases import outbox

    row = outbox.Row("planned", 0, 0)
    for to in moves:
        approved = data.draw(st.booleans())
        try:
            nxt = outbox.move(row, to, resend_approved=approved)  # type: ignore[arg-type]
        except outbox.OutboxRefused:
            assert (
                to not in outbox.MOVES[row.state]
                or (row.state == "ambiguous" and to == "planned" and not approved)
                or row.sent_count + (to == "sending") > 1 + row.resends
            )
            continue
        assert nxt.sent_count <= 1 + nxt.resends
        assert nxt.sent_count == row.sent_count + (to == "sending")
        assert nxt.resends == row.resends + (row.state == "ambiguous" and to == "planned")
        row = nxt
    for state in outbox.FINAL:
        assert outbox.MOVES[state] == frozenset()


def test_the_case_teams_kibana_case_ends_the_wait_and_plans_no_write() -> None:
    waiting = opened(actor=person(kibana_ok=False)).after
    assert waiting.kibana_wait == WAITING_FOR_KIBANA
    step = machine.decide(waiting, TeamOpened("IR-2026-1107-01", "k-team"), ARGUS, NOW)
    assert (step.kind, step.writes, step.after.kibana_wait, step.after.mirrored) == (
        "published", (), None, False,
    )  # fmt: skip
    assert step.details == {"by": "case_team", "incident_id": "IR-2026-1107-01",
                            "kibana_case_id": "k-team"}  # fmt: skip
    assert replay([_record(opened(actor=person(kibana_ok=False))), _record(step)]) == step.after
    with pytest.raises(CaseRefused) as by_person:
        machine.decide(waiting, TeamOpened("IR-2026-1107-01", "k-team"), person(), NOW)
    assert by_person.value.code == "forbidden"
    with pytest.raises(CaseRefused) as not_waiting:
        machine.decide(step.after, TeamOpened("IR-2026-1107-01", "k-team"), ARGUS, NOW)
    assert not_waiting.value.code == "conflict"
    with pytest.raises(CaseRefused) as unnamed:
        machine.decide(waiting, TeamOpened(" ", "k-team"), ARGUS, NOW)
    assert unnamed.value.code == "invalid"


def test_replay_refuses_a_broken_history() -> None:
    first = _record(opened())
    with pytest.raises(machine.ReplayError, match="at least one event"):
        replay([])
    take = _record(machine.decide(opened().after, Take(), person(), NOW))
    gap = EventRecord(take.case_id, 3, take.kind, take.from_state, take.to_state, take.details)
    with pytest.raises(machine.ReplayError, match="does not follow"):
        replay([first, gap])
    wrong = EventRecord(take.case_id, 2, take.kind, "suspected", take.to_state, take.details)
    with pytest.raises(machine.ReplayError, match="starts from"):
        replay([first, wrong])
    lie = EventRecord(take.case_id, 2, take.kind, take.from_state, "closed", take.details)
    with pytest.raises(machine.ReplayError, match="ends in"):
        replay([first, lie])
    odd = EventRecord(first.case_id, 1, "opened", None, "open", {"set": {"bogus": 1}})
    with pytest.raises(machine.ReplayError, match="unknown fields"):
        replay([odd])


def test_payload_hash_is_canonical() -> None:
    assert kibana.payload_hash({"b": 1, "a": [1, "é"]}) == kibana.payload_hash(
        {"a": [1, "é"], "b": 1}
    )
    assert kibana.payload_hash({"a": 1}) != kibana.payload_hash({"a": "1"})
