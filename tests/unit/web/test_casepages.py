"""Q-B3: the words and rules behind the case pages that need no database: an action is shown
available exactly when the case machine would allow it, every refusal reads in plain words, every
event and every Kibana finding has a sentence, a request's standing is derived in one place, and
groups hold at most twenty alike requests with their sample."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, get_args

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.cases import approvals
from argus.cases.machine import (
    EVENT_KINDS,
    Assign,
    CaseRefused,
    Contain,
    MergeInto,
    Release,
    Reopen,
    RequestClosure,
    RequestMerge,
    Take,
    decide,
)
from argus.cases.model import (
    REASONS,
    REQUEST_REASONS,
    Actor,
    Case,
    QuietWindow,
    State,
)
from argus.cases.model import Capability as CaseCapability
from argus.kibana_sync.model import Kind
from argus.web import casepages
from argus.web.auth import Reviewer
from argus.web.capabilities import Capability
from argus.web.v1 import case_models as m

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 26, 6, 0, tzinfo=UTC)
CASE_CAPS = (Capability.VIEW, Capability.REVIEW, Capability.MANAGE_CASES, Capability.REOPEN,
             Capability.APPROVE)  # fmt: skip
VERIFIED = QuietWindow(True, "72 hours quiet")
UNVERIFIED = QuietWindow(False, "nothing proves it yet")


def reviewer(*caps: Capability, user_id: int = 7) -> Reviewer:
    return Reviewer(
        user_id=user_id, username="u", display_name="U", csrf_token="t", previous_seen_at=None,
        capabilities=frozenset(caps),
    )  # fmt: skip


def a_case(state: State, owner: int | None = None) -> Case:
    confirmed = state != "suspected"
    closed = state == "closed"
    return Case(
        id=uuid.UUID(int=5), number=5, title="t", state=state, severity="high", version=2,
        cause="person", owner_user_id=owner if state == "assigned" else None,
        opened_at=NOW if confirmed else None, closed_at=NOW if closed else None,
        closure_reason="benign_expected" if closed else None,
        closure_request_id=1 if closed and confirmed else None,
    )  # fmt: skip


# --------------------------------------------------------------------------- words


def test_every_closure_reason_has_its_words_and_its_note_rule() -> None:
    assert set(casepages.REASON_WORDS) == set(REASONS)
    assert set(casepages.NOTE_NEEDED) <= set(REQUEST_REASONS)
    for label, meaning in casepages.REASON_WORDS.values():
        assert label
        assert meaning.endswith(".")
        assert label[0].isupper()


@pytest.mark.parametrize("reason", sorted(REQUEST_REASONS))
def test_the_note_a_reason_needs_is_the_machines(reason: str) -> None:
    """The page asks for words exactly when the machine will."""
    case = a_case("open")
    actor = Actor.person(7, frozenset({"manage_cases"}), via="web")
    needed = reason in casepages.NOTE_NEEDED
    if needed:
        with pytest.raises(CaseRefused) as refused:
            decide(case, RequestClosure(reason, None, VERIFIED), actor, NOW)  # type: ignore[arg-type]
        assert refused.value.code == "invalid", refused.value.message
    else:
        decide(case, RequestClosure(reason, None, VERIFIED), actor, NOW)  # type: ignore[arg-type]


def test_every_case_event_has_a_sentence_and_no_detail_breaks_it() -> None:
    names = {7: "Mina", 8: "Omar"}
    for kind in EVENT_KINDS:
        said, detail = casepages.event_words(kind, {}, "Mina", names)
        assert said
        assert not said.endswith(" ")
        assert detail is None
        said, detail = casepages.event_words(
            kind,
            {"to": 8, "reason": "benign_expected", "note": "a note", "verdict_by": "user:7",
             "summary": "s", "approval": 4, "proposed": True},
            "Mina", names,
        )  # fmt: skip
        assert said
    assert casepages.event_words("assigned", {"to": 8}, "Mina", names)[0] == (
        "Mina assigned the case to Omar"
    )
    assert casepages.event_words("closure_requested", {"reason": "risk_accepted", "note": "w"},
                                 "Mina", names) == (
        "Mina asked to close the case as left as it is, by decision", "w")  # fmt: skip
    proposed = casepages.event_words(
        "closure_requested",
        {"proposed": True, "reason": "benign_policy", "note": "ev"},
        "ARGUS (proposer)",
        names,
    )
    assert proposed[0] == "ARGUS proposed closing the case as benign: allowed by policy"


@given(
    kind=st.sampled_from(EVENT_KINDS),
    details=st.dictionaries(
        st.sampled_from(
            [
                "to",
                "reason",
                "note",
                "attestation",
                "verdict_by",
                "summary",
                "approval",
                "proposed",
                "set",
                "members",
            ]
        ),
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.text(max_size=30),
            st.lists(st.integers(), max_size=3),
        ),
        max_size=8,
    ),
)
def test_a_damaged_event_detail_never_breaks_the_page(kind: str, details: dict[str, Any]) -> None:
    said, detail = casepages.event_words(kind, details, "Someone", {})
    assert isinstance(said, str)
    assert said
    assert detail is None or isinstance(detail, str)


def test_every_finding_kind_has_its_words() -> None:
    assert set(casepages.FINDING_WORDS) == {k.value for k in Kind}
    assert all(not w.endswith(".") for w in casepages.FINDING_WORDS.values())


def test_every_approval_kind_has_words_and_the_models_name_them_all() -> None:
    assert set(casepages.KIND_WORDS) == set(get_args(m.ApprovalKind))
    assert casepages.approval_words("closure", "benign_expected", 12, None) == (
        "Close case 12: benign: expected activity"
    )
    assert casepages.approval_words("merge", "duplicate", 12, 3) == "Merge case 12 into case 3"
    assert casepages.approval_words("resend", None, 12, None) == (
        "Send again to Kibana for case 12"
    )
    assert casepages.approval_words("compensating", None, 4, None).endswith("case 4")
    assert casepages.approval_words("reconfirm", None, 4, None).startswith("Confirm again")
    assert set(get_args(m.ClosureReason)) == set(REASONS)


def test_a_sentence_has_a_capital_and_a_full_stop() -> None:
    assert casepages.sentence("cannot take a closed case") == "Cannot take a closed case."
    assert casepages.sentence("Already done.") == "Already done."
    assert casepages.sentence("really?") == "Really?"
    assert casepages.sentence("   ") == ""


def test_a_refusal_for_the_wrong_state_says_which_states_would_work() -> None:
    exc = CaseRefused("conflict", "cannot take a closed case")
    assert (
        casepages.why_not(exc, "take")
        == "Only an open or assigned case can be taken; this one is closed."
    )
    assert casepages.why_not(exc, "reopen") == (
        "Only a closed case can be reopened; this one is closed."
    )
    assert casepages.why_not(exc, None) == "Cannot take a closed case."
    other = CaseRefused("conflict", "you own this case already")
    assert casepages.why_not(other, "take") == "You own this case already."
    assert casepages.why_not(CaseRefused("conflict", "cannot confirm a open case"), "contain") == (
        "Only an open or assigned case can be confirmed contained; this one is open."
    )


# --------------------------------------------------------------------------- actions


def concrete(action: str, case: Case, actor: Actor, others: int) -> bool:
    """Whether the machine allows a realistic command for ``action`` (ignoring who may see the
    button): the oracle the page's answer is compared with."""
    try:
        if action == "take":
            decide(case, Take(), actor, NOW)
        elif action == "assign":
            decide(case, Assign(user_id=99, assignable=True), actor, NOW)
        elif action == "release":
            decide(case, Release(), actor, NOW)
        elif action == "contain":
            decide(case, Contain("it is quiet", UNVERIFIED), actor, NOW)
        elif action == "merge":
            if case.state == "closed" or others == 0:
                return False
            if case.confirmed:
                decide(case, RequestMerge(uuid.UUID(int=9), "open", None), actor, NOW)
            else:
                decide(case, MergeInto(uuid.UUID(int=9), "suspected", None), actor, NOW)
        elif action == "reopen":
            decide(case, Reopen("a second look"), actor, NOW)
        else:  # request_closure: any reason that works
            reasons = [r for r in REQUEST_REASONS if r not in ("remediated_verified",
                                                              "attempt_no_impact")]  # fmt: skip
            return any(_closure_ok(case, actor, r) for r in reasons)
    except CaseRefused:
        return False
    return True


def _closure_ok(case: Case, actor: Actor, reason: str) -> bool:
    try:
        decide(case, RequestClosure(reason, "words", UNVERIFIED), actor, NOW)  # type: ignore[arg-type]
    except CaseRefused:
        return False
    return True


@given(
    state=st.sampled_from(["suspected", "open", "assigned", "contained", "closed"]),
    caps=st.sets(st.sampled_from(CASE_CAPS)),
    owner=st.sampled_from([7, 8]),
    others=st.integers(0, 2),
)
def test_an_action_is_shown_available_exactly_when_the_machine_allows_it(
    state: State, caps: set[Capability], owner: int, others: int
) -> None:
    me = reviewer(*caps)
    case = a_case(state, owner)
    actor = casepages.actor_of(me)
    choices = casepages.closure_choices(case, me, UNVERIFIED, NOW)
    shown = {
        a.action: a for a in casepages.case_actions(case, me, UNVERIFIED, choices, others, NOW)
    }
    assert set(shown) == {"take", "assign", "release", "contain", "request_closure", "merge",
                          "reopen"}  # fmt: skip
    for action, found in shown.items():
        allowed = concrete(action, case, actor, others)
        assert found.enabled == allowed, (action, state, caps, found.why_not)
        assert (found.why_not is None) == found.enabled
        if found.why_not:
            assert found.why_not[0].isupper()
            assert found.why_not.endswith((".", ")"))


def test_a_missing_capability_is_said_in_the_words_of_the_access_page() -> None:
    me = reviewer(Capability.VIEW)
    case = a_case("open")
    choices = casepages.closure_choices(case, me, UNVERIFIED, NOW)
    shown = {a.action: a for a in casepages.case_actions(case, me, UNVERIFIED, choices, 1, NOW)}
    assert shown["take"].why_not == (
        "Your account may not take cases: it needs the “manage_cases” capability (manage cases:"
        " take, assign, contain, request closure, merge, open). Ask an ARGUS admin."
    )
    assert "“reopen”" in (shown["reopen"].why_not or "")
    assert not any(c.enabled for c in choices)


def test_the_closure_choices_say_which_need_words_and_which_need_two_people() -> None:
    me = reviewer(Capability.VIEW, Capability.MANAGE_CASES)
    got = {c.reason: c for c in casepages.closure_choices(a_case("assigned", 7), me,
                                                         UNVERIFIED, NOW)}  # fmt: skip
    assert set(got) == set(REQUEST_REASONS)
    assert [r for r, c in got.items() if c.note == "required"] == sorted(
        casepages.NOTE_NEEDED, key=list(casepages.REASON_WORDS).index)  # fmt: skip
    assert {r for r, c in got.items() if c.approvers == 2} == {"remediated_unverified",
                                                               "risk_accepted"}  # fmt: skip
    assert not got["remediated_verified"].enabled
    assert got["benign_expected"].enabled
    verified = {c.reason: c for c in casepages.closure_choices(a_case("assigned", 7), me,
                                                              VERIFIED, NOW)}  # fmt: skip
    assert verified["remediated_verified"].enabled
    assert verified["attempt_no_impact"].enabled


# --------------------------------------------------------------------------- requests


@pytest.mark.parametrize(
    ("kwargs", "status"),
    [
        ({}, "pending"),
        ({"rejected": 1}, "rejected"),
        ({"rejected": 1, "approved": 1}, "rejected"),  # a rejection settles it for good
        ({"approved": 1}, "approved"),
        ({"approved": 1, "now": NOW + timedelta(days=9)}, "approved"),  # decided in time
        ({"now": NOW + timedelta(days=9)}, "expired"),
        ({"case_now": 3}, "stale"),
        ({"case_state": "closed"}, "stale"),
        ({"kind": "reconfirm", "case_now": 9, "case_state": "closed"}, "pending"),
        ({"kind": "resend", "case_now": 9}, "pending"),
        ({"approved": 1, "required": 2}, "pending"),
        ({"approved": 2, "required": 2}, "approved"),
    ],
)
def test_where_a_request_stands(kwargs: dict[str, Any], status: str) -> None:
    base: dict[str, Any] = {
        "kind": "closure", "case_version": 2, "case_now": 2, "case_state": "open",
        "expires_at": NOW + timedelta(hours=20), "now": NOW, "approved": 0, "required": 1,
        "rejected": 0,
    }  # fmt: skip
    assert casepages.request_status(**{**base, **kwargs}) == status


def request(rid: int, number: int, reason: str = "benign_expected", **kw: Any) -> m.ApprovalOut:
    base: dict[str, Any] = {
        "id": rid, "kind": "closure", "words": "w", "reason": reason,
        "case": m.CaseRef(id=uuid.UUID(int=number), number=number, title="t", state="open"),
        "case_version": 2, "target": None, "status": "pending", "status_words": "w",
        "requested_by": None, "proposed_by": "proposer", "requested_at": NOW,
        "expires_at": NOW + timedelta(hours=9), "required": 1, "decisions": [], "payload": {},
        "payload_hash": f"{rid:064x}", "alerts_then": 1, "alerts_now": 1, "alerts_same": True,
        "note": None, "kibana_version": None, "hold": None,
        "you": m.YouOut(can_decide=True, why_not=None, decided=None), "group": None,
    }  # fmt: skip
    return m.ApprovalOut(**{**base, **kw})


def test_a_group_holds_twenty_alike_requests_and_a_lone_one_is_no_group() -> None:
    mixed = [request(i, i) for i in range(1, 46)]  # 45 of one reason
    mixed += [request(100 + i, 100 + i, "benign_policy") for i in range(2)]
    mixed.append(request(200, 200, "benign_expected", required=2))  # a two-person reason
    mixed.append(request(201, 201, "risk_accepted", required=2))
    mixed.append(request(202, 202, you=m.YouOut(can_decide=False, why_not="no", decided=None)))
    mixed.append(request(203, 203, status="approved"))
    mixed.append(request(204, 204, kind="merge", reason="duplicate"))
    groups = casepages.groups_of(mixed)
    sizes = sorted((g.reason, len(g.items)) for g in groups)
    assert sizes == [("benign_expected", 5), ("benign_expected", 20), ("benign_expected", 20),
                     ("benign_policy", 2)]  # fmt: skip
    for g in groups:
        ids = [i.request_id for i in g.items]
        assert len(ids) <= approvals.GROUP_LIMIT
        assert set(g.sample) <= set(ids)
        assert len(g.sample) == approvals.sample_size(len(ids))
        assert g.sample == approvals.sample(ids, casepages.group_seed(ids))
        assert {a.group for a in mixed if a.id in ids} == {g.key}
    assert all(a.group is None for a in mixed if a.id in (200, 201, 202, 203, 204))
    one = casepages.groups_of([request(1, 1), request(2, 2, "benign_policy")])
    assert one == []


def test_a_groups_key_and_sample_follow_its_set_of_requests_alone() -> None:
    ids = [5, 9, 12, 20]
    assert casepages.group_key("benign_expected", ids) == casepages.group_key(
        "benign_expected", list(reversed(ids))
    )
    assert casepages.group_key("benign_expected", ids) != casepages.group_key("benign_policy", ids)
    assert casepages.group_key("benign_expected", ids) != casepages.group_key(
        "benign_expected", ids[:-1]
    )
    assert casepages.group_seed(ids) == casepages.group_seed(sorted(ids, reverse=True))


def test_the_page_acts_as_a_manager_for_a_preview_and_as_themselves_to_ask() -> None:
    me = reviewer(Capability.VIEW)
    assert casepages.preview_actor(me).may(CaseCapability.MANAGE)  # for anyone who may view
    assert not casepages.actor_of(me).may(CaseCapability.MANAGE)
    mine = casepages.actor_of(reviewer(Capability.VIEW, Capability.MANAGE_CASES, user_id=12))
    assert (mine.name, mine.via) == ("user:12", "web")


def test_a_stored_record_is_read_only_for_the_types_it_should_hold() -> None:
    assert casepages._only(3, int) == 3
    assert casepages._only(True, int) is None  # a boolean is not a count
    assert casepages._only(True, bool) is True
    assert casepages._only("a", str) == "a"
    assert casepages._only(["a"], str) is None
    check = casepages._check_row(
        type(
            "R",
            (),
            {
                "outcome": {
                    "checks": [
                        {"template": "t", "eid": 5, "status": "ok", "server_ms": True, "heavy": 1},
                        4,
                        None,
                    ],
                    "requests": "3",
                    "error": 9,
                },
                "status": "done",
                "id": 1,
                "version": 1,
                "template": "ti.lookup",
                "entity": "e",
                "requested_by": "u",
                "requested_at": NOW,
                "started_at": None,
                "finished_at": NOW,
                "assessed": False,
            },
        )()
    )
    assert check.lines[0].eid is None
    assert check.lines[0].server_ms is None
    assert check.requests is None
    assert check.why_not is None
    assert len(check.lines) == 1
