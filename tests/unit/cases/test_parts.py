"""Pure parts of the case record (Q-C1): approval expiry, Kibana tags, the opener's plan."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.cases import approvals, kibana, opener
from argus.cases.model import Actor, Case, Indicator, max_severity
from argus.cases.opener import Candidate, Indexed

NOW = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("now", "expires"),
    [
        (datetime(2026, 10, 20, 1, 0, tzinfo=UTC), datetime(2026, 10, 20, 17, 30, tzinfo=UTC)),
        (datetime(2026, 10, 20, 2, 30, tzinfo=UTC), datetime(2026, 10, 21, 17, 30, tzinfo=UTC)),
        (datetime(2026, 10, 20, 10, 0, tzinfo=UTC), datetime(2026, 10, 21, 17, 30, tzinfo=UTC)),
        (datetime(2026, 10, 20, 20, 0, tzinfo=UTC), datetime(2026, 10, 21, 17, 30, tzinfo=UTC)),
    ],
    ids=["before-the-window", "as-it-opens", "inside-it", "evening"],
)
def test_an_approval_lasts_to_the_end_of_the_next_write_window(
    now: datetime, expires: datetime
) -> None:
    assert approvals.expires_at(now) == expires


@given(st.datetimes(min_value=datetime(2026, 1, 1), max_value=datetime(2030, 1, 1),  # noqa: DTZ001
                    timezones=st.just(UTC)))  # fmt: skip
def test_expiry_is_within_72_hours_and_after_a_window_starts(now: datetime) -> None:
    expires = approvals.expires_at(now)
    assert now < expires <= now + timedelta(hours=72)
    start = datetime.combine(expires.date(), approvals.WRITE_WINDOW[0])
    assert start > now
    assert expires == datetime.combine(expires.date(), approvals.WRITE_WINDOW[1])


def test_two_people_for_unverified_remediation_and_accepted_risk() -> None:
    reasons = ("remediated_unverified", "risk_accepted", "benign_expected", None)
    assert [approvals.required_approvals(r) for r in reasons] == [2, 2, 1, 1]  # type: ignore[arg-type]


def _case(**changes: object) -> Case:
    base = Case(uuid.UUID(int=5), 42, "t", "open", "high", 3, "person")
    return replace(base, **changes)  # type: ignore[arg-type]


def test_arguss_tags_for_each_state() -> None:
    case_tag = f"argus:case:{uuid.UUID(int=5)}"
    assert kibana.argus_tags(_case()) == sorted(
        ["argus", case_tag, "argus:owner:argus", "argus:state:open"]
    )
    assert kibana.argus_tags(_case(state="assigned", owner_user_id=7)) == sorted(
        ["argus", case_tag, "argus:owner:user-7", "argus:state:assigned"]
    )
    assert kibana.argus_tags(_case(state="contained")) == sorted(
        ["argus", case_tag, "argus:owner:argus", "argus:state:contained"]
    )
    closed = _case(state="closed", closure_reason="risk_accepted")
    assert kibana.argus_tags(closed) == sorted(
        ["argus", case_tag, "argus:state:closed", "argus:closed", "argus:reason:risk_accepted"]
    )
    assert [kibana.KIBANA_STATUS[s] for s in ("open", "assigned", "contained", "closed")] == [
        "open", "in-progress", "in-progress", "closed",
    ]  # fmt: skip
    assert kibana.title(_case()) == "[ARGUS 42] t"


def test_an_update_sends_only_what_changed_then_says_why() -> None:
    before, after = _case(), _case(state="assigned", owner_user_id=7)
    update, comment = kibana.update(before, after, "taken", by="user:7")
    assert update.payload == {"status": "in-progress", "argus_tags": kibana.argus_tags(after)}
    assert comment.payload == {"template": "taken", "params": {"by": "user:7"}}
    (only,) = kibana.update(before, before, "note")
    assert only.op == "comment"


def test_actors() -> None:
    with pytest.raises(ValueError, match=r"users\.id"):
        Actor.person(0, via="x")
    assert Actor.argus("opener").name == "argus:opener"
    assert Actor.person(3, via="cli").name == "user:3"
    assert max_severity("low", "critical", "medium") == "critical"


# --------------------------------------------------------------------------- the opener's plan

INV = [uuid.UUID(int=200 + n) for n in range(8)]


Entities = tuple[tuple[str, str], ...]


def cand(n: int, *, ip: str = "10.0.0.1", person: bool = True, entities: Entities = (),
         signals: dict[str, tuple[str, object]] | None = None, listed: tuple[str, ...] = (),
         at: int = 0) -> Candidate:  # fmt: skip
    return Candidate(
        "review" if person else "assessment", n, INV[n], person, NOW + timedelta(minutes=at),
        "Rule", "medium", (Indicator("ip", ip, "actor"),), True, frozenset(entities), listed,
        signals if signals is not None else {"proxy.regularity": ("known", 0.1)},
    )  # fmt: skip


def test_the_case_with_the_strongest_match_wins_and_the_others_are_suggested() -> None:
    """Q-C2: one case holds the best match (an actor before a C2): it is joined; the weaker
    match is named as a suggestion, not joined."""
    cases = [
        Indexed(uuid.UUID(int=1), 7, "open", None, set(), {("ip", "10.0.0.1"): "actor"}),
        Indexed(uuid.UUID(int=3), 1, "open", None, set(), {("ip", "8.8.8.8"): "c2"}),
    ]
    (opening,) = opener.plan([cand(0, entities=(("ip", "8.8.8.8"),))], cases, now=NOW,
                             created_last_hour=0)  # fmt: skip
    assert (opening.decision, opening.case_ref, opening.link) == (
        "linked",
        uuid.UUID(int=1),
        "actor",
    )
    assert opening.reasons == ("same actor 10.0.0.1", "also matches case 1 (suggested, not joined)")
    assert [(s.case.number, s.kind) for s in opening.suggested] == [(1, "also")]


def test_cases_that_match_equally_are_never_joined_silently() -> None:
    """Q-C2: two cases share the actor: the investigation joins neither (it is ambiguous), both
    are suggested, and it is opened on its own merits; the tie opens that one case only (review
    R5): the next investigation of the same actor is suggested to all three and opens none."""
    cases = [
        Indexed(uuid.UUID(int=1), 7, "open", None, set(), {("ip", "10.0.0.1"): "actor"}),
        Indexed(uuid.UUID(int=2), 3, "assigned", None, set(), {("ip", "10.0.0.1"): "actor"}),
    ]
    opening, later = opener.plan([cand(0), cand(1, at=1)], cases, now=NOW, created_last_hour=0)
    assert opening.decision == "opened"
    assert opening.case_ref == "new:1"
    assert sorted((s.case.number, s.kind) for s in opening.suggested) == [(3, "tie"), (7, "tie")]
    assert all("not joined" in reason for reason in opening.reasons[-2:])
    assert later.decision == "attempt"
    assert "was opened by this tie" in later.reasons[0]
    assert len(later.suggested) == 3


def test_a_plan_links_later_candidates_to_cases_it_opens() -> None:
    plan = opener.plan([cand(1, at=1), cand(0, at=0), cand(2, ip="10.0.0.9", at=2,
                        entities=(("ip", "203.0.113.5"),), listed=())], [], now=NOW,
                       created_last_hour=0)  # fmt: skip
    assert [(o.candidate.source_id, o.decision, o.case_ref) for o in plan] == [
        (0, "opened", "new:1"), (1, "linked", "new:1"), (2, "opened", "new:2"),
    ]  # fmt: skip


def test_the_hourly_cap_defers_new_cases_but_not_links() -> None:
    plan = opener.plan(
        [cand(0), cand(1, ip="10.0.0.2", at=1), cand(2, at=2)], [], now=NOW,
        created_last_hour=opener.MAX_NEW_PER_HOUR - 1,
    )  # fmt: skip
    assert [o.decision for o in plan] == ["opened", "deferred", "linked"]


def test_members_are_not_planned_twice_and_closed_cases_get_followers() -> None:
    held = Indexed(uuid.UUID(int=1), 1, "open", None, {INV[0]}, {})
    closed = Indexed(uuid.UUID(int=2), 2, "closed", NOW - timedelta(days=13), set(),
                     {("ip", "10.0.0.5"): "actor"})  # fmt: skip
    stale = Indexed(uuid.UUID(int=3), 3, "closed", NOW - timedelta(days=15), set(),
                    {("ip", "10.0.0.6"): "actor"})  # fmt: skip
    plan = opener.plan([cand(0), cand(1, ip="10.0.0.5", at=1), cand(2, ip="10.0.0.6", at=2)],
                       [held, closed, stale], now=NOW, created_last_hour=0)  # fmt: skip
    assert [(o.decision, o.parent) for o in plan] == [
        ("member_already", None), ("opened", uuid.UUID(int=2)), ("opened", None),
    ]  # fmt: skip
    assert "follows closed case 2" in plan[1].reasons


def test_impact_and_floor_signals_are_only_known_ones() -> None:
    unknown = cand(0, signals={"proxy.regularity": ("unknown", None), "ti.listed": ("unknown", 3)})
    assert opener.impact(unknown) == []
    assert opener.floor(unknown) == []
    listed = cand(0, signals={"ti.listed": ("known", 2)})
    assert opener.impact(listed) == ["a campus host in contact with a threat-listed address"]
    rare = cand(0, person=False, signals={"proxy.hosts_to_destination": ("known", 1)})
    assert opener.floor(rare) == ["a destination few campus hosts reach"]
    assert opener.title(cand(0), ["a regular beacon"]) == "Suspected beaconing from 10.0.0.1"


def test_a_create_describes_the_case_from_its_alerts() -> None:
    case = _case(
        indicators=frozenset(
            {Indicator("ip", "10.0.0.1", "actor"), Indicator("ip", "77.221.155.150", "c2")}
        ),
        members=frozenset({uuid.UUID(int=9)}),
    )
    span = kibana.AlertSpan(datetime(2026, 10, 8, 4, 0, tzinfo=UTC), None)
    payload = kibana.create(case, span).payload
    assert payload["settings"] == {"syncAlerts": False}
    assert payload["description"] == {
        "template": "case_description",
        "params": {
            "case": str(case.id), "link": f"/go/case/{case.id}", "what": "t",
            "hosts": ["10.0.0.1"], "more_hosts": 0, "indicators": ["77.221.155.150"],
            "more_indicators": 0, "investigations": 1,
            "first_alert": "2026-10-08T04:00:00+00:00", "latest_alert": None,
        },
    }  # fmt: skip
    many = _case(indicators=frozenset(Indicator("ip", f"10.0.0.{n}", "actor") for n in range(25)))
    params = kibana.create(many).payload["description"]["params"]
    assert (len(params["hosts"]), params["more_hosts"]) == (20, 5)


def test_only_identity_fields_with_specific_values_are_actors() -> None:
    """F13: a shared domain, OS or group, or a generic account name, never links two
    people's incidents."""
    import json

    from argus.assets.classify import IpClassifier

    key = json.dumps([
        ["user.domain", "ACME"], ["host.os.name", "Windows"], ["user.group.name", "staff"],
        ["user.roles", "admin"], ["user.name", "root"], ["user.name", "Administrator"],
        ["host.name", "-"], ["user.name", "alice"], ["host.name", "lab-pc-7"],
        ["source.ip", "10.0.0.7"],
    ])  # fmt: skip
    actors, campus = opener._actors(key, IpClassifier(None))
    assert sorted((a.kind, a.value) for a in actors) == [
        ("host", "lab-pc-7"), ("ip", "10.0.0.7"), ("user", "alice"),
    ]  # fmt: skip
    assert campus


def test_a_persons_verdict_confirms_the_suspected_case_it_is_in_or_links_to() -> None:
    """F5 (plan §7.1 "new or suspected -> open"): ARGUS's proposal came first."""

    def suspected() -> Indexed:
        return Indexed(uuid.UUID(int=1), 4, "suspected", None, {INV[0]},
                       {("ip", "10.0.0.1"): "actor"})  # fmt: skip

    (held,) = opener.plan([cand(0)], [suspected()], now=NOW, created_last_hour=0)
    assert (held.decision, held.case_ref, held.link) == ("opened", uuid.UUID(int=1), None)
    assert held.reasons[0] == "a person's true-positive verdict confirms suspected case 4"
    (linked,) = opener.plan([cand(1)], [suspected()], now=NOW, created_last_hour=0)
    assert (linked.decision, linked.case_ref, linked.link) == ("opened", uuid.UUID(int=1), "actor")
    then = opener.plan([cand(0), cand(1, at=1)], [suspected()], now=NOW, created_last_hour=0)
    assert [o.decision for o in then] == ["opened", "linked"]  # it is open by then
    for other in (cand(0, signals={}), cand(0, person=False)):  # no impact; ARGUS's own proposal
        (kept,) = opener.plan([other], [suspected()], now=NOW, created_last_hour=0)
        assert kept.decision == "member_already"


def test_a_verdict_on_a_member_does_not_confirm_a_case_argus_suggested() -> None:
    """D-162: a suggested case (cause raised) is confirmed with Confirm; a person's verdict on one
    investigation is recorded, and says nothing about the rest of the case."""

    def suggested() -> Indexed:
        return Indexed(uuid.UUID(int=1), 4, "suspected", None, {INV[0]},
                       {("ip", "10.0.0.1"): "actor"}, cause="raised")  # fmt: skip

    (held,) = opener.plan([cand(0)], [suggested()], now=NOW, created_last_hour=0)
    assert (held.decision, held.case_ref) == ("member_already", uuid.UUID(int=1))
    (linked,) = opener.plan([cand(1)], [suggested()], now=NOW, created_last_hour=0)
    assert (linked.decision, linked.case_ref, linked.link) == ("linked", uuid.UUID(int=1), "actor")
    assert not any("confirms" in r for o in (held, linked) for r in o.reasons)
    other = Indexed(uuid.UUID(int=1), 4, "suspected", None, {INV[0]},
                    {("ip", "10.0.0.1"): "actor"}, cause="proposal")  # fmt: skip
    (confirmed,) = opener.plan([cand(0)], [other], now=NOW, created_last_hour=0)
    assert confirmed.decision == "opened"  # ARGUS's proposal case is still confirmed this way


def test_a_kibana_title_fits_kibanas_limit() -> None:
    """F11: Kibana refuses titles over 160 characters, counted in UTF-16 code units."""
    assert kibana.title(_case(title="t")) == "[ARGUS 42] t"
    for text in ("x" * 200, "\U0001f512" * 100, "a" + "\U0001f512" * 99):
        fitted = kibana.title(_case(title=text))
        assert len(fitted.encode("utf-16-le")) // 2 <= kibana.KIBANA_TITLE_LIMIT
        assert fitted.startswith("[ARGUS 42] ")
        assert fitted.endswith("…")


@given(st.text(st.characters(codec="utf-8", exclude_categories=("Cc", "Cs")), min_size=1,
               max_size=200))  # fmt: skip
def test_every_title_fits_and_keeps_its_start(text: str) -> None:
    fitted = kibana.title(_case(title=text, number=999_999))
    assert len(fitted.encode("utf-16-le")) // 2 <= kibana.KIBANA_TITLE_LIMIT
    assert fitted == "[ARGUS 999999] " + text or (
        fitted.endswith("…") and text.startswith(fitted[len("[ARGUS 999999] ") : -1].rstrip())
    )


def test_only_w3_writes_close_a_kibana_case() -> None:
    closed = _case(state="closed", closure_reason="benign_expected")
    assert all(kibana.closes_case(w) for w in kibana.close(closed))
    opened_ = _case()
    assert not kibana.closes_case(kibana.create(opened_))
    assert not any(
        kibana.closes_case(w) for w in kibana.update(opened_, _case(severity="low"), "x")
    )


def test_the_campus_test_alone_is_the_openers_own() -> None:
    """``opener.is_campus_actor`` (Q-H4 review R5) answers without a query what ``_actors`` says."""
    import ipaddress
    import json

    from argus.assets.classify import IpClassifier

    classifier = IpClassifier(None, campus_prefixes=[ipaddress.ip_network("10.8.0.0/16")])
    for pairs, expected in (
        ([["source.ip", "10.201.7.13"]], True),
        ([["source.ip", "8.8.8.8"]], False),
        ([["host.name", "lab-pc-7"]], True),
        ([["source.ip", "8.8.8.8"], ["host.name", "lab-pc-7"]], True),
        ([], False),
    ):
        key = json.dumps(pairs)
        assert opener.is_campus_actor(key, classifier) is expected
        assert opener._actors(key, classifier)[1] is expected
    assert opener.is_campus_actor("not json", classifier) is False
