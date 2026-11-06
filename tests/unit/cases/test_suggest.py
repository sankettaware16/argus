"""AR2b (D-154, D-155, D-160) and AR2c (D-168, D-170): a suggested case from evidence across
investigations. The rule is pure: a campus host seen by two or more rules or with the same flag on
two or more days, when one of its investigations is in Needs attention, actors that reach the same
rare targets, and campaigns found from the history window, within 72 hours, become one suspected
case; what is already in a case is linked or suggested, never reopened, and what an open case holds
is never suggested into a new one; ARGUS names no value."""

from __future__ import annotations

import ipaddress
import string
import uuid
from datetime import UTC, date, datetime, timedelta

from hypothesis import given
from hypothesis import strategies as st

from argus.cases import suggest
from argus.cases.membership import Shared
from argus.cases.model import SEVERITIES
from argus.cases.suggest import (
    Action,
    Dismissed,
    Existing,
    Held,
    LinkCase,
    OpenCase,
    Seen,
    SuggestMembers,
)

NOW = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
HOST = ("ip", "10.20.30.40")
BEACON = "regular traffic, like a beacon"
LISTED = "on a threat list"
OUT = "flagged by outside threat intel"
RAISING = (BEACON, OUT)  # a beacon whose server VirusTotal flags: in Needs attention (D-164)
SERVERS = [("ip", "203.0.113.7"), ("domain", "c2.example.net"), ("ip", "203.0.113.8")]
GIT = ("185.220.101.4", "185.220.101.5", "185.220.101.6")  # three outside addresses
TITLE_CHARS = frozenset(string.ascii_letters + string.digits + " .,:()/&+-—→'")  # ' quotes a rule


def seen(n: int, *, rule: str = "rule-a", hours: float = 1, day: int = 24,
         actors: tuple[tuple[str, str], ...] = (HOST,), campus: bool = True,
         flags: tuple[str, ...] = (), targets: tuple[tuple[str, str], ...] = (),
         severity: str = "low", held: Held | None = None) -> Seen:  # fmt: skip
    return Seen(
        uuid.UUID(int=n), rule, severity,  # type: ignore[arg-type]
        date(2026, 10, day), NOW - timedelta(hours=hours), frozenset(actors),
        frozenset(actors if campus else ()), flags, frozenset(targets), held,
    )  # fmt: skip


def plan(items: list[Seen], existing: list[Existing] | None = None, **more: object) -> list[Action]:
    return suggest.plan(items, existing or [], now=NOW, **more)  # type: ignore[arg-type]


def opened(actions: list[Action]) -> list[OpenCase]:
    return [a for a in actions if isinstance(a, OpenCase)]


# -- the Amadey shape: one host, two rules, one flag ------------------------------------------


def amadey() -> list[Seen]:
    """A download and a beacon from one host on one day, both low or medium, both flagged."""
    return [seen(1, rule="download", severity="low", flags=RAISING, hours=6),
            seen(2, rule="beacon", severity="medium", flags=RAISING, hours=5)]  # fmt: skip


def test_a_host_seen_by_two_rules_with_a_flag_is_one_suggested_case() -> None:
    (case,) = opened(plan(amadey()))
    assert [m.investigation_id.int for m in case.members] == [1, 2]
    assert case.severity == "medium"  # the highest of the members
    assert case.flags == RAISING
    assert case.title == "Suspected beaconing from 10.20.30.40"
    assert case.attention.startswith(
        "ARGUS suggests this case: 2 investigations of one campus host"
    )
    assert "2 rules fired" in case.attention
    assert [(a.kind, a.value, a.role) for a in case.actors] == [("ip", "10.20.30.40", "actor")]


def test_a_suggested_case_names_no_value_in_its_reason() -> None:
    """The reason (``attention``) holds counts and words only. The title names the incident with
    values of a strict shape (D-230: an address here, never other text from the logs)."""
    (case,) = opened(plan(amadey()))
    assert "10.20.30.40" not in case.attention
    assert "10.20.30.40" in case.title


def test_two_rules_without_any_flag_are_not_a_story() -> None:
    items = [seen(1, rule="a"), seen(2, rule="b")]
    assert plan(items) == []


def test_two_rules_flagged_but_not_raised_are_not_a_story() -> None:
    """D-168: the pair without a raise was 395 of the 471 cases a replay suggested. A beacon flag
    alone (302 investigations a day) or any one flag raises nothing, so it joins nothing."""
    beacon = [seen(1, rule="download", flags=(BEACON,)), seen(2, rule="beacon", flags=(BEACON,))]
    assert plan(beacon) == []
    one_flag = [seen(1, rule="download", flags=(LISTED,)), seen(2, rule="beacon", flags=(BEACON,))]
    assert plan(one_flag) == []  # a threat-list hit is a raise only with another flag on the same
    (case,) = opened(plan([seen(1, rule="x", flags=(LISTED, BEACON)), seen(2, rule="y")]))
    assert case.flags == (LISTED, BEACON)  # one member is raised: the host is a story


def test_one_rule_without_a_repeated_flag_is_not_a_story() -> None:
    assert plan([seen(1, flags=RAISING), seen(2, flags=RAISING, hours=2)]) == []  # one day


def test_the_same_flag_on_two_days_is_a_story_even_for_one_rule() -> None:
    items = [seen(1, flags=RAISING, day=23, hours=30), seen(2, flags=RAISING, day=24)]
    (case,) = opened(plan(items))
    assert "the same flag on 2 days (flagged by outside threat intel, regular" in case.attention
    other = [seen(1, flags=RAISING, day=23, hours=30),
             seen(2, flags=(LISTED, "successful answers after the alert"), day=24)]  # fmt: skip
    assert plan(other) == []  # two different sets of flags share none


def test_only_the_last_72_hours_count() -> None:
    old = [
        seen(1, rule="download", flags=RAISING, hours=73),
        seen(2, rule="beacon", flags=RAISING, hours=1),
    ]
    assert plan(old) == []
    edge = [seen(1, rule="download", flags=RAISING, hours=72),
            seen(2, rule="beacon", flags=RAISING, hours=1)]  # fmt: skip
    assert len(opened(plan(edge))) == 1


def test_an_outside_address_is_not_a_host_story() -> None:
    items = [seen(1, rule="a", flags=RAISING, campus=False),
             seen(2, rule="b", flags=RAISING, campus=False)]  # fmt: skip
    assert plan(items) == []


def test_a_lone_investigation_is_never_a_case() -> None:
    assert plan([seen(1, flags=RAISING, rule="a")]) == []


def test_other_hosts_do_not_mix() -> None:
    other = ("ip", "10.1.1.1")
    items = [
        seen(1, rule="a", flags=RAISING),
        seen(2, rule="b", flags=RAISING, actors=(other,)),
    ]
    assert plan(items) == []


def test_severity_is_at_least_medium_and_follows_the_highest() -> None:
    (low,) = opened(plan([seen(1, rule="a", flags=(LISTED, BEACON)), seen(2, rule="b")]))
    assert low.severity == "medium"
    (high,) = opened(plan([seen(1, rule="a", flags=(LISTED, BEACON), severity="critical"),
                           seen(2, rule="b")]))  # fmt: skip
    assert high.severity == "critical"


# -- the Git shape: actors that reach the same rare targets -----------------------------------


def paths(*names: str) -> tuple[tuple[str, str], ...]:
    return tuple(("url", f"/~{n}/.git") for n in names)


def git(shared: tuple[str, ...] = ("hostel5", "hostel9", "rsapcouncil")) -> list[Seen]:
    scout = seen(1, rule="scan", actors=(("ip", GIT[1]),), campus=False, severity="high",
                 targets=paths(*shared), hours=40)  # fmt: skip
    collector = seen(2, rule="volume", actors=(("ip", GIT[0]),), campus=False, severity="high",
                     targets=paths(*shared, "elsewhere"), hours=20)  # fmt: skip
    return [scout, collector]


def test_two_outside_addresses_reaching_the_same_rare_directories_are_one_case() -> None:
    (case,) = opened(plan(git()))
    assert {m.investigation_id.int for m in case.members} == {1, 2}
    assert case.title == "Suspected Git-folder scan by 2 outside IPs — no web check yet"
    assert "2 actors reached the same 3 rare targets" in case.attention
    assert {(a.kind, a.value) for a in case.actors} == {("ip", GIT[0]), ("ip", GIT[1])}
    assert {t.value for t in case.targets} == {"/~hostel5/.git", "/~hostel9/.git",
                                               "/~rsapcouncil/.git"}  # fmt: skip
    assert all(t.role == "indicator" for t in case.targets)
    assert case.severity == "high"


def test_actors_at_the_same_rare_targets_need_one_investigation_in_needs_attention() -> None:
    """Replayed, 85 of the 87 cases suggested were such stories of low, unraised investigations
    (D-170). The rule still takes a high or critical one (the Git exfiltration) and a raised one."""

    def story(first: Seen) -> list[Seen]:
        return [first, seen(2, actors=(("ip", GIT[1]),), campus=False, targets=paths("a", "b"))]

    def one(**more: object) -> Seen:
        return seen(1, actors=(("ip", GIT[0]),), campus=False, targets=paths("a", "b"), **more)  # type: ignore[arg-type]

    assert plan(story(one())) == []  # low, no flag
    assert plan(story(one(flags=(BEACON,)))) == []  # a flag alone raises nothing
    assert plan(story(one(severity="medium"))) == []
    assert len(opened(plan(story(one(severity="high"))))) == 1
    assert len(opened(plan(story(one(severity="critical"))))) == 1
    assert len(opened(plan(story(one(flags=RAISING))))) == 1
    assert suggest.in_attention(one(severity="high"))
    assert not suggest.in_attention(one())


def test_one_shared_target_is_a_coincidence_two_are_a_story() -> None:
    assert plan(git(shared=("hostel5",))) == []
    assert len(opened(plan(git(shared=("hostel5", "hostel9"))))) == 1


def test_a_target_many_actors_reach_is_not_rare() -> None:
    crowd = [seen(10 + k, actors=(("ip", f"198.51.100.{k}"),), campus=False, severity="high",
                  targets=paths("a", "b")) for k in range(suggest.MAX_RARE_ACTORS + 1)]  # fmt: skip
    assert plan(crowd) == []
    few = crowd[: suggest.MAX_RARE_ACTORS]
    assert len(opened(plan(few))) == 1  # the same targets, rare enough


def test_shared_infrastructure_is_never_a_target() -> None:
    both = tuple(SERVERS[:2])
    items = [
        seen(1, actors=(("ip", GIT[0]),), campus=False, targets=both, severity="high"),
        seen(2, actors=(("ip", GIT[1]),), campus=False, targets=both),
    ]
    assert len(opened(plan(items))) == 1  # a rare control server joins the two
    common = Shared().with_common(SERVERS[:2])
    assert plan(items, shared=common) == []  # ... unless it is in very many investigations


def test_the_same_actor_hitting_targets_twice_is_not_two_actors() -> None:
    items = [
        seen(1, actors=(("ip", GIT[0]),), campus=False, targets=paths("a", "b")),
        seen(2, actors=(("ip", GIT[0]),), campus=False, targets=paths("a", "b"), hours=3),
    ]
    assert plan(items) == []


def test_a_third_actor_with_one_shared_target_stays_out() -> None:
    third = seen(3, actors=(("ip", GIT[2]),), campus=False, targets=paths("hostel5"))
    (case,) = opened(plan([*git(), third]))
    assert {m.investigation_id.int for m in case.members} == {1, 2}


# -- overlapping evidence is one case ---------------------------------------------------------


def test_host_and_target_evidence_that_share_an_investigation_merge_into_one_case() -> None:
    a = seen(1, rule="download", flags=RAISING, targets=tuple(SERVERS[:2]))
    b = seen(2, rule="beacon", flags=RAISING, targets=tuple(SERVERS[:2]))
    other = ("ip", "10.77.0.9")
    c = seen(3, rule="beacon", flags=RAISING, actors=(other,), targets=tuple(SERVERS[:2]))
    (case,) = opened(plan([a, b, c]))
    assert {m.investigation_id.int for m in case.members} == {1, 2, 3}
    assert "rules fired" in case.attention
    assert "actors reached the same" in case.attention


# -- cases that exist already -----------------------------------------------------------------


def raised_case(number: int = 5, actor: tuple[str, str] = HOST) -> Existing:
    return Existing(uuid.UUID(int=900 + number), number, frozenset({actor}))


def test_investigations_arriving_later_join_the_suggested_case() -> None:
    case = raised_case()
    holding = Held(case.ref, case.number, "suspected", "raised")
    first = [replace_held(s, holding) for s in amadey()]
    new = [seen(3, rule="beacon", flags=RAISING, hours=0.5), seen(4, rule="download", hours=0.2)]
    actions = plan([*first, *new], [case])
    (link,) = actions
    assert isinstance(link, LinkCase)
    assert link.case is case
    assert {m.investigation_id.int for m in link.members} == {3, 4}
    assert opened(actions) == []


def test_a_lone_arrival_of_the_cases_host_joins_it_with_no_story_of_its_own() -> None:
    (link,) = plan([seen(7, rule="other", hours=0.1)], [raised_case()])
    assert isinstance(link, LinkCase)
    assert [m.investigation_id.int for m in link.members] == [7]
    assert link.reason == "an actor of this suggested case"


def test_a_lone_arrival_that_two_suggested_cases_claim_joins_neither() -> None:
    assert plan([seen(7, hours=0.1)], [raised_case(5), raised_case(6)]) == []


def test_members_of_an_open_case_get_suggestions_not_a_competing_case() -> None:
    held = Held(uuid.UUID(int=77), 3, "open", "verdict")
    items = [replace_held(seen(1, rule="download", flags=RAISING), held),
             seen(2, rule="beacon", flags=RAISING)]  # fmt: skip
    (offer,) = plan(items)
    assert isinstance(offer, SuggestMembers)
    assert (offer.case_id, offer.number, offer.kind) == (held.case_id, 3, "also")
    assert [m.investigation_id.int for m in offer.members] == [2]


def test_a_closed_case_holds_its_members_and_opens_nothing_for_them() -> None:
    closed = Held(uuid.UUID(int=78), 4, "closed", "verdict")
    items = [replace_held(seen(1, rule="download", flags=RAISING), closed),
             seen(2, rule="beacon", flags=RAISING)]  # fmt: skip
    assert plan(items) == []  # one free member is not a case; the closed case is not reopened


def test_a_group_that_matches_two_suggested_cases_is_offered_to_both() -> None:
    items = amadey()
    actions = plan(items, [raised_case(5), raised_case(6)])
    assert {(a.number, a.kind) for a in actions if isinstance(a, SuggestMembers)} == {
        (5, "tie"), (6, "tie")
    }  # fmt: skip
    assert opened(actions) == []


def test_a_decided_case_is_not_planned_again() -> None:
    case = raised_case()
    holding = Held(case.ref, case.number, "suspected", "raised")
    assert plan([replace_held(s, holding) for s in amadey()], [case]) == []


def test_the_hours_new_case_budget_is_kept() -> None:
    hosts = [("ip", f"10.9.0.{k}") for k in range(5)]
    items = []
    for k, host in enumerate(hosts):
        items += [seen(10 * k + 1, rule="a", flags=RAISING, actors=(host,)),
                  seen(10 * k + 2, rule="b", flags=RAISING, actors=(host,))]  # fmt: skip
    assert len(opened(plan(items, new_budget=3))) == 3
    assert opened(plan(items, new_budget=0)) == []
    assert len(opened(plan(items, new_budget=99))) == 5


def replace_held(s: Seen, held: Held) -> Seen:
    from dataclasses import replace

    return replace(s, held=held)


# -- a target is a directory ------------------------------------------------------------------


def test_a_path_is_reduced_to_the_directory_it_names() -> None:
    assert suggest.path_target("/~hostel5/.git/HEAD") == "/~hostel5/.git"
    assert suggest.path_target("/~hostel5/.git/objects/ab/cdef?x=1#y") == "/~hostel5/.git"
    assert suggest.path_target("/.git/config") == "/.git/config"
    assert suggest.path_target("/wp-login.php?redirect=/") == "/wp-login.php"
    assert suggest.path_target("//a//b///c") == "/a/b"
    assert suggest.path_target("/") is None
    assert suggest.path_target("") is None
    assert suggest.path_target("?only=query") is None


@given(st.text(max_size=400))
def test_a_path_target_is_short_and_has_no_query_and_is_stable(value: str) -> None:
    found = suggest.path_target(value)
    if found is None:
        return
    assert found.startswith("/")
    assert len(found) <= suggest.PATH_CHARS
    assert "?" not in found
    assert "#" not in found
    assert len([p for p in found.split("/") if p]) <= suggest.PATH_SEGMENTS
    assert suggest.path_target(found) == found


# -- properties of the whole rule -------------------------------------------------------------

HOSTS = [("ip", f"10.5.0.{k}") for k in range(3)]
OUTSIDE = [("ip", f"198.51.100.{k}") for k in range(5)]
TARGETS = [("url", f"/d{k}") for k in range(4)] + SERVERS[:2]
seens = st.builds(
    seen,
    st.integers(1, 10_000),
    rule=st.sampled_from(["a", "b", "c"]),
    hours=st.floats(0, 100),
    day=st.integers(22, 25),
    actors=st.lists(st.sampled_from(HOSTS + OUTSIDE), min_size=1, max_size=2, unique=True).map(
        tuple
    ),
    campus=st.booleans(),
    flags=st.sampled_from([(), (BEACON,), (LISTED,), (BEACON, LISTED)]),
    targets=st.lists(st.sampled_from(TARGETS), max_size=4, unique=True).map(tuple),
    severity=st.sampled_from(SEVERITIES),
)  # fmt: skip


@given(st.lists(seens, max_size=14, unique_by=lambda s: s.investigation_id),
       st.randoms(use_true_random=False))  # fmt: skip
def test_the_rule_is_order_independent_and_each_investigation_is_in_one_action(
    items: list[Seen], rnd: object
) -> None:
    shuffled = list(items)
    rnd.shuffle(shuffled)  # type: ignore[attr-defined]
    actions = plan(items)
    again = plan(shuffled)
    assert actions == again
    members = [m.investigation_id for a in actions for m in a.members]
    assert len(members) == len(set(members))
    window = {s.investigation_id for s in items if NOW - suggest.WINDOW <= s.at <= NOW}
    assert set(members) <= window
    for case in opened(actions):
        assert len(case.members) >= 2
        assert case.severity in SEVERITIES
        assert SEVERITIES.index(case.severity) >= SEVERITIES.index("medium")
        assert len(case.attention) <= 500
        assert len(case.title) <= 200
        assert case.attention.startswith("ARGUS suggests this case: ")
        assert not any(v in case.attention for _, v in HOSTS + OUTSIDE)  # no value from the logs
        assert not (set(case.title) - TITLE_CHARS)  # a title: plain characters only (D-230)
    # with nothing in a case yet, nothing is linked or offered
    assert all(isinstance(a, OpenCase) for a in actions)


@given(st.lists(seens, max_size=14, unique_by=lambda s: s.investigation_id))
def test_no_flag_and_no_shared_target_means_no_case(items: list[Seen]) -> None:
    from dataclasses import replace

    plain = [replace(s, flags=(), targets=frozenset()) for s in items]
    assert plan(plain) == []


@given(st.lists(seens, max_size=14, unique_by=lambda s: s.investigation_id),
       st.integers(0, 4))  # fmt: skip
def test_the_budget_caps_new_cases(items: list[Seen], budget: int) -> None:
    assert len(opened(plan(items, new_budget=budget))) <= budget


# -- D-162: the hour's budget is the suggester's own and goes to the most telling stories ------


def story(k: int, *, severity: str = "low", hours: float = 2) -> list[Seen]:
    """A flagged story on its own campus host (number k): two rules, ids 10k+1 and 10k+2."""
    host = ("ip", f"10.9.0.{k}")
    return [
        seen(10 * k + n, rule=rule, flags=RAISING, actors=(host,), severity=severity, hours=hours)
        for n, rule in ((1, "a"), (2, "b"))
    ]


def chosen(actions: list[Action]) -> set[int]:
    return {m.investigation_id.int // 10 for a in opened(actions) for m in a.members}


def test_the_budget_goes_to_flagged_stories_first_then_the_most_severe_then_the_newest() -> None:
    # two stories without any flag (actors at the same rare directories) have the lowest ids
    plain = [
        seen(10 * k + n, actors=(("ip", f"198.51.100.{10 * k + n}"),), campus=False,
             targets=paths("p", "q"), severity="critical")
        for k in (1, 2) for n in (1, 2)
    ]  # fmt: skip
    flagged = [*story(7), *story(8)]
    assert len(opened(plan([*plain, *flagged], new_budget=99))) == 3  # the plain four are one
    assert chosen(plan([*plain, *flagged], new_budget=2)) == {7, 8}  # a flag beats severity
    mixed = [*story(5, severity="medium"), *story(6, severity="critical"),
             *story(7, severity="high")]  # fmt: skip
    assert chosen(plan(mixed, new_budget=1)) == {6}
    assert chosen(plan(mixed, new_budget=2)) == {6, 7}
    newer = [*story(5, hours=30), *story(6, hours=1), *story(7, hours=10)]
    assert chosen(plan(newer, new_budget=2)) == {6, 7}  # the same severity: the newest


def test_the_suggesters_budget_is_its_own_constant() -> None:
    assert suggest.MAX_SUGGESTED_PER_HOUR >= 1
    hosts = [s for k in range(suggest.MAX_SUGGESTED_PER_HOUR + 2) for s in story(k + 1)]
    assert len(opened(plan(hosts))) == suggest.MAX_SUGGESTED_PER_HOUR  # the default budget


@given(st.lists(seens, max_size=14, unique_by=lambda s: s.investigation_id), st.integers(0, 4))
def test_a_smaller_budget_keeps_the_front_of_the_same_order(items: list[Seen], budget: int) -> None:
    every = opened(plan(items, new_budget=99))
    assert opened(plan(items, new_budget=budget)) == every[:budget]


# -- a person's "no" stands -------------------------------------------------------------------


def test_a_dismissed_suggestion_is_not_made_again_for_the_same_host() -> None:
    no = Dismissed(frozenset({HOST}), frozenset(RAISING))
    assert len(opened(plan(amadey()))) == 1
    assert plan(amadey(), dismissed=[no]) == []
    wider = Dismissed(frozenset({HOST, ("ip", "10.1.1.1")}), frozenset({BEACON, OUT, LISTED}))
    assert plan(amadey(), dismissed=[wider]) == []


def test_a_flag_kind_the_dismissed_case_did_not_have_is_news() -> None:
    no = Dismissed(frozenset({HOST}), frozenset(RAISING))
    news = [seen(1, rule="download", flags=RAISING), seen(2, rule="beacon", flags=(LISTED,))]
    (case,) = opened(plan(news, dismissed=[no]))
    assert LISTED in case.flags
    bare = Dismissed(frozenset({HOST}), frozenset())  # a dismissed case with no flag at all
    assert len(opened(plan(amadey(), dismissed=[bare]))) == 1
    both = [no, Dismissed(frozenset({HOST}), frozenset({LISTED}))]
    assert plan(news, dismissed=both) == []  # two dismissals together had both kinds


def test_another_host_or_a_wider_set_of_actors_is_not_the_dismissed_story() -> None:
    elsewhere = Dismissed(frozenset({("ip", "10.1.1.1")}), frozenset(RAISING))
    assert len(opened(plan(amadey(), dismissed=[elsewhere]))) == 1
    servers = tuple(SERVERS[:2])
    wider = [
        seen(1, rule="download", flags=RAISING, targets=servers),
        seen(2, rule="beacon", flags=RAISING, targets=servers),
        seen(3, rule="beacon", flags=RAISING, actors=(("ip", "10.77.0.9"),), targets=servers),
    ]
    narrow = Dismissed(frozenset({HOST}), frozenset(RAISING))
    assert len(opened(plan(wider, dismissed=[narrow]))) == 1  # a second host is a new story


def test_a_dismissal_does_not_stop_links_to_a_suggested_case() -> None:
    no = Dismissed(frozenset({HOST}), frozenset(RAISING))
    (link,) = plan([seen(7, rule="other", hours=0.1)], [raised_case()], dismissed=[no])
    assert isinstance(link, LinkCase)


# -- the reason counts the case's members -----------------------------------------------------


def test_the_reason_counts_the_investigations_of_the_case_not_those_another_case_holds() -> None:
    closed = Held(uuid.UUID(int=79), 6, "closed", "raised")
    held = [replace_held(seen(1, rule="x", flags=RAISING, hours=9), closed),
            replace_held(seen(2, rule="y", flags=RAISING, hours=8), closed)]  # fmt: skip
    new = [seen(3, rule="download", flags=RAISING, hours=2),
           seen(4, rule="beacon", flags=RAISING, hours=1)]  # fmt: skip
    (case,) = opened(plan([*held, *new]))
    assert [m.investigation_id.int for m in case.members] == [3, 4]
    assert case.attention.startswith("ARGUS suggests this case: 2 investigations of one campus")
    assert "4 investigations" not in case.attention


def test_an_offer_and_a_link_count_the_investigations_they_carry() -> None:
    open_case = Held(uuid.UUID(int=77), 3, "open", "verdict")
    items = [replace_held(seen(1, rule="download", flags=RAISING), open_case),
             seen(2, rule="beacon", flags=RAISING)]  # fmt: skip
    (offer,) = plan(items)
    assert isinstance(offer, SuggestMembers)
    assert offer.reason.startswith("1 investigation of one campus host: ")  # not "2"
    case = raised_case()
    holding = Held(case.ref, case.number, "suspected", "raised")
    later = [
        *(replace_held(s, holding) for s in amadey()),
        seen(3, rule="beacon", flags=RAISING),
        seen(4, rule="download", flags=RAISING),
    ]
    (link,) = plan(later, [case])
    assert isinstance(link, LinkCase)
    assert link.reason.startswith("2 investigations of one campus host: ")  # not "4"


# -- shared infrastructure is no actor, as it is no target ------------------------------------

CDN = ("ip", "104.16.0.9")
CLOUD = Shared(networks=(ipaddress.ip_network("104.16.0.0/13"),))


def test_an_actor_in_a_shared_network_joins_nothing_later() -> None:
    case = raised_case(actor=CDN)
    arrival = seen(7, actors=(CDN,), campus=False, hours=0.1)
    (link,) = plan([arrival], [case])  # an ordinary address would join the case
    assert isinstance(link, LinkCase)
    assert plan([arrival], [case], shared=CLOUD) == []


def test_an_actor_in_a_shared_network_is_no_story_with_others() -> None:
    both = paths("a", "b")
    items = [seen(1, actors=(CDN,), campus=False, targets=both, severity="high"),
             seen(2, actors=(("ip", GIT[0]),), campus=False, targets=both)]  # fmt: skip
    assert len(opened(plan(items))) == 1
    assert plan(items, shared=CLOUD) == []
    assert plan(items, shared=Shared().with_common([CDN])) == []  # in very many investigations


def test_a_campus_host_in_very_many_investigations_is_no_host_story() -> None:
    assert len(opened(plan(amadey()))) == 1
    assert plan(amadey(), shared=Shared().with_common([HOST])) == []


@given(st.lists(seens, max_size=14, unique_by=lambda s: s.investigation_id))
def test_when_every_actor_is_shared_nothing_is_suggested(items: list[Seen]) -> None:
    everyone = Shared().with_common(HOSTS + OUTSIDE)
    assert plan(items, [raised_case(5)], shared=everyone) == []
