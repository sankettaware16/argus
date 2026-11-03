"""AR2c (D-168, D-170): suggested cases from campaigns, and the rule that what an open case holds is
never suggested into a new one. The user's reason: on this campus a true positive often stays
active after the owner is told (personal laptops cannot be forced to clean), so its alerts keep
coming; they belong to the case already there, and a new device that reaches the campaign's
destinations is offered to that case, one offer for each device.
"""

from __future__ import annotations

import uuid
from dataclasses import replace

from hypothesis import given
from hypothesis import strategies as st

from argus.campaigns.analysis import Campaign
from argus.campaigns.families import Key
from argus.cases import suggest
from argus.cases.model import SEVERITIES
from argus.cases.suggest import (
    Action,
    Dismissed,
    Existing,
    Held,
    LinkCase,
    Live,
    OpenCase,
    Seen,
    SuggestMembers,
)
from tests.unit.cases.test_suggest import BEACON, HOST, LISTED, NOW, OUT, RAISING, seen

DOMAIN = "rapid-dns-hosting.com"
SISTER = "win-service-portal.com"
KEYS = frozenset({("domain", DOMAIN), ("domain", SISTER)})
CAMPAIGN_FLAGS = (OUT, "many campus devices reach one rare domain")


def device(n: int) -> Key:
    return ("ip", f"10.2.0.{n}")


def ids(*numbers: int) -> frozenset[uuid.UUID]:
    return frozenset(uuid.UUID(int=n) for n in numbers)


def campaign(numbers: tuple[int, ...], hosts: tuple[int, ...], **more: object) -> Campaign:
    base: dict[str, object] = {
        "members": ids(*numbers), "hosts": frozenset(device(h) for h in hosts),
        "parents": (DOMAIN, SISTER), "servers": (), "flagged": (DOMAIN,),
        "infrastructure": ("AS64501 (Shady Hosting)",), "benign": ("cdn-edge-bench.net",),
        "random_share": 0.9,
    }  # fmt: skip
    return Campaign(**{**base, **more})  # type: ignore[arg-type]


def member(n: int, *, flags: tuple[str, ...] = CAMPAIGN_FLAGS, **more: object) -> Seen:
    """Investigation ``n`` of device ``n``: one alert of a rule, a low severity, flagged."""
    fields: dict[str, object] = {"rule": "dns", "actors": (device(n),), "flags": flags}
    return seen(n, **{**fields, **more})  # type: ignore[arg-type]


def story(hosts: int = 4) -> tuple[list[Seen], Campaign]:
    items = [member(n) for n in range(1, hosts + 1)]
    return items, campaign(tuple(range(1, hosts + 1)), tuple(range(1, hosts + 1)))


def plan(items: list[Seen], found: list[Campaign], **more: object) -> list[Action]:
    return suggest.plan(items, more.pop("existing", []), now=NOW, campaigns=found, **more)  # type: ignore[arg-type]


def opened(actions: list[Action]) -> list[OpenCase]:
    return [a for a in actions if isinstance(a, OpenCase)]


# -- a campaign is one suggested case -----------------------------------------------------------


def test_devices_that_reach_one_operator_are_one_suggested_case() -> None:
    items, found = story(4)
    (case,) = opened(plan(items, [found]))
    assert sorted(m.investigation_id.int for m in case.members) == [1, 2, 3, 4]
    assert (
        case.title
        == "Contact with rapid-dns-hosting.com and 1 more flagged server from 4 campus devices"
    )
    assert case.attention.startswith("ARGUS suggests this case: one operator, 4 campus devices: ")
    assert DOMAIN in case.attention
    assert SISTER in case.attention
    assert "AS64501 (Shady Hosting)" in case.attention
    assert "(benign, ARGUS recommends closing): cdn-edge-bench.net" in case.attention
    assert case.flags == CAMPAIGN_FLAGS
    assert case.severity == "medium"  # at least medium: ARGUS saw evidence of something
    assert {(a.kind, a.value) for a in case.actors} == {device(n) for n in range(1, 5)}
    assert {(t.kind, t.value) for t in case.targets} == set(KEYS)
    assert all(t.role == "indicator" for t in case.targets)
    assert len(case.attention) <= 500
    assert len(case.title) <= 200


def test_one_investigation_for_each_device_is_enough_no_pair_of_rules_is_needed() -> None:
    items, found = story(3)
    assert len({s.rule for s in items}) == 1  # one rule, one alert a device
    assert len(opened(plan(items, [found]))) == 1
    assert plan(items, []) == []  # without the campaign, nothing: nothing raises a lone device


def test_no_campus_address_is_in_the_title_or_the_words() -> None:
    items, found = story(3)
    (case,) = opened(plan(items, [found]))
    assert not any(v in case.title for _, v in found.hosts)
    assert not any(v in case.attention for _, v in found.hosts)  # a campus address goes nowhere


def test_the_members_are_those_unreviewed_in_the_last_72_hours() -> None:
    items, found = story(4)
    stale = replace(items[0], at=NOW - suggest.WINDOW * 2)
    (case,) = opened(plan([stale, *items[1:]], [found]))
    assert sorted(m.investigation_id.int for m in case.members) == [2, 3, 4]
    assert plan([stale, items[1]], [found]) == []  # one member is no case


def test_benign_investigations_are_split_off_not_members() -> None:
    items, found = story(3)
    benign = member(9, flags=())  # a device that reached only the popular family
    (case,) = opened(plan([*items, benign], [found]))
    assert 9 not in {m.investigation_id.int for m in case.members}


def test_two_campaigns_that_share_a_device_are_one_case() -> None:
    items = [member(n) for n in range(1, 6)]
    a = campaign((1, 2, 3), (1, 2, 3), parents=(DOMAIN,))
    b = campaign((3, 4, 5), (3, 4, 5), parents=(SISTER,))
    (case,) = opened(plan(items, [a, b]))
    assert sorted(m.investigation_id.int for m in case.members) == [1, 2, 3, 4, 5]


def test_a_host_story_joins_the_campaign_only_through_a_raised_member() -> None:
    items, found = story(3)
    extra = member(30, actors=(device(1),), flags=(BEACON,), rule="beacon")  # same device 1
    (case,) = opened(plan([*items, extra], [found]))
    assert 30 in {m.investigation_id.int for m in case.members}  # device 1's raised: host story
    lone = member(31, actors=(device(8),), flags=(BEACON,), rule="beacon")
    other = member(32, actors=(device(8),), flags=(BEACON,), rule="download")
    (case,) = opened(plan([*items, lone, other], [found]))
    assert not {31, 32} & {m.investigation_id.int for m in case.members}  # no raise, no story


def test_the_flagged_campaign_goes_first_in_the_hours_budget() -> None:
    items, found = story(3)
    plain = [member(50 + n, actors=(device(40 + n),), flags=(LISTED, BEACON), rule="x")
             for n in range(2)]  # fmt: skip
    again = [member(60 + n, actors=(device(40 + n),), flags=(LISTED, BEACON), rule="y")
             for n in range(2)]  # fmt: skip
    cases = opened(plan([*items, *plain, *again], [found], new_budget=1))
    assert len(cases) == 1  # the budget is one: flagged first, then the most severe, then newest


# -- a person's "no" stands for a campaign ------------------------------------------------------


def test_a_dismissed_campaign_is_not_suggested_again_when_new_devices_join_it() -> None:
    items, found = story(4)
    no = Dismissed(frozenset(device(n) for n in (1, 2)), frozenset(CAMPAIGN_FLAGS), KEYS)
    assert plan(items, [found], dismissed=[no]) == []  # new devices, the same destinations
    bigger = Dismissed(frozenset(), frozenset(CAMPAIGN_FLAGS), KEYS | {("domain", "more.com")})
    assert plan(items, [found], dismissed=[bigger]) == []
    news = campaign(
        found.members and (1, 2, 3, 4), (1, 2, 3, 4), parents=(DOMAIN, SISTER, "new.com")
    )
    narrow = Dismissed(frozenset(), frozenset(CAMPAIGN_FLAGS), KEYS)
    assert len(opened(plan(items, [news], dismissed=[narrow]))) == 1  # a new domain is news


def test_a_flag_the_dismissed_campaign_did_not_have_is_news() -> None:
    items, found = story(4)
    no = Dismissed(frozenset(), frozenset({OUT}), KEYS)
    assert len(opened(plan(items, [found], dismissed=[no]))) == 1  # the campaign flag is new


# -- what an open case holds is never suggested into a new case (D-170) -------------------------


def live(
    number: int = 7, *, state: str = "open", hosts: tuple[int, ...] = (1, 2, 3, 4),
    held: frozenset[Key] = KEYS,
) -> Live:  # fmt: skip
    return Live(uuid.UUID(int=700 + number), number, state, frozenset(device(h) for h in hosts),
                held)  # fmt: skip


def suspected(number: int = 5, *, hosts: tuple[int, ...] = (1, 2, 3, 4)) -> Existing:
    return Existing(uuid.UUID(int=900 + number), number, frozenset(device(h) for h in hosts), KEYS)


def held(case: Live | Existing, state: str, cause: str) -> Held:
    return Held(case.ref, case.number, state, cause)


def test_a_new_day_of_a_host_an_open_case_holds_creates_no_suggestion() -> None:
    """The campaign case exists and holds device 1 and the campaign's domains. Device 1's alerts
    come again on a new day: no new suggested case, no offer (the opener joins it)."""
    case = live()
    items, _ = story(4)
    members = [replace(s, held=held(case, "open", "verdict")) for s in items]
    new_day = member(21, actors=(device(1),), day=25, hours=0.5)
    assert plan([*members, new_day], [campaign((1, 2, 3, 4, 21), (1, 2, 3, 4))], live=[case]) == []
    assert plan([new_day], [campaign((21,), (1,))], live=[case]) == []
    assert (
        plan([new_day, member(22, actors=(device(1),), flags=RAISING, rule="b")], [], live=[case])
        == []
    )


def test_a_new_host_reaching_the_campaigns_indicators_is_offered_to_the_same_case() -> None:
    case = live()
    items, _ = story(4)
    members = [replace(s, held=held(case, "open", "verdict")) for s in items]
    newcomer = member(21, actors=(device(9),), hours=0.5)
    actions = plan([*members, newcomer], [campaign((1, 2, 3, 4, 21), (1, 2, 3, 4, 9))], live=[case])
    (offer,) = actions
    assert isinstance(offer, SuggestMembers)
    assert (offer.case_id, offer.number, offer.kind) == (case.ref, 7, "also")
    assert [m.investigation_id.int for m in offer.members] == [21]
    assert opened(actions) == []


def test_each_new_host_gets_one_offer_and_a_known_host_none() -> None:
    case = live()
    found = campaign((1, 2, 3, 4, 21, 22, 23, 24), (1, 2, 3, 4, 9, 10))
    items = [
        replace(member(1), held=held(case, "open", "verdict")),
        member(21, actors=(device(9),)),
        member(22, actors=(device(9),), hours=2),  # a second investigation of the same new host
        member(23, actors=(device(10),)),
        member(24, actors=(device(2),)),  # a host the case has already
    ]
    actions = plan(items, [found], live=[case])
    assert all(isinstance(a, SuggestMembers) and a.case_id == case.ref for a in actions)
    offers = {
        tuple(sorted(m.investigation_id.int for m in a.members))
        for a in actions
        if isinstance(a, SuggestMembers)
    }
    assert offers == {(21, 22), (23,)}  # one offer a host; device 2 gets none


def test_a_campaign_whose_indicators_are_held_opens_no_case_even_with_no_known_host() -> None:
    case = live(hosts=(99,))  # the case holds the domains but none of these devices yet
    items, found = story(3)
    actions = plan(items, [found], live=[case])
    assert opened(actions) == []
    assert {a.number for a in actions if isinstance(a, SuggestMembers)} == {7}
    assert len(actions) == 3  # one offer for each of the three new devices


def test_a_host_an_open_case_holds_opens_no_new_case_for_its_other_alerts() -> None:
    """Amadey's host is in an open case; its download and beacon alerts, both raised, would be a
    host story. They are not suggested into a new case."""
    case = Live(uuid.UUID(int=701), 7, "open", frozenset({HOST}), frozenset())
    pair = [seen(1, rule="download", flags=RAISING), seen(2, rule="beacon", flags=RAISING)]
    assert len(opened(plan(pair, []))) == 1  # without the case it is a story
    assert plan(pair, [], live=[case]) == []  # with it: nothing (the host is the case's already)


def test_a_case_in_any_state_but_closed_holds_what_it_has() -> None:
    items, found = story(3)
    for state in ("open", "assigned", "contained", "suspected"):
        actions = plan(items, [found], live=[live(state=state)])
        assert opened(actions) == [], state
    assert len(opened(plan(items, [found], live=[]))) == 1  # a closed case is not in the list


def test_a_suggested_case_nobody_confirmed_takes_in_new_hosts_and_new_days() -> None:
    case = suspected()
    items, _ = story(4)
    members = [replace(s, held=held(case, "suspected", "raised")) for s in items]
    newcomer = member(21, actors=(device(9),), hours=0.5)
    new_day = member(22, actors=(device(1),), day=25, hours=0.4)
    actions = plan(
        [*members, newcomer, new_day],
        [campaign((1, 2, 3, 4, 21, 22), (1, 2, 3, 4, 9))],
        existing=[case],
    )
    (link,) = actions
    assert isinstance(link, LinkCase)
    assert link.case == case
    assert sorted(m.investigation_id.int for m in link.members) == [21, 22]
    assert opened(actions) == []


def test_a_new_host_alone_reaches_a_suggested_case_through_the_indicators() -> None:
    case = suspected(hosts=(1, 2))
    newcomer = member(21, actors=(device(9),), hours=0.5)
    second = member(22, actors=(device(10),), hours=0.4)
    actions = plan([newcomer, second], [campaign((21, 22), (9, 10))], existing=[case])
    (link,) = actions
    assert isinstance(link, LinkCase)
    assert link.case == case
    assert opened(actions) == []


def test_several_cases_holding_it_are_each_offered_it_as_a_tie() -> None:
    a, b = live(7, hosts=(98,)), live(8, hosts=(99,))  # two cases that hold the destinations
    items, found = story(3)
    actions = plan(items, [found], live=[a, b])
    offers = [x for x in actions if isinstance(x, SuggestMembers)]
    assert {(o.number, o.kind) for o in offers} == {(7, "tie"), (8, "tie")}
    assert opened(actions) == []


def test_shared_rare_targets_an_open_case_holds_make_no_new_case() -> None:
    targets = (("url", "/~hostel5/.git"), ("url", "/~hostel9/.git"))
    scout = seen(1, rule="scan", actors=(("ip", "185.220.101.5"),), campus=False, targets=targets,
                 severity="high")  # fmt: skip
    collector = seen(2, rule="volume", actors=(("ip", "185.220.101.4"),), campus=False,
                     targets=targets)  # fmt: skip
    assert len(opened(suggest.plan([scout, collector], [], now=NOW))) == 1
    case = Live(uuid.UUID(int=777), 3, "open", frozenset({("ip", "185.220.101.5")}),
                frozenset(targets))  # fmt: skip
    actions = suggest.plan([scout, collector], [], now=NOW, live=[case])
    assert opened(actions) == []
    (offer,) = actions  # the collector is a new actor reaching the case's directories
    assert isinstance(offer, SuggestMembers)
    assert offer.case_id == case.ref
    assert [m.investigation_id.int for m in offer.members] == [2]


def test_a_closed_case_of_the_investigations_still_keeps_them_out_of_new_cases() -> None:
    items, found = story(3)
    closed = Held(uuid.UUID(int=79), 6, "closed", "verdict")
    members = [replace(s, held=closed) for s in items]
    assert plan(members, [found]) == []  # as before: a closed case is not reopened or competed with


def test_the_devices_a_campaign_found_behind_a_key_that_names_none_are_the_actors() -> None:
    """A DNS rule's key lists every source address, so ``Seen.actors`` is empty; the campaign
    found the devices among the entities and the suggester treats them as its actors."""
    case = live(hosts=(1, 2))
    blank = [replace(member(n), actors=frozenset(), campus=frozenset()) for n in (21, 22, 23)]
    devices = {
        uuid.UUID(int=21): frozenset({device(1), device(2)}),  # both known to the case
        uuid.UUID(int=22): frozenset({device(2), device(9)}),  # one new
        uuid.UUID(int=23): frozenset({device(8)}),  # a new one
    }
    found = campaign((21, 22, 23), (1, 2, 8, 9), member_hosts=devices)
    actions = plan(blank, [found], live=[case])
    offers = {
        tuple(sorted(m.investigation_id.int for m in a.members))
        for a in actions
        if isinstance(a, SuggestMembers)
    }
    assert opened(actions) == []
    assert offers == {(22,), (23,)}
    (opened_case,) = opened(
        plan(blank, [found])
    )  # without the case: one, with the devices as actors
    assert {(a.kind, a.value) for a in opened_case.actors} == {
        device(1),
        device(2),
        device(8),
        device(9),
    }


# -- properties ---------------------------------------------------------------------------------

HOSTS = [device(n) for n in range(1, 7)]
members_st = st.builds(
    lambda n, h, flags, hours: member(n, actors=(HOSTS[h],), flags=flags, hours=hours),
    st.integers(1, 5_000),
    st.integers(0, 5),
    st.sampled_from([(), (BEACON,), RAISING, CAMPAIGN_FLAGS, (LISTED, BEACON)]),
    st.floats(0, 100),
)


@given(st.lists(members_st, max_size=12, unique_by=lambda s: s.investigation_id),
       st.sets(st.integers(0, 5), min_size=1))  # fmt: skip
def test_a_case_that_holds_every_host_and_the_domains_gets_no_competitor(
    items: list[Seen], held_hosts: set[int]
) -> None:
    case = Live(uuid.UUID(int=1), 1, "open", frozenset(HOSTS[h] for h in held_hosts), KEYS)
    every = [replace(s, held=None) for s in items]
    found = campaign(tuple(s.investigation_id.int for s in every), tuple(range(1, 7)))
    for action in plan(every, [found], live=[case]):
        assert not isinstance(action, OpenCase)
        if isinstance(action, SuggestMembers):
            assert action.case_id == case.ref
            for m in action.members:
                assert not m.actors <= case.actors  # a host the case has already gets no offer


@given(st.lists(members_st, max_size=12, unique_by=lambda s: s.investigation_id))
def test_campaign_planning_keeps_the_old_invariants(items: list[Seen]) -> None:
    found = campaign(tuple(s.investigation_id.int for s in items), tuple(range(1, 7)))
    actions = plan(items, [found])
    again = plan(list(reversed(items)), [found])
    assert actions == again
    members = [m.investigation_id for a in actions for m in a.members]
    assert len(members) == len(set(members))
    for case in opened(actions):
        assert len(case.members) >= 2
        assert SEVERITIES.index(case.severity) >= SEVERITIES.index("medium")
        assert len(case.attention) <= 500
        assert len(case.title) <= 200
