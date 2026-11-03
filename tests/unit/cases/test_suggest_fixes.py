"""D-174: what the adversarial review of AR2c found in the suggester, each as a scenario.

A campaign is offered to, or taken in by, the case that holds one of its indicators and no other;
investigations another open case holds are not moved; a dismissal compares against every domain
and server of the campaign; offers have an hourly budget of their own.
"""

from __future__ import annotations

import uuid
from dataclasses import replace

from hypothesis import given
from hypothesis import strategies as st

from argus.campaigns.analysis import Campaign
from argus.cases import suggest
from argus.cases.suggest import (
    Dismissed,
    Existing,
    LinkCase,
    Live,
    OpenCase,
    Seen,
    SuggestMembers,
)
from tests.unit.cases.test_suggest_campaigns import (
    CAMPAIGN_FLAGS,
    DOMAIN,
    KEYS,
    NOW,
    SISTER,
    campaign,
    device,
    held,
    live,
    member,
    opened,
    story,
    suspected,
)
from tests.unit.cases.test_suggest_campaigns import plan as campaign_plan


def plan(items: list[Seen], found: list[Campaign], **more: object):  # type: ignore[no-untyped-def]
    return campaign_plan(items, found, **more)


def ids_of(case: OpenCase) -> list[int]:
    return sorted(m.investigation_id.int for m in case.members)


# -- a campaign belongs to the case that holds its indicators (review 2) -------------------------


def test_a_case_that_merely_shares_a_device_does_not_absorb_the_campaign() -> None:
    """A manual case for an old, unrelated alert holds device 1. It holds none of the campaign's
    domains or servers: the campaign is not offered to it, it opens a case of its own."""
    unrelated = Live(uuid.UUID(int=7), 7, "open", frozenset({device(1)}),
                     frozenset({("domain", "git.example.org")}))  # fmt: skip
    items, found = story(6)
    actions = plan(items, [found], live=[unrelated])
    assert not [a for a in actions if isinstance(a, SuggestMembers)]
    (case,) = opened(actions)
    assert ids_of(case) == [1, 2, 3, 4, 5, 6]


def test_a_readdressed_laptop_does_not_swallow_a_devices_investigations_silently() -> None:
    """DHCP: last week's case for another person's laptop holds 10.2.0.3, which is now a device of
    the campaign. Its alerts are not quietly offered to that case."""
    old = Live(uuid.UUID(int=8), 8, "assigned", frozenset({device(3)}), frozenset())
    items, found = story(6)
    actions = plan(items, [found], live=[old])
    assert [type(a) for a in actions] == [OpenCase]
    assert 3 in ids_of(opened(actions)[0])


def test_the_campaign_is_never_linked_into_an_unconfirmed_host_story() -> None:
    """A suggested case for one device's own alerts (not confirmed yet) holds device 2. The old
    code linked the whole campaign into it."""
    host_story = Existing(uuid.UUID(int=9), 9, frozenset({device(2)}), frozenset())
    items, found = story(6)
    actions = plan(items, [found], existing=[host_story])
    assert not [a for a in actions if isinstance(a, LinkCase)]
    assert not [a for a in actions if isinstance(a, SuggestMembers)]
    assert ids_of(opened(actions)[0]) == [1, 2, 3, 4, 5, 6]


def test_two_unconfirmed_host_stories_make_no_tie_for_a_campaign() -> None:
    first = Existing(uuid.UUID(int=11), 11, frozenset({device(1)}), frozenset())
    second = Existing(uuid.UUID(int=12), 12, frozenset({device(2)}), frozenset())
    items, found = story(6)
    actions = plan(items, [found], existing=[first, second])
    assert [type(a) for a in actions] == [OpenCase]


def test_the_case_that_holds_the_campaigns_indicators_is_the_one_that_takes_it() -> None:
    items, found = story(4)
    mine = suspected(5, hosts=(1, 2))  # holds the campaign's domains
    other = Existing(uuid.UUID(int=9), 9, frozenset({device(3)}), frozenset())
    (link,) = plan(items, [found], existing=[other, mine])
    assert isinstance(link, LinkCase)
    assert link.case == mine
    open_case = live(7, hosts=(98,))
    actions = plan(items, [found], live=[open_case])
    assert {a.number for a in actions if isinstance(a, SuggestMembers)} == {7}
    assert opened(actions) == []


# -- investigations another open case holds are not moved ---------------------------------------


def test_investigations_another_open_case_holds_stay_there_and_are_named() -> None:
    other = Live(uuid.UUID(int=7), 7, "open", frozenset({device(1)}), frozenset())
    items, found = story(6)
    items = [replace(s, held=held(other, "open", "verdict")) if s.investigation_id.int <= 2 else s
             for s in items]  # fmt: skip
    (case,) = opened(plan(items, [found], live=[other]))
    assert ids_of(case) == [3, 4, 5, 6]  # the free members only
    assert "Also in case 7 (2 investigations)" in case.attention
    assert case.attention.startswith("ARGUS suggests this case: one operator, 6 campus devices: ")
    assert {(a.kind, a.value) for a in case.actors} >= {device(n) for n in range(3, 7)}


def test_the_campaign_still_needs_two_free_devices() -> None:
    other = Live(uuid.UUID(int=7), 7, "open", frozenset({device(1)}), frozenset())
    items, found = story(4)
    items = [replace(s, held=held(other, "open", "verdict")) if s.investigation_id.int <= 3 else s
             for s in items]  # fmt: skip
    assert plan(items, [found], live=[other]) == []  # one free device: no case
    items, found = story(5)
    items = [replace(s, held=held(other, "open", "verdict")) if s.investigation_id.int <= 3 else s
             for s in items]  # fmt: skip
    assert len(opened(plan(items, [found], live=[other]))) == 1  # two free devices: a case


def test_a_closed_case_is_not_named() -> None:
    items, found = story(6)
    closed = Live(uuid.UUID(int=7), 7, "closed", frozenset(), frozenset())
    items = [replace(s, held=held(closed, "closed", "verdict")) if s.investigation_id.int == 1
             else s for s in items]  # fmt: skip
    (case,) = opened(plan(items, [found]))
    assert "Also in case" not in case.attention
    assert 1 not in ids_of(case)  # (a closed case's investigation is still not taken from it)


# -- a dismissal compares against every domain and server (review 8) -----------------------------


def big(domains: int, devices: int) -> tuple[list[Seen], Campaign]:
    items = [member(n) for n in range(1, devices + 1)]
    parents = tuple(f"dga{n:04d}.example-bad.net" for n in range(domains))
    found = campaign(tuple(range(1, devices + 1)), tuple(range(1, devices + 1)), parents=parents,
                     flagged=parents[:1])  # fmt: skip
    return items, found


def dismissed_after(items: list[Seen], found: Campaign) -> Dismissed:
    (case,) = opened(plan(items, [found]))
    return Dismissed(frozenset((a.kind, a.value) for a in case.actors), frozenset(case.flags),
                     frozenset((t.kind, t.value) for t in case.targets))  # fmt: skip


def test_a_dismissed_campaign_of_25_domains_stays_dismissed_after_a_device_joins() -> None:
    items, found = big(25, 6)
    no = dismissed_after(items, found)
    assert len(no.indicators) == 25  # all of them were stored (the old code kept 20)
    assert plan(items, [found], dismissed=[no]) == []
    more_items, more = big(25, 7)  # a seventh device joins
    assert plan(more_items, [more], dismissed=[no]) == []
    news_items, news = big(26, 7)  # a new domain is news
    assert len(opened(plan(news_items, [news], dismissed=[no]))) == 1


def test_a_campaign_case_stores_its_domains_in_full_up_to_a_bound() -> None:
    items, found = big(300, 6)
    (case,) = opened(plan(items, [found]))
    stored = {(t.kind, t.value) for t in case.targets}
    assert len(stored) == suggest.MAX_CAMPAIGN_KEYS
    assert stored == set(sorted(found.keys())[: suggest.MAX_CAMPAIGN_KEYS])
    assert len(case.actors) + len(case.targets) <= 500  # one change may add 500 indicators
    no = dismissed_after(items, found)
    assert plan(items, [found], dismissed=[no]) == []  # compared against what was stored
    other_items, other = big(300, 8)
    assert plan(other_items, [other], dismissed=[no]) == []


def test_other_targets_are_still_kept_to_twenty() -> None:
    targets = tuple(("url", f"/~h{n}/.git") for n in range(40))
    a = Seen(uuid.UUID(int=1), "scan", "high", NOW.date(), NOW, frozenset({("ip", "185.1.1.1")}),
             frozenset(), (), frozenset(targets), None)  # fmt: skip
    b = replace(a, investigation_id=uuid.UUID(int=2), actors=frozenset({("ip", "185.1.1.2")}))
    (case,) = opened(suggest.plan([a, b], [], now=NOW))
    assert len(case.targets) == suggest.MAX_TARGETS


# -- offers have an hourly budget of their own (review 9) ---------------------------------------


def newcomers(count: int, case: Live) -> list[Seen]:
    old = replace(member(1), held=held(case, "open", "verdict"))
    return [old, *(member(100 + n, actors=(device(100 + n),)) for n in range(count))]


def test_offers_stop_at_the_hourly_budget() -> None:
    case = live(7, hosts=(1,))
    items = newcomers(40, case)
    found = campaign(tuple(s.investigation_id.int for s in items), (1, *range(100, 140)))
    every = plan(items, [found], live=[case])
    assert len([a for a in every if isinstance(a, SuggestMembers)]) == 30  # the default
    few = plan(items, [found], live=[case], offer_budget=3)
    assert len([a for a in few if isinstance(a, SuggestMembers)]) == 3
    assert plan(items, [found], live=[case], offer_budget=0) == []
    assert plan(items, [found], live=[case], offer_budget=-4) == []
    assert suggest.MAX_OFFERS_PER_HOUR == 30


def test_an_investigation_offered_to_the_case_already_is_not_offered_again() -> None:
    case = live(7, hosts=(1,))
    items = newcomers(4, case)
    found = campaign(tuple(s.investigation_id.int for s in items), (1, 100, 101, 102, 103))
    done = {(uuid.UUID(int=100), case.ref), (uuid.UUID(int=101), case.ref)}
    actions = plan(items, [found], live=[case], offered=done)
    offered = {m.investigation_id.int for a in actions if isinstance(a, SuggestMembers)
               for m in a.members}  # fmt: skip
    assert offered == {102, 103}  # a person's dismissal of an offer stands: the row is there
    # the budget is spent on offers that are new, not on the ones already made
    spent = plan(items, [found], live=[case], offered=done, offer_budget=1)
    assert len([a for a in spent if isinstance(a, SuggestMembers)]) == 1
    assert plan(items, [found], live=[case], offered={(s.investigation_id, case.ref)
                                                      for s in items}) == []  # fmt: skip


@given(st.integers(0, 12), st.integers(0, 40))
def test_the_offers_never_exceed_the_budget_and_never_repeat(budget: int, count: int) -> None:
    case = live(7, hosts=(1,))
    items = newcomers(count, case)
    found = campaign(tuple(s.investigation_id.int for s in items), (1, *range(100, 100 + count)))
    actions = plan(items, [found], live=[case], offer_budget=budget)
    offers = [a for a in actions if isinstance(a, SuggestMembers)]
    assert len(offers) <= max(budget, 0)
    investigations = [m.investigation_id for a in offers for m in a.members]
    assert len(investigations) == len(set(investigations))


# -- a campaign component only ever goes to a case that holds its indicators ---------------------


@given(
    st.lists(
        st.tuples(
            st.sets(st.integers(1, 6)),  # the devices the case holds
            st.sampled_from(["campaign", "other", "none"]),  # what indicators it holds
            st.booleans(),  # a suggested case nobody confirmed (else an open one)
        ),
        max_size=5,
    )
)
def test_a_campaign_is_only_offered_or_linked_to_a_case_that_holds_its_indicators(
    cases: list[tuple[set[int], str, bool]],
) -> None:
    items, found = story(6)
    indicators = {"campaign": KEYS, "other": frozenset({("domain", "elsewhere.example")}),
                  "none": frozenset()}  # fmt: skip
    cases_live: list[Live] = []
    cases_suggested: list[Existing] = []
    for n, (devices, what, unconfirmed) in enumerate(cases):
        actors = frozenset(device(h) for h in devices)
        if unconfirmed:
            cases_suggested.append(
                Existing(uuid.UUID(int=500 + n), 20 + n, actors, indicators[what])
            )
        else:
            cases_live.append(
                Live(uuid.UUID(int=600 + n), 40 + n, "open", actors, indicators[what])
            )
    actions = plan(items, [found], live=cases_live, existing=cases_suggested)
    allowed = {c.ref for c in [*cases_live, *cases_suggested] if c.indicators & KEYS}
    for action in actions:
        if isinstance(action, LinkCase):
            assert action.case.ref in allowed
        if isinstance(action, SuggestMembers):
            assert action.case_id in allowed
    if not allowed:
        assert len(opened(actions)) == 1  # nothing holds it: a case of its own


def test_the_domains_and_servers_the_tests_use() -> None:
    assert {DOMAIN, SISTER} == {v for _, v in KEYS}
    assert CAMPAIGN_FLAGS[1] == "many campus devices reach one rare domain"
