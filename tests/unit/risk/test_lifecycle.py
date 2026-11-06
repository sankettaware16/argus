"""The incident lifecycle (E2): match, fold, material change, merge blockers, caps and ageing.
Made-up values only."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pytest

from argus.risk import incident_config, lifecycle
from argus.risk.lifecycle import Facts, Incident, Material, advance, changes, facts_of
from argus.risk.link import Component, Link
from argus.risk.observe import ObjectRef, Observation

from .conftest import NOW, obs

pytestmark = pytest.mark.unit
LINKING = incident_config.load()


def dev(n: int) -> ObjectRef:
    return ObjectRef("device", f"ip:10.2.0.{n}")


def comp(*refs: ObjectRef, campaign: bool = False) -> Component:
    links = [Link(refs[0], None, "lane", "decisive", 0, timedelta(0), "in a lane: decisive")]
    links += [Link(refs[0], r, "rare", "domain:rare-example.org", 4, timedelta(hours=1),
                   "the same rare domain") for r in refs[1:]]  # fmt: skip
    return Component(
        tuple(sorted(refs)), dict.fromkeys(refs, ("decisive",)), tuple(links), campaign
    )


def facts(
    rows: list[Observation], at: datetime = NOW, flagged: frozenset[str] = frozenset()
) -> Facts:
    return facts_of(rows, at, lambda t: t in flagged)


def step(held: list[Incident], comps: list[Component], rows: list[Observation],
         at: datetime = NOW) -> lifecycle.Outcome:  # fmt: skip
    out = advance(held, comps, facts(rows, at), at, LINKING)
    for n, inc in enumerate(out.incidents):  # what the store does: ids for the new ones
        if inc.id is None and inc.state != "merged":
            inc.id = 1000 + n
    return out


def test_a_new_component_opens_an_incident_with_every_group_of_the_window() -> None:
    rows = [obs("rule:L1", key=dev(1).key, hours_ago=h) for h in (1, 30, 100)]
    out = step([], [comp(dev(1))], rows)
    assert len(out.opened) == 1
    inc = out.opened[0]
    assert len(inc.groups) == 3
    assert inc.version == 1
    assert inc.changed == ["new incident"]
    assert inc.objects == {dev(1): "actor"}


def test_new_days_and_rules_fold_in_silently() -> None:
    first = [obs("rule:L1", key=dev(1).key, hours_ago=30)]
    out = step([], [comp(dev(1))], first)
    later = [*first, obs("rule:L1", key=dev(1).key, hours_ago=1, gid=uuid.uuid4())]
    again = step(out.incidents, [comp(dev(1))], later)
    inc = again.incidents[0]
    assert not again.opened
    assert not again.requeued
    assert len(inc.groups) == 2
    assert inc.version == 1


def test_a_new_kind_of_evidence_is_material_and_said() -> None:
    first = [obs("rule:L1", key=dev(1).key, hours_ago=30)]
    out = step([], [comp(dev(1))], first)
    later = [*first, obs("ev:tunnel", key=dev(1).key, hours_ago=1, stages=4)]
    again = step(out.incidents, [comp(dev(1))], later)
    inc = again.incidents[0]
    assert again.requeued == [inc]
    assert inc.version == 2
    assert any("tunnel" in c for c in inc.changed)
    assert any("stage" in c for c in inc.changed)


def test_more_devices_across_a_bucket_is_material() -> None:
    rows = [obs("rule:L1", key=dev(n).key, hours_ago=2) for n in (1, 2, 3, 4)]
    out = step([], [comp(dev(1))], rows)
    again = step(out.incidents, [comp(dev(1), dev(2), dev(3), dev(4))], rows)
    assert again.requeued
    assert any("4-10 devices" in c for c in again.incidents[0].changed)


def test_material_changes_only_on_the_listed_dimensions() -> None:
    old = Material(frozenset({"rule:L1"}), 1, frozenset({"dns"}), frozenset(), 0, "P3")
    assert changes(old, old) == []
    assert changes(old, Material(old.sources, old.stages, old.families, old.flagged, 0, "P4")) == []
    assert changes(old, Material(old.sources | {"rule:L2"}, 1, old.families, frozenset(), 0,
                                 "P3")) == ["1 new rule"]  # fmt: skip
    flagged = Material(old.sources, 1, old.families, frozenset({"domain:c2-example.net"}), 0, "P3")
    assert changes(old, flagged) == ["newly flagged: c2-example.net"]
    assert changes(old, Material(old.sources, 1, old.families, frozenset(), 0, "P1")) == [
        "priority rose to P1"
    ]


def test_quiet_then_a_stop_proposal_then_sealed_then_a_linked_new_incident() -> None:
    rows = [obs("rule:L1", key=dev(1).key, hours_ago=1)]
    out = step([], [comp(dev(1))], rows)
    inc = out.incidents[0]
    step(out.incidents, [], rows, NOW + timedelta(hours=80))
    assert inc.state == "quiet"
    assert inc.stop_proposed_at is None
    step(out.incidents, [], rows, NOW + timedelta(days=15))
    assert inc.state == "quiet"
    assert inc.stop_proposed_at is not None
    later = NOW + timedelta(days=31)
    fresh = [obs("rule:L1", key=dev(1).key, hours_ago=-31 * 24 + 1, gid=uuid.uuid4())]
    after = step(out.incidents, [comp(dev(1))], fresh, later)
    assert inc.state == "sealed"
    assert len(after.opened) == 1
    assert after.opened[0].follows == inc.id


def test_activity_again_makes_a_quiet_incident_active() -> None:
    rows = [obs("rule:L1", key=dev(1).key, hours_ago=1)]
    out = step([], [comp(dev(1))], rows)
    step(out.incidents, [], rows, NOW + timedelta(hours=80))
    back = [*rows, obs("rule:L1", key=dev(1).key, hours_ago=-80, gid=uuid.uuid4())]
    step(out.incidents, [comp(dev(1))], back, NOW + timedelta(hours=81))
    assert out.incidents[0].state == "active"


def test_two_incidents_a_component_bridges_merge_into_the_older() -> None:
    rows = [obs("rule:L1", key=dev(n).key, hours_ago=2) for n in (1, 2)]
    out = step([], [comp(dev(1)), comp(dev(2))], rows)
    a, b = sorted(out.incidents, key=lambda i: i.id or 0)
    again = step(out.incidents, [comp(dev(1), dev(2))], rows)
    assert again.merged == [(a, b)]
    assert b.state == "merged"
    assert b.merged_into == a.id
    assert set(a.objects) == {dev(1), dev(2)}


@pytest.mark.parametrize("blocker", ["owner", "decision", "both_decided", "sealed"])
def test_merge_blockers_keep_incidents_apart(blocker: str) -> None:
    """A person's decision on either incident keeps them apart (people merge cases themselves),
    as do different owners and a sealed one; the link is kept as a recommendation."""
    rows = [obs("rule:L1", key=dev(n).key, hours_ago=2) for n in (1, 2)]
    out = step([], [comp(dev(1)), comp(dev(2))], rows)
    a, b = sorted(out.incidents, key=lambda i: i.id or 0)
    if blocker == "owner":
        a.owner, b.owner = 1, 2
    elif blocker == "decision":
        b.decision = "confirmed"
    elif blocker == "both_decided":
        a.owner = b.owner = 1
        a.decision = b.decision = "confirmed"
    else:
        b.state = "sealed"
    again = step(out.incidents, [comp(dev(1), dev(2))], rows)
    assert not again.merged
    assert b.state != "merged"
    assert dev(2) not in a.objects or blocker == "sealed"


def test_past_the_group_cap_a_linked_overflow_takes_the_rest() -> None:
    rows = [obs("rule:L1", key=dev(1).key, hours_ago=1 + n / 10, gid=uuid.uuid4())
            for n in range(250)]  # fmt: skip
    out = step([], [comp(dev(1))], rows)
    root = next(i for i in out.incidents if not i.overflow)
    kids = [i for i in out.incidents if i.overflow]
    assert len(root.groups) == LINKING.caps.groups
    assert len(kids) == 1
    assert len(kids[0].groups) == 50
    assert kids[0].root is root
    assert not kids[0].new
    assert out.opened == [root]


def test_a_merge_never_passes_the_cap_of_risk_objects() -> None:
    first = [dev(n) for n in range(1, 31)]
    second = [dev(n) for n in range(31, 61)]
    rows = [obs("rule:L1", key=r.key, hours_ago=2) for r in first + second]
    out = step([], [comp(*first), comp(*second)], rows)
    again = step(out.incidents, [comp(first[0], second[0])], rows)
    assert not again.merged
    assert max(i.size for i in again.incidents) <= LINKING.caps.objects


def test_the_view_part_has_the_contracts_fields() -> None:
    rows = [obs("rule:L1", key=dev(1).key, hours_ago=1),
            obs("rule:L2", key="domain:site.example.edu", kind="site", role="target")]  # fmt: skip
    site = ObjectRef("site", "domain:site.example.edu")
    out = step([], [comp(dev(1), site)], rows)
    view = lifecycle.view_part(out.incidents[0], NOW)
    assert set(view) >= {"lane", "objects", "active", "first_seen", "last_seen", "version",
                         "changed"}  # fmt: skip
    roles = {o["label"]: o["role"] for o in view["objects"]}
    assert roles == {"10.2.0.1": "actor", "site.example.edu": "affected"}
    assert view["lane"] == "decisive"
    assert view["active"] is True
    assert (
        lifecycle.label(ObjectRef("device", "ip:10.2.0.1@2026-10-20")) == "10.2.0.1 (on 2026-10-20)"
    )


def test_a_new_object_linked_to_a_member_joins_its_incident() -> None:
    from argus.risk import link
    from argus.risk.score import Stats

    t = "domain:rare-example.org"
    first = [obs("rule:L1", key=dev(1).key, hours_ago=5, threats=(t,))]
    out = step([], [comp(dev(1))], first)
    rows = [*first, obs("rule:L2", key=dev(2).key, hours_ago=1, threats=(t,))]
    starts = lifecycle.candidates_of({dev(2): ("burst",)}, out.incidents)  # dev1 left its lane
    comps = link.link_all(rows, NOW, starts, LINKING, Stats(), link.World())
    again = step(out.incidents, comps, rows)
    assert not again.opened
    assert set(again.incidents[0].objects) == {dev(1), dev(2)}
    assert lifecycle.MEMBER not in again.incidents[0].lanes


# --------------------------------------------------------------------------- sealing, merges


def a_pass(held: list[Incident], rows: list[Observation],
           lanes: dict[ObjectRef, tuple[str, ...]], at: datetime) -> lifecycle.Outcome:  # fmt: skip
    """One pass as the engine runs it: seal, the candidates, the linker (the 14-day window),
    then the lifecycle."""
    from argus.risk import link
    from argus.risk.score import Stats

    lifecycle.seal(held, at, LINKING)
    window = [o for o in rows if at - timedelta(days=14) <= o.at <= at]
    starts = lifecycle.candidates_of(lanes, held)
    comps = link.link_all(window, at, starts, LINKING, Stats(), link.World())
    return step(held, comps, window, at)


def test_a_sealed_incident_with_no_new_activity_never_comes_back() -> None:
    rows = [obs("rule:L1", key=dev(1).key, hours_ago=1)]
    held: list[Incident] = []
    opened: list[Incident] = []
    for day in range(130):  # longer than four seals
        out = a_pass(held, rows, {dev(1): ("decisive",)} if day == 0 else {},
                     NOW + timedelta(days=day))  # fmt: skip
        held = out.incidents
        opened += out.opened
    assert len(opened) == 1
    assert [i.state for i in held] == ["sealed"]


def test_members_of_an_incident_sealed_at_this_pass_open_nothing() -> None:
    rows = [obs("rule:L1", key=dev(1).key, hours_ago=1)]
    out = step([], [comp(dev(1))], rows)
    member = Component((dev(1),), {dev(1): (lifecycle.MEMBER,)},
                       (Link(dev(1), None, "lane", "member", 0, timedelta(0), "in a lane"),),
                       False)  # fmt: skip
    again = step(out.incidents, [member], rows, NOW + timedelta(days=31))
    assert out.incidents[0].state == "sealed"
    assert not again.opened


def test_a_follow_on_opens_only_with_an_alert_group_the_sealed_incident_lacks() -> None:
    old = [obs("rule:L1", key=dev(1).key, hours_ago=1)]
    out = step([], [comp(dev(1))], old)
    inc = out.incidents[0]
    later = NOW + timedelta(days=LINKING.lifecycle.seal_days)
    still = step(out.incidents, [comp(dev(1))], old, later)  # still in a lane, nothing new
    assert inc.state == "sealed"
    assert not still.opened
    fresh = obs("rule:L2", key=dev(1).key, hours_ago=-24 * LINKING.lifecycle.seal_days + 2)
    after = step(out.incidents, [comp(dev(1))], [*old, fresh], later + timedelta(hours=1))
    assert len(after.opened) == 1
    new = after.opened[0]
    assert new.follows == inc.id
    assert set(new.groups) == {fresh.group}
    assert new.first_seen == fresh.at


def test_merging_two_capped_incidents_keeps_the_group_cap_and_moves_the_overflows() -> None:
    cap = LINKING.caps.groups
    rows = [obs("rule:L1", key=dev(d).key, hours_ago=1 + n / 100, gid=uuid.uuid4())
            for d in (1, 2) for n in range(cap + 30)]  # fmt: skip
    out = step([], [comp(dev(1)), comp(dev(2))], rows)
    a, b = sorted((i for i in out.incidents if not i.overflow), key=lambda i: i.id or 0)
    assert len([i for i in out.incidents if i.overflow]) == 2
    again = step(out.incidents, [comp(dev(1), dev(2))], rows, NOW + timedelta(minutes=5))
    assert again.merged == [(a, b)]
    live = [i for i in again.incidents if i.state != "merged"]
    assert all(len(i.groups) <= cap for i in live)
    kids = [i for i in live if i.overflow]
    assert kids
    assert all(k.root is a and k.parent in (a.id, None) for k in kids)
    held = [g for i in live for g in i.groups]
    assert len(held) == len(set(held)) == 2 * (cap + 30)  # none lost, none twice
