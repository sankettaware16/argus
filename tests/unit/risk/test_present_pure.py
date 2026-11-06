"""The presenter's pure parts (P4-F E5, on the linker): benign alternatives and their tests, the
checks, the certainty word, the priority step as the lifecycle's ``band_of`` (a band that rises
is a material change the lifecycle says; a person's confirm changes no evidence band), the
closed case's memory, and Hypothesis properties: the governor never holds back a P1 or P2 and
fills only the day's room with P3, then P4; the replay's governor shows every incident once or
keeps it waiting. Made-up values only."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.risk import alternatives as alt
from argus.risk import incident_config, incident_replay, lifecycle, present, run
from argus.risk import priority as prio
from argus.risk.lifecycle import Incident, Material
from argus.risk.link import Component, Link
from argus.risk.observe import ObjectRef, Observation
from tests.unit.risk.conftest import CONFIG, NOW, obs

pytestmark = pytest.mark.unit
CTX = present.Context(CONFIG)
LINKING = incident_config.load()
DEV = ObjectRef("device", "ip:10.1.1.1")


def ev(**more: object) -> alt.Evidence:
    base: dict[str, object] = {"object_kinds": frozenset({"device"})}
    return alt.Evidence(**{**base, **more})  # type: ignore[arg-type]


def states(found: list[alt.Alternative]) -> dict[str, str]:
    return {a.name.split(" (")[0]: a.state for a in found}


def test_a_rare_destination_rules_out_an_update_service_and_a_common_one_fits() -> None:
    rare = states(alt.alternatives(ev(kinds=frozenset({"beacon"}), reach={"ip:a": 1})))
    assert rare["A software update or telemetry service"] == "ruled_out"
    assert rare["A research crawler or a student project"] == "ruled_out"
    assert rare["A rule's usual noise"] == "ruled_out"
    common = states(alt.alternatives(ev(reach={"domain:cdn.test": 40, "ip:b": 25})))
    assert common["A software update or telemetry service"] == "fits"
    assert common["A rule's usual noise"] == "fits"
    nothing = states(alt.alternatives(ev()))
    assert nothing["A software update or telemetry service"] == "unknown"


def test_a_shared_gateway_fits_only_when_the_asset_map_says_so() -> None:
    name = "A shared gateway"
    assert states(alt.alternatives(ev(hubs=1)))[name] == "fits"
    assert states(alt.alternatives(ev(named_hosts=1)))[name] == "ruled_out"
    assert states(alt.alternatives(ev(object_kinds=frozenset({"account"}))))[name] == "ruled_out"
    assert states(alt.alternatives(ev()))[name] == "unknown"


def test_an_old_threat_list_entry_is_tested_only_with_intel() -> None:
    assert "An old threat-list entry" not in states(alt.alternatives(ev()))
    stale = states(alt.alternatives(ev(kinds=frozenset({"ti"}), stale_intel=True)))
    assert stale["An old threat-list entry"] == "fits"
    fresh = states(alt.alternatives(ev(kinds=frozenset({"ti"}))))
    assert fresh["An old threat-list entry"] == "ruled_out"


def test_a_campus_site_attacked_from_outside_has_its_own_alternatives() -> None:
    found = states(alt.alternatives(ev(acting=False, object_kinds=frozenset({"site"}))))
    assert found["A soft-404 site"] == "unknown"
    assert found["An authorised scanner"] == "unknown"


def test_checks_say_what_was_looked_at() -> None:
    found = alt.checks(ev(kinds=frozenset({"ti", "beacon"}), reach={"ip:a": 1},
                          signals=frozenset({"proxy.regularity"})))  # fmt: skip
    assert [(c.state, c.text) for c in found] == [
        ("checked", "on a threat list (current)"),
        ("unknown", "outside threat intel: no verdict on its destinations"),
        ("checked", "regular timing, like a beacon"),
        ("ruled_out", "no other campus device reaches its destinations"),
        ("unknown", "who used the device: sign-ins are not part of this priority"),
    ]


def test_the_certainty_word() -> None:
    fits = [alt.Alternative("x", "fits", "t")]
    out = [alt.Alternative("x", "ruled_out", "t")]
    assert alt.certainty(confirmed=True, lanes=(), strong=False, found=fits) == "Confirmed"
    assert alt.certainty(confirmed=False, lanes={"decisive"}, strong=True, found=out) == "Likely"
    assert alt.certainty(confirmed=False, lanes={"decisive"}, strong=False,
                         found=out) == "Suspected"  # fmt: skip
    assert alt.certainty(confirmed=False, lanes={"burst"}, strong=False, found=out) == "Suspected"
    assert alt.certainty(confirmed=False, lanes={"burst"}, strong=True, found=fits) == "Unclear"
    assert alt.certainty(confirmed=False, lanes={"slow"}, strong=False,
                         found=fits) == "Likely harmless"  # fmt: skip
    assert alt.certainty(confirmed=False, lanes=(), strong=False, found=out) == "Unclear"


# --------------------------------------------------------------------------- the priority step


def rows(points: float, *, strong: bool = False, hours_ago: float = 1.0) -> list[Observation]:
    out = [obs("rule:L1", base=points, hours_ago=hours_ago, stages=0b0100, family="squid")]
    if strong:
        out.append(obs("ev:outside", base=50.0, strong=True, hours_ago=hours_ago,
                       threats=("domain:bad-example.net",)))  # fmt: skip
    return out


def verdicts(items: list[Observation]) -> dict[ObjectRef, object]:
    return dict(run.evaluate_all(items, NOW, CONFIG, {}, set()).verdicts)


def comp(*refs: ObjectRef) -> Component:
    links = [Link(refs[0], None, "lane", "decisive", 0, timedelta(0), "in a lane: decisive")]
    return Component(tuple(sorted(refs)), dict.fromkeys(refs, ("decisive",)), tuple(links),
                     False)  # fmt: skip


def test_the_ranker_sets_the_incidents_priority_from_its_verdicts() -> None:
    items = rows(40.0, strong=True)
    found = verdicts(items)
    band_of = present.ranker(found, NOW, CONFIG)  # type: ignore[arg-type]
    inc = Incident(None, NOW, NOW, NOW, {DEV: "actor"})
    band = band_of(inc)
    objs = [present.obj_of(DEV, found[DEV])]  # type: ignore[arg-type]
    expected = present.rank(objs, NOW, CONFIG, NOW)
    assert (inc.priority, band) == (expected.priority, expected.band)
    assert band == prio.band_of(inc.priority)
    assert objs[0].strong
    assert objs[0].kinds == {"outside"}
    assert objs[0].parts[0].source == "ev:outside"
    empty = Incident(None, NOW, NOW, NOW, {ObjectRef("device", "ip:10.9.9.9"): "actor"})
    assert (band_of(empty), empty.priority) == ("P4", 0)


def test_a_band_that_rises_is_a_material_change_the_lifecycle_says() -> None:
    weak = rows(8.0)
    facts = lifecycle.facts_of(weak, NOW, lambda t: False)
    out = lifecycle.advance(
        [], [comp(DEV)], facts, NOW, LINKING, present.ranker(verdicts(weak), NOW, CONFIG)
    )  # type: ignore[arg-type]
    inc = out.opened[0]
    inc.id = 1
    assert inc.band == "P4"
    later = NOW + timedelta(hours=1)
    strong = rows(60.0, strong=True, hours_ago=0.5)
    facts = lifecycle.facts_of(strong, later, lambda t: False)
    again = lifecycle.advance(
        [inc], [comp(DEV)], facts, later, LINKING, present.ranker(verdicts(strong), later, CONFIG)
    )  # type: ignore[arg-type]
    assert again.requeued == [inc]
    assert inc.band in ("P1", "P2", "P3")
    assert f"priority rose to {inc.band}" in inc.changed
    assert inc.version == 2


def test_a_persons_confirm_raises_the_card_but_no_evidence_band() -> None:
    """The trust factor puts a confirmed P2 in P1 on the card; the evidence band (the lifecycle's
    material, the case's severity) stays."""
    for points in range(10, 400, 2):
        found = verdicts(rows(float(points), strong=True))
        objs = [present.obj_of(DEV, found[DEV])]  # type: ignore[arg-type]
        plain = present.value(objs, NOW, CTX, confirmed=False, reach={}, signals=(),
                              rule_names={}, lanes={"decisive"}, last_seen=NOW)  # fmt: skip
        trusted = present.value(objs, NOW, CTX, confirmed=True, reach={}, signals=(),
                                rule_names={}, lanes={"decisive"}, last_seen=NOW)  # fmt: skip
        assert trusted.priority >= plain.priority
        assert trusted.evidence_band == plain.evidence_band == plain.band
        assert (plain.certainty, trusted.certainty) == ("Likely", "Confirmed")
        if plain.band == "P2" and trusted.band == "P1":
            break
    else:
        pytest.fail("no score that a confirm moves from P2 to P1")
    assert trusted.view()["band"] == "P1"
    assert any(i.text == "confirmed by a person" for i in trusted.why)
    assert plain.why
    assert plain.why[0].text == "outside detection (VirusTotal)"


def test_the_why_line_names_rules_only_as_words() -> None:
    found = verdicts(rows(40.0))
    objs = [present.obj_of(DEV, found[DEV])]  # type: ignore[arg-type]
    named = present.value(objs, NOW, CTX, confirmed=False, reach={}, signals=(),
                          rule_names={"L1": "Beacon rule"}, lanes={"burst"},
                          last_seen=NOW)  # fmt: skip
    plain = present.value(objs, NOW, CTX, confirmed=False, reach={}, signals=(),
                          rule_names={}, lanes={"burst"}, last_seen=NOW)  # fmt: skip
    assert named.why[0].text == "rule: Beacon rule"
    assert plain.why[0].text == "a rule"
    assert (named.priority, named.band, named.certainty) == (plain.priority, plain.band,
                                                             plain.certainty)  # fmt: skip


def test_threats_and_reach_come_from_the_acting_rule_observations() -> None:
    items = [
        obs("rule:L1", threats=("ip:45.0.0.1", "domain:x.test")),
        obs("rule:L1", key="ip:10.1.1.2", threats=("ip:45.0.0.1",)),
        obs("rule:L1", key="ip:10.1.1.3", role="target", threats=("ip:45.0.0.9",)),
        obs("ev:beacon", key="ip:10.1.1.4", threats=("ip:45.0.0.8",)),
        obs("rule:L1", key="ip:10.1.1.5", threats=("ip:45.0.0.7",), hours_ago=24 * 9),
    ]
    threats, reach = present.threats_of(items, NOW, timedelta(days=7))
    assert threats == {DEV: {"ip:45.0.0.1", "domain:x.test"},
                       ObjectRef("device", "ip:10.1.1.2"): {"ip:45.0.0.1"}}  # fmt: skip
    assert reach == {"ip:45.0.0.1": 2, "domain:x.test": 1}


# --------------------------------------------------------------------------- memory, governor


def material(**more: object) -> dict[str, object]:
    base = Material(frozenset({"rule:L1"}), 0b0100, frozenset({"squid"}), frozenset(), 0, "P3")
    return {**base.as_json(), **more}


def test_a_closed_cases_memory_breaks_only_on_a_strong_change() -> None:
    shown = material()
    assert not present.breaks(shown, shown)
    assert not present.breaks(shown, material(sources=["rule:L1", "rule:L2"]))  # a new rule
    assert not present.breaks(shown, material(devices=2))  # more devices
    assert not present.breaks(shown, material(band="P4"))  # a band that falls
    assert present.breaks(shown, material(flagged=["domain:bad-example.net"]))
    assert present.breaks(shown, material(stages=0b0110))
    assert present.breaks(shown, material(families=["dns", "squid"]))
    assert present.breaks(shown, material(band="P2"))
    assert present.breaks({}, shown)  # never shown: no memory


waiting = st.lists(
    st.tuples(st.sampled_from(["P1", "P2", "P3", "P4"]), st.integers(0, 100)), max_size=40
)


@given(waiting, st.integers(0, 30), st.integers(1, 20))
def test_the_governor_never_hides_p1_or_p2_and_keeps_to_the_room(
    items: list[tuple[str, int]], shown_today: int, room: int
) -> None:
    rows_ = [(i, band, p) for i, (band, p) in enumerate(items)]
    chosen = present.govern(rows_, shown_today, room)
    urgent = {i for i, band, _ in rows_ if band in ("P1", "P2")}
    assert urgent <= chosen
    rest = [(band, p, i) for i, band, p in rows_ if band in ("P3", "P4")]
    taken = [r for r in rest if r[2] in chosen]
    assert len(taken) == min(len(rest), max(0, room - shown_today - len(urgent)))
    if taken:  # P3 before P4, the highest priorities first
        worst = max((b, -p) for b, p, _ in taken)
        assert all((b, -p) >= worst for b, p, i in rest if i not in chosen)


def test_the_replays_governor_carries_what_waits_to_the_next_day() -> None:
    assert incident_replay.shown({"P3": 24}) == (10, 14)
    assert incident_replay.shown({"P4": 8}, 14) == (10, 12)
    assert incident_replay.shown({"P1": 12, "P3": 1}, 2) == (12, 3)


days = st.lists(st.dictionaries(st.sampled_from(["P1", "P2", "P3", "P4"]), st.integers(0, 30)),
                max_size=20)  # fmt: skip


@given(days, st.integers(1, 20))
def test_the_replays_governor_shows_every_item_once_or_keeps_it_waiting(
    per_day: list[dict[str, int]], room: int
) -> None:
    held, total = 0, 0
    for bands in per_day:
        shown, after = incident_replay.shown(bands, held, room)
        urgent = bands.get("P1", 0) + bands.get("P2", 0)
        assert shown >= urgent
        assert shown <= max(room, urgent)
        total += shown
        held = after
    assert total + held == sum(sum(b.values()) for b in per_day)


def test_elsewhere_and_adoption_follow_the_cases_that_hold_the_alert_groups() -> None:
    own = present.Group(uuid.UUID(int=1), 3, NOW, None, False)
    persons = present.Group(uuid.UUID(int=2), 3, NOW, uuid.UUID(int=20), True)
    engines = present.Group(uuid.UUID(int=3), 3, NOW, uuid.UUID(int=30), True, engine=True)
    decided = present.Group(uuid.UUID(int=4), 3, NOW, uuid.UUID(int=40), False)
    suggested = present.Group(uuid.UUID(int=5), 3, NOW, uuid.UUID(int=50), True, adoptable=True)
    assert present._elsewhere([own, engines], None) is None
    assert present._elsewhere([own, persons], None) is None  # a free group: presented with it
    assert present._elsewhere([persons], None) == persons.case_id  # nothing free: a person has it
    assert present._elsewhere([decided], None) == decided.case_id  # nothing free: waits
    assert present._elsewhere([decided, own], None) is None
    assert present._elsewhere([persons], persons.case_id) is None  # its own case
    assert present._elsewhere([persons, decided], uuid.UUID(int=9)) is None  # a case: never
    assert present._elsewhere([suggested], None) is None  # ARGUS's own suggestion: adopted
    assert present._adoptable([own, suggested], set()) == suggested.case_id
    assert present._adoptable([own, suggested], {suggested.case_id}) is None  # type: ignore[arg-type]


def test_the_fallback_title_and_the_indicators_of_a_new_case() -> None:
    found = verdicts(rows(40.0, strong=True))
    o = present.obj_of(DEV, found[DEV])  # type: ignore[arg-type]
    assert present.fallback_title([o], "decisive") == "Possible incident: campus device 10.1.1.1"
    assert present.fallback_title([o], None) == "Watched: campus device 10.1.1.1"
    marks = present.indicators([o], {"domain:bad-example.net", "ip:45.0.0.1"},
                               {"domain:bad-example.net": 1, "ip:45.0.0.1": 40})  # fmt: skip
    assert [(m.kind, m.value, m.role) for m in marks] == [
        ("ip", "10.1.1.1", "actor"), ("domain", "bad-example.net", "indicator")]  # fmt: skip
    day = present.obj_of(ObjectRef("device", "ip:10.1.1.1@2026-10-20"), found[DEV])  # type: ignore[arg-type]
    assert [m.value for m in present.indicators([day], (), {})] == ["10.1.1.1"]
    assert day.label == "10.1.1.1 (on 2026-10-20)"


def test_site_day_is_the_sites_calendar_day() -> None:
    assert isinstance(present.site_day(NOW), type(NOW.date()))
    assert present.site_day(datetime(2026, 10, 20, 23, 0, tzinfo=NOW.tzinfo)) >= NOW.date()


def stored(n: int, band: str, *, shown_in: str | None, case: bool = False) -> present.Stored:
    """A root incident as the shadow left it: a card shown in that mode, no case."""
    return present.Stored(
        n, "active", 1, ("new incident",), {}, NOW - timedelta(days=1), 40, band, ("burst",),
        {"lane": "burst", "shown_in": shown_in}, uuid.UUID(int=n) if case else None,
        NOW - timedelta(days=1), NOW, NOW - timedelta(days=1), "Possible incident", "Suspected",
        shown_in is not None, NOW.date() if shown_in else None, NOW if shown_in else None,
        {"band": band} if shown_in else {}, NOW if shown_in else None,
        "suspected" if case else None,
    )  # fmt: skip


def test_switching_on_sends_shadows_cards_through_the_daily_room() -> None:
    """What shadow showed is not shown when presenting: the first presenting pass governs the
    incidents without a case again (P1 and P2 at once, P3 within the room), so switching on
    does not put weeks of shadow in front of a person at once; a card this mode showed stays."""
    rows = [stored(1, "P1", shown_in="shadow"), stored(2, "P3", shown_in="shadow"),
            stored(3, "P3", shown_in="shadow"), stored(4, "P3", shown_in="present", case=True),
            stored(5, "P4", shown_in=None)]  # fmt: skip
    world = present.World(rows, {}, {}, frozenset(), {}, {}, {}, {}, {}, 0, set())
    ctx = present.Context(CONFIG, present.Options(True, 2))  # the P1 takes one of the two
    planned = present.plan(world, NOW, ctx)
    shown = {p.id for p in planned.incidents if p.shown}
    assert 1 in shown  # a P1 at once
    assert 4 in shown  # a card presenting already showed
    assert shown & {2, 3, 5} == {2}  # one P3 in the day's room, the lowest id of equals
    assert all(p.view["shown_in"] == ("present" if p.shown else None) for p in planned.incidents)
    again = present.plan(world, NOW, present.Context(CONFIG, present.Options(False, 10)))
    assert {p.id for p in again.incidents if p.shown} == {1, 2, 3, 4, 5}  # shadow's own room
