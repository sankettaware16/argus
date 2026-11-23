"""An incident at a glance (AR10, D-250; P4-F V2 and V4): the numbers and the four series the
Visualiser draws, made from the stored report only. Which field a chart splits on follows the
case's shape; a count and the panel under it come from one list of the report; every day from the
first alert to the last has its bar; the call says whose it is; names of people are never counted
or drawn."""

from __future__ import annotations

from dataclasses import replace
from datetime import date, timedelta
from itertools import pairwise

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.incident import glance as g
from argus.incident import model as m
from argus.incident.build import build
from tests.unit.incident import kit

pytestmark = pytest.mark.unit


def amadey() -> m.IncidentReport:
    return build(kit.amadey(), kit.ctx())


def git() -> m.IncidentReport:
    return build(kit.git(), kit.ctx())


def scanners() -> m.IncidentReport:
    return build(kit.scanners(), kit.ctx())


def with_days(
    report: m.IncidentReport, rows: list[tuple[str, tuple[int, ...]]]
) -> m.IncidentReport:
    days = tuple(m.ReportDayRow(day=d, counts=c, total=sum(c)) for d, c in rows)
    return report.model_copy(update={"timeline": report.timeline.model_copy(update={"days": days})})


# --------------------------------------------------------------------------- shapes and counts


def test_a_campus_device_case_shows_its_device_its_servers_and_its_rules() -> None:
    report = amadey()
    glance = g.glance_of(report)
    assert glance.alerts == report.meta.alerts_total == 35
    assert glance.actors == 1
    assert (glance.targets, glance.targets_word, glance.targets_more) == (4, "server", False)
    assert glance.listed == 0
    assert glance.first == report.header.first_alert_at
    assert glance.last == report.header.last_alert_at
    assert glance.rules == 2
    assert not glance.rules_more
    assert glance.shape == g.Shape(
        "source.ip", "Top campus devices", "destination.ip", "Servers reached"
    )
    assert [(s.label, s.value) for s in glance.top_actors] == [(kit.HOST, 35)]
    assert [(s.label, s.value) for s in glance.rule_rows] == [
        ("Rule beacon", 21),
        ("Rule download", 14),
    ]
    assert glance.days == tuple(d.day for d in report.timeline.days)  # five days in a row
    assert [layer.name for layer in glance.layers] == list(report.timeline.columns)
    assert all(len(layer.values) == len(glance.days) for layer in glance.layers)
    assert sum(sum(layer.values) for layer in glance.layers) == glance.alerts


def test_the_servers_count_and_the_servers_panel_are_the_same_list() -> None:
    """F3: the row said "4 servers" while the panel drew one bar (the device's)."""
    report = amadey()
    glance = g.glance_of(report)
    c2 = [i.value for i in report.indicators if i.role == "c2"]
    assert [s.label for s in glance.top_targets] == c2
    assert glance.targets == len(c2) == len(glance.top_targets)
    assert all(s.value is None for s in glance.top_targets)  # named, not counted by the report
    assert all("VirusTotal" in s.note for s in glance.top_targets)
    assert not g.bars(glance.top_targets)  # a list in the dashboard: no invented bar lengths


def test_an_outside_scan_case_counts_and_draws_the_sites_the_alerts_name() -> None:
    report = git()
    glance = g.glance_of(report)
    assert glance.shape == g.Shape(
        "source.ip", "Top outside addresses", "url.domain", "Campus sites reached"
    )
    assert [s.label for s in glance.top_actors] == [kit.COLLECTOR, kit.SCOUT, kit.PROBER]
    first, second = (s.value for s in glance.top_actors[:2])
    assert first is not None
    assert second is not None
    assert first > second
    assert glance.targets_word == "site"
    sites = [t for t in report.targets if t.kind == "site"]
    assert glance.targets == len(sites) == 1
    assert [(s.label, s.value) for s in glance.top_targets] == [(t.value, t.alerts) for t in sites]


def test_sites_come_before_the_server_they_live_on() -> None:
    """The scan case names two sites and the server under them: one kind is counted and drawn
    (a live chart splits on one field), the sites."""
    report = scanners()
    kinds = {t.kind for t in report.targets}
    assert kinds == {"site", "host"}
    glance = g.glance_of(report)
    assert glance.shape.targets_field == g.SITE
    assert glance.targets == 2
    assert {s.label for s in glance.top_targets} == {
        t.value for t in report.targets if t.kind == "site"
    }


def overlapping() -> m.IncidentReport:
    """The scan case with two addresses, one of whose investigations also names the other
    site: each site is credited with that investigation's alerts."""
    f = kit.scanners(count=2)
    first = f.docs[0]
    both = replace(first, alert_id="a-x", fields={**first.fields, "url.domain": (kit.SITES[1],)})
    return build(replace(f, docs=(*f.docs, both)), kit.ctx(own_domains=("example.edu",)))


def test_targets_whose_counts_overlap_are_named_not_counted_or_drawn_as_bars() -> None:
    """Review: one investigation that names several sites gave every site its whole count, so
    the bars added up to more than the case (7 + 3 for a case of 7 alerts)."""
    report = overlapping()
    glance = g.glance_of(report)
    assert glance.alerts == 7
    assert glance.targets == 2
    assert all(s.value is None for s in glance.top_targets)
    assert not g.bars(glance.top_targets)
    by = {s.label: s.note for s in glance.top_targets}
    assert by[kit.SITES[0]] == "in investigations of 3 alerts, with other sites"
    assert by[kit.SITES[1]] == "in investigations of 7 alerts, with other sites"
    flags = tuple(t.model_copy(update={"shared": False}) for t in report.targets)
    older = g.glance_of(report.model_copy(update={"targets": flags}))  # no flag: the sum tells
    assert all(s.value is None for s in older.top_targets)
    apart = g.glance_of(scanners())  # each investigation names one site: counted and drawn
    assert g.bars(apart.top_targets)
    assert sum(s.value or 0 for s in apart.top_targets) <= apart.alerts


def test_counts_are_kept_unless_they_overlap() -> None:
    items = (g.Slice("a", 3, "Lab"), g.Slice("b", 4))
    assert g.counted(items, 7, "site") == items
    assert g.counted(items, 0, "site") == items  # the case's total is not known
    assert g.counted(items, 6, "site") == (
        g.Slice("a", None, "Lab; in investigations of 3 alerts, with other sites"),
        g.Slice("b", None, "in investigations of 4 alerts, with other sites"),
    )
    assert all(s.value is None for s in g.counted(items, 7, "site", shared=True))
    named = (g.Slice("c", None, "x"),)
    assert g.counted(named, 1, "site", shared=True) == named


def test_actors_whose_counts_overlap_are_not_drawn_as_bars() -> None:
    report = git()
    total = report.meta.alerts_total
    doubled = tuple(a.model_copy(update={"alerts": total}) for a in report.actors)
    glance = g.glance_of(report.model_copy(update={"actors": doubled}))
    assert glance.top_actors
    assert not g.bars(glance.top_actors)
    assert all("with other actors" in s.note for s in glance.top_actors)


def test_internal_servers_alone_are_drawn_on_the_destination_address() -> None:
    report = scanners()
    hosts = tuple(t for t in report.targets if t.kind == "host")
    glance = g.glance_of(report.model_copy(update={"targets": hosts, "targets_total": 1}))
    assert glance.shape.targets_field == g.SERVER_IP
    assert glance.shape.targets_title == "Campus servers reached"
    assert (glance.targets, glance.targets_word) == (1, "server")


def test_a_cut_list_of_targets_is_said_with_a_plus() -> None:
    report = git()
    glance = g.glance_of(report.model_copy(update={"targets_total": 30}))
    assert glance.targets_more
    assert g.more(glance.targets, glance.targets_more) == "1+"


def test_a_thing_the_report_cannot_say_is_not_drawn_and_not_invented() -> None:
    report = amadey().model_copy(
        update={"actors": (), "assets": (), "indicators": (), "indicators_total": 0}
    )
    glance = g.glance_of(report)
    assert glance.shape.actors_field is None
    assert glance.shape.targets_field is None
    assert glance.top_actors == ()
    assert glance.top_targets == ()
    assert glance.actors == 0
    assert glance.targets == 0


def test_names_of_people_are_not_counted_or_drawn() -> None:
    report = amadey()
    person = report.actors[0].model_copy(update={"value": "alice.example", "kind": "user"})
    glance = g.glance_of(report.model_copy(update={"actors": (person,)}))
    assert glance.actors == 0
    assert glance.top_actors == ()
    assert glance.shape.actors_field is None
    assert "alice" not in repr(glance)


def test_actors_that_are_all_hosts_split_on_the_host_name() -> None:
    report = amadey()
    host = report.actors[0].model_copy(update={"kind": "host", "value": "lab-pc-1"})
    shape = g.shape_of(report.model_copy(update={"actors": (host,)}))
    assert (shape.actors_field, shape.actors_title) == ("host.name", "Top hosts")


def test_a_domain_server_is_a_site_or_a_dns_name_by_what_the_reports_own_queries_read() -> None:
    report = amadey()
    domain = report.indicators[-1].model_copy(update={"role": "c2", "kind": "domain"})
    some = tuple(i for i in report.indicators if i.role != "c2")
    plain = report.model_copy(update={"indicators": (*some, domain), "queries": ()})
    assert g.shape_of(plain).targets_field == "url.domain"
    dns_query = report.queries[0].model_copy(update={"text": 'dns.question.name : "x.example"'})
    asking_dns = plain.model_copy(update={"queries": (dns_query,)})
    assert g.shape_of(asking_dns).targets_field == "dns.question.name"
    assert g.glance_of(asking_dns).targets == 1


def test_every_command_and_control_server_is_counted_and_listed_names_and_addresses() -> None:
    """Review: with two C2 domains and two C2 addresses the count said 2 servers while the report
    listed 4. Every one is counted and listed (names first); one live chart cannot split on both
    fields, so such a panel is a list."""
    report = amadey()
    ips = [i for i in report.indicators if i.role == "c2"]
    names = [
        ips[0].model_copy(update={"kind": "domain", "value": v}) for v in ("a.example", "b.example")
    ]
    mixed = report.model_copy(update={"indicators": (*ips[:2], *names), "queries": ()})
    glance = g.glance_of(mixed)
    assert glance.targets == 4
    assert [s.label for s in glance.top_targets] == [
        "a.example",
        "b.example",
        ips[0].value,
        ips[1].value,
    ]
    assert not glance.targets_charted
    assert glance.shape.targets_field == "url.domain"
    assert g.glance_of(report).targets_charted  # addresses alone: a chart over destination.ip
    alone = report.model_copy(update={"indicators": tuple(names), "queries": ()})
    assert g.glance_of(alone).targets_charted
    twice = report.model_copy(update={"indicators": (*report.indicators, ips[0])})
    assert g.glance_of(twice).targets == 4  # one server named twice is one server


def test_listed_indicators_are_the_ones_the_report_says_the_local_lists_hold() -> None:
    report = amadey()
    held = [i.model_copy(update={"evidence": f"{g.LISTED}; seen"}) for i in report.indicators[:2]]
    changed = report.model_copy(update={"indicators": (*held, *report.indicators[2:])})
    assert g.glance_of(changed).listed == 2


def test_a_count_the_report_cut_is_said_with_a_plus() -> None:
    assert g.more(25, True) == "25+"
    assert g.more(3, False) == "3"
    report = amadey()
    many = tuple(report.actors[0].model_copy(update={"value": f"10.0.0.{n}"}) for n in range(25))
    glance = g.glance_of(report.model_copy(update={"actors": many}))
    assert glance.actors == 25
    assert glance.actors_more
    assert len(glance.top_actors) == g.TOP


def test_the_bars_are_the_biggest_first_ties_by_name_and_never_empty_values() -> None:
    report = git()
    actors = [
        report.actors[0].model_copy(update={"value": v, "alerts": n})
        for v, n in (("b", 3), ("a", 3), ("c", 9), ("z", 0))
    ]
    glance = g.glance_of(report.model_copy(update={"actors": tuple(actors)}))
    assert [(s.label, s.value) for s in glance.top_actors] == [("c", 9), ("a", 3), ("b", 3)]


def test_a_panel_is_bars_only_from_two_counted_items() -> None:
    assert not g.bars(())
    assert not g.bars((g.Slice("a", 3),))
    assert g.bars((g.Slice("a", 3), g.Slice("b", 1)))
    assert not g.bars((g.Slice("a", 3), g.Slice("b", None)))


# --------------------------------------------------------------------------- days and weeks


def test_a_day_with_no_alert_is_a_gap_not_left_out() -> None:
    """F2: the git case had alerts on 23 and 25 Oct; 24 Oct is drawn, empty."""
    report = git()
    assert [d.day for d in report.timeline.days] == ["2026-10-23", "2026-10-25"]
    glance = g.glance_of(report)
    assert glance.step == 1
    assert glance.bucket == "day"
    assert glance.days == ("2026-10-23", "2026-10-24", "2026-10-25")
    (layer,) = glance.layers
    assert layer.values[1] == 0
    assert sum(layer.values) == sum(d.total for d in report.timeline.days)


def test_a_long_case_is_drawn_by_weeks_from_its_first_day() -> None:
    report = amadey()
    start = date(2026, 1, 5)
    rows = [((start + timedelta(days=k)).isoformat(), (1, 2)) for k in (0, 6, 7, 80)]
    glance = g.glance_of(with_days(report, rows))
    assert glance.step == 7
    assert glance.bucket == "week"
    assert glance.days[0] == "2026-01-05"
    assert glance.days[1] == "2026-01-12"
    assert len(glance.days) == 12  # 81 days: weeks 0..11
    beacon, download = glance.layers
    assert beacon.values[0] == 2  # day 0 and day 6 are week 0
    assert beacon.values[1] == 1  # day 7 is week 1
    assert sum(beacon.values) == 4
    assert sum(download.values) == 8


def test_a_very_long_case_keeps_to_a_readable_number_of_bars() -> None:
    report = amadey()
    rows = [("2020-01-01", (1, 0)), ("2026-01-01", (0, 1))]
    glance = g.glance_of(with_days(report, rows))
    assert glance.step % 7 == 0
    assert len(glance.days) <= g.MAX_BARS + 1
    assert glance.bucket.endswith("days")


def test_a_day_the_calendar_lacks_is_drawn_as_the_report_lists_it() -> None:
    report = amadey()
    glance = g.glance_of(with_days(report, [("2026-02-30", (1, 1)), ("2026-03-01", (2, 0))]))
    assert glance.days == ("2026-02-30", "2026-03-01")
    assert [layer.values for layer in glance.layers] == [(1, 2), (1, 0)]


@given(
    offsets=st.lists(st.integers(min_value=0, max_value=900), min_size=1, max_size=30),
    counts=st.lists(st.integers(min_value=0, max_value=50), min_size=2, max_size=2),
)
def test_every_day_from_the_first_to_the_last_is_a_bar_and_no_alert_is_lost(
    offsets: list[int], counts: list[int]
) -> None:
    report = amadey()
    start = date(2025, 6, 1)
    rows = [((start + timedelta(days=k)).isoformat(), (counts[0], counts[1])) for k in offsets]
    glance = g.glance_of(with_days(report, rows))
    span = max(offsets) - min(offsets) + 1
    assert glance.days[0] == (start + timedelta(days=min(offsets))).isoformat()
    days = [date.fromisoformat(d) for d in glance.days]
    assert all(b - a == timedelta(days=glance.step) for a, b in pairwise(days))
    assert len(days) == -(-span // glance.step)  # every bar from the first day to the last
    assert (glance.step == 1) == (span <= g.DAILY_UP_TO)
    assert len(days) <= g.MAX_BARS + 1
    for i, layer in enumerate(glance.layers):
        assert len(layer.values) == len(days)
        assert sum(layer.values) == counts[i] * len(offsets)


# --------------------------------------------------------------------------- the first questions


def test_the_call_says_whose_it_is_and_never_a_bare_true_positive_on_an_undecided_case() -> None:
    v = amadey().verdict
    assert v.kind == "proposal"
    assert g.call_of(v) == "True positive, 80% sure (ARGUS's call, not confirmed by a person)"
    assert (v.reviewed, v.investigations) == (0, 5)
    person = v.model_copy(update={"kind": "person", "confidence": None, "reviewed": 5})
    assert g.call_of(person) == "True positive (a person's verdict)"
    case = v.model_copy(update={"kind": "case"})
    assert g.call_of(case) == "True positive (a person confirmed the case)"
    reading = v.model_copy(update={"kind": "reading", "confidence": None})
    assert g.call_of(reading) == "True positive (ARGUS's reading, not confirmed by a person)"
    assert g.call_of(git().verdict) == "No call yet"


def test_a_verdict_of_some_reviews_says_how_many_never_a_persons_verdict() -> None:
    """Review: a TA marked one of sixteen investigations benign and the call read "Benign:
    expected activity (a person's verdict)", so the other fifteen looked decided."""
    f = kit.scanners()
    members = (replace(f.members[0], reviewed_outcome="benign_expected"), *f.members[1:])
    report = build(replace(f, members=members), kit.ctx(own_domains=("example.edu",)))
    assert (report.verdict.kind, report.verdict.reviewed) == ("person", 1)
    assert report.verdict.investigations == len(members) == 16
    call = g.glance_of(report).call
    assert call == "Benign: expected activity (people reviewed 1 of 16 investigations)"
    assert "a person's verdict" not in call
    every = tuple(replace(x, reviewed_outcome="benign_expected") for x in f.members)
    done = build(replace(f, members=every), kit.ctx(own_domains=("example.edu",)))
    assert g.glance_of(done).call == "Benign: expected activity (a person's verdict)"
    unread = build(replace(f, members=every, members_total=40), kit.ctx())
    assert "people reviewed 16 of 40 investigations" in g.glance_of(unread).call
    older = report.verdict.model_copy(update={"reviewed": 0, "investigations": 0})
    assert g.call_of(older) == "Benign: expected activity (from people's reviews)"


@given(
    outcome=st.sampled_from([None, *m.OUTCOMES]),
    kind=st.sampled_from(["person", "proposal", "reading", "case", "none"]),
    confidence=st.one_of(st.none(), st.floats(min_value=0, max_value=1)),
    reviewed=st.integers(min_value=0, max_value=50),
    investigations=st.integers(min_value=0, max_value=50),
)
def test_a_call_that_is_not_a_persons_says_so(
    outcome: str | None, kind: str, confidence: float | None, reviewed: int, investigations: int
) -> None:
    v = amadey().verdict.model_copy(
        update={
            "outcome": outcome,
            "kind": kind,
            "confidence": confidence,
            "words": "x" if outcome is None else outcome.replace("_", " "),
            "reviewed": reviewed,
            "investigations": investigations,
        }
    )
    said = g.call_of(v)
    assert said
    whole = kind == "case" or (kind == "person" and reviewed >= investigations > 0)
    if outcome is None:
        assert said == "No call yet"
    elif whole:
        assert "a person" in said
    elif kind == "person":  # some of the investigations, or not known how many
        assert "a person" not in said
        assert "people" in said
    else:
        assert "not confirmed by a person" in said


def test_the_status_says_the_severity_activity_and_dwell_of_the_report() -> None:
    report = amadey()
    glance = g.glance_of(report)
    assert glance.severity == "High"
    assert (glance.standing, glance.activity) == ("ongoing", "Still active")
    assert glance.dwell == report.timeline.dwell_words == "4 days 19 hours"
    quiet = g.glance_of(git())
    assert quiet.activity == "Quiet"
    unknown = report.model_copy(
        update={
            "summary": report.summary.model_copy(update={"standing": "unknown"}),
            "timeline": report.timeline.model_copy(update={"dwell_words": None}),
        }
    )
    assert g.glance_of(unknown).activity == "Not known"
    assert g.glance_of(unknown).dwell == "Not known"


# --------------------------------------------------------------------------- what the alerts hold


def test_a_field_is_carried_when_at_least_half_of_the_alerts_hold_it() -> None:
    docs = [
        {"source.ip": ("203.0.113.1",), "url.domain": ("a.example",)},
        {"source.ip": ("203.0.113.2",)},
        {"source.ip": ("203.0.113.3",), "url.domain": ("",)},
        {"source.ip": ("203.0.113.4",), "url.domain": ("b.example",)},
    ]
    assert g.carried_of(docs) == ("source.ip", "url.domain")
    assert g.carried_of(docs[1:3]) == ("source.ip",)
    assert g.carried_of([]) is None


def test_the_report_keeps_what_its_alerts_hold_and_a_chart_is_drawable_only_then() -> None:
    report = git()
    assert report.meta.carried == ("source.ip", "url.domain")
    glance = g.glance_of(report)
    assert glance.drawable("source.ip")
    assert glance.drawable("url.domain")
    assert not glance.drawable("destination.ip")
    assert not glance.drawable(None)
    unknown = g.glance_of(
        report.model_copy(update={"meta": report.meta.model_copy(update={"carried": None})})
    )
    assert unknown.drawable("destination.ip")  # not known: the chart is drawn as before


def test_a_threshold_shaped_case_holds_only_the_grouping_field() -> None:
    """F6: a threshold rule's alerts carry the field they are grouped by and not the site."""
    facts = kit.git()
    thin = tuple(replace(d, fields={"source.ip": d.fields["source.ip"]}) for d in facts.docs)
    report = build(replace(facts, docs=thin), kit.ctx())
    assert report.meta.carried == ("source.ip",)
    assert not g.glance_of(report).drawable(g.SITE)
