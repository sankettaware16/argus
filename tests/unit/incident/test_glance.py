"""An incident at a glance (AR10, D-250): the numbers and four series the Visualiser draws, made
from the stored report only; which field a chart splits on follows the case's shape; and names of
people are never counted or drawn."""

from __future__ import annotations

import pytest

from argus.incident import glance as g
from argus.incident import model as m
from argus.incident.build import build
from tests.unit.incident import kit

pytestmark = pytest.mark.unit


def amadey() -> m.IncidentReport:
    return build(kit.amadey(), kit.ctx())


def git() -> m.IncidentReport:
    return build(kit.git(), kit.ctx())


def test_a_campus_device_case_shows_its_device_its_servers_and_its_rules() -> None:
    report = amadey()
    glance = g.glance_of(report)
    assert glance.alerts == report.meta.alerts_total == 35
    assert glance.actors == 1
    assert (glance.targets, glance.targets_word) == (4, "server")
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
    assert glance.days == tuple(d.day for d in report.timeline.days)
    assert [layer.name for layer in glance.layers] == list(report.timeline.columns)
    assert all(len(layer.values) == len(glance.days) for layer in glance.layers)
    assert sum(sum(layer.values) for layer in glance.layers) == glance.alerts


def test_an_outside_scan_case_shows_the_addresses_and_the_sites_they_reached() -> None:
    report = git()
    glance = g.glance_of(report)
    assert glance.shape == g.Shape(
        "source.ip", "Top outside addresses", "url.domain", "Campus sites reached"
    )
    assert [s.label for s in glance.top_actors] == [kit.COLLECTOR, kit.SCOUT, kit.PROBER]
    assert glance.top_actors[0].value > glance.top_actors[1].value
    assert glance.targets_word == "site"
    sites = {a.label for a in report.assets if a.kind == "directory" and a.label}
    assert glance.targets == len(sites)
    assert {s.label for s in glance.top_targets} == sites
    assert sum(s.value for s in glance.top_targets) == sum(
        max(a.alerts, 1) for a in report.assets if a.kind == "directory" and a.label
    )


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
