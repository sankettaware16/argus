"""Where a case's outside actors went and what they got (D-240): the campus targets, and for each
outside actor the threat list, the outside intel and the successful answers ARGUS stored."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from argus.incident import build, targets
from argus.incident import model as m
from argus.incident.view import hide_logs
from tests.unit.incident import kit

pytestmark = pytest.mark.unit


def report(checks: bool = True) -> m.IncidentReport:
    return build.build(kit.scanners(checks=checks), kit.ctx(campus_domains=("example.edu",)))


def test_the_sites_and_the_server_the_outside_addresses_went_against_are_targets() -> None:
    rep = report()
    by = {t.value: t for t in rep.targets}
    assert set(by) == {*kit.SITES, kit.SERVER}
    assert rep.targets_total == 3
    assert by[kit.SERVER].kind == "host"
    assert by[kit.SERVER].actors == 16
    site = by[kit.SITES[0]]
    assert site.kind == "site"
    assert site.actors == 8
    assert site.alerts == sum(x.alerts for i, x in enumerate(kit.scanners().members) if i % 2 == 0)
    assert site.first_seen is not None
    assert site.last_seen is not None
    assert site.first_seen <= site.last_seen


def test_a_site_that_gave_a_successful_answer_says_which_file() -> None:
    by = {t.value: t for t in report().targets}
    assert (by[kit.SITES[0]].answered, by[kit.SITES[0]].served) == (1, ("/.env",))
    assert by[kit.SERVER].answered is None  # no stored record is about the server itself
    nothing = {t.value: t for t in report(checks=False).targets}
    assert nothing[kit.SITES[0]].answered is None  # not checked is not "none seen"
    assert nothing[kit.SITES[0]].served == ()


def test_a_case_of_campus_devices_has_no_targets_and_a_device_table() -> None:
    rep = build.build(kit.amadey(), kit.ctx())
    assert rep.targets == ()
    assert rep.targets_total == 0
    assert any(a.kind == "device" for a in rep.assets)


def test_each_outside_actor_carries_the_threat_list_the_intel_and_the_answers() -> None:
    actors = {a.value: a for a in report().actors}
    assert len(actors) == 16
    assert actors[kit.PROBERS[0]].listed
    assert actors[kit.PROBERS[1]].listed
    assert not actors[kit.PROBERS[2]].listed
    assert actors[kit.PROBERS[2]].intel == "VirusTotal: 9 of 94 engines flag this IP"
    assert actors[kit.PROBERS[5]].intel is None  # no outside answer cached
    assert (actors[kit.PROBERS[0]].answered, actors[kit.PROBERS[0]].served) == (2, ("/.env",))
    assert actors[kit.PROBERS[10]].answered is None  # no web check stored for it
    assert actors[kit.PROBERS[10]].served == ()


def test_a_campus_device_actor_has_no_outside_fields() -> None:
    actors = build.build(kit.amadey(), kit.ctx()).actors
    assert all(a.intel is None and a.answered is None and not a.served for a in actors)


def test_without_log_access_the_answers_are_hidden() -> None:
    hidden = hide_logs(report())
    assert all(a.answered is None and a.served == () for a in hidden.actors)
    assert all(t.answered is None and t.served == () for t in hidden.targets)
    assert hidden.targets[0].value == report().targets[0].value  # the targets themselves stay


def test_an_alert_that_records_its_own_answer_marks_the_address_and_site_checked() -> None:
    facts = kit.scanners(checks=False)
    first = facts.docs[0]
    fields = {**first.fields, "http.response.status_code": ("200",)}
    docs = (replace(first, fields=fields), *facts.docs[1:])
    rep = build.build(replace(facts, docs=docs), kit.ctx(campus_domains=("example.edu",)))
    actor = next(a for a in rep.actors if a.value == kit.PROBERS[0])
    assert (actor.answered, actor.served) == (1, ("/.env",))
    site = next(t for t in rep.targets if t.value == kit.SITES[0])
    assert (site.answered, site.served) == (1, ("/.env",))


def with_followup(
    facts: Any, ip: str, *, total: int, size: int | None = None, complete: bool | None = None
) -> Any:
    """The case with ``ip``'s stored ``web.followups`` answer replaced by one of ``total`` rows."""
    rows = []
    for row in facts.evidence:
        if row.template == "web.followups" and row.params["ip"] == ip:
            snapshot = {**row.snapshot, "total": total}
            if complete is not None:
                snapshot["rows_complete"] = complete
            params = {**row.params, **({} if size is None else {"size": size})}
            row = replace(row, snapshot=snapshot, params=params)
        rows.append(row)
    return replace(facts, evidence=tuple(rows))


def test_a_count_read_from_a_sample_that_hit_its_cap_is_not_exact() -> None:
    """The review of AR9 (F12): a client with thousands of 2xx answers showed "yes (20)" as if
    exact. The stored search asks for 20 rows and counts no more, so 20 means 20 or more."""
    facts = with_followup(kit.scanners(), kit.PROBERS[0], total=20)
    rep = build.build(facts, kit.ctx(campus_domains=("example.edu",)))
    actors = {a.value: a for a in rep.actors}
    assert (actors[kit.PROBERS[0]].answered, actors[kit.PROBERS[0]].answered_exact) == (20, False)
    assert actors[kit.PROBERS[1]].answered_exact  # two rows of a sample of 20: all of them
    by = {t.value: t for t in rep.targets}
    assert by[kit.SITES[0]].answered_exact is False  # the site read from the cut sample
    assert by[kit.SITES[1]].answered_exact is True
    assert by[kit.SERVER].answered_exact is True  # (nothing is stored about it: not checked)


@pytest.mark.parametrize(
    ("total", "size", "complete", "exact"),
    [
        (19, None, None, True),
        (20, None, None, False),
        (4, 5, None, True),
        (5, 5, None, False),
        (3, None, False, False),  # the stored answer says its rows are not complete
        (3, None, True, True),
    ],
)
def test_the_stored_sample_says_whether_a_count_is_exact(
    total: int, size: int | None, complete: bool | None, exact: bool
) -> None:
    facts = with_followup(kit.scanners(), kit.PROBERS[0], total=total, size=size, complete=complete)
    rep = build.build(facts, kit.ctx(campus_domains=("example.edu",)))
    actor = next(a for a in rep.actors if a.value == kit.PROBERS[0])
    assert actor.answered_exact is exact


def test_there_are_more_outside_addresses_than_the_report_lists() -> None:
    rep = build.build(kit.scanners(count=30), kit.ctx(campus_domains=("example.edu",)))
    assert len(rep.actors) == 25
    assert rep.outsiders_total == 30
    assert (
        build.build(kit.scanners(), kit.ctx(campus_domains=("example.edu",))).outsiders_total == 16
    )
    assert build.build(kit.amadey(), kit.ctx()).outsiders_total == 0  # campus devices only


@pytest.mark.parametrize(
    ("template", "params", "want"),
    [
        (
            "ti.lookup",
            {"values": ["1.2.3.4", "evil.example", "1.2.3.4"]},
            ("1.2.3.4", "evil.example"),
        ),
        ("web.followups", {"ip": "203.0.113.5", "start": "x"}, ("203.0.113.5",)),
        (
            "web.path_outcomes",
            {"ip": "203.0.113.5", "site": "home.example.edu"},
            ("203.0.113.5", "home.example.edu"),
        ),
        (
            "proxy.pair",
            {"host": "10.0.0.1", "destination": "198.51.100.7"},
            ("10.0.0.1", "198.51.100.7"),
        ),
        ("unknown.template", {"ip": "1.1.1.1"}, ()),
        ("ti.lookup", {"values": "not a list"}, ()),
    ],
)
def test_a_check_names_what_it_asked_about(
    template: str, params: dict[str, Any], want: tuple[str, ...]
) -> None:
    assert targets.asked(template, params) == want


def test_the_threat_list_lookup_lines_carry_their_values() -> None:
    lines = [e for e in report().evidence if e.query.template.startswith("ti.lookup")]
    assert sorted(e.asked for e in lines) == [(kit.PROBERS[0], kit.PROBERS[1]), (kit.PROBERS[2],)]
