"""The Visualiser's comment, "Incident at a glance" (AR10, D-250): a numbers row that always
renders, the charts after it, its place in a post, and how an update says it again."""

from __future__ import annotations

import re

import pytest

from argus.caseteam import guard, lens, plan, render, visual
from argus.caseteam.model import Author, Plan, unit_hash
from argus.gateway.kibana.models import MAX_TEXT, utf16_len
from argus.incident import model as m
from tests.unit.caseteam import kit
from tests.unit.caseteam.test_plan import alerts, posted_after

pytestmark = pytest.mark.unit
CTX = kit.CTX
SPACE = "acme-soc"


def comment(report: m.IncidentReport, **more: bool) -> str:
    return visual.comment(report, SPACE, **more)[0]


def numbers_row(text: str) -> list[str]:
    head, _, row = (line for line in text.split("\n") if line.startswith("|"))
    assert head.startswith("| Alerts | Actors | Targets")
    return [c.strip() for c in row.strip("|").split("|")]


# --------------------------------------------------------------------------- the numbers row


def test_the_numbers_row_has_the_alerts_actors_targets_listed_indicators_times_and_rules() -> None:
    text = comment(kit.git())
    assert text.startswith("## Incident at a glance\n\n")
    head = next(line for line in text.split("\n") if line.startswith("| Alerts"))
    assert head == (
        "| Alerts | Actors | Targets | On threat lists | First alert (IST) | Last alert (IST)"
        " | Rules |"
    )
    alerts_n, actors, targets, listed, first, last, rules = numbers_row(text)
    assert (alerts_n, actors, targets, listed, rules) == ("22", "3", "1 site", "0 indicators", "1")
    assert first == "23 Oct 2026, 11:00 AM IST"
    assert last == "25 Oct 2026, 11:00 PM IST"


def test_the_numbers_come_from_the_report_the_pdf_and_the_comments_are_made_from() -> None:
    report = kit.amadey()
    alerts_n, actors, targets, _, first, last, rules = numbers_row(comment(report))
    assert alerts_n == str(report.meta.alerts_total)
    assert actors == str(len(report.actors))
    assert targets == f"{len({i.value for i in report.indicators if i.role == 'c2'})} servers"
    assert rules == str(len(report.timeline.phases))
    assert first.startswith("23 Oct 2026")
    assert last.startswith("28 Oct 2026")


def test_threat_listed_indicators_are_counted_from_what_the_report_says_of_each() -> None:
    report = kit.amadey()
    listed = report.indicators[0].model_copy(update={"evidence": "on the local threat lists"})
    changed = report.model_copy(update={"indicators": (listed, *report.indicators[1:])})
    assert numbers_row(comment(changed))[3] == "1 indicator"


def test_the_numbers_row_renders_with_no_chart_when_the_report_has_no_alert_time() -> None:
    report = kit.amadey()
    header = report.header.model_copy(update={"first_alert_at": None, "last_alert_at": None})
    text = comment(report.model_copy(update={"header": header}))
    assert numbers_row(text)[4:6] == ["not known", "not known"]
    assert "!{lens" not in text
    assert "No alert time is known" in text
    guard.check(text, CTX.allowed)


def test_a_case_with_nothing_to_draw_still_says_its_numbers() -> None:
    report = kit.amadey().model_copy(
        update={
            "actors": (),
            "assets": (),
            "indicators": (),
            "indicators_total": 0,
            "timeline": kit.amadey().timeline.model_copy(update={"phases": (), "days": ()}),
        }
    )
    text = comment(report)
    assert numbers_row(text)[1] == "0"
    kinds = [lens.problems(b) for b in text.split("\n") if b.startswith("!{lens")]
    assert all(not p for p in kinds)
    guard.check(text, CTX.allowed)


# --------------------------------------------------------------------------- the charts


def test_the_two_cases_get_their_four_charts_on_the_fields_their_shape_uses() -> None:
    outside = comment(kit.git())  # outside scanners against campus web sites
    campus = comment(kit.amadey())  # a campus device reaching outside servers
    for text, actor, target, actors_title, targets_title in (
        (outside, "source.ip", "url.domain", "Top outside addresses", "Campus sites reached"),
        (campus, "source.ip", "destination.ip", "Top campus devices", "Servers reached"),
    ):
        blocks = [b for b in text.split("\n") if b.startswith("!{lens")]
        assert len(blocks) == 4
        fields = [re.findall(r'"sourceField":"([^"]+)"', b) for b in blocks]
        assert fields[0] == ["@timestamp", "___records___", "kibana.alert.rule.name"]
        assert fields[1][0] == actor
        assert fields[2][0] == target
        assert fields[3] == ["kibana.alert.rule.name", "___records___"]
        for caption in ("Alerts over time, by rule", actors_title, targets_title):
            assert f"**{caption}**\n\n!{{lens" in text
        assert "**Rules that raised the alerts**\n\n!{lens" in text
        guard.check(text, CTX.allowed)


def test_charts_are_in_a_fixed_order_each_on_its_own_line_after_a_blank_line() -> None:
    text = comment(kit.git())
    lines = text.split("\n")
    for at, line in enumerate(lines):
        if line.startswith("!{lens"):
            assert lines[at - 1] == ""
            assert lines[at - 2].startswith("**")
            assert at + 1 == len(lines) or lines[at + 1] == ""


def test_the_incident_id_is_the_filter_of_every_chart() -> None:
    for report in (kit.amadey(), kit.git()):
        for block in (b for b in comment(report).split("\n") if b.startswith("!{lens")):
            assert f'"params":{{"query":"{report.header.incident_id}"}}' in block


def test_the_space_names_the_alerts_index_nothing_else_does() -> None:
    text = visual.comment(kit.git(), "other-space")[0]
    assert ".alerts-security.alerts-other-space" in text
    assert "acme" not in text.lower().replace("acme-ir-", "")
    assert "acme" not in text


def test_an_actor_or_space_a_block_could_not_hold_leaves_the_charts_out_not_the_numbers() -> None:
    odd = visual.comment(kit.git(), "a space")[0]  # not a plain name
    assert "!{lens" not in odd
    assert "| Alerts |" in odd
    guard.check(odd, CTX.allowed)


def test_the_comment_is_under_kibanas_limit_and_drops_charts_from_the_end_never_the_numbers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = kit.git()
    full = comment(report)
    assert utf16_len(full) < MAX_TEXT
    blocks = [b for b in full.split("\n") if b.startswith("!{lens")]
    assert len(blocks) == 4
    # room for two charts only: the table of rules and the targets go first
    monkeypatch.setattr(visual, "FIT", len(full) - len(blocks[3]) - len(blocks[2]) // 2)
    two = comment(report)
    assert len([b for b in two.split("\n") if b.startswith("!{lens")]) == 2
    assert "**Alerts over time, by rule**" in two
    assert "**Rules that raised" not in two
    monkeypatch.setattr(visual, "FIT", 10)
    none = comment(report)
    assert "!{lens" not in none
    assert none.count("| Alerts |") == 1
    assert numbers_row(none)[0] == "22"


def test_the_comment_is_the_visualisers_and_it_changes_only_when_the_case_does() -> None:
    report = kit.amadey()
    a = visual.steps(report, SPACE)
    (step,) = a
    assert step.author is Author.VISUALISER
    assert step.kind == "comment"
    assert step.part == "glance"
    assert step.key == "comment:glance:1"
    assert step.units == (unit_hash(visual.body(report, SPACE)),)
    assert visual.steps(report, SPACE) == a
    assert not visual.due(report, SPACE, frozenset(step.units))
    later = report.model_copy(update={"meta": report.meta.model_copy(update={"alerts_total": 99})})
    assert visual.due(later, SPACE, frozenset(step.units))
    assert visual.comment(later, SPACE, update=True)[0].startswith(
        "## Update: Incident at a glance"
    )


# --------------------------------------------------------------------------- in a post


def test_the_glance_follows_the_evidence_comment_and_comes_before_the_queries() -> None:
    first = plan.first_plan(kit.amadey(), 1, alerts(4), CTX)
    parts = [s.part for s in first.steps]
    assert parts.index("glance") == parts.index("evidence") + 1
    assert parts.index("glance") < parts.index("queries")
    (step,) = [s for s in first.steps if s.part == "glance"]
    assert step.author is Author.VISUALISER
    assert step.text is not None
    assert step.text.startswith("## Incident at a glance")
    assert all(len(s.request_hash) == 64 for s in first.steps)


def test_a_post_with_many_evidence_comments_puts_the_glance_after_the_last_of_them() -> None:
    report = kit.amadey()
    line = report.evidence[0]
    many = report.model_copy(update={"evidence": tuple(line for _ in range(1))})
    first = plan.first_plan(many, 1, [], CTX)
    parts = [s.part for s in first.steps]
    assert parts.count("glance") == 1
    last_evidence = max(i for i, p in enumerate(parts) if p == "evidence")
    assert parts[last_evidence + 1] == "glance"


def test_the_plan_hash_binds_the_glance_so_an_approval_covers_it() -> None:
    report = kit.amadey()
    a = plan.first_plan(report, 1, alerts(3), CTX)
    later = report.model_copy(update={"meta": report.meta.model_copy(update={"alerts_total": 5})})
    b = plan.first_plan(later, 1, alerts(3), CTX)
    assert a.plan_hash != b.plan_hash
    assert [s.request_hash for s in a.steps if s.part == "glance"] != [
        s.request_hash for s in b.steps if s.part == "glance"
    ]


def update_of(first: Plan, report: m.IncidentReport, newer: m.IncidentReport) -> Plan:
    return plan.update_plan(
        newer,
        2,
        alerts(0),
        CTX,
        posted_after(first, report),
        max_alerts=500,
    )


def test_an_unchanged_case_says_nothing_new_and_a_changed_one_says_its_glance_again() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    assert update_of(first, report, report).steps == ()
    later = report.model_copy(update={"meta": report.meta.model_copy(update={"alerts_total": 99})})
    steps = update_of(first, report, later).steps
    glances = [s for s in steps if s.part == "glance"]
    assert len(glances) == 1
    assert glances[0].author is Author.VISUALISER
    assert glances[0].text is not None
    assert glances[0].text.startswith("## Update: Incident at a glance")


def test_a_case_posted_before_the_visualiser_gets_its_glance_as_a_first_one() -> None:
    """Case 1 was posted by the six; its next round brings the glance, headed as a first one."""
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    old = Plan(
        first.incident_id,
        first.case_id,
        first.gen,
        first.report_version,
        tuple(s for s in first.steps if s.part != "glance"),
    )
    steps = update_of(old, report, report).steps
    (glance,) = [s for s in steps if s.part == "glance"]
    assert glance.text is not None
    assert glance.text.startswith("## Incident at a glance\n")
    assert render.comment_limit_ok(glance.text)


def test_the_glance_is_the_only_new_step_of_that_round_when_nothing_else_changed() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    old = Plan(
        first.incident_id,
        first.case_id,
        first.gen,
        first.report_version,
        tuple(s for s in first.steps if s.part != "glance" and s.kind != "file"),
    )
    posted = posted_after(old, report)
    assert posted.files == {}  # no file was posted: every file is new
    steps = update_of(old, report, report).steps
    assert [s.part for s in steps if s.kind == "comment"][:1] == ["glance"]
