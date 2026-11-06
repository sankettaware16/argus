"""The Visualiser's comment, "Incident at a glance" (AR10, D-250; P4-F V2, V3, V4): what a person
decides on first, a numbers row that always renders, what is new since the glance before, the
charts (or a short list where a chart would mislead), its place in a post, and how later rounds
keep **one living comment**: edited in place when it moved, correctable by a person's refresh,
left alone once a person changed it."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.caseteam import guard, lens, plan, render, visual
from argus.caseteam.model import (
    COMMENT_GONE,
    NOT_THEIRS,
    PERSON_EDIT,
    Author,
    Plan,
    Step,
    left_by_person,
    text_hash,
    unit_hash,
)
from argus.gateway.kibana.models import MAX_TEXT, utf16_len
from argus.incident import build
from argus.incident import glance as g
from argus.incident import model as m
from tests.unit.caseteam import kit
from tests.unit.caseteam.test_edit_plan import posted_from
from tests.unit.caseteam.test_plan import alerts, more_evidence, posted_after
from tests.unit.incident import kit as incident_kit

pytestmark = pytest.mark.unit
CTX = kit.CTX
SPACE = "acme-soc"
BEFORE = visual.Seen(1, 10, 1, 1, 0, 1, "ongoing", "Servers reached")


def comment(report: m.IncidentReport, **more: Any) -> str:
    return visual.comment(report, SPACE, **more)[0]


def table_rows(text: str, head: str) -> list[str]:
    lines = text.split("\n")
    at = next(i for i, line in enumerate(lines) if line.startswith(head))
    return [c.strip() for c in lines[at + 2].strip("|").split("|")]


def numbers_row(text: str) -> list[str]:
    return table_rows(text, "| Alerts | Actors | Targets")


def blocks(text: str) -> list[str]:
    return [b for b in text.split("\n") if b.startswith("!{lens")]


def fields_of(block: str) -> list[str]:
    return re.findall(r'"sourceField":"([^"]+)"', block)


def with_meta(report: m.IncidentReport, **change: Any) -> m.IncidentReport:
    return report.model_copy(update={"meta": report.meta.model_copy(update=change)})


def with_header(report: m.IncidentReport, **change: Any) -> m.IncidentReport:
    return report.model_copy(update={"header": report.header.model_copy(update=change)})


# --------------------------------------------------------------------------- the rows


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


def test_a_cut_target_list_is_said_with_a_plus() -> None:
    report = kit.git().model_copy(update={"targets_total": 40})
    assert numbers_row(comment(report))[2] == "1+ sites"


def test_the_status_row_says_what_a_person_decides_on_first() -> None:
    text = comment(kit.amadey())
    head = next(line for line in text.split("\n") if line.startswith("| Severity"))
    assert head == "| Severity | Call | Activity | Dwell (first to last alert) |"
    assert table_rows(text, "| Severity") == [
        "High",
        "True positive, 80% sure \\(ARGUS's call, not confirmed by a person\\)",
        "Still active",
        "4 days 19 hours",
    ]
    assert table_rows(comment(kit.git()), "| Severity")[1:3] == ["No call yet", "Quiet"]
    assert text.index("| Severity") < text.index("| Alerts")


def test_threat_listed_indicators_are_counted_from_what_the_report_says_of_each() -> None:
    report = kit.amadey()
    listed = report.indicators[0].model_copy(update={"evidence": "on the local threat lists"})
    changed = report.model_copy(update={"indicators": (listed, *report.indicators[1:])})
    assert numbers_row(comment(changed))[3] == "1 indicator"


def test_the_numbers_row_renders_with_no_chart_when_the_report_has_no_alert_time() -> None:
    report = with_header(kit.amadey(), first_alert_at=None, last_alert_at=None)
    text = comment(report)
    assert numbers_row(text)[4:6] == ["not known", "not known"]
    assert "!{lens" not in text
    assert "No alert time is known" in text
    assert f"- {render.val(kit.amadey().actors[0].value)}: 35 alerts" in text  # lists stay
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
    assert all(not lens.problems(b) for b in blocks(text))
    guard.check(text, CTX.allowed)


# --------------------------------------------------------------------------- the charts


def test_the_two_cases_get_their_charts_on_the_fields_their_shape_uses() -> None:
    campus = comment(kit.amadey())  # one campus device reaching four outside servers
    outside = comment(kit.git())  # three outside scanners against one campus site
    a = blocks(campus)
    assert [fields_of(b)[0] for b in a] == [
        "@timestamp",
        "destination.ip",
        "kibana.alert.rule.name",
    ]
    assert "**Servers reached**\n\n!{lens" in campus
    assert "**Top campus devices**\n\n- " in campus  # one device: a list, not a one-bar chart
    b = blocks(outside)
    assert [fields_of(x)[0] for x in b] == ["@timestamp", "source.ip", "kibana.alert.rule.name"]
    assert "**Top outside addresses**\n\n!{lens" in outside
    assert "**Campus sites reached**\n\n- ` home.example.edu `: 22 alerts" in outside
    for text in (campus, outside):
        assert "**Alerts over time, by rule**\n\n!{lens" in text
        assert "**Rules that raised the alerts**\n\n!{lens" in text
        assert fields_of(blocks(text)[0]) == ["@timestamp", "___records___", RULE]
        assert fields_of(blocks(text)[-1]) == [RULE, "___records___"]
        guard.check(text, CTX.allowed)


RULE = "kibana.alert.rule.name"


def test_two_or_more_items_are_a_live_chart_one_is_a_list() -> None:
    report = kit.git()
    one = report.model_copy(update={"actors": report.actors[:1]})
    text = comment(one)
    assert "source.ip" not in "".join(fields_of(b)[0] for b in blocks(text))
    assert f"- {render.val(report.actors[0].value)}: " in text


def test_a_field_most_alerts_lack_is_listed_from_the_report_with_the_reason() -> None:
    """F6: a threshold rule's alerts hold the grouping field only, so a live chart over the site
    would be empty and read as "nothing was reached"."""
    report = kit.git()
    many = report.model_copy(
        update={
            "targets": (  # the case's 22 alerts, split between two sites
                report.targets[0].model_copy(update={"alerts": 17}),
                report.targets[0].model_copy(update={"value": "lab.example.edu", "alerts": 5}),
            ),
            "targets_total": 2,
        }
    )
    drawn = comment(with_meta(many, carried=("source.ip", "url.domain")))
    assert "url.domain" in "".join(fields_of(b)[0] for b in blocks(drawn))
    thin = comment(with_meta(many, carried=("source.ip",)))
    assert "url.domain" not in "".join(fields_of(b)[0] for b in blocks(thin))
    assert "most of the case's alerts do not hold ` url.domain `" in thin
    assert "- ` home.example.edu `: 17 alerts\n- ` lab.example.edu `: 5 alerts" in thin
    unknown = comment(with_meta(many, carried=None))  # an older report: drawn as before
    assert "url.domain" in "".join(fields_of(b)[0] for b in blocks(unknown))
    guard.check(thin, CTX.allowed)


def test_servers_named_by_address_and_by_name_are_a_list_with_the_reason() -> None:
    """Review: the count left out the C2 addresses whenever a C2 domain existed. Every server is
    counted and listed; one live chart cannot split on both fields, so it is not drawn."""
    report = kit.amadey()
    ips = [i for i in report.indicators if i.role == "c2"]
    names = [ips[0].model_copy(update={"kind": "domain", "value": "c2.example"})]
    listed = (*ips[:2], *names)
    mixed = report.model_copy(
        update={"indicators": listed, "indicators_total": len(listed), "queries": ()}
    )
    text = comment(mixed)
    assert numbers_row(text)[2] == "3 servers"
    assert "url.domain" not in "".join(fields_of(b)[0] for b in blocks(text))
    assert (
        "Listed from ARGUS's report: a live chart splits on one field, and these are not all"
        " named in ` url.domain `." in text
    )
    for server in ("c2.example", ips[0].value, ips[1].value):
        assert f"- ` {server} `" in text
    guard.check(text, CTX.allowed)
    alone = comment(report)  # addresses alone: drawn on destination.ip, no reason to give
    assert "destination.ip" in "".join(fields_of(b)[0] for b in blocks(alone))
    assert "splits on one field" not in alone


def test_a_long_list_shows_its_first_few_and_how_many_more() -> None:
    report = kit.git()
    sites = tuple(
        report.targets[0].model_copy(update={"value": f"s{n}.example.edu", "alerts": 30 - n})
        for n in range(8)
    )
    text = comment(with_meta(report.model_copy(update={"targets": sites}), carried=("source.ip",)))
    assert text.count("- ` s") == visual.LISTED_AT
    assert "- and 3 more (the one-page dashboard lists them)" in text


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
        for block in blocks(comment(report)):
            assert f'"params":{{"query":"{report.header.incident_id}"}}' in block


def test_the_space_names_the_alerts_index_nothing_else_does() -> None:
    text = visual.comment(kit.git(), "other-space")[0]
    assert ".alerts-security.alerts-other-space" in text
    assert "acme" not in text.lower().replace("acme-ir-", "")


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
    shown = blocks(full)
    assert len(shown) == 3
    # room for the first chart and the actors only: the site list and the rules table go first
    room = len(full) - len(shown[2]) - 40 + visual.NEWS_ROOM
    monkeypatch.setattr(visual, "FIT", room)
    two = comment(report)
    assert len(blocks(two)) == 2
    assert "**Alerts over time, by rule**" in two
    assert "**Rules that raised" not in two
    monkeypatch.setattr(visual, "FIT", 10)
    none = comment(report)
    assert "!{lens" not in none
    assert none.count("| Alerts |") == 1
    assert numbers_row(none)[0] == "22"


# --------------------------------------------------------------------------- what the charts count


def test_the_charts_say_how_many_of_the_cases_alerts_they_count() -> None:
    """F4: the charts count only the alerts attached and tagged (at most a set number)."""
    text = comment(kit.amadey(), tagged=20)
    assert (
        "The charts count the 20 tagged alerts (of 35): Kibana draws them live from the alerts"
        " attached to this case and tagged ` ACME-IR-2026-1026-01 `." in text
    )
    assert "The charts count the tagged alerts:" in comment(kit.amadey())
    big = with_meta(kit.amadey(), alerts_total=5000)
    assert "the 500 tagged alerts (of 5,000)" in comment(big, tagged=500)


def test_no_attached_alert_means_no_live_chart_but_the_lists_and_numbers_stay() -> None:
    text = comment(kit.amadey(), tagged=0)
    assert "!{lens" not in text
    assert "No alert is attached to this case yet, so no live chart is drawn." in text
    assert "**Top campus devices**" in text
    assert "**Servers reached**\n\n- ` 77.221.155.150 `: VirusTotal: 7 of 94" in text
    guard.check(text, CTX.allowed)


def test_the_chart_range_ends_after_the_last_alert_was_made_not_only_the_last_event() -> None:
    """F5: the charts plot ``@timestamp``; a rule's lookback or a late run makes alerts after
    their events, which fell off the right edge."""
    report = kit.amadey()
    h = report.header
    assert h.last_alert_at is not None
    assert h.first_alert_at is not None
    late = with_header(
        report,
        first_detected_at=h.first_alert_at + timedelta(minutes=5),
        last_detected_at=h.last_alert_at + timedelta(hours=9),
    )
    scope = visual.scope_of(late, SPACE)
    assert scope is not None
    assert scope.first == h.first_alert_at
    assert scope.last == h.last_alert_at + timedelta(hours=9)
    early = with_header(report, first_detected_at=h.first_alert_at - timedelta(hours=2))
    scope = visual.scope_of(early, SPACE)
    assert scope is not None
    assert scope.first == h.first_alert_at - timedelta(hours=2)
    plain = visual.scope_of(report, SPACE)  # an older report: the alert times as before
    assert plain is not None
    assert (plain.first, plain.last) == (h.first_alert_at, h.last_alert_at)


@given(
    first=st.integers(min_value=0, max_value=10_000),
    span=st.integers(min_value=0, max_value=50_000),
    made_after=st.integers(min_value=-120, max_value=20_000),
    made_span=st.integers(min_value=0, max_value=50_000),
)
def test_every_alert_and_every_alerts_making_is_inside_the_chart_range(
    first: int, span: int, made_after: int, made_span: int
) -> None:
    t0 = datetime(2026, 10, 1, tzinfo=UTC)
    a, b = t0 + timedelta(minutes=first), t0 + timedelta(minutes=first + span)
    c = a + timedelta(minutes=made_after)
    d = c + timedelta(minutes=made_span)
    report = with_header(
        kit.amadey(), first_alert_at=a, last_alert_at=b, first_detected_at=c, last_detected_at=d
    )
    scope = visual.scope_of(report, SPACE)
    assert scope is not None
    low = datetime.fromisoformat(scope.time_range["from"])
    high = datetime.fromisoformat(scope.time_range["to"])
    for t in (a, b, c, d):
        assert low < t < high


# --------------------------------------------------------------------------- what is new


def test_a_first_glance_says_nothing_is_new_a_later_one_says_what_moved() -> None:
    report = kit.amadey()
    assert "New since" not in comment(report)
    text = comment(report, since=BEFORE)
    assert "New since report version 1: 25 more alerts, 3 more servers, 1 more rule." in text
    assert text.index("| Alerts") < text.index("New since") < text.index("The charts count")
    same = visual.seen_of(report, 2)
    assert "New since report version 2: the same counts." in comment(report, since=same)
    more = replace(same, alerts=40, actors=3, standing="quiet")
    assert "New since report version 2: 5 fewer alerts, 2 fewer actors; active again." in comment(
        report, since=more
    )
    quiet = with_meta(kit.git(), alerts_total=22)
    was = replace(visual.seen_of(quiet, 3), alerts=21, standing="ongoing", listed=2)
    said = comment(quiet, since=was)
    assert (
        "New since report version 3: 1 more alert, 2 fewer indicators on threat lists; now quiet."
        in said
    )


def test_targets_of_another_list_are_said_not_compared_and_unknown_is_not_active_again() -> None:
    """Review: a device case's 4 servers were compared with the 2 sites of a later version ("2
    fewer sites"), and a standing that was never known was said to be "active again"."""
    servers = visual.seen_of(kit.amadey(), 1)
    assert (servers.targets, servers.targets_title) == (4, "Servers reached")
    sites = scan_report()
    said = news_of(sites, servers)
    assert "fewer sites" not in said
    assert "targets now counted as sites" in said
    same_list = replace(servers, targets_title=visual.seen_of(sites, 1).targets_title)
    assert "2 fewer sites" in news_of(sites, same_list)
    older = visual.Seen.load({k: v for k, v in servers.dump().items() if k != "targets_title"})
    assert older is not None
    assert older.targets_title == ""
    assert "site" not in news_of(sites, older)  # an older glance: its list is not known
    ongoing = kit.amadey()
    assert ongoing.summary.standing == "ongoing"
    unknown = replace(visual.seen_of(ongoing, 1), standing="unknown")
    assert news_of(ongoing, unknown) == "New since report version 1: the same counts; still active."
    quiet = replace(unknown, standing="quiet")
    assert news_of(ongoing, quiet) == "New since report version 1: the same counts; active again."


def scan_report() -> m.IncidentReport:
    return build.build(incident_kit.scanners(), incident_kit.ctx(campus_domains=("example.edu",)))


def news_of(report: m.IncidentReport, before: visual.Seen) -> str:
    return visual.news(g.glance_of(report), before)


@given(
    counts=st.lists(st.integers(min_value=0, max_value=10**6), min_size=6, max_size=6),
    standing=st.sampled_from(["ongoing", "quiet", "unknown"]),
    tagged=st.one_of(st.none(), st.integers(min_value=0, max_value=1000)),
)
def test_the_core_and_the_charts_never_depend_on_what_is_new(
    counts: list[int], standing: str, tagged: int | None
) -> None:
    report = kit.git()
    before = visual.Seen(*counts, standing=standing)
    whole, core = visual.comment(report, SPACE, tagged=tagged, since=before)
    assert core == visual.core(report, SPACE, tagged=tagged)
    assert blocks(whole) == blocks(core)
    assert visual.unit(report, SPACE, tagged=tagged) == unit_hash(core)
    assert utf16_len(whole) <= MAX_TEXT
    guard.check(whole, CTX.allowed)


@given(st.builds(visual.Seen, *[st.integers(min_value=0, max_value=10**9)] * 6,
                 standing=st.sampled_from(["ongoing", "quiet", "unknown"]),
                 targets_title=st.sampled_from(["", "Campus sites reached", "Servers reached"]),
                 ))  # fmt: skip
def test_what_a_glance_showed_survives_its_payload(seen: visual.Seen) -> None:
    assert visual.Seen.load(seen.dump()) == seen


@pytest.mark.parametrize(
    "raw",
    [None, [], "x", {}, {"version": 1}, {**BEFORE.dump(), "alerts": -1},
     {**BEFORE.dump(), "rules": True}, {**BEFORE.dump(), "actors": "3"}],
)  # fmt: skip
def test_a_payload_that_holds_no_counts_to_trust_is_no_glance(raw: object) -> None:
    assert visual.Seen.load(raw) is None


def test_an_unknown_standing_in_a_payload_is_read_as_unknown() -> None:
    loaded = visual.Seen.load({**BEFORE.dump(), "standing": "<b>"})
    assert loaded is not None
    assert loaded.standing == "unknown"


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
    assert "The charts count the 4 tagged alerts (of 35)" in step.text
    assert step.units == (visual.unit(kit.amadey(), SPACE, tagged=4),)
    assert step.payload == {"seen": visual.seen_of(kit.amadey(), 1).dump(), "since": None}
    assert all(len(s.request_hash) == 64 for s in first.steps)


def test_a_post_with_many_evidence_comments_puts_the_glance_after_the_last_of_them() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, [], CTX)
    parts = [s.part for s in first.steps]
    assert parts.count("glance") == 1
    last_evidence = max(i for i, p in enumerate(parts) if p == "evidence")
    assert parts[last_evidence + 1] == "glance"


def test_the_plan_hash_binds_the_glance_so_an_approval_covers_it() -> None:
    report = kit.amadey()
    a = plan.first_plan(report, 1, alerts(3), CTX)
    b = plan.first_plan(with_meta(report, alerts_total=5), 1, alerts(3), CTX)
    assert a.plan_hash != b.plan_hash
    assert [s.request_hash for s in a.steps if s.part == "glance"] != [
        s.request_hash for s in b.steps if s.part == "glance"
    ]


def whole_posted(first: Plan, report: m.IncidentReport) -> plan.Posted:
    """A case whose first plan went through: every part's comments (the refresh reads them) and
    the living glance."""
    glance = posted_after(first, report)
    return posted_from(
        first,
        comments={**posted_from(first).comments, **glance.comments},
        glance=glance.glance,
        attached=glance.attached,
    )


def update_of(first: Plan, report: m.IncidentReport, newer: m.IncidentReport, n: int = 0) -> Plan:
    return plan.update_plan(newer, 2, alerts(n), CTX, posted_after(first, report), max_alerts=500)


def glance_steps(p: Plan) -> list[Step]:
    return [s for s in p.steps if s.part == visual.PART]


def applied(posted: plan.Posted, step: Step) -> plan.Posted:
    """What the case holds once a glance step went through (as the store reads it back)."""
    comments = dict(posted.comments)
    if step.kind == "comment":
        comments[step.key] = plan.PostedComment(
            step.key, step.part, step.author.value, "c-glance", step.text or ""
        )
    else:
        of = str(step.payload["of"])
        comments[of] = replace(comments[of], text=step.text or "")
    glance = plan.PostedGlance(
        step.units[0],
        visual.Seen.load(step.payload.get("seen")),
        visual.Seen.load(step.payload.get("since")),
    )
    return replace(posted, comments=comments, glance=glance)


def test_an_unchanged_case_says_nothing_new() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    assert update_of(first, report, report).steps == ()


def test_a_changed_case_edits_its_one_glance_in_place_and_says_what_is_new() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    (posted_glance,) = [s for s in first.steps if s.part == "glance"]
    later = with_meta(report, alerts_total=99)
    steps = update_of(first, report, later).steps
    (glance,) = [s for s in steps if s.part == "glance"]
    assert (glance.key, glance.kind, glance.author) == (
        "edit:comment:glance:1",
        "edit_comment",
        Author.VISUALISER,
    )
    assert glance.text is not None
    assert glance.text.startswith("## Incident at a glance\n")
    assert "Update:" not in glance.text
    assert "New since report version 1: 64 more alerts." in glance.text
    assert glance.payload["of"] == visual.KEY
    assert glance.payload["comment_id"] == "c-glance"
    assert glance.payload["was_hash"] == text_hash(posted_glance.text or "")
    assert glance.payload[plan.ROUND] is True
    assert glance.payload["seen"] == visual.seen_of(later, 2).dump()
    assert glance.payload["since"] == visual.seen_of(report, 1).dump()
    assert glance.units == (visual.unit(later, SPACE, tagged=3),)
    assert not plan.is_correction(glance.kind, glance.payload)  # a round's step, not a refresh
    template, params = plan.request_of(glance, "kid-1", later, "WzEsMV0=")
    assert template.name == "team.edit_comment"
    assert params.model_dump()["author"] == "argus-visualiser"


def test_newly_tagged_alerts_move_the_glance() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    steps = update_of(first, report, report, n=5).steps  # two more alerts attached
    (glance,) = [s for s in steps if s.part == "glance"]
    assert glance.text is not None
    assert "The charts count the 5 tagged alerts (of 35)" in glance.text
    posted = replace(posted_after(first, report), gone=frozenset({alerts(1)[0].alert_id}))
    gone = plan.update_plan(report, 2, alerts(3), CTX, posted, max_alerts=500)
    (fewer,) = [s for s in gone.steps if s.part == "glance"]
    assert fewer.text is not None
    assert "The charts count the 2 tagged alerts (of 35)" in fewer.text


def tagged_of(step: Step) -> str:
    assert step.text is not None
    found = re.search(r"The charts count the ([0-9,]+) tagged alerts", step.text)
    assert found is not None
    return found.group(1)


def test_alerts_an_attach_left_out_are_tried_again_but_not_counted_as_tagged() -> None:
    """Review: under Sync alerts an attach leaves closed alerts out. Each round tried them again
    and counted them, so the glance said 10 for good while Kibana tagged 6, and a round undid a
    refresh's correction. They are still tried, but counted only once an attach takes them."""
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(10), CTX)
    (posted_glance,) = glance_steps(first)
    assert tagged_of(posted_glance) == "10"  # planned before the attach: it cannot know
    left = frozenset(a.alert_id for a in alerts(4, 6))
    posted = replace(
        whole_posted(first, report),
        attached=frozenset(a.alert_id for a in alerts(6)),
        left_out=left,
    )
    v2 = more_evidence(report)
    round_2 = plan.update_plan(v2, 2, alerts(10), CTX, posted, max_alerts=500)
    tried = {a for s in round_2.steps if s.kind == "attach" for a, _ in s.payload["alerts"]}
    assert tried == left  # tried again: a person may have opened them, or Sync alerts is off
    (edit,) = glance_steps(round_2)
    assert edit.kind == "edit_comment"
    assert tagged_of(edit) == "6"  # the round corrects the first glance
    assert (
        "The charts count the 6 tagged alerts (of 35; 4 more were left unattached while Sync"
        " alerts was on): Kibana draws them live" in (edit.text or "")
    )
    posted = applied(posted, edit)
    assert glance_steps(plan.refresh_plan(v2, 2, CTX, posted)) == []  # a refresh agrees
    v3 = with_meta(v2, alerts_total=40)
    (again,) = glance_steps(plan.update_plan(v3, 3, alerts(10), CTX, posted, max_alerts=500))
    assert tagged_of(again) == "6"  # never back to 10 while they stay left out
    assert "4 more were left unattached" in (again.text or "")
    taken = replace(posted, attached=posted.attached | left, left_out=frozenset())
    (now,) = glance_steps(plan.update_plan(v3, 3, alerts(10), CTX, taken, max_alerts=500))
    assert tagged_of(now) == "10"  # once an attach took them, the next round counts them
    assert "left unattached" not in (now.text or "")


def test_a_case_whose_attaches_all_left_alerts_out_keeps_its_live_charts() -> None:
    """Every alert was left out (the case was not open while Sync alerts was on): none is known
    to be tagged, but the round tries them again and the charts are live, so they stay."""
    report = kit.amadey()
    whole, _ = visual.comment(report, SPACE, tagged=0, left_out=25)
    assert (
        "The charts count the tagged alerts, none yet (of 35; 25 more were left unattached while"
        " Sync alerts was on)" in whole
    )
    assert blocks(whole)
    assert "No alert is attached" not in whole
    nothing = comment(report, tagged=0)
    assert "No alert is attached to this case yet, so no live chart is drawn." in nothing
    assert not blocks(nothing)


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
    assert (glance.key, glance.kind) == (visual.KEY, "comment")
    assert glance.text is not None
    assert glance.text.startswith("## Incident at a glance\n")
    assert "New since" not in glance.text
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


def test_a_glance_a_person_changed_or_removed_is_left_alone_for_good() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    posted = replace(whole_posted(first, report), left_alone=frozenset({visual.KEY}))
    later = with_meta(report, alerts_total=99)
    steps = plan.update_plan(later, 2, alerts(0), CTX, posted, max_alerts=500).steps
    assert [s for s in steps if s.part == "glance"] == []
    assert glance_steps(plan.refresh_plan(later, 2, CTX, posted)) == []


def test_a_round_edit_once_landed_is_not_planned_again() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    later = with_meta(report, alerts_total=99)
    (edit,) = [s for s in update_of(first, report, later).steps if s.part == "glance"]
    posted = applied(whole_posted(first, report), edit)
    again = plan.update_plan(later, 3, alerts(0), CTX, posted, max_alerts=500)
    assert [s for s in again.steps if s.part == "glance"] == []
    assert glance_steps(plan.refresh_plan(later, 3, CTX, posted)) == []  # it reads as it should


def test_a_refresh_corrects_a_glance_whose_form_is_not_what_argus_writes_now() -> None:
    """F7: a glance posted with a broken form is corrected in place by a person's refresh."""
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    posted = whole_posted(first, report)
    living = posted.comments[visual.KEY]
    broken = replace(living, text=living.text.replace("!{lens{", '!{lens{"x":1,', 1))
    posted = replace(posted, comments={**posted.comments, visual.KEY: broken})
    (fix,) = plan.refresh_plan(report, 1, CTX, posted).steps
    assert (fix.key, fix.kind, fix.author) == (
        "edit:comment:glance:1",
        "edit_comment",
        Author.VISUALISER,
    )
    assert fix.text == living.text  # the same report: the same glance as first posted
    assert fix.payload["was_hash"] == text_hash(broken.text)
    assert plan.ROUND not in fix.payload
    assert plan.is_correction(fix.kind, fix.payload)  # a person's refresh


def test_a_refresh_keeps_the_line_that_says_what_is_new() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    later = with_meta(report, alerts_total=99)
    (edit,) = [s for s in update_of(first, report, later).steps if s.part == "glance"]
    posted = applied(whole_posted(first, report), edit)
    living = posted.comments[visual.KEY]
    stale = replace(living, text=living.text.replace("ARGUS counted", "ARGUS once counted"))
    posted = replace(posted, comments={**posted.comments, visual.KEY: stale})
    (fix,) = glance_steps(plan.refresh_plan(later, 2, CTX, posted))
    assert fix.text == edit.text
    assert fix.text is not None
    assert "New since report version 1: 64 more alerts." in fix.text


def test_a_new_form_of_the_same_report_is_a_correction_that_adds_no_news(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A glance posted by an older ARGUS (another form) is corrected by a refresh of the same
    report: its core moved, but nothing in the case is new, so no "New since" line appears; a
    round of that report plans nothing (only a new report version makes a round)."""
    report = kit.amadey()
    monkeypatch.setattr(visual, "INTRO", "An older ARGUS wrote this.")
    first = plan.first_plan(report, 1, alerts(3), CTX)
    monkeypatch.undo()
    posted = whole_posted(first, report)
    (fix,) = glance_steps(plan.refresh_plan(report, 1, CTX, posted))
    assert fix.text is not None
    assert visual.INTRO in fix.text
    assert "An older ARGUS" not in fix.text
    assert "New since" not in fix.text
    assert fix.payload["since"] is None
    assert fix.units == (visual.unit(report, SPACE, tagged=3),)


def test_a_refresh_never_posts_a_first_glance() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    whole = whole_posted(first, report)
    others = {k: c for k, c in whole.comments.items() if k != visual.KEY}
    posted = replace(whole, comments=others, glance=None)
    assert plan.refresh_plan(report, 1, CTX, posted).steps == ()


@given(
    totals=st.lists(st.integers(min_value=1, max_value=10_000), min_size=1, max_size=8),
    tagged=st.lists(st.integers(min_value=0, max_value=600), min_size=8, max_size=8),
    standing=st.lists(st.sampled_from(["ongoing", "quiet"]), min_size=8, max_size=8),
)
def test_rounds_keep_one_living_glance_and_each_landed_edit_is_final(
    totals: list[int], tagged: list[int], standing: list[str]
) -> None:
    """Over any run of rounds: a round plans at most one glance step, an edit of the one comment
    that says what is new against the glance it replaces; once it landed, the same report and
    alerts plan nothing more for it, and a refresh finds nothing to correct."""
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    posted = whole_posted(first, report)
    shown = visual.seen_of(report, 1)
    for version, (total, n, now_standing) in enumerate(
        zip(totals, tagged, standing, strict=False), 2
    ):
        summary = report.summary.model_copy(update={"standing": now_standing})
        now = with_meta(report, alerts_total=total).model_copy(update={"summary": summary})
        step = plan.glance_step(now, version, posted, space=SPACE, tagged=n)
        if step is None:
            assert visual.unit(now, SPACE, tagged=n) == (
                posted.glance.unit if posted.glance else ""
            )
            continue
        assert step.kind == "edit_comment"
        assert step.payload["of"] == visual.KEY
        assert step.payload[plan.ROUND] is True
        assert step.payload["since"] == shown.dump()
        assert step.text is not None
        assert "Update:" not in step.text
        assert f"New since report version {shown.version}:" in step.text
        guard.check(step.text, CTX.allowed)
        posted = applied(posted, step)
        shown = visual.seen_of(now, version)
        assert plan.glance_step(now, version, posted, space=SPACE, tagged=n) is None
        refresh = plan.glance_step(now, version, posted, space=SPACE, tagged=n, refresh=True)
        assert refresh is None


def test_a_comment_is_left_alone_only_for_what_someone_did_in_kibana() -> None:
    assert left_by_person(PERSON_EDIT)
    assert left_by_person(COMMENT_GONE)
    assert left_by_person(f"{NOT_THEIRS} argus-visualiser")
    assert not left_by_person(visual.SKIPPED)  # a missing key is ARGUS's own, not a person's
    assert not left_by_person("asha: done by hand in Kibana")  # a person's skip of one step
    assert not left_by_person(None)


def test_a_rounds_glance_edit_is_not_a_correction_and_reads_so_in_the_preview() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    (edit,) = glance_steps(update_of(first, report, with_meta(report, alerts_total=99)))
    assert edit.describe() == "argus-visualiser updates its comment in place (glance)"
    assert not plan.is_correction(edit.kind, edit.payload)
    fix = replace(edit, payload={k: v for k, v in edit.payload.items() if k != plan.ROUND})
    assert fix.describe() == "argus-visualiser corrects its comment (glance)"
    assert plan.is_correction(fix.kind, fix.payload)
    assert plan.is_correction("retitle", {})
    assert not plan.is_correction("comment", {})
