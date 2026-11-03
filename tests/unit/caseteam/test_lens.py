"""The charts embedded in a case comment (AR10, D-250): every ``!{lens{...}}`` block ARGUS writes
parses with a scanner that does what Kibana 8.19's parser does (prefix, brace depth, JSON.parse),
stays over the case's own tagged alerts, and the guardian lets only such a block through."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus.caseteam import guard, lens, visual
from argus.incident import glance as g
from argus.incident import model as m
from tests.unit.caseteam import kit

pytestmark = pytest.mark.unit
FIRST = datetime(2026, 10, 23, 4, 30, tzinfo=UTC)
LAST = datetime(2026, 10, 28, 0, 30, tzinfo=UTC)
SCOPE = lens.Scope("acme-soc", "ACME-IR-2026-1026-01", FIRST, LAST)
ALLOWED = (kit.LINK_BASE + "/go/case/", kit.KIBANA)


def kibana_scan(text: str) -> list[Any]:
    """What the cases Markdown plugin does with ``text`` (docs/ar10-visualiser.md), written
    again, apart from the code under test: find the prefix, count braces from there until a ``}``
    closes more than was opened, ``JSON.parse`` what was collected, take that ``}``."""
    out: list[Any] = []
    at = text.find("!{lens")
    while at >= 0:
        collected = ""
        open_objects = 0
        i = at + len("!{lens")
        while True:
            assert i < len(text), "the block never closes: Kibana would show the raw text"
            ch = text[i]
            if ch == "{":
                open_objects += 1
            elif ch == "}":
                open_objects -= 1
                if open_objects == -1:
                    break
            collected += ch
            i += 1
        out.append(json.loads(collected))  # raises where JSON.parse throws
        at = text.find("!{lens", i + 1)
    return out


def blocks_of(text: str) -> list[str]:
    return [line for line in text.split("\n") if line.startswith("!{lens")]


def all_blocks(scope: lens.Scope = SCOPE) -> list[str]:
    return [
        lens.block(scope, lens.alerts_over_time(scope)),
        lens.block(scope, lens.top_values(scope, "Top outside addresses", "source.ip")),
        lens.block(scope, lens.top_values(scope, "Campus sites reached", "url.domain")),
        lens.block(scope, lens.rules_table(scope)),
    ]


def strings(node: Any) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for k, v in node.items() for s in (*strings(k), *strings(v))]
    if isinstance(node, list):
        return [s for v in node for s in strings(v)]
    return []


# --------------------------------------------------------------------------- what a block is


def test_a_block_is_one_line_the_prefix_then_balanced_json_then_one_brace() -> None:
    for text in all_blocks():
        assert "\n" not in text
        assert text.startswith("!{lens{")
        assert text.endswith("}}")
        (parsed,) = kibana_scan(text)
        assert set(parsed) == {"timeRange", "attributes"}
        assert lens.scan(text) == [json.dumps(parsed, separators=(",", ":"), ensure_ascii=True)]
        assert lens.problems(text) == []


def test_the_time_range_is_absolute_and_an_hour_wider_than_the_alerts_each_side() -> None:
    for text in all_blocks():
        (parsed,) = kibana_scan(text)
        assert parsed["timeRange"] == {
            "from": "2026-10-23T03:30:00.000Z",
            "to": "2026-10-28T01:30:00.000Z",
            "mode": "absolute",
        }


def test_every_chart_is_over_the_cases_tagged_alerts_in_a_self_contained_data_view() -> None:
    for text in all_blocks():
        (parsed,) = kibana_scan(text)
        attrs = parsed["attributes"]
        state = attrs["state"]
        assert attrs["references"] == []  # no saved data view of ARGUS's making
        (view,) = state["adHocDataViews"].values()
        assert view["title"] == ".alerts-security.alerts-acme-soc"  # alerts, never the logs
        assert view["timeFieldName"] == "@timestamp"
        (ref,) = state["internalReferences"]
        assert ref["type"] == "index-pattern"
        assert ref["id"] == view["id"]
        assert ref["name"] == "indexpattern-datasource-layer-layer1"
        (flt,) = state["filters"]
        assert flt["meta"]["key"] == "kibana.alert.workflow_tags"
        assert flt["meta"]["type"] == "phrase"
        assert flt["meta"]["negate"] is False
        assert flt["meta"]["params"] == {"query": "ACME-IR-2026-1026-01"}
        assert flt["query"] == {"match_phrase": {"kibana.alert.workflow_tags": SCOPE.incident_id}}
        assert state["query"] == {"query": "", "language": "kuery"}


def test_alerts_over_time_is_securitys_own_stacked_bar_split_by_rule() -> None:
    attrs = lens.alerts_over_time(SCOPE)
    assert attrs["visualizationType"] == "lnsXY"
    layer = attrs["state"]["visualization"]["layers"][0]
    assert layer["seriesType"] == "bar_stacked"
    cols = attrs["state"]["datasourceStates"]["formBased"]["layers"]["layer1"]["columns"]
    assert cols[layer["xAccessor"]]["operationType"] == "date_histogram"
    assert cols[layer["xAccessor"]]["sourceField"] == "@timestamp"
    assert cols[layer["xAccessor"]]["params"]["interval"] == "auto"
    assert cols[layer["xAccessor"]]["params"]["includeEmptyRows"] is True
    assert cols[layer["accessors"][0]]["operationType"] == "count"
    assert cols[layer["accessors"][0]]["sourceField"] == "___records___"
    assert cols[layer["splitAccessor"]]["operationType"] == "terms"
    assert cols[layer["splitAccessor"]]["sourceField"] == "kibana.alert.rule.name"


def test_the_top_charts_split_on_the_field_they_are_given_and_the_table_on_the_rule() -> None:
    bars = lens.top_values(SCOPE, "Top outside addresses", "source.ip")
    cols = bars["state"]["datasourceStates"]["formBased"]["layers"]["layer1"]["columns"]
    assert cols["c-top"]["sourceField"] == "source.ip"
    assert cols["c-top"]["dataType"] == "ip"
    assert bars["state"]["visualization"]["layers"][0]["seriesType"] == "bar_horizontal"
    sites = lens.top_values(SCOPE, "Campus sites reached", "url.domain")
    site_cols = sites["state"]["datasourceStates"]["formBased"]["layers"]["layer1"]["columns"]
    assert site_cols["c-top"]["dataType"] == "string"
    table = lens.rules_table(SCOPE)
    assert table["visualizationType"] == "lnsDatatable"
    assert [c["columnId"] for c in table["state"]["visualization"]["columns"]] == [
        "c-rule",
        "c-count",
    ]


def test_a_block_holds_only_plain_strings_so_the_brace_count_is_exact() -> None:
    for text in all_blocks():
        (parsed,) = kibana_scan(text)
        for s in strings(parsed):
            assert lens.SAFE.fullmatch(s), s
            assert not set(s) & set("{}[]<>\"'`\\")
        assert text.count("{") == text.count("}")


# --------------------------------------------------------------------------- the property


moments = st.datetimes(
    min_value=datetime(2020, 1, 1, tzinfo=UTC).replace(tzinfo=None),
    max_value=datetime(2035, 1, 1, tzinfo=UTC).replace(tzinfo=None),
    timezones=st.just(UTC),
)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    space=st.from_regex(r"[a-z][a-z0-9_-]{0,30}", fullmatch=True),
    ident=st.from_regex(r"ACME-IR-[0-9]{4}-[0-9]{4}-[0-9]{2}", fullmatch=True),
    first=moments,
    span=st.timedeltas(min_value=timedelta(0), max_value=timedelta(days=400)),
    field=st.sampled_from(["source.ip", "host.name", "url.domain", "destination.ip"]),
)
def test_any_scope_gives_blocks_that_parse_the_way_kibana_parses_them(
    space: str, ident: str, first: datetime, span: timedelta, field: str
) -> None:
    scope = lens.Scope(space, ident, first, first + span)
    texts = [
        lens.block(scope, lens.alerts_over_time(scope)),
        lens.block(scope, lens.top_values(scope, "Top", field)),
        lens.block(scope, lens.rules_table(scope)),
    ]
    comment = "\n\n".join(f"**c**\n\n{t}" for t in texts)
    parsed = kibana_scan(comment)
    assert len(parsed) == 3
    for text, got in zip(texts, parsed, strict=True):
        assert lens.problems(text) == []
        assert got["timeRange"]["mode"] == "absolute"
        (flt,) = got["attributes"]["state"]["filters"]
        assert flt["meta"]["params"]["query"] == ident
        (view,) = got["attributes"]["state"]["adHocDataViews"].values()
        assert view["title"] == f".alerts-security.alerts-{space}"
    guard.check(comment, ALLOWED)


def every_report() -> list[m.IncidentReport]:
    return [kit.amadey(), kit.git()]


def test_every_rendered_comment_of_the_two_cases_has_blocks_that_parse() -> None:
    for report in every_report():
        text = visual.comment(report, "acme-soc")[0]
        parsed = kibana_scan(text)
        assert len(parsed) == len(blocks_of(text)) >= 3
        for got in parsed:
            assert got["attributes"]["state"]["filters"][0]["meta"]["params"]["query"] == (
                report.header.incident_id
            )
        guard.check(text, ALLOWED)


_NAMES = st.text(min_size=1, max_size=12)


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    value=st.text(max_size=80),
    label=st.text(max_size=80),
    alerts=st.integers(min_value=0, max_value=10_000),
    kind=st.sampled_from(["ip", "host", "user"]),
)
def test_text_from_the_report_never_reaches_a_block(
    value: str, label: str, alerts: int, kind: str
) -> None:
    """Whatever an actor, an asset or a rule is called, no brace, quote or name gets into a block:
    the report's text is drawn by Kibana from the alerts, never copied into the chart."""
    report = kit.git()
    actor = report.actors[0].model_copy(update={"value": value or "x", "kind": kind})
    asset = report.assets[0].model_copy(update={"label": label or None, "value": value or "x"})
    changed = report.model_copy(update={"actors": (actor,), "assets": (asset,)})
    text = visual.comment(changed, "acme-soc")[0]
    # a value such as "[" is in every block anyway (its JSON has brackets): only what the blocks of
    # the same report with plain names do not already hold would be a leak
    plain_actor = report.actors[0].model_copy(update={"value": "x", "kind": kind})
    plain_asset = report.assets[0].model_copy(update={"label": None, "value": "x"})
    plain = report.model_copy(update={"actors": (plain_actor,), "assets": (plain_asset,)})
    already = "\n".join(blocks_of(visual.comment(plain, "acme-soc")[0]))
    for line in blocks_of(text):
        assert lens.problems(line) == []
        for part in (value, label):
            if part and set(part) & set("{}[]<>\"'`\\") and part not in already:
                assert part not in line
    guard.check(text, ALLOWED)


def test_no_name_of_a_person_is_in_a_chart() -> None:
    report = kit.amadey()
    person = report.actors[0].model_copy(update={"value": "alice.example", "kind": "user"})
    changed = report.model_copy(update={"actors": (person, *report.actors[1:])})
    text = visual.comment(changed, "acme-soc")[0]
    assert "alice" not in text
    for line in blocks_of(text):
        assert "user.name" not in line
        assert "user.id" not in line


# --------------------------------------------------------------------------- the guardian


def tampered(change: Any) -> str:
    (parsed,) = kibana_scan(all_blocks()[0])
    change(parsed)
    return "!{lens" + json.dumps(parsed, separators=(",", ":")) + "}"


@pytest.mark.parametrize(
    ("make", "why"),
    [
        (lambda p: p["attributes"].update(title="a <b>x</b>"), "string"),
        (lambda p: p["attributes"].update(title="a {brace"), "lens block"),  # the count breaks
        (lambda p: p["attributes"].update(title='say "hi\\'), "string"),
        (lambda p: p["attributes"].update(title="[link](http://e.example)"), "string"),
        (lambda p: p["attributes"].update(title="@everyone"), None),  # '@' alone is plain
        (lambda p: p.update(extra=1), "nothing else"),
        (lambda p: p["timeRange"].update(mode="relative"), "absolute"),
        (lambda p: p["timeRange"].update(**{"from": "now-7d"}), "absolute"),
        (lambda p: p["attributes"].update(visualizationType="lnsMetric"), "chart kinds"),
        (lambda p: p["attributes"].update(references=[{"id": "x"}]), "self-contained"),
        (lambda p: p["attributes"]["state"]["filters"].clear(), "incident's tag"),
        (
            lambda p: p["attributes"]["state"]["filters"][0]["meta"].update(negate=True),
            "incident's tag",
        ),
        (
            lambda p: p["attributes"]["state"]["filters"][0]["meta"].update(disabled=True),
            "switched off",
        ),
        (
            lambda p: next(iter(p["attributes"]["state"]["adHocDataViews"].values())).update(
                title="acme-logs-squid"
            ),
            "alerts index",
        ),
        (lambda p: p["attributes"]["state"]["adHocDataViews"].update(second={}), "exactly one"),
    ],
)
def test_the_guardian_refuses_a_block_that_is_not_the_kind_arguss_charts_are(
    make: Any, why: str | None
) -> None:
    text = tampered(make)
    problems = lens.problems(text)
    if why is None:
        assert problems == []
        return
    assert problems, "refused"
    assert why in " ".join(problems), problems
    with pytest.raises(guard.GuardRefusal):
        guard.check(f"## x\n\n{text}", ALLOWED)


@pytest.mark.parametrize(
    "text",
    [
        '!{lens{"timeRange":{"from":"2026-10-23T03:30:00.000Z"}',  # never closes
        "!{lens{not json}}",
        "!{lens{}}",
        '!{lens{"a":1}}} trailing',
        "!{lens",
        "!{lens}",
    ],
)
def test_a_block_that_does_not_close_parse_or_stand_alone_is_refused(text: str) -> None:
    assert lens.problems(text)
    with pytest.raises(guard.GuardRefusal):
        guard.check(f"## x\n\n{text}", ALLOWED)


def test_a_chart_block_anywhere_but_alone_on_its_line_is_refused() -> None:
    block = all_blocks()[0]
    for text in (f"see {block}", f"**x** {block}", f"- {block}", f"{block} and more"):
        with pytest.raises(guard.GuardRefusal):
            guard.check(f"## x\n\n{text}", ALLOWED)
    guard.check(f"## x\n\n{block}\n\nand more", ALLOWED)


def test_a_block_in_a_code_fence_is_only_code_and_a_hostile_one_is_not_let_through() -> None:
    block = all_blocks()[0]
    guard.check(f"```\n{block}\n```", ALLOWED)
    with pytest.raises(guard.GuardRefusal):
        guard.check('!{lens{"a":"<img src=x onerror=1>"}}', ALLOWED)


def test_the_text_of_a_report_cannot_open_a_chart_block() -> None:
    """A sentence is escaped before it is posted: ``!{lens`` cannot start a line of it."""
    from argus.caseteam import render

    assert not render.say("!{lens{}}").startswith("!{lens")
    guard.check("## x\n\n" + render.say('!{lens{"a":1}}'), ALLOWED)


def test_the_scanner_counts_braces_in_strings_too_as_kibanas_does() -> None:
    """The reason strings hold no brace: a brace inside quotes still moves the count."""
    with pytest.raises(ValueError, match="Expecting"):  # the block ends early: not JSON
        kibana_scan('!{lens{"a":"}"}}')
    assert lens.scan('!{lens{"a":"}"}}') == ['{"a":"}"']


def test_a_glance_with_the_two_fixtures_names_a_field_for_each_chart() -> None:
    assert g.shape_of(kit.git()).actors_field == "source.ip"
    assert g.shape_of(kit.git()).targets_field == "url.domain"
    assert re.fullmatch(r"[a-z.]+", g.shape_of(kit.amadey()).targets_field or "")
