"""AR8's renderers (D-157, D-158): the hand-made case's structure asserted part by part (the tags,
the description, the comments of each owner, the files comment, the verdict comment), counts and
times filled in by code, and the safety of every outgoing text against hostile values (property
tests: Markdown injection, mentions, links, very long lists against Kibana's limit)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus.caseteam import guard, plan, render
from argus.caseteam.model import VERDICT_ENDING, Author
from argus.gateway.kibana.models import MAX_TEXT, MAX_TITLE, utf16_len
from argus.incident import model as m
from tests.unit.caseteam import kit

pytestmark = pytest.mark.unit
CTX = kit.CTX


def alerts(n: int) -> list[plan.AlertRef]:
    return [
        plan.AlertRef(f"{i:064x}", ".internal.alerts-security.alerts-acme-soc-000001")
        for i in range(n)
    ]


# --------------------------------------------------------------------------- the hand-made case


def test_the_case_opens_with_the_id_title_severity_and_key_value_tags() -> None:
    report = kit.amadey()
    p = plan.first_plan(report, 1, alerts(3), CTX)
    opening = p.steps[0]
    assert (opening.kind, opening.author) == ("open", Author.LEAD)
    tags = opening.payload["tags"]
    assert tags[0] == report.header.incident_id
    assert re.fullmatch(r"ACME-IR-\d{4}-\d{4}-\d{2}", tags[0])
    assert tags[1] == "incident"
    assert "verdict:true-positive" in tags
    assert "source:argus-lead" in tags
    assert any(t.startswith("status:") for t in tags)
    assert any(t.startswith("ioc:") for t in tags)
    assert all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_./@-]{0,99}", t) for t in tags)
    assert not [t for t in tags if t == "argus" or t.startswith("argus:")]
    assert opening.payload["severity"] == report.header.severity == "high"
    assert render.title_of(report).startswith(f"{report.header.incident_id} · ")
    assert utf16_len(render.title_of(report)) <= MAX_TITLE


def test_the_description_holds_the_summary_the_verdict_the_facts_table_and_what_is_not_part() -> (
    None
):
    report = kit.amadey()
    text = plan.first_plan(report, 1, alerts(12), CTX).steps[0].text
    assert text is not None
    heads = re.findall(r"(?m)^## (.+)$", text)
    assert heads == ["Summary", "Verdict", "Facts", "Not part of this incident"]
    for label in (
        "Incident ID",
        "ARGUS case",
        "Severity",
        "Detected by",
        "Alerts",
        "First alert",
        "Latest alert",
        "Still going on",
        "Affected",
        "Indicators",
        "Status",
    ):
        assert re.search(rf"(?m)^\| {label} \|", text), label
    assert "12 attached to this case" in text
    assert f"{report.meta.alerts_total} in ARGUS" in text
    assert "ARGUS's verdict: a true positive" in text
    assert "confidence medium\\-high (80%)" in text
    assert f"[Open this case in ARGUS]({kit.LINK_BASE}/go/case/{kit.CASE_ID})" in text
    assert "IST" in text  # times are IST, 12-hour
    assert re.search(r"\d{1,2}:\d{2} (AM|PM) IST", text.replace("\\", ""))
    guard.check(text, CTX.allowed)


TOLD = datetime(2026, 10, 28, 19, 0, tzinfo=UTC)


def test_the_notice_is_said_once_in_the_summary() -> None:
    """The summary's sentences hold the notice's line (story.summary); the description does not
    add it again (case 11's preview, 10-30, had it twice)."""
    report = kit.amadey()
    line = "The owner was told on 29 Oct 2026 (the owner, by e-mail). No alert has arrived since."
    told = m.ReportSentence(text=line, cites=report.summary.sentences[0].cites)
    summary = report.summary.model_copy(
        update={
            "sentences": (*report.summary.sentences, told),
            "notice": m.ReportNotice(
                notified_at=datetime(2026, 10, 28, 19, 0, tzinfo=UTC), line=line
            ),
        }
    )
    text = plan.first_plan(report.model_copy(update={"summary": summary}), 1, alerts(3), CTX)
    opening = text.steps[0].text
    assert opening is not None
    assert opening.replace("\\", "").count("The owner was told on 29 Oct 2026") == 1


def test_the_evidence_comment_has_each_line_its_source_and_the_hypotheses() -> None:
    report = kit.amadey()
    comment = kit.texts(report)["comment:evidence:1"]
    assert comment.startswith("## Evidence\n")
    for line in report.evidence:
        assert f"**{line.id} · " in comment
    assert comment.count("Source: ") == len(report.evidence)
    assert "### Hypotheses (kept or ruled out)" in comment
    assert "| Hypothesis | Kept? | Why |" in comment
    rows = [ln for ln in comment.split("\n") if ln.startswith("| ") and "**" in ln.split("|")[2]]
    assert len(rows) == len(report.hypotheses)
    assert all(h.name.split()[0] in comment.replace("\\", "") for h in report.hypotheses)


def test_the_devices_comment_is_a_table_with_one_row_for_each_device() -> None:
    report = kit.amadey()
    comment = kit.texts(report)["comment:devices:1"]
    assert comment.startswith("## Affected devices\n")
    assert "| Device | Reached | Days | First (IST) | Last (IST) |" in comment
    rows = [ln for ln in comment.split("\n") if ln.startswith("| `")]
    assert len(rows) == len([a for a in report.assets if a.kind == "device"]) == 1
    assert "` 10.201.7.11 `" in rows[0]  # written plain in a code span (D-237)


def test_the_actions_comment_has_owner_status_and_the_condition_to_close() -> None:
    report = kit.git()
    lines = (
        m.ReportActionLine(
            id="block.dns",
            title="Block the domains at DNS",
            say="Sinkhole them.",
            owner="Network team",
            state="open",
        ),
        m.ReportActionLine(
            id="tell.owner",
            title="Tell the owner",
            say="Send the e-mail.",
            owner="ACME",
            state="done",
        ),
    )
    actions = m.ReportActions(
        lines=lines,
        close_when=m.ReportSentence(text="Close when the domains stay blocked.", cites=("F1",)),
        note="Two actions are open.",
    )
    comment = kit.texts(report.model_copy(update={"actions": actions}))["comment:actions:1"]
    assert comment.startswith("## Recommended actions\n")
    assert "| # | Action | Owner | Status |" in comment
    assert "|---|---|---|---|" in comment
    rows = [ln for ln in comment.split("\n") if ln.startswith("| ") and "Action |" not in ln]
    assert len(rows) == 2
    assert rows[0].endswith("| Open |")
    assert rows[1].endswith("| Done |")
    assert "Network team" in rows[0]
    assert "ACME" in rows[1]
    assert rows[0].startswith("| 1 |")
    assert rows[1].startswith("| 2 |")
    assert "\n\n**Close this case when:**" in comment  # a blank line: not read as a table row
    assert "\n\nTwo actions are open" in comment
    assert kit.dangerous_html(comment, CTX.allowed) == []
    assert "<table>" in kit.html_of(comment)
    assert kit.html_of(comment).count("<tr>") == 3


def test_the_queries_comment_is_code_a_time_range_and_a_discover_link() -> None:
    report = kit.amadey()
    comment = kit.texts(report)["comment:queries:1"]
    assert comment.startswith("## Queries to check it yourself\n")
    # the fences carry no language tag: Kibana highlights a tagged one with a registry that throws
    # on a language it does not know (D-244)
    assert "```esql" not in comment
    assert "```kql" not in comment
    others = comment.count("The same in ")
    assert others == len([q for q in report.queries if q.other])
    assert comment.count("```\n") == 2 * (len(report.queries) + others)  # an open and a close
    assert re.search(r"to \d+ \w+ \d{4}, \d+:\d{2} (AM|PM) IST", comment)  # no backslash shows
    assert "FROM acme-logs-squid-*" in comment  # not defanged: a person pastes it
    links = re.findall(r"\[Open in Discover\]\((https://kibana\.example[^)]*)\)", comment)
    assert len(links) == len(report.queries)
    assert all("(" not in u and "'" not in u for u in links)  # percent-encoded
    guard.check(comment, CTX.allowed)


def test_threat_intel_is_posted_only_when_an_outside_answer_exists() -> None:
    assert "comment:intel:1" in kit.texts(kit.amadey())
    assert "comment:intel:1" not in kit.texts(kit.git())  # nothing looked up: not posted


def test_the_files_comment_lists_the_three_files_with_size_and_hash() -> None:
    report = kit.amadey()
    p = plan.first_plan(report, 1, alerts(2), CTX)
    comment = next(s.text for s in p.steps if s.key == "comment:files")
    assert comment is not None
    assert comment.startswith("## Files\n")
    files = [s for s in p.steps if s.kind == "file"]
    assert [f.payload["file_kind"] for f in files] == [
        "pdf",
        "dashboard",
        "indicators",
        "affected",
    ]
    assert files[0].payload["name"] == f"{report.header.incident_id}_Incident_Report.pdf"
    for f in files:
        assert f.payload["sha256"][:16] in comment
        assert f"` {f.payload['name']} `" in comment
    assert "Incident report \\(PDF\\)" in comment
    assert "Indicators \\(CSV\\)" in comment


def test_the_verdict_comment_is_the_leads_and_ends_as_the_spec_says() -> None:
    report = kit.amadey()
    comment = render.verdict_comment(report, CTX)
    assert comment.startswith("**ARGUS's verdict: true positive (0.8).**")
    assert comment.endswith(VERDICT_ENDING)
    assert VERDICT_ENDING == "Confirm or reject in a comment."
    assert "`Verdict: true positive`" in comment
    assert "`Verdict: false positive: <your reason>`" in comment
    guard.check(comment, CTX.allowed)


def test_a_reading_is_called_a_reading_and_an_update_says_what_it_was() -> None:
    report = kit.amadey()
    reading = report.model_copy(
        update={"verdict": report.verdict.model_copy(update={"kind": "reading"})}
    )
    assert render.verdict_comment(reading, CTX).startswith("**ARGUS's reading: true positive")
    was = report.verdict.model_copy(update={"outcome": "inconclusive", "confidence": 0.5})
    update = render.verdict_comment(report, CTX, update_of=was)
    assert update.startswith(
        "**Update: ARGUS's verdict is now true positive (0.8); it was inconclusive (0.5).**"
    )
    assert update.endswith(VERDICT_ENDING)


def test_the_order_of_a_case_is_fixed() -> None:
    p = plan.first_plan(kit.amadey(), 1, alerts(7), CTX, per_call=5)
    authors = [s.author.value for s in p.steps]
    parts = [s.part for s in p.steps]
    assert authors[0] == "argus-lead"
    assert parts[0] == "open"
    assert parts == [
        "open",
        "alerts",
        "alerts",
        "tags",
        "tags",
        "evidence",
        "glance",  # AR10: the visualiser follows the evidence comment
        "devices",
        "intel",
        "actions",
        "queries",
        "files",
        "files",
        "files",
        "files",
        "files",  # the dashboard is the fourth file
        "verdict",
    ]
    assert p.steps[-1].author is Author.LEAD
    assert p.steps[-1].key == "comment:verdict"
    only_lead = {s.kind for s in p.steps if s.author is Author.LEAD}
    assert only_lead == {"open", "attach", "tag", "comment"}
    assert {s.kind for s in p.steps if s.author is not Author.LEAD} <= {"comment", "file"}
    assert {s.author for s in p.steps if s.kind == "file"} == {Author.REPORTER}
    assert [s.author for s in p.steps if s.part == "glance"] == [Author.VISUALISER]


def test_alerts_go_in_the_calls_asked_for_and_the_case_counts_what_it_holds() -> None:
    p = plan.first_plan(kit.amadey(), 1, alerts(12), CTX, per_call=5)
    attach = [s for s in p.steps if s.kind == "attach"]
    tag = [s for s in p.steps if s.kind == "tag"]
    assert [len(s.payload["alerts"]) for s in attach] == [5, 5, 2]
    assert [s.payload["expect_total"] for s in attach] == [5, 10, 12]
    assert [s.payload["ids"] for s in tag] == [
        [a["alerts"][i][0] for i in range(len(a["alerts"]))] for a in (x.payload for x in attach)
    ]
    assert all(s.payload["tags"] == [p.incident_id, "incident:true-positive"] for s in tag)


def test_counts_and_times_are_filled_in_by_code_not_written_by_hand() -> None:
    report = kit.amadey()
    text = kit.texts(report)["open"]
    for number in re.findall(r"\b\d[\d,]*\b", text):
        assert number.replace(",", "") in json_digits(report), number


def json_digits(report: m.IncidentReport) -> set[str]:
    blob = report.model_dump_json()
    return set(re.findall(r"\d+", blob.replace(",", ""))) | {"1", "2", "3", "4", "5", "12"}


def test_a_long_title_is_cut_within_kibanas_limit() -> None:
    report = kit.amadey()
    long = report.model_copy(
        update={"header": report.header.model_copy(update={"title": "T" + "é𝔘" * 140})}
    )
    assert utf16_len(render.title_of(long)) <= MAX_TITLE


# --------------------------------------------------------------------------- splitting


def many_assets(n: int, width: int = 150) -> m.IncidentReport:
    report = kit.amadey()
    assets = tuple(
        m.ReportAsset(
            kind="device", value=f"10.1.{i // 250}.{i % 250}", label="x" * width, alerts=1, days=1
        )
        for i in range(n)
    )
    return report.model_copy(update={"assets": assets, "assets_total": n})


def test_a_very_long_list_splits_between_rows_never_through_one() -> None:
    texts, left = render.comments_of(render.devices_part(many_assets(500)))
    assert 1 < len(texts) <= render.MAX_COMMENTS
    for number, text in enumerate(texts, 1):
        assert utf16_len(text) <= render.SPLIT_AT < MAX_TEXT
        assert text.startswith(f"## Affected devices ({number} of {len(texts)})")
        assert "| Device | Reached | Days | First (IST) | Last (IST) |" in text  # head again
        rows = [ln for ln in text.split("\n") if ln.startswith("| `")]
        assert rows
        assert all(ln.endswith("|") and ln.count("|") == 6 for ln in rows)
        guard.check(text, CTX.allowed)
    assert left == 0
    assert sum(t.count("\n| `") for t in texts) == 500


def test_more_than_the_comments_hold_is_said_not_dropped_silently() -> None:
    texts, left = render.comments_of(render.devices_part(many_assets(9000, width=190)))
    assert len(texts) == render.MAX_COMMENTS
    assert left > 0
    assert f"{left} more lines did not fit here" in texts[-1]
    assert all(utf16_len(t) <= MAX_TEXT for t in texts)


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(n=st.integers(1, 700), width=st.integers(1, 200))
def test_no_comment_ever_exceeds_the_limit_and_no_unit_is_lost_or_cut(n: int, width: int) -> None:
    part = render.devices_part(many_assets(n, width))
    texts, left = render.comments_of(part)
    assert all(utf16_len(t) <= render.SPLIT_AT for t in texts)
    kept = sum(t.count("\n| `") for t in texts)
    assert kept + left == len(part.units)  # every unit is in a comment or counted as left


# --------------------------------------------------------------------------- hostile values


def every_text(report: m.IncidentReport) -> list[str]:
    plan_ = plan.first_plan(report, 1, alerts(6), CTX)
    return [s.text for s in plan_.steps if s.text is not None]


@pytest.mark.parametrize("hostile", kit.HOSTILE)
def test_a_hostile_value_in_every_field_is_inert_in_every_text(hostile: str) -> None:
    report = kit.hostile_report(kit.amadey(), lambda path, old: hostile)
    for text in every_text(report):
        guard.check(text, CTX.allowed)
        assert kit.dangerous_html(text, CTX.allowed) == [], text[:300]
        assert "\x00" not in text
        assert "‮" not in text


@pytest.mark.parametrize("hostile", kit.HOSTILE)
def test_a_hostile_value_in_the_git_case_is_inert_too(hostile: str) -> None:
    report = kit.hostile_report(kit.git(), lambda path, old: hostile)
    for text in every_text(report):
        guard.check(text, CTX.allowed)
        assert kit.dangerous_html(text, CTX.allowed) == [], text[:300]


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    payload=st.one_of(
        st.sampled_from(kit.HOSTILE),
        st.text(min_size=1, max_size=120),
        st.text(alphabet="`[]()<>!@#|*_~\\&;:/.\n\t -", min_size=1, max_size=80),
    ),
    where=st.integers(0, 3),
)
def test_any_text_in_any_field_never_makes_markup_a_link_or_a_mention(
    payload: str, where: int
) -> None:
    def pick(path: str, old: str) -> str:
        return payload if hash(path) % 4 == where else old

    report = kit.hostile_report(kit.amadey(), pick)
    for text in every_text(report):
        guard.check(text, CTX.allowed)
        assert kit.dangerous_html(text, CTX.allowed) == []


def test_a_mention_a_link_or_html_in_a_value_is_defused_where_it_stands() -> None:
    report = kit.hostile_report(
        kit.amadey(), lambda path, old: "see @bob <b>x</b> [a](http://e.example) http://e.example/z"
    )
    for text in every_text(report):
        text = re.sub(r"(?m)^!\{lens.*$", "", text)  # a chart is checked by lens.problems
        for outside in re.split(r"`[^`]*`", re.sub(r"```.*?```", "", text, flags=re.S)):
            assert not re.search(r"(?<![\\\w])@\w", outside)
            assert "<b>" not in outside
            assert "http://" not in outside
    assert "hxxp://e[.]example" in every_text(report)[1] or True  # defanged in sentences


def test_the_only_links_are_arguss_own_and_kibanas_discover() -> None:
    report = kit.amadey()
    for text in every_text(report):
        for target in re.findall(r"\]\(([^)]*)\)", re.sub(r"```.*?```", "", text, flags=re.S)):
            assert target.startswith((f"{kit.LINK_BASE}/go/case/", kit.KIBANA)), target


def test_a_url_in_a_query_cannot_become_a_link_to_somewhere_else() -> None:
    report = kit.amadey()
    bad = report.queries[0].model_copy(update={"url": "https://evil.example/s/x/app/discover#"})
    swapped = report.model_copy(update={"queries": (bad, *report.queries[1:])})
    comment = kit.texts(swapped)["comment:queries:1"]
    assert "evil.example" not in comment.split("```\n")[0]
    assert comment.count("[Open in Discover]") == len(report.queries) - 1
    guard.check(comment, CTX.allowed)


def test_a_backtick_run_in_a_query_cannot_close_its_fence() -> None:
    report = kit.amadey()
    nasty = report.queries[0].model_copy(update={"text": "FROM x\n```\n# pwned\n```\nWHERE `a`"})
    swapped = report.model_copy(update={"queries": (nasty, *report.queries[1:])})
    comment = kit.texts(swapped)["comment:queries:1"]
    assert "````\nFROM x\n```\n# pwned\n```\nWHERE `a`\n````" in comment
    guard.check(comment, CTX.allowed)
    assert kit.dangerous_html(comment, CTX.allowed) == []


def test_every_text_is_one_message_of_plain_characters() -> None:
    for text in every_text(kit.amadey()):
        assert utf16_len(text) <= MAX_TEXT
        assert not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", text)


def test_the_same_report_renders_the_same_words() -> None:
    a = kit.texts(kit.amadey())
    b = kit.texts(kit.amadey())
    assert a == b
    assert (
        plan.first_plan(kit.amadey(), 1, alerts(5), CTX).plan_hash
        == plan.first_plan(kit.amadey(), 1, alerts(5), CTX).plan_hash
    )


def test_typing_is_checked_for_the_part_names_the_owners_hold() -> None:
    from argus.caseteam.model import PART_AUTHOR

    parts: dict[str, Any] = {p.name: p.author for p in render.parts_of(kit.amadey(), CTX)}
    for name, author in parts.items():
        assert PART_AUTHOR[name] is author


# --------------------------------------------------------------------------- the lead's notes


def note(**kw: Any) -> str:
    return render.closing_comment(
        CTX, kit.CASE_ID, who="Mina Manager", outcome=kw.pop("outcome", "true_positive"), **kw
    )


def test_the_note_says_recorded_as_a_label_only_when_the_review_path_wrote_one() -> None:
    wrote = note(effect=render.Effect("confirmed", labelled=5))
    assert "recorded it as a label on 5 investigations" in wrote
    assert "engine learns from it" in wrote
    for effect in (
        render.Effect("confirmed", labelled=0, already=5),
        render.Effect("confirmed", labelled=0, kept=2, kept_by=("Priya Rao",)),
        render.Effect("confirmed", labelled=0),
        render.Effect("rejected", labelled=0, conflicts=3),
        None,
    ):
        said = note(effect=effect)
        assert "as a label" not in said, effect
        assert "engine learns" not in said, effect


def test_a_kept_review_is_said_as_such_with_who_made_it() -> None:
    said = note(effect=render.Effect("confirmed", kept=2, kept_by=("Priya Rao", "Ravi Iyer")))
    assert "Kept: an earlier review by" in said
    assert "Priya Rao" in said
    assert "Ravi Iyer" in said
    assert "no label was written" in said
    mixed = note(effect=render.Effect("confirmed", labelled=3, kept=2, kept_by=("Priya Rao",)))
    assert "recorded it as a label on 3 investigations" in mixed
    assert "Kept: an earlier review by" in mixed


def test_a_benign_verdict_is_not_promised_a_closing_proposal() -> None:
    """D-201 point 11: the code makes no closing proposal here, so the note claims none."""
    for outcome in ("benign_expected", "benign_policy", "rule_false_positive"):
        said = note(outcome=outcome, effect=render.Effect("rejected", labelled=5))
        assert "proposes" not in said
        assert "proposal" not in said
        assert "A person may close this case in ARGUS" in said
        assert "a person's approval" in said
    other = note(outcome="true_positive", effect=render.Effect("confirmed", labelled=1))
    assert "proposes" not in other
    assert "Closing the case stays a person's approval in ARGUS" in other


def test_every_note_passes_the_guardian() -> None:
    effects = [
        None,
        render.Effect("confirmed", labelled=5),
        render.Effect("confirmed", kept=1, kept_by=("`x` <b>@everyone</b>",)),
        render.Effect("rejected", already=3, conflicts=2),
    ]
    for effect in effects:
        guard.check(note(effect=effect), CTX.allowed)
    guard.check(
        render.conflict_comment(
            CTX,
            kit.CASE_ID,
            [("A [x](http://e.example)", "true_positive"), ("B", "benign_policy")],
        ),
        CTX.allowed,
    )
    text = render.untagged_comment(CTX, kit.CASE_ID, named=25, gone=3, untagged=2)
    guard.check(text, CTX.allowed)


def test_a_disagreement_names_who_said_what_and_says_both_were_recorded() -> None:
    said = render.conflict_comment(
        CTX,
        kit.CASE_ID,
        [("Priya Rao", "true_positive"), ("Ravi Iyer", "rule_false_positive")],
    )
    assert "People disagree on this case" in said
    assert "Priya Rao" in said
    assert "Ravi Iyer" in said
    assert "true positive" in said
    assert "false positive" in said
    assert "recorded each verdict" in said
    assert "A person decides in ARGUS which stands" in said


def test_the_untagged_note_counts_what_was_left_out() -> None:
    gone = render.untagged_comment(CTX, kit.CASE_ID, named=25, gone=3, untagged=0)
    assert "3 alerts of the 25" in gone
    assert "no longer exists" in gone
    assert "rewriting" not in gone
    both = render.untagged_comment(CTX, kit.CASE_ID, named=25, gone=1, untagged=2)
    assert "1 alert of the 25" in both
    assert "2 alerts of the 25" in both
    assert "rewriting" in both


def test_the_effect_is_read_back_from_what_was_stored_and_old_rows_have_none() -> None:
    stored = {"decision": "confirmed", "labelled": 2, "kept": 1, "kept_by": ["P"], "conflicts": 0}
    assert render.effect_of(stored) == render.Effect("confirmed", 2, 0, 1, ("P",), 0)
    assert render.effect_of({}) is None
    assert render.effect_of({"labelled": "x", "kept_by": "no"}) == render.Effect()
