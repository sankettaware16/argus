"""Plans (AR8, D-195 points 4 and 5): generation 1, the "Update" rounds that post only what
changed (never an edit, never a delete, a file only when its bytes changed, under a versioned
name), the lead's note after a person's verdict, and the hash an approval binds."""

from __future__ import annotations

import pytest

from argus.caseteam import plan, render
from argus.caseteam.model import Author, Plan, Step, unit_hash
from argus.gateway.kibana import models
from argus.incident import model as m
from tests.unit.caseteam import kit

pytestmark = pytest.mark.unit
CTX = kit.CTX
IDX = ".internal.alerts-security.alerts-acme-soc-000001"


def alerts(n: int, start: int = 0) -> list[plan.AlertRef]:
    return [plan.AlertRef(f"{i:064x}", IDX) for i in range(start, start + n)]


def posted_after(first: Plan, report: m.IncidentReport, n: int = 8) -> plan.Posted:
    """What the case holds once ``first`` went through (as the store derives it)."""
    units: dict[str, frozenset[str]] = {}
    files: dict[str, str] = {}
    attached: set[str] = set()
    verdict = None
    for s in first.steps:
        if s.kind == "comment":
            units[s.part] = units.get(s.part, frozenset()) | frozenset(s.units)
        elif s.kind == "file":
            files[s.payload["file_kind"]] = s.payload["sha256"]
        elif s.kind == "attach":
            attached |= {a for a, _ in s.payload["alerts"]}
        if s.part == "verdict":
            verdict = (s.payload["outcome"], s.payload["confidence"])
    return plan.Posted("kid-1", 1, 1, units, files, frozenset(attached), verdict)


def more_evidence(report: m.IncidentReport) -> m.IncidentReport:
    line = report.evidence[-1].model_copy(update={"id": "E99", "title": "A newer check"})
    return report.model_copy(update={"evidence": (*report.evidence, line)})


# --------------------------------------------------------------------------- generation 1


def test_every_step_is_hashed_and_the_plan_hash_binds_text_and_author() -> None:
    report = kit.amadey()
    a = plan.first_plan(report, 1, alerts(6), CTX)
    assert all(len(s.request_hash) == 64 for s in a.steps)
    assert a.plan_hash == plan.first_plan(report, 1, alerts(6), CTX).plan_hash
    assert a.plan_hash != plan.first_plan(report, 1, alerts(7), CTX).plan_hash  # another alert
    other = report.model_copy(
        update={"summary": report.summary.model_copy(update={"headline": "x"})}
    )
    changed = report.model_copy(
        update={"verdict": report.verdict.model_copy(update={"words": "something else"})}
    )
    assert a.plan_hash != plan.first_plan(changed, 1, alerts(6), CTX).plan_hash
    assert other.summary.headline == "x"
    swapped = Plan(
        a.incident_id,
        a.case_id,
        a.gen,
        a.report_version,
        tuple(
            Step(
                s.key,
                s.kind,
                Author.EVIDENCE if s.key == "comment:actions:1" else s.author,
                s.part,
                s.text,
                s.payload,
                s.units,
                s.request_hash,
            )
            for s in a.steps
        ),
    )
    assert swapped.plan_hash != a.plan_hash  # the author is part of what is approved


def test_the_generation_number_is_where_a_plan_is_stored_not_what_it_says() -> None:
    a = plan.first_plan(kit.amadey(), 1, alerts(3), CTX)
    from dataclasses import replace

    assert replace(a, gen=7).plan_hash == a.plan_hash


def test_a_step_becomes_the_exact_request_of_its_author() -> None:
    report = kit.amadey()
    a = plan.first_plan(report, 1, alerts(2), CTX)
    by_key = {s.key: s for s in a.steps}
    template, params = plan.request_of(by_key["comment:queries:1"], "kid-1", report)
    assert template.name == "team.comment"
    assert params.author == "argus-hunter"
    template, params = plan.request_of(by_key["open"], None, report)
    assert template.name == "team.create"
    assert isinstance(params, models.TeamCaseCreate)
    template, params = plan.request_of(by_key["file:pdf"], "kid-1", report)
    assert template.name == "team.file"
    assert params.file.mime == "application/pdf"


def test_a_file_whose_bytes_changed_is_refused_not_sent() -> None:
    report = kit.amadey()
    a = plan.first_plan(report, 1, alerts(1), CTX)
    step = next(s for s in a.steps if s.key == "file:indicators")
    forged = Step(
        step.key,
        step.kind,
        step.author,
        step.part,
        None,
        {**step.payload, "sha256": "0" * 64},
        (),
        step.request_hash,
    )
    with pytest.raises(ValueError, match="not the one the plan hashed"):
        plan.request_of(forged, "kid-1", report)


# --------------------------------------------------------------------------- updates


def test_an_unchanged_report_has_nothing_to_post() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(5), CTX)
    again = plan.update_plan(report, 2, alerts(5), CTX, posted_after(first, report), max_alerts=25)
    assert again.steps == ()
    assert again.gen == 2
    assert again.kibana_case_id == "kid-1"


def test_a_new_evidence_line_is_one_update_comment_by_the_evidence_agent() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(5), CTX)
    newer = more_evidence(report)
    update = plan.update_plan(newer, 2, alerts(5), CTX, posted_after(first, report), max_alerts=25)
    # the evidence agent's comment, and the PDF (which holds the evidence) uploaded again with
    # the reporter's note; the CSVs did not change
    assert [(s.key, s.author) for s in update.steps] == [
        ("comment:evidence:1", Author.EVIDENCE),
        ("file:pdf", Author.REPORTER),
        ("comment:files", Author.REPORTER),
    ]
    text = update.steps[0].text
    assert text is not None
    assert text.startswith("## Update: Evidence\n")
    assert "New since report version 1: 1 lines (version 2)." in text
    assert "A newer check" in text
    assert "**E99 · " in text
    assert "**E1 · " not in text  # only what is new
    assert update.steps[0].units == (
        unit_hash(next(u for u in render.evidence_part(newer).units if "E99" in u)),
    )


def test_what_no_longer_applies_is_counted_not_hidden_and_never_deleted() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(5), CTX)
    fewer = report.model_copy(update={"evidence": report.evidence[:-1]})
    # a changed line replaces one: one new unit, one earlier unit gone
    swapped = report.model_copy(
        update={
            "evidence": (
                *report.evidence[:-1],
                report.evidence[-1].model_copy(update={"title": "Another way in"}),
            )
        }
    )
    update = plan.update_plan(
        swapped, 2, alerts(5), CTX, posted_after(first, report), max_alerts=25
    )
    [step] = [s for s in update.steps if s.part == "evidence"]
    assert step.text is not None
    assert "1 earlier lines no longer apply; see the report." in step.text
    nothing_new = plan.update_plan(
        fewer, 2, alerts(5), CTX, posted_after(first, report), max_alerts=25
    )
    assert [s for s in nothing_new.steps if s.kind == "comment" and s.part == "evidence"] == []


def test_a_file_is_uploaded_again_only_when_it_changed_with_a_versioned_name() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(5), CTX)
    newer = more_evidence(report)
    update = plan.update_plan(newer, 4, alerts(5), CTX, posted_after(first, report), max_alerts=25)
    files = [s for s in update.steps if s.kind == "file"]
    assert [f.payload["file_kind"] for f in files] == ["pdf"]  # the CSVs did not change
    assert files[0].payload["name"] == f"{report.header.incident_id}_Incident_Report_v4.pdf"
    listing = next(s for s in update.steps if s.key == "comment:files")
    assert listing.text is not None
    assert listing.text.startswith("## Update: new files")
    assert "_Incident_Report_v4" in listing.text.replace("[.]pdf", "")
    assert "indicators[.]csv" not in listing.text
    assert "affected_devices" not in listing.text


def test_the_verdict_is_said_again_only_when_it_changed_and_it_is_the_last_step() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(5), CTX)
    posted = posted_after(first, report)
    same = plan.update_plan(more_evidence(report), 2, alerts(5), CTX, posted, max_alerts=25)
    assert "comment:verdict" not in [s.key for s in same.steps]
    changed = report.model_copy(
        update={"verdict": report.verdict.model_copy(update={"confidence": 0.95})}
    )
    update = plan.update_plan(more_evidence(changed), 2, alerts(5), CTX, posted, max_alerts=25)
    assert update.steps[-1].key == "comment:verdict"
    assert update.steps[-1].author is Author.LEAD
    assert update.steps[-1].text is not None
    assert update.steps[-1].text.startswith("**Update: ARGUS's verdict is now true positive (0.95)")
    assert update.steps[-1].text.endswith("Confirm or reject in a comment.")


def test_new_alerts_are_attached_and_tagged_up_to_the_cap_and_none_twice() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(5), CTX)
    posted = posted_after(first, report)
    update = plan.update_plan(report, 2, alerts(8), CTX, posted, max_alerts=25)
    attach = [s for s in update.steps if s.kind == "attach"]
    assert [a[0] for s in attach for a in s.payload["alerts"]] == [f"{i:064x}" for i in (5, 6, 7)]
    assert attach[0].payload["expect_total"] == 8
    capped = plan.update_plan(report, 2, alerts(20), CTX, posted, max_alerts=7)
    assert sum(len(s.payload["alerts"]) for s in capped.steps if s.kind == "attach") == 2


def test_an_update_never_opens_edits_or_deletes() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(5), CTX)
    update = plan.update_plan(
        more_evidence(report), 2, alerts(9), CTX, posted_after(first, report), max_alerts=25
    )
    assert {s.kind for s in update.steps} <= {"attach", "tag", "comment", "file"}
    assert "open" not in [s.kind for s in update.steps]


# --------------------------------------------------------------------------- after a verdict


def test_a_note_is_one_lead_comment_keyed_by_what_it_says() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(5), CTX)
    posted = posted_after(first, report)
    effect = render.Effect("confirmed", labelled=5)
    texts = [
        render.closing_comment(
            CTX, report.header.case_id, who="Mina Manager", outcome="true_positive", effect=effect
        )
        for _ in range(2)
    ]
    a = plan.note_plan(report, 1, posted, key=plan.closing_key("c-1|" + "a" * 64), text=texts[0])
    b = plan.note_plan(report, 1, posted, key=plan.closing_key("c-2|" + "a" * 64), text=texts[1])
    assert [s.author for s in a.steps] == [Author.LEAD]
    assert a.steps[0].key != b.steps[0].key
    assert a.steps[0].key.startswith("comment:closing:")
    text = a.steps[0].text
    assert text is not None
    assert "Mina Manager" in text
    assert "true positive" in text
    assert "a person's approval" in text


def test_a_notes_keys_are_stable_and_differ_by_what_they_name() -> None:
    assert plan.closing_key("c-1|h") == plan.closing_key("c-1|h")
    assert plan.closing_key("c-1|h") != plan.closing_key("c-1|h2")  # an edited text is a new one
    pairs = [(1, "true_positive"), (2, "rule_false_positive")]
    assert plan.conflict_key(pairs) == plan.conflict_key(list(reversed(pairs)))
    assert plan.conflict_key(pairs) != plan.conflict_key([(1, "true_positive")])
    assert plan.untagged_key(7) == "comment:untagged:7"


def test_alerts_go_in_calls_of_the_size_the_settings_say_and_the_case_counts_what_it_holds() -> (
    None
):
    for per_call in (5, 25, 100):
        steps = plan.alert_steps(alerts(60), ("T", "incident:true-positive"), per_call=per_call)
        attach = [s for s in steps if s.kind == "attach"]
        tag = [s for s in steps if s.kind == "tag"]
        assert [len(s.payload["alerts"]) for s in attach] == _sizes(60, per_call)
        assert [len(s.payload["ids"]) for s in tag] == _sizes(60, per_call)
        assert [s.payload["expect_total"] for s in attach][-1] == 60
        assert [s.kind for s in steps] == ["attach"] * len(attach) + ["tag"] * len(tag)


def _sizes(n: int, per_call: int) -> list[int]:
    return [min(per_call, n - i) for i in range(0, n, per_call)]


def test_five_hundred_alerts_are_twenty_calls_of_twenty_five_and_each_fits_the_model() -> None:
    report = kit.amadey()
    big = plan.first_plan(report, 1, alerts(500), CTX, per_call=25)
    attach = [s for s in big.steps if s.kind == "attach"]
    assert len(attach) == 20
    assert max(len(s.payload["alerts"]) for s in attach) == 25
    assert len([s for s in big.steps if s.kind == "tag"]) == 20


def test_an_update_leaves_out_the_alerts_a_tag_call_found_gone() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(5), CTX)
    posted = posted_after(first, report)
    gone = frozenset({f"{6:064x}"})
    posted = plan.Posted(
        posted.kibana_case_id, 1, 1, posted.units, posted.files, posted.attached,
        posted.verdict, gone,
    )  # fmt: skip
    update = plan.update_plan(more_evidence(report), 2, alerts(9), CTX, posted, max_alerts=25)
    named = [a for s in update.steps if s.kind == "attach" for a, _ in s.payload["alerts"]]
    assert f"{6:064x}" not in named
    assert f"{5:064x}" in named


@pytest.mark.parametrize(
    ("index", "concrete"),
    [
        (".internal.alerts-security.alerts-acme-soc-000009", True),
        (".internal.alerts-security.alerts-acme-soc-000010", True),
        (".alerts-security.alerts-acme-soc", False),  # the alias
        (".internal.alerts-security.alerts-other-000001", False),  # another space's
        (".internal.alerts-security.alerts-acme-soc-9", False),
        (".internal.alerts-security.alerts-acme-soc-0000091", False),
        (".internal.alerts-security.alerts-acme-soc-00000a", False),
        ("alerts", False),
        ("", False),
    ],
)
def test_only_the_spaces_concrete_alert_indices_are_attached(index: str, concrete: bool) -> None:
    assert plan.Target("acme-soc").concrete(index) is concrete
