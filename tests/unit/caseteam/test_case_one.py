"""The Kibana case of a web-scan incident like case 1 (D-237, D-240): sixteen outside addresses
probing campus web servers for ``.env`` files, rendered from fixtures. What the user saw in Kibana
(literal backslashes, ``[.]``, "no affected asset", "no action applies", "not confirmed yet" next
to a confirmed report, three identical evidence headings and reasons) must not come back."""

from __future__ import annotations

import re
from dataclasses import replace

import pytest

from argus.caseteam import guard, plan
from argus.incident import build
from argus.incident import model as m
from argus.responder import catalogue as cat
from tests.unit.caseteam import kit as team
from tests.unit.incident import kit

pytestmark = pytest.mark.unit
CATALOGUE = cat.load()


def report(**more: object) -> m.IncidentReport:
    facts = kit.scanners(**{k: v for k, v in more.items() if k == "checks"})  # type: ignore[arg-type]
    ctx = kit.ctx(catalogue=CATALOGUE, own_domains=("example.edu",))
    return build.build(facts, ctx)


def texts(rep: m.IncidentReport) -> dict[str, str]:
    return team.texts(rep)


def test_no_backslash_before_punctuation_kibana_shows_and_no_defanging() -> None:
    every = texts(report())
    assert every  # a description and the owners' comments
    for key, text in every.items():
        assert not re.search(r"\\[,:'\"!?;=<@$%&/^]", text), key  # a backslash that would show
        assert "[.]" not in text, key
        assert "hxxp" not in text, key
        guard.check(text, team.CTX.allowed)


def test_the_devices_comment_lists_the_targets_and_the_outside_actors() -> None:
    rep = report()
    comment = texts(rep)["comment:devices:1"]
    assert comment.startswith("## Campus targets and outside actors\n")
    assert "The case names no affected asset" not in comment
    assert "### Campus targets" in comment
    assert "### Outside actors" in comment
    # (a) the targets: the sites and the server, with alerts, first and last, and the answers
    assert "| Target | Kind | Alerts | Outside addresses | First (IST) | Last (IST) |" in comment
    for site in kit.SITES:
        assert f"` {site} `" in comment
    assert f"` {kit.SERVER} `" in comment
    assert "yes (1): ` /.env `" in comment  # a site that gave a successful answer for a file
    # (b) one row for each outside address, with the threat list, outside intel and answers
    assert (
        "| Address | Role | Alerts | First (IST) | Last (IST) | Threat list | Outside intel"
        in comment
    )
    rows = [ln for ln in comment.split("\n") if ln.startswith("| ` 203.0.113.")]
    assert len(rows) == len(kit.PROBERS) == 16
    assert any("| listed |" in r for r in rows)
    assert any("| not listed |" in r for r in rows)
    assert any("VirusTotal: 9 of 94 engines flag this IP" in r for r in rows)
    assert any("| yes (2): ` /.env ` |" in r for r in rows)
    assert any("| not checked |" in r for r in rows)


def test_the_facts_table_says_who_and_what_was_affected_and_what_is_true_of_the_case() -> None:
    rep = report()
    text = texts(rep)["open"]
    assert "| Affected | 3 campus sites and hosts attacked by 16 outside addresses |" in text
    assert "0 assets" not in text
    assert "no affected asset" not in text
    row = next(ln for ln in text.split("\n") if ln.startswith("| ARGUS case |"))
    assert "suggested by ARGUS from its own evidence" in row
    assert "not confirmed yet" not in row  # the row never says both (D-229)


def test_a_case_a_person_reviewed_does_not_say_unconfirmed() -> None:
    facts = kit.scanners()
    reviewed = replace(
        facts, members=tuple(replace(x, reviewed_outcome="true_positive") for x in facts.members)
    )
    rep = build.build(reviewed, kit.ctx(catalogue=CATALOGUE, own_domains=("example.edu",)))
    assert rep.verdict.kind == "person"
    row = next(ln for ln in texts(rep)["open"].split("\n") if ln.startswith("| ARGUS case |"))
    assert "a person reviewed the report \\(a true positive\\)" in row
    assert "no person has confirmed" not in row
    assert "not confirmed yet" not in row


def test_the_actions_are_a_table_like_the_hand_made_one_with_the_condition_to_close() -> None:
    rep = report()
    comment = texts(rep)["comment:actions:1"]
    assert "No action in the responder's catalogue applies" not in comment
    assert "| # | Action | Owner | Status |" in comment
    rows = [ln for ln in comment.split("\n") if re.match(r"\| \d+ \|", ln)]
    assert [r.split("|")[1].strip() for r in rows] == ["1", "2"]
    assert "Remove the exposed file" in rows[0]
    assert "Website owner" in rows[0]
    assert "Change every secret the file held" in rows[1]
    assert "\n\n**Close this case when:**" in comment
    assert {a.family for a in rep.actions.lines} == {"exposed_file"}


def test_a_case_with_no_stored_answers_still_names_no_action_it_cannot_support() -> None:
    """Without a stored web check or an alert that records its own answer, no family matches and
    the comment says so (the catalogue's families are keyed on facts, not on a rule's name)."""
    comment = texts(report(checks=False))["comment:actions:1"]
    assert "No action in the responder's catalogue applies" in comment


def test_each_evidence_check_has_its_own_heading_that_names_what_it_asked() -> None:
    comment = texts(report())["comment:evidence:1"]
    # the bold is the check's title; what it asked follows, outside the bold (D-244)
    found = re.findall(r"^\*\*(E\d+ · [^*\n]+)\*\*([^\n]*)$", comment, re.M)
    heads = [title + asked for title, asked in found]
    assert len(heads) == len(set(heads)), "two lines with one heading"
    # the threat-list look-up names its values; the lines of one check differ by their subject
    lookups = [h for h in heads if "threat lists" in h]
    assert len(lookups) == 2
    assert len(set(lookups)) == 2
    assert any("` 203.0.113.101 `, ` 203.0.113.102 `" in h for h in lookups)
    followups = [h for h in heads if "successful web answers" in h]
    assert len(followups) == len(set(followups)) >= 2
    assert all("` 203.0.113." in h for h in followups)


def test_each_hypothesis_has_its_own_reason() -> None:
    comment = texts(report())["comment:evidence:1"]
    table = comment.split("### Hypotheses (kept or ruled out)")[1]
    rows = [ln for ln in table.split("\n") if ln.startswith("| ") and "**" in ln.split("|")[2]]
    reasons = [r.split("|")[3].strip() for r in rows]
    assert len(reasons) == 4, reasons
    assert len(set(reasons)) == len(reasons), reasons
    threat, benign, rule, research = reasons  # no campus device: "one device" is not asked
    assert threat.startswith("It rests on:")
    assert benign.startswith("Ruled out by facts a harmless explanation does not account for:")
    assert rule.startswith("Ruled out: the activity is backed by facts beyond the rule:")
    assert "evidence flag" in threat
    assert "evidence flag" not in rule
    assert research.startswith("Not settled by what ARGUS holds")


def test_the_outside_actors_table_is_posted_in_the_first_plan() -> None:
    rep = report()
    p = plan.first_plan(rep, 1, [], team.CTX)
    by_key = {s.key: s for s in p.steps}
    assert "comment:devices:1" in by_key
    assert by_key["comment:devices:1"].author.value == ("argus-evidence")
    assert "comment:actions:1" in by_key
