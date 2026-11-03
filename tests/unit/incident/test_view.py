"""What a person without log access sees of the report (AR7): everything derived from log content
reads as hidden, in the fact and in every sentence that cites it; the rest stays; hiding twice
changes nothing more; the report still validates (a hidden sentence cites a fact that is there)."""

from __future__ import annotations

import pytest

from argus.incident import model as m
from argus.incident.build import build
from argus.incident.view import hide_logs
from tests.unit.incident import kit

pytestmark = pytest.mark.unit


def test_what_the_logs_said_is_hidden_and_the_rest_is_left() -> None:
    report = build(kit.git(), kit.ctx())
    hidden = hide_logs(report)
    logs = {f.id for f in report.facts if f.from_logs}
    assert logs  # the web checks' answers, and the actors' request counts
    for fact in hidden.facts:
        if fact.id in logs:
            assert fact.text == m.HIDDEN
            assert fact.numbers == ()
            assert fact.safe is None
        else:
            assert fact == next(f for f in report.facts if f.id == fact.id)
    for _, sentence in m.sentences_of(hidden):
        if set(sentence.cites) & logs:
            assert sentence.text == m.HIDDEN
    assert all(e.count is None for e in hidden.evidence if e.from_logs)
    assert all(a.requests is None for a in hidden.actors)
    assert [a.value for a in hidden.actors] == [a.value for a in report.actors]
    assert hidden.header == report.header
    assert hidden.queries == report.queries  # the queries stay: they hold what the alerts name


def test_hiding_twice_changes_nothing_and_a_report_without_logs_is_untouched() -> None:
    report = build(kit.git(), kit.ctx())
    once = hide_logs(report)
    assert hide_logs(once) == once
    plain = build(kit.amadey(), kit.ctx()).model_copy(update={"evidence": ()})
    facts = tuple(f for f in plain.facts if not f.from_logs)
    clean = plain.model_copy(update={"facts": facts})
    assert hide_logs(clean) is clean


def test_accounts_are_left_out_of_the_assets() -> None:
    report = build(kit.amadey(), kit.ctx())
    with_account = report.model_copy(
        update={
            "assets": (
                *report.assets,
                m.ReportAsset(kind="account", value="someone@example.edu", alerts=2),
            )
        }
    )
    assert {a.kind for a in hide_logs(with_account).assets} == {"device"}
    assert {a.kind for a in with_account.assets} == {"device", "account"}


def test_the_hidden_report_is_still_a_sound_report() -> None:
    hidden = hide_logs(build(kit.git(), kit.ctx()))
    assert m.IncidentReport.model_validate(hidden.model_dump(mode="json")) == hidden
