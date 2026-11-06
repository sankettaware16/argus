"""The accounts in the incident report (AR6, D-216): the probable users of the case's devices are in
the report as facts read from the logs (no model is ever shown one), in the PDF and the accounts
CSV, hidden from an account without log access, and a report without accounts is byte for byte what
it was before."""

from __future__ import annotations

import csv
import io
from dataclasses import replace
from datetime import timedelta

import pytest
from pypdf import PdfReader

from argus.incident import files, plain, prose
from argus.incident import model as m
from argus.incident.build import build
from argus.incident.gather import CaseFacts
from argus.incident.view import hide_logs
from argus.signins import attribute as a
from argus.signins import model as sm
from argus.signins import view
from tests.unit.incident import kit
from tests.unit.signins import kit as sk

pytestmark = pytest.mark.unit
NAME, OTHER = "user-ar6-alpha", "user-ar6-beta"
RULES = sm.Rules()


def users_for(*names: str, crowd: bool = False, gap: bool = False) -> view.Users:
    """The sign-ins of the Amadey host over the days of its alerts, by ``names``."""
    first, last = kit.at(0, 1), kit.at(4, 20)
    start, end = a.window_of(first, last, RULES.pad)
    found: dict[object, sm.DayRecord] = {}
    for day in a.window_days(start, end):
        sightings = tuple(
            sk.sighting(n, address=kit.HOST, day=day, hours=tuple(range(24)), events=48)
            for n in names
        )
        accounts = 9 if crowd else len(names)
        looked = sm.day_end(day) + timedelta(days=1)
        lookup = sm.Lookup(kit.HOST, day, looked, True, accounts, 0)
        found[day] = sm.DayRecord(kit.HOST, day, lookup, sightings)
    if gap:
        found.pop(next(iter(found)))
    spans = {kit.HOST: (first, last)}
    return view.assemble([kit.HOST], {kit.HOST: found}, spans, RULES, kit.AS_AT, 1)  # type: ignore[arg-type]


def facts_with(users: view.Users | None) -> CaseFacts:
    return replace(kit.amadey(), users=users)


def report(*names: str, **more: bool) -> m.IncidentReport:
    return build(facts_with(users_for(*names, **more)), kit.ctx())


def pdf_text(data: bytes) -> str:
    return "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(data)).pages)


# ---------------------------------------------------------------- the report


def test_a_report_without_accounts_is_what_it_was_before() -> None:
    plain_report = build(kit.amadey(), kit.ctx())
    assert plain_report.users == m.ReportUsers()
    assert build(facts_with(None), kit.ctx()) == plain_report
    assert build(facts_with(view.EMPTY), kit.ctx()) == plain_report
    without = plain_report.model_dump(mode="json")
    assert m.content_hash(plain_report) == m.content_hash(
        plain_report.model_copy(update={"users": m.ReportUsers(lead="")})
    )
    assert "users" in without  # the field is there for the client, not in the hash


def test_the_accounts_are_a_fact_read_from_the_logs_with_no_safe_form() -> None:
    rep = report(NAME)
    (device,) = rep.users.devices
    assert (device.device, device.state) == (kit.HOST, "likely")
    (account,) = device.accounts
    assert account.name == NAME
    assert account.browsers == ("Chrome on Windows",)
    assert account.days >= 5
    assert account.signins > 0
    fact = next(f for f in rep.facts if f.id == device.sentence.cites[0])
    assert fact.from_logs is True
    assert fact.safe is None
    assert NAME in fact.text
    assert device.sentence.text == fact.text
    assert rep.users.lead == a.LEAD
    assert rep.users.signins
    assert all(s.device == kit.HOST for s in rep.users.signins)
    assert all(NAME in s.text for s in rep.users.signins)
    assert m.check(rep) == []  # every sentence still cites a fact that says its numbers


def test_the_other_facts_keep_their_numbers_when_accounts_are_added() -> None:
    before = build(kit.amadey(), kit.ctx())
    after = report(NAME)
    assert after.facts[: len(before.facts)] == before.facts


def test_a_shared_device_names_no_one_and_an_unknown_one_says_what_is_missing() -> None:
    shared = report(NAME, OTHER, "user-c", "user-d", "user-e", crowd=True)
    (device,) = shared.users.devices
    assert device.state == "shared"
    assert device.accounts == ()
    for who in (NAME, OTHER):
        assert who not in str(shared.model_dump(mode="json")["users"])
    unknown = report(NAME, gap=True)
    assert unknown.users.devices[0].state == "unknown"
    assert [x.name for x in unknown.users.devices[0].accounts] == [NAME]  # so far


# ---------------------------------------------------------------- privacy


def test_an_account_without_log_access_sees_the_state_and_the_count_and_no_name() -> None:
    rep = report(NAME, OTHER)
    hidden = hide_logs(rep)
    (device,) = hidden.users.devices
    assert device.state == "possible"
    assert device.account_count == 2
    assert device.accounts == ()
    assert hidden.users.signins == ()
    assert device.sentence.text == m.HIDDEN
    everything = hidden.model_dump_json()
    assert NAME not in everything
    assert OTHER not in everything
    assert hide_logs(hidden) == hidden
    assert NAME in rep.model_dump_json()  # and the full report still has it


def test_no_model_is_ever_shown_an_account() -> None:
    rep = report(NAME, OTHER)
    seen = prose.shown(rep)
    text = prose.request_text(seen)
    for who in (NAME, OTHER):
        assert who not in text
    assert all(not f.from_logs for f in seen.facts.values())
    assert kit.HOST not in text  # nor the device: only facts with a safe form are shown
    for fact in rep.facts:
        if NAME in fact.text:
            assert fact.id not in seen.ids
            assert fact.safe is None


# ---------------------------------------------------------------- files


def rows(data: str) -> list[list[str]]:
    assert data.startswith("﻿")
    return list(csv.reader(io.StringIO(data[1:])))


def test_the_accounts_csv_has_a_row_for_each_account_and_the_files_follow_the_report() -> None:
    rep = report(NAME, OTHER)
    got = rows(files.accounts_csv(rep))
    assert got[0] == list(files.ACCOUNT_COLUMNS)
    assert sorted(r[0] for r in got[1:]) == [NAME, OTHER]
    assert {r[1] for r in got[1:]} == {kit.HOST}
    assert {r[2] for r in got[1:]} == {"possible"}
    assert all(r[8] == "Chrome on Windows" and "IST" in r[5] and "IST" in r[6] for r in got[1:])
    assert files.accounts_name(rep).endswith("_affected_accounts.csv")
    assert files.accounts_name(rep) in files.bundle(rep)
    bare = build(kit.amadey(), kit.ctx())
    assert files.has_accounts(rep)
    assert not files.has_accounts(bare)
    assert files.accounts_name(bare) not in files.bundle(
        bare
    )  # a report without accounts: as before
    assert len(files.bundle(bare)) == 4  # the PDF, the dashboard (AR10) and two CSVs
    assert len(files.bundle(rep)) == 5


def test_an_account_name_a_spreadsheet_could_run_is_neutralised() -> None:
    rep = report("=cmd|' /C calc'!A0")
    cells = rows(files.accounts_csv(rep))[1]
    assert not cells[0].startswith("=")
    assert cells[0].startswith("'")


def test_the_pdf_names_the_accounts_under_the_affected_assets_and_says_it_is_a_lead() -> None:
    rep = report(NAME, OTHER)
    text = pdf_text(files.pdf(rep))
    assert "Accounts that signed in from the affected devices" in text
    assert NAME in text
    assert OTHER in text
    assert "a lead, not proof" in text.replace("\n", " ")
    assert "Sign-ins from the affected devices, as context" in text
    assert files.pdf(rep) == files.pdf(rep)  # the same report is the same bytes
    assert NAME not in pdf_text(files.pdf(build(kit.amadey(), kit.ctx())))


def test_the_terminal_text_lists_the_accounts_of_a_report_that_has_them() -> None:
    text = "\n".join(plain.lines(report(NAME)))
    assert "ACCOUNTS THAT SIGNED IN FROM THE DEVICES (personal data)" in text
    assert NAME in text
    assert "ACCOUNTS" not in "\n".join(plain.lines(build(kit.amadey(), kit.ctx())))


# ---------------------------------------------------------------- the hash without the accounts


def test_the_core_hash_ignores_the_accounts_and_nothing_else() -> None:
    """D-225: a person's confirm holds for versions that differ only in who signed in."""
    plain = build(kit.amadey(), kit.ctx())
    with_users = plain.model_copy(
        update={"users": m.ReportUsers(lead="A lead.", devices=(_device("user-ar6-alpha"),))}
    )
    more_users = plain.model_copy(
        update={
            "users": m.ReportUsers(
                lead="A lead.", devices=(_device("user-ar6-alpha"), _device("user-ar6-beta"))
            )
        }
    )
    assert m.content_hash(plain) != m.content_hash(with_users) != m.content_hash(more_users)
    assert m.core_hash(plain) == m.core_hash(with_users) == m.core_hash(more_users)
    evidence = plain.evidence[-1].model_copy(update={"id": "E99", "title": "A newer check"})
    changed = plain.model_copy(update={"evidence": (*plain.evidence, evidence)})
    assert m.core_hash(changed) != m.core_hash(plain)
    verdict = plain.verdict.model_copy(update={"outcome": "benign_expected"})
    assert m.core_hash(plain.model_copy(update={"verdict": verdict})) != m.core_hash(plain)
    # naming v2: a retitle renames what a person confirmed, it does not change it
    header = plain.header.model_copy(
        update={"title": f"{plain.header.incident_id} · Likely a new name", "certainty": "Likely"}
    )
    summary = plain.summary.model_copy(update={"headline": "A new headline: Likely a new name"})
    renamed = plain.model_copy(update={"header": header, "summary": summary})
    assert m.content_hash(renamed) != m.content_hash(plain)
    assert m.core_hash(renamed) == m.core_hash(plain)


def _device(name: str) -> m.ReportDeviceUsers:
    account = m.ReportAccount(
        name=name, device=kit.HOST, first_seen=kit.AS_AT, last_seen=kit.AS_AT, signins=3,
        failed=0, days=1, browsers=("Chrome on Windows",),
    )  # fmt: skip
    sentence = m.ReportSentence(text=f"{kit.HOST}: Probable user.", cites=("F1",))
    return m.ReportDeviceUsers(
        device=kit.HOST, state="likely", sentence=sentence, accounts=(account,), account_count=1,
        at_least=False,
    )  # fmt: skip
