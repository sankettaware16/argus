"""The analyst brief (D-332): a large model words what is happening, why it is real, the impact
and the steps asked for, over the report's own facts; code decides what is kept. A fake model
answers: a line that cites nothing, an unknown fact, an invented number, an address no cited fact
holds, a token it was not given, markup or the opposite of the verdict is dropped; a required
part left empty, a malformed answer, a refusal and an absent model leave the report as code wrote
it, with the reason said. The model never sees a campus address or an account."""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pypdf import PdfReader

from argus.assets import parse_asset_map
from argus.incident import brief, files, plain, store
from argus.incident import model as m
from argus.incident.build import build
from argus.incident.view import hide_logs
from argus.llm.gateway import Call, Completion, NoCapacity, Refused
from argus.llm.privacy import Privacy, load_policy
from argus.llm.providers import Tier
from argus.signins import attribute as a
from argus.signins import model as sm
from argus.signins import view
from tests.unit.incident import kit
from tests.unit.signins import kit as sk

pytestmark = pytest.mark.unit

ASSETS = parse_asset_map(
    b"""
defaults: {site.organization: Example}
networks:
  - name: Glasshouse Annex
    range: 10.201.7.0/24
    fields: {site.type: lab, site.zone: north}
  - name: Hostel Nine
    range: 10.198.0.0/16
    fields: {site.type: hostel, site.zone: hostel}
"""
)
PRIVACY = Privacy.build(load_policy(), ASSETS, (ipaddress.ip_network("198.51.100.0/24"),))
RULES = sm.Rules()
USER, OTHER = "brief.alpha", "user-brief-beta"  # a dotted account name must be hidden too
CAMPUS_IP = re.compile(r"\b10\.(?:198|201)\.\d{1,3}\.\d{1,3}\b")
TOKEN = re.compile(r"I1\.[A-Z]+_\d+")


def users_of(by_host: dict[str, list[str]]) -> view.Users:
    """The sign-ins of each address over the days of the case's alerts."""
    first, last = kit.at(0, 1), kit.at(4, 20)
    start, end = a.window_of(first, last, RULES.pad)
    records: dict[str, dict[object, sm.DayRecord]] = {}
    for host, names in by_host.items():
        found: dict[object, sm.DayRecord] = {}
        for day in a.window_days(start, end):
            sightings = tuple(
                sk.sighting(n, address=host, day=day, hours=tuple(range(24)), events=48)
                for n in names
            )
            looked = sm.day_end(day) + timedelta(days=1)
            found[day] = sm.DayRecord(host, day, sm.Lookup(host, day, looked, True, len(names), 0),
                                      sightings)  # fmt: skip
        records[host] = found
    spans = dict.fromkeys(by_host, (first, last))
    return view.assemble(list(by_host), records, spans, RULES, kit.AS_AT, len(by_host))  # type: ignore[arg-type]


def hosts_of(devices: int) -> list[str]:
    return sorted(
        {e.value for e in kit.amadey(devices=devices).entities if CAMPUS_IP.match(e.value)}
    )


def report(devices: int = 4, same: int = 3, **more: Any) -> m.IncidentReport:
    """The Amadey case on ``devices`` addresses; ``USER`` signed in from the first ``same``."""
    hosts = hosts_of(devices)
    by_host = {h: [USER] if n < same else [OTHER] for n, h in enumerate(hosts)}
    return build(replace(kit.amadey(devices=devices, **more), users=users_of(by_host)), kit.ctx())


def view_of(rep: m.IncidentReport) -> brief.Shown:
    return brief.shown(brief.facts_of(rep), PRIVACY, rep)


def done(text: str) -> Completion:
    return Completion(text, "fake", "model-9", 10, 20, 0.0, 5, uuid.uuid4())


def answering(answer: str | dict[str, Any]) -> Any:
    seen: list[Call] = []

    async def complete(call: Call) -> Completion:
        seen.append(call)
        return done(answer if isinstance(answer, str) else json.dumps(answer))

    complete.calls = seen  # type: ignore[attr-defined]
    return complete


def raising(exc: Exception) -> Any:
    async def complete(call: Call) -> Completion:
        raise exc

    return complete


def fact_with(shown: brief.Shown, needle: str) -> str:
    return next(k for k, v in shown.sent.items() if needle in v)


def good(shown: brief.Shown) -> dict[str, Any]:
    """An answer every line of which passes: plain words over facts it cites, a token it was
    given, a number as its fact gives it."""
    alerts = fact_with(shown, "35 alerts")
    intel = fact_with(shown, "VirusTotal")
    who = fact_with(shown, "One account")
    token = TOKEN.search(shown.sent[who])
    assert token is not None
    line = lambda text, *cites: {"text": text, "cites": list(cites)}  # noqa: E731
    return {
        "statement": [
            line("A device keeps reporting to servers that outside detection flags.", intel)
        ],
        "points": [
            line("The rules raised 35 alerts.", alerts),
            line(f"{token.group(0)} is most likely behind most of the addresses.", who),
        ],
        "why": [line("Outside detection flags the servers it reaches.", intel)],
        "impact": [line("What was typed on the device may be exposed.", alerts)],
        "actions": [
            {**line("Take the device off the network.", alerts), "who": "owner", "when": "now"},
            {**line("Block the servers at the proxy.", intel), "who": "network", "when": "today"},
        ],
    }


async def improved(rep: m.IncidentReport, answer: Any, **more: Any) -> brief.Improved:
    complete = answer if callable(answer) else answering(answer)
    return await brief.improve(rep, PRIVACY, complete, **more)


# --------------------------------------------------------------------------- the facts


def test_the_facts_are_the_reports_own_and_hash_the_same_until_they_change() -> None:
    rep = report()
    facts = brief.facts_of(rep)
    texts = [f.text for f in facts]
    assert [f.id for f in facts] == [f"F{n}" for n in range(1, len(facts) + 1)]
    assert texts[0].startswith("ARGUS's title for the incident: ")
    assert all(f.text in texts for f in rep.facts)  # every fact of the report, once
    assert len(set(texts)) == len(texts) <= brief.MAX_FACTS
    assert any(t.startswith("Alerts by day: ") for t in texts)
    assert any(t.startswith(f"Account {USER}: ") for t in texts)
    assert brief.facts_sha(facts) == brief.facts_sha(brief.facts_of(report()))
    assert brief.facts_sha(facts) != brief.facts_sha(brief.facts_of(report(devices=5)))


def test_the_model_never_sees_a_campus_address_or_an_account() -> None:
    rep = report()
    shown = view_of(rep)
    sent = shown.request.text
    assert shown.request.validate().allowed
    assert not CAMPUS_IP.search(sent)
    assert USER not in sent
    assert OTHER not in sent
    assert "I1.USER_1" in sent
    assert "I1.IP_1" in sent
    assert kit.SERVERS[0] in sent  # an outside server is what the incident is about


# --------------------------------------------------------------------------- the checks


async def test_a_checked_answer_becomes_the_brief_with_the_real_names_put_back() -> None:
    rep = report()
    out = await improved(rep, good(view_of(rep)))
    assert out.why is None
    assert out.by == "fake/model-9"
    assert out.called
    got = out.report.brief
    assert got is not None
    assert out.report.brief_note is None
    assert got.dropped == 0
    assert got.by == "fake/model-9"
    assert got.at == rep.meta.as_at
    assert got.basis == brief.basis_of(rep)
    assert got.points[1].text == f"{USER} is most likely behind most of the addresses."
    assert [(x.who, x.when) for x in got.actions] == [("owner", "now"), ("network", "today")]
    cited = {c for part in (got.statement, got.points, got.why, got.impact, got.actions)
             for line in part for c in line.cites}  # fmt: skip
    assert set(got.facts) == cited
    # a model's words are not evidence: the report's hashes are what they were
    assert m.content_hash(out.report) == m.content_hash(rep)
    assert m.core_hash(out.report) == m.core_hash(rep)


async def test_the_call_asks_the_large_model_with_the_briefs_own_purpose() -> None:
    rep = report()
    complete = answering(good(view_of(rep)))
    await brief.improve(rep, PRIVACY, complete)
    (call,) = complete.calls
    assert (call.purpose, call.tier, call.json) == ("brief", Tier.LARGE, True)
    assert call.max_output == brief.MAX_OUTPUT[Tier.LARGE]
    assert not CAMPUS_IP.search(call.request.text)
    assert USER not in call.request.text


BAD_LINES = [
    {"text": "The rules raised 36 alerts.", "cites": ["ALERTS"]},  # a number no fact holds
    {"text": "The rules raised 35 alerts.", "cites": []},  # cites nothing
    {"text": "The rules raised 35 alerts.", "cites": ["F999"]},  # an unknown fact
    {"text": "The rules raised **35** alerts.", "cites": ["ALERTS"]},  # markup
    {"text": "See http://example.test for more.", "cites": ["ALERTS"]},  # a link
    {"text": "I1.IP_99 raised 35 alerts.", "cites": ["ALERTS"]},  # a token it was not given
    {"text": "10.9.9.9 raised 35 alerts.", "cites": ["ALERTS"]},  # an address no cited fact holds
    {"text": "This is harmless, a false positive.", "cites": ["ALERTS"]},  # against the verdict
    {"text": "x" * (m.BRIEF_TEXT + 1), "cites": ["ALERTS"]},  # too long
    {"text": "The rules raised 35 alerts.", "cites": ["ALERTS"], "extra": 1},  # not the shape
]


@pytest.mark.parametrize("bad", BAD_LINES)
async def test_a_line_that_fails_a_check_is_dropped_and_counted(bad: dict[str, Any]) -> None:
    rep = report()
    assert rep.verdict.outcome == "true_positive"
    shown = view_of(rep)
    alerts = fact_with(shown, "35 alerts")
    line = {**bad, "cites": [alerts if c == "ALERTS" else c for c in bad["cites"]]}
    answer = good(shown)
    answer["points"].append(line)
    got = (await improved(rep, answer)).report.brief
    assert got is not None
    assert got.dropped == 1
    assert len(got.points) == 2
    assert got.points == (await improved(rep, good(shown))).report.brief.points  # type: ignore[union-attr]


@pytest.mark.parametrize("change", [{"who": "everyone"}, {"when": "someday"}])
async def test_a_step_names_who_and_when_from_the_lists(change: dict[str, str]) -> None:
    rep = report()
    answer = good(view_of(rep))
    answer["actions"][0].update(change)
    got = (await improved(rep, answer)).report.brief
    assert got is not None
    assert got.dropped == 1
    assert [x.who for x in got.actions] == ["network"]


@given(n=st.integers(min_value=0, max_value=10**9))
def test_no_line_keeps_a_number_its_facts_do_not_hold(n: int) -> None:
    rep = _REPORT
    shown = _SHOWN
    alerts = fact_with(shown, "35 alerts")
    held = {int(d) for d in m.digits_of(shown.sent[alerts])}
    kept = brief._line({"text": f"The rules raised {n} alerts.", "cites": [alerts]}, shown,
                       rep.verdict.outcome, frozenset({"text", "cites"}))  # fmt: skip
    assert kept is None or n in held
    if n == 35:
        assert kept is not None


_REPORT = report()
_SHOWN = view_of(_REPORT)


def _empty(key: str) -> Any:
    def mutate(answer: dict[str, Any]) -> Any:
        return {**answer, key: []}

    return mutate


@pytest.mark.parametrize(
    "mutate",
    [
        _empty("statement"),
        lambda ans: {**ans, "points": ans["points"][:1]},  # too thin a summary
        lambda ans: {k: v for k, v in ans.items() if k != "impact"},
        lambda ans: {**ans, "verdict": "benign"},
        lambda ans: {**ans, "why": "none"},
        lambda ans: "not json",
        lambda ans: [ans],
    ],
)
async def test_an_answer_too_thin_or_not_the_shape_asked_for_is_refused(mutate: Any) -> None:
    rep = report()
    out = await improved(rep, mutate(good(view_of(rep))))
    assert out.report.brief is None
    assert out.by is None
    assert out.report.brief_note
    assert out.report.brief_note.startswith("the model's brief was not")
    assert out.report.model_copy(update={"brief_note": None}) == rep


async def test_a_brief_resting_on_fewer_than_three_facts_is_refused() -> None:
    rep = report()
    shown = view_of(rep)
    alerts = fact_with(shown, "35 alerts")
    answer = good(shown)
    for part in answer.values():
        for line in part:
            line["cites"] = [alerts]
    answer["points"][1]["text"] = "The rules raised 35 alerts in all."
    out = await improved(rep, answer)
    assert out.report.brief is None
    assert out.why == "the model's brief was not used: the brief rests on fewer than three facts"


@pytest.mark.parametrize(
    ("failure", "says"),
    [
        (NoCapacity(kit.AS_AT, "every provider is at its cap"), "no model can take it now"),
        (Refused("the provider said no"), "no model answered (Refused)"),
        (RuntimeError("boom"), "the model call failed (RuntimeError)"),
    ],
)
async def test_a_model_that_fails_leaves_the_report_as_code_wrote_it(
    failure: Exception, says: str
) -> None:
    rep = report()
    out = await improved(rep, raising(failure))
    assert out.report.brief is None
    assert out.called
    assert out.report.brief_note is not None
    assert out.report.brief_note.startswith(says)


async def test_no_model_or_no_privacy_layer_changes_nothing() -> None:
    rep = report()
    assert (await brief.improve(rep, PRIVACY, None)).report is rep
    assert (await brief.improve(rep, None, answering({}))).report is rep


async def test_facts_the_privacy_check_refuses_are_never_sent() -> None:
    class Leaky(Privacy):
        """A privacy layer whose scrubber lets everything through."""

        class scrub(PRIVACY.scrub):  # type: ignore[name-defined,misc]  # noqa: N801
            def text(self, value: str, limit: int | None = None, *, quoted: bool = True) -> str:
                return value

    leaky = Leaky(PRIVACY.policy, PRIVACY.classifier, PRIVACY.campus)
    rep = report()
    complete = answering(good(view_of(rep)))
    out = await brief.improve(rep, leaky, complete)
    assert complete.calls == []
    assert out.report.brief is None
    assert out.why in ("the privacy check refused the facts",
                       "the facts could not be made safe (ValueError)")  # fmt: skip


async def test_an_account_name_the_scrubber_cannot_find_stops_the_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The last check before the call: an account written in a form the name matcher does not
    read (here ``DOMAIN\\name``) is never sent; the report keeps code's text."""
    odd = "CORP\\brief-gamma"
    rep = report()
    users = rep.users.model_copy(update={"devices": tuple(
        d.model_copy(update={"accounts": tuple(
            a.model_copy(update={"name": odd}) for a in d.accounts)})
        for d in rep.users.devices)})  # fmt: skip
    facts = tuple(f.model_copy(update={"text": f.text.replace(USER, odd)}) for f in rep.facts)
    same = rep.users.same
    assert same is not None
    users = users.model_copy(update={"same": same.model_copy(
        update={"text": same.text.replace(USER, odd)})})  # fmt: skip
    hyps = tuple(h.model_copy(update={"why": tuple(
        w.model_copy(update={"text": w.text.replace(USER, odd)}) for w in h.why)})
        for h in rep.hypotheses)  # fmt: skip
    changed = rep.model_copy(update={"users": users, "facts": facts, "hypotheses": hyps})
    complete = answering(good(view_of(rep)))
    out = await brief.improve(changed, PRIVACY, complete)
    if complete.calls:  # the matcher found it: then nothing of it was sent
        assert "gamma" not in complete.calls[0].request.text
    else:
        assert out.report.brief is None
        assert out.why == "the facts could not be made safe (ValueError)"
    # and a form no matcher reads (the words run together) is stopped by the last check
    glued = changed.model_copy(update={"facts": tuple(
        f.model_copy(update={"text": f.text.replace(odd, "CORP::brief//gamma")})
        for f in changed.facts)})  # fmt: skip
    asked = answering(good(view_of(rep)))
    stopped = await brief.improve(glued, PRIVACY, asked)
    assert asked.calls == []
    assert stopped.why == "the facts could not be made safe (ValueError)"


# --------------------------------------------------------------------------- keeping a brief


async def test_the_same_facts_keep_the_brief_without_a_second_call() -> None:
    rep = report()
    first = (await improved(rep, good(view_of(rep)))).report.brief
    assert first is not None
    complete = answering("never asked")
    again = await brief.improve(report(), PRIVACY, complete, previous=first)
    assert complete.calls == []
    assert not again.called
    assert again.report.brief == first


async def test_a_young_brief_is_kept_while_the_verdict_and_the_standing_stand() -> None:
    rep = report()
    first = (await improved(rep, good(view_of(rep)))).report.brief
    assert first is not None
    later = report(devices=5, same=4)  # more evidence: other facts, the same verdict and standing
    assert brief.facts_sha(brief.facts_of(later)) != first.facts_sha
    assert brief.basis_of(later) == first.basis
    complete = answering("never asked")
    kept = await brief.improve(later, PRIVACY, complete, previous=first, keep=timedelta(hours=6))
    assert complete.calls == []
    assert kept.report.brief == first
    # past its time, or with no time to keep it, the model is asked again
    asked = answering(good(view_of(later)))
    fresh = await brief.improve(later, PRIVACY, asked, previous=first)
    assert len(asked.calls) == 1
    assert fresh.report.brief is not None
    assert fresh.report.brief.facts_sha != first.facts_sha


async def test_a_brief_never_outlives_a_change_of_the_cases_state() -> None:
    rep = report()
    first = (await improved(rep, good(view_of(rep)))).report.brief
    assert first is not None
    closed = report(devices=5, same=4, state="closed")  # other facts, and the case is closed
    assert brief.basis_of(closed) != first.basis
    out = await brief.improve(closed, PRIVACY, raising(Refused("no")), previous=first,
                              keep=timedelta(days=1))  # fmt: skip
    assert out.report.brief is None
    assert out.called


async def test_a_failed_call_keeps_the_brief_before_while_its_basis_stands() -> None:
    rep = report()
    first = (await improved(rep, good(view_of(rep)))).report.brief
    assert first is not None
    later = report(devices=5, same=4)
    out = await brief.improve(
        later, PRIVACY, raising(NoCapacity(kit.AS_AT, "later")), previous=first
    )
    assert out.called
    assert out.report.brief == first
    assert out.report.brief_note is None


def test_a_new_brief_is_a_version_of_its_own_and_a_lost_one_is_not() -> None:
    plain = report()
    line = m.ReportBriefLine(text="A device reports to flagged servers.", cites=("F1",))
    made = m.ReportBrief(statement=(line,), points=(line, line), facts={"F1": "A fact."},
                         facts_sha="a" * 64, by="fake/model-9", at=plain.meta.as_at,
                         basis=brief.basis_of(plain))  # fmt: skip
    with_brief = plain.model_copy(update={"brief": made})
    other = plain.model_copy(update={"brief": made.model_copy(update={"facts_sha": "b" * 64})})
    assert store._new_brief(plain, with_brief)
    assert store._new_brief(with_brief, other)
    assert not store._new_brief(with_brief, with_brief)
    assert not store._new_brief(with_brief, plain)  # the newest keeps its brief
    assert not store._new_brief(plain, plain)


def test_a_brief_must_hold_the_facts_it_cites() -> None:
    line = m.ReportBriefLine(text="A device reports to flagged servers.", cites=("F2",))
    with pytest.raises(ValueError, match="cites F2"):
        m.ReportBrief(statement=(line,), points=(line,), facts={"F1": "A fact."},
                      facts_sha="a" * 64, by="x", at=kit.AS_AT, basis="b")  # fmt: skip


# --------------------------------------------------------------------------- where it shows


def pdf_text(data: bytes) -> str:
    return "\n".join(p.extract_text() for p in PdfReader(__import__("io").BytesIO(data)).pages)


async def test_the_pdf_opens_with_the_brief_and_keeps_the_evidence() -> None:
    rep = report()
    briefed = (await improved(rep, good(view_of(rep)))).report
    text = " ".join(pdf_text(files.pdf(briefed)).split())
    order = ["A device keeps reporting to servers", "1. Summary", "2. Why it is judged real",
             "3. Impact", "4. Actions asked for", "Incident at a glance", "5. Timeline",
             "6. Affected assets", "9. Evidence", "12. Scope and limits"]  # fmt: skip
    at = [text.index(part) for part in order]
    assert at == sorted(at)
    assert "Take the device off the network." in text
    assert "Device owner" in text
    assert "written by ARGUS AI (fake/model-9)" in text
    assert "One account," in text  # the one-device line, with the accounts
    # without a brief the PDF is the one it was
    plain = " ".join(pdf_text(files.pdf(rep)).split())
    assert "1. Summary" in plain
    assert "8. Recommended actions" in plain
    assert "Actions asked for" not in plain
    assert "ARGUS AI" not in plain


async def test_the_terminal_report_opens_with_the_brief_or_says_why_there_is_none() -> None:
    rep = report()
    briefed = (await improved(rep, good(view_of(rep)))).report
    text = plain.lines(briefed)
    assert text.index("SUMMARY") > next(n for n, x in enumerate(text) if x.startswith("ANALYST"))
    assert "    1. Take the device off the network. (Device owner, immediately)" in text
    assert any(x.strip().startswith("One account,") for x in text)
    refused = (await improved(rep, raising(Refused("no")))).report
    assert "no analyst brief: no model answered (Refused)" in plain.lines(refused)
    assert not any("ANALYST" in x or "analyst" in x for x in plain.lines(rep))


async def test_a_person_without_log_access_does_not_see_the_brief() -> None:
    rep = report()
    briefed = (await improved(rep, good(view_of(rep)))).report
    hidden = hide_logs(briefed)
    assert hidden.brief is None
    assert hidden.brief_note == m.HIDDEN
    assert hidden.users.same is not None
    assert hidden.users.same.text == m.HIDDEN
    assert USER not in hidden.model_dump_json()


# --------------------------------------------------------------------------- one device or many


def test_one_account_behind_most_addresses_reads_as_one_device() -> None:
    rep = report(devices=4, same=3)
    same = rep.users.same
    assert same is not None
    assert same.text.startswith(f"One account, {USER}, is the probable user on 3 of the 4")
    fact = next(f for f in rep.facts if f.id == same.cites[0])
    assert fact.from_logs
    assert fact.safe is not None
    assert USER not in fact.safe
    one = next(h for h in rep.hypotheses if h.name.startswith("One device"))
    assert one.status == "kept"
    assert any("one account behind most of the addresses" in s.text for s in one.why)


@pytest.mark.parametrize(("devices", "same"), [(4, 2), (2, 2), (6, 3)])
def test_too_few_addresses_or_too_small_a_share_is_not_one_device(devices: int, same: int) -> None:
    rep = report(devices=devices, same=same)
    assert rep.users.same is None
    one = next(h for h in rep.hypotheses if h.name.startswith("One device"))
    assert one.status == ("ruled_out" if devices >= 3 else "open")
