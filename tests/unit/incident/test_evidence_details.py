"""An evidence line carries the deciding values its stored answer holds (D-325): the URLs a
destination was asked for (without query strings), the kinds of event among the stored rows and
a pair's rhythm. Read from the stored answer only, bounded, hidden from an account without log
access, and rendered in Kibana's Markdown, the PDF and the terminal without anything acting."""

from __future__ import annotations

import io
import re
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from pypdf import PdfReader

from argus.caseteam import guard
from argus.caseteam.render import evidence_part
from argus.incident import evidence, files, plain
from argus.incident import gather as g
from argus.incident import model as m
from argus.incident.build import build
from argus.incident.view import hide_logs
from tests.unit.caseteam import kit as team
from tests.unit.incident import kit

pytestmark = pytest.mark.unit

DEST = "198.51.100.9"
SEP = ":"  # user and secret, kept apart so no scanner reads a credential here
WINDOW = {"start": kit.at(2, 1).isoformat(), "end": kit.at(2, 7).isoformat()}
URLS = [
    (f"http://{DEST}:8080/api/v1/ext/remote?id=alice@example.org&token=s3cret", 9000),
    (f"http://{DEST}:8080/api/v1/ext/remote?id=bob", 1200),
    (f"http://visitor{SEP}pw@{DEST}:8080/api/v1/ext/cookies#frag", 640),  # user information
    (f"http://{DEST}:8080/api/v1/ext/history;jsessionid=ABC123", 320),
    (f"http://{DEST}:8080/api/v1/ext/bookmarks", 160),
    (f"http://{DEST}:8080/api/v1/ext/extensions", 80),
    (f"http://{DEST}:8080/api/v1/ext/ping", 40),
    (f"http://{DEST}:8080/api/v1/ext/eighth", 20),
]


def destination_snapshot(urls: list[tuple[str, int]] = URLS) -> dict[str, Any]:
    return {
        "aggregations": {
            "host_count": {"value": 1},
            "hosts": {"buckets": [{"key": kit.HOST, "doc_count": sum(n for _, n in urls)}]},
            "urls": {"buckets": [{"key": u, "doc_count": n} for u, n in urls]},
        }
    }


def event(method: str, url: str, status: int, action: str, port: int) -> dict[str, Any]:
    return {
        "_source": {
            "@timestamp": kit.at(2, 2).isoformat(),
            "http": {"request": {"method": method}, "response": {"status_code": status}},
            "url": {"original": url},
            "event": {"action": action},
            "destination": {"port": port},
        }
    }


def events_snapshot() -> dict[str, Any]:
    base = f"http://{DEST}:8080/api/v1/ext"
    rows = [event("POST", f"{base}/cookies?u=alice", 200, "TCP_MISS", 8080)] * 5
    rows += [event("GET", f"{base}/ping", 200, "TCP_MISS", 8080)] * 3
    rows += [event("POST", f"{base}/history", 503, "TCP_DENIED", 8080)]
    return {"rows": rows, "total": len(rows), "rows_complete": True}


def pair_snapshot(gap_minutes: int, beats: int) -> dict[str, Any]:
    start = kit.at(2, 1)
    ms = int(start.timestamp() * 1000)
    buckets = [{"key": ms + i * gap_minutes * 60_000, "doc_count": 4} for i in range(beats)]
    return {
        "aggregations": {
            "requests": {"value": 4 * beats},
            "bytes": {"value": 52_000},
            "first": {"value": ms},
            "last": {"value": buckets[-1]["key"]},
            "beats": {"buckets": buckets},
        }
    }


# --------------------------------------------------------------------------- the values


def test_a_destinations_urls_lose_their_query_strings_and_user_information() -> None:
    found = evidence.shown("proxy.destination", {"ip": DEST, **WINDOW}, destination_snapshot())
    assert found is not None
    assert found.label == evidence.SHOWS["proxy.destination"]
    texts = [d.text for d in found.details]
    assert texts == [
        f"http://{DEST}:8080/api/v1/ext/remote",  # two that differ only in the query are one
        f"http://{DEST}:8080/api/v1/ext/cookies",
        f"http://{DEST}:8080/api/v1/ext/history",
        f"http://{DEST}:8080/api/v1/ext/bookmarks",
        f"http://{DEST}:8080/api/v1/ext/extensions",
        f"http://{DEST}:8080/api/v1/ext/ping",
    ]
    assert [d.count for d in found.details] == [10200, 640, 320, 160, 80, 40]
    joined = " ".join(texts)
    for secret in ("alice", "token", "s3cret", "visitor", "@", "frag", "jsessionid", "ABC"):
        assert secret not in joined


def test_a_value_from_the_logs_is_one_printable_line_and_capped() -> None:
    hostile = [
        ("http://x.example/‮evil​\x00path\nnext", 5),
        ("http://x.example/" + "a" * 5000, 4),
        ("", 3),
        (7, 2),  # not text: left out
    ]
    found = evidence.shown(
        "proxy.destination",
        {"ip": DEST},
        destination_snapshot(hostile),  # type: ignore[arg-type]
    )
    assert found is not None
    assert len(found.details) == 2
    for d in found.details:
        assert all(c.isprintable() for c in d.text)
        assert len(d.text) <= evidence.DETAIL_CHARS
    assert found.details[0].text == "http://x.example/ evil path next"


@pytest.mark.parametrize(
    "snapshot",
    [
        None,
        "text",
        {"aggregations": None},
        {"aggregations": {"urls": {"buckets": "x"}}},
        {"aggregations": {"urls": {"buckets": [{"key": "http://x/", "doc_count": "many"}]}}},
        {"aggregations": {"urls": {"buckets": [{"key": "http://x/", "doc_count": 0}]}}},
    ],
)
def test_a_damaged_or_empty_answer_shows_no_values(snapshot: Any) -> None:
    assert evidence.shown("proxy.destination", {"ip": DEST}, snapshot) is None


def test_a_template_without_deciding_values_shows_none() -> None:
    assert evidence.shown("proxy.host", {"ip": kit.HOST}, destination_snapshot()) is None


def test_the_log_events_are_counted_by_their_kind() -> None:
    params = {"source": "proxy", "ip": kit.HOST, "narrow": [], **WINDOW}
    found = evidence.shown("logs.source_events", params, events_snapshot())
    assert found is not None
    assert found.label == evidence.SHOWS["logs.source_events"]
    assert [(d.text, d.count) for d in found.details] == [
        ("POST /api/v1/ext/cookies · 200 · TCP_MISS · port 8080", 5),
        ("GET /api/v1/ext/ping · 200 · TCP_MISS · port 8080", 3),
        ("POST /api/v1/ext/history · 503 · TCP_DENIED · port 8080", 1),
    ]
    assert "alice" not in str(found)


def test_a_web_events_path_and_agent_make_its_kind_and_the_kinds_are_capped() -> None:
    rows = [
        {"_source": {"http.request.method": "GET", "url.path": f"/p{i}?q=me",
                     "http.response.status_code": 404, "user_agent.original": "x" * 400}}
        for i in range(10)
    ]  # fmt: skip
    found = evidence.shown("logs.source_events", {"source": "unknown"}, {"rows": rows})
    assert found is not None
    assert len(found.details) == evidence.DETAILS
    first = found.details[0].text
    assert first.startswith("GET /p0 · 404 · agent x")
    assert len(first) < 200
    assert "q=me" not in first


def test_a_pairs_rhythm_is_read_from_its_busy_periods() -> None:
    params = {"host": kit.HOST, "destination": DEST, **WINDOW}
    found = evidence.shown("proxy.pair", params, pair_snapshot(gap_minutes=5, beats=40))
    assert found is not None
    assert found.label == evidence.SHOWS["proxy.pair"]
    texts = [d.text for d in found.details]
    assert texts[0] == "busy in 40 periods of 1 minute"
    assert texts[1] == "typical gap between busy periods: 5 minutes"
    assert texts[2].startswith("regular: about every 5 minutes")
    assert all(d.count is None for d in found.details)


def test_a_pair_with_one_busy_period_has_no_gap_and_one_without_times_none() -> None:
    params = {"host": kit.HOST, "destination": DEST, **WINDOW}
    one = evidence.shown("proxy.pair", params, pair_snapshot(gap_minutes=5, beats=1))
    assert one is not None
    assert [d.text for d in one.details] == ["busy in 1 period of 1 minute"]
    assert evidence.shown("proxy.pair", {"host": kit.HOST}, pair_snapshot(5, 3)) is None


# --------------------------------------------------------------------------- the report


def infostealer() -> g.CaseFacts:
    facts = kit.amadey()
    inv = kit.inv_id(0)
    more = (
        g.EvidenceRow(inv, "proxy.destination", 1, {"ip": DEST, **WINDOW}, "ok", None,
                      destination_snapshot(), kit.at(2, 8)),
        g.EvidenceRow(inv, "logs.source_events", 1,
                      {"source": "proxy", "ip": kit.HOST, "narrow": [], **WINDOW}, "ok", 9,
                      events_snapshot(), kit.at(2, 8)),
        g.EvidenceRow(inv, "proxy.pair", 1, {"host": kit.HOST, "destination": DEST, **WINDOW},
                      "ok", 160, pair_snapshot(5, 40), kit.at(2, 8)),
    )  # fmt: skip
    return replace(facts, evidence=(*facts.evidence, *more))


@pytest.fixture(scope="module")
def report() -> m.IncidentReport:
    return build(infostealer(), kit.ctx())


def line_of(report: m.IncidentReport, template: str) -> m.ReportEvidenceLine:
    return next(e for e in report.evidence if e.query.template == f"{template}@1" and e.details)


def test_the_report_carries_each_lines_deciding_values(report: m.IncidentReport) -> None:
    assert m.check(report) == []
    urls = line_of(report, "proxy.destination")
    assert urls.shows == evidence.SHOWS["proxy.destination"]
    assert urls.details[0] == m.ReportDetail(
        text=f"http://{DEST}:8080/api/v1/ext/remote", count=10200
    )
    events = line_of(report, "logs.source_events")
    assert events.details[0].count == 5
    rhythm = line_of(report, "proxy.pair")
    assert rhythm.details[1].text == "typical gap between busy periods: 5 minutes"
    # the kit's pair checks hold no busy periods: their lines show their sentence alone
    bare = [e for e in report.evidence if e.query.template == "proxy.pair@1" and not e.details]
    assert bare
    assert all(e.shows is None for e in bare)


def test_an_account_without_log_access_sees_no_value(report: m.IncidentReport) -> None:
    hidden = hide_logs(report)
    for line in hidden.evidence:
        if line.from_logs:
            assert line.details == ()
            assert line.shows is None
    assert "ext/remote" not in hidden.model_dump_json()
    assert hide_logs(hidden) == hidden


def test_a_line_without_values_hashes_as_one_made_before_they_existed() -> None:
    report = build(kit.amadey(), kit.ctx())
    assert all(not e.details for e in report.evidence)
    body = report.model_dump(mode="json")
    for line in body["evidence"]:
        line.pop("details")
        line.pop("shows")
    old = m.IncidentReport.model_validate(body)
    assert m.content_hash(old) == m.content_hash(report)
    with_values = build(infostealer(), kit.ctx())
    without = with_values.model_copy(
        update={"evidence": tuple(
            e.model_copy(update={"details": (), "shows": None}) for e in with_values.evidence
        )}
    )  # fmt: skip
    assert m.content_hash(without) != m.content_hash(with_values)


def test_the_kibana_evidence_comment_lists_the_values_in_code_spans(
    report: m.IncidentReport,
) -> None:
    part = evidence_part(report)
    unit = next(u for u in part.units if "ext/remote" in u)
    lines = unit.split("\n")
    at = lines.index(f"{evidence.SHOWS['proxy.destination']}:")
    assert lines[at + 1] == f"- ` http://{DEST}:8080/api/v1/ext/remote ` · 10,200 times"
    assert len([ln for ln in lines[at + 1 :] if ln.startswith("- ")]) == 6
    events = next(u for u in part.units if "TCP_DENIED" in u)
    assert "- ` POST /api/v1/ext/cookies · 200 · TCP_MISS · port 8080 ` · 5 times" in events
    rhythm = next(u for u in part.units if "typical gap" in u)
    assert "- ` typical gap between busy periods: 5 minutes `" in rhythm
    assert "alice" not in "\n".join(part.units)
    for text in team.texts(report).values():
        guard.check(text, team.CTX.allowed)


def test_a_hostile_value_stays_inside_its_code_span(report: m.IncidentReport) -> None:
    evil = "http://x/a`` **b** [c](http://evil.example/p) ![i](http://evil.example/i.png) | <b>"
    urls = line_of(report, "proxy.destination")
    line = urls.model_copy(update={"details": (m.ReportDetail(text=evil, count=1),)})
    swapped = report.model_copy(
        update={"evidence": tuple(line if e.id == urls.id else e for e in report.evidence)}
    )
    for text in team.texts(swapped).values():
        guard.check(text, team.CTX.allowed)
    unit = next(u for u in evidence_part(swapped).units if "evil.example" in u)
    item = next(ln for ln in unit.split("\n") if "evil.example" in ln)
    assert re.fullmatch(r"- (`{3,}) .* \1 · 1 time", item), item


def test_the_pdf_and_the_terminal_show_the_values(report: m.IncidentReport) -> None:
    reader = PdfReader(io.BytesIO(files.pdf(report)))
    text = "\n".join(p.extract_text() for p in reader.pages)
    flat = " ".join(text.split())
    assert evidence.SHOWS["proxy.destination"] in flat
    assert "api/v1/ext/remote (10,200 times)" in flat
    assert "TCP_DENIED" in flat
    assert "alice" not in flat
    hidden = PdfReader(io.BytesIO(files.pdf(hide_logs(report))))
    assert "ext/remote" not in " ".join(p.extract_text() for p in hidden.pages)
    shown = "\n".join(plain.lines(report))
    assert f"http://{DEST}:8080/api/v1/ext/cookies (640 times)" in shown


def test_the_pdf_escapes_a_hostile_value(report: m.IncidentReport) -> None:
    urls = line_of(report, "proxy.destination")
    evil = '<font color="red">x</font> & <a href="http://evil.example">y</a>'
    line = urls.model_copy(update={"details": (m.ReportDetail(text=evil, count=2),)})
    swapped = report.model_copy(
        update={"evidence": tuple(line if e.id == urls.id else e for e in report.evidence)}
    )
    reader = PdfReader(io.BytesIO(files.pdf(swapped)))
    text = " ".join(" ".join(p.extract_text() for p in reader.pages).split())
    assert '<font color="red">x</font>' in text  # shown as text, never read as markup


def test_the_csvs_are_unchanged_by_the_values(report: m.IncidentReport) -> None:
    """The evidence lives in the PDF; the CSVs keep the hand-made case's columns."""
    bare = report.model_copy(
        update={"evidence": tuple(
            e.model_copy(update={"details": (), "shows": None}) for e in report.evidence
        )}
    )  # fmt: skip
    assert files.indicators_csv(report) == files.indicators_csv(bare)
    assert files.affected_csv(report) == files.affected_csv(bare)
    assert set(files.bundle(report)) == set(files.bundle(bare))


def test_a_window_too_long_for_a_reading_still_gives_a_line() -> None:
    params = {"host": kit.HOST, "start": kit.at(2).isoformat(),
              "end": (kit.at(2) + timedelta(days=30)).isoformat()}  # fmt: skip
    assert evidence.shown("proxy.pair", params, pair_snapshot(5, 3)) is not None
