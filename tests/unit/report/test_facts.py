"""Q-F2: provenance lines, check outcomes ("nothing found" only from a known zero, never from a
failed or untrusted check), facts with their E-ids, observations kept beside ARGUS's words."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.context.evidence import STATUS_RANK
from argus.report import facts as fx
from argus.report.model import HIDDEN
from tests.unit.report.kit import T0, T1, key_of, keys, request, row, signal

pytestmark = pytest.mark.unit

AGGS = {
    "destinations": {"buckets": [{"key": "45.9.9.9", "doc_count": 48}]},
    "destination_count": {"value": 1},
    "statuses": {"buckets": [{"key": 200, "doc_count": 48}]},
    "actions": {"buckets": []},
    "timeline": {"buckets": [{"key": int(T0.timestamp() * 1000) + 600_000 * i,
                              "doc_count": 4 if i % 3 == 0 else 0} for i in range(18)]},
}  # fmt: skip


# ----------------------------------------------------------------------------- provenance


def test_the_line_of_a_complete_aggregation() -> None:
    r = row("proxy.host", snapshot={"total": 0, "rows": [], "aggregations": AGGS})
    p = fx.provenance(request("proxy.host", 3), r)
    assert p.line == ("E3 · proxy.host@1 · about 10.20.3.4 · squid, 09 Oct 10:00\u201313:00 UTC"
                      " · aggregation · complete · log ingest not measured · 612 ms")  # fmt: skip
    assert p.subject == "10.20.3.4"
    assert (p.eid, p.template, p.family, p.source) == ("E3", "proxy.host@1", "log", "squid")
    assert (p.window_start, p.window_end, p.from_logs) == (T0, T1, True)
    assert (p.status, p.rows, p.truncated, p.exact, p.server_ms) == ("ok", 0, False, True, 612)


def test_the_line_of_rows_a_watermark_a_copy_and_a_cut() -> None:
    r = row("ti.lookup", row_count=1, took_ms=1500, reused_from_version=1, version=2,
            snapshot={"rows": [{}]})  # fmt: skip
    p = fx.provenance(request("ti.lookup", 1), r)
    assert p.line == ("E1 · ti.lookup@1 · about 45.9.9.9 · acme-threat-intel · 1 row"
                      " · complete · 1.5 s · copied from version 1")  # fmt: skip
    assert (p.family, p.from_logs, p.version, p.reused_from_version) == ("ti", False, 2, 1)
    cut = row("web.followups", row_count=50, truncated=True, coverage={"total": "lower_bound"},
              source_watermark=T1 + timedelta(minutes=41), snapshot={"rows": []})  # fmt: skip
    q = fx.provenance(request("web.followups", 2), cut)
    assert q.line == ("E2 · web.followups@1 · about 185.220.101.5 · nginx, 09 Oct"
                      " 10:00\u201313:00 UTC · at least 50 rows · partial: cut at the row limit"
                      " · logs to 13:41 UTC · 612 ms")  # fmt: skip
    assert (q.exact, q.truncated, q.watermark) == (False, True, T1 + timedelta(minutes=41))
    inexact = row("web.followups", row_count=20, coverage={"total": "lower_bound"},
                  snapshot={"rows": []})  # fmt: skip
    assert (
        "at least 20 rows · partial: the total is a lower bound"
        in fx.provenance(request("web.followups", 2), inexact).line
    )


@pytest.mark.parametrize(
    ("status", "coverage", "words"),
    [
        ("timeout", {"timed_out": True}, "failed: the SIEM did not answer in time"),
        ("failed", {}, "failed: the check failed"),
        ("failed", {"unstorable": True}, "failed: the answer could not be stored"),
        ("skipped_budget", {"reason": "pack_budget"},
         "not run: the investigation's own budget of checks was used up"),
        ("skipped_budget", {"reason": "rederive"}, "not run: a re-derivation never asks the SIEM"),
        ("skipped_budget", {}, "not run: ARGUS's SIEM budget for it was used up"),
        ("deferred", {"reason": "context_partial"},
         "not run: ARGUS put off its SIEM checks for up to a day"),
        ("source_lag", {"missing_indices": ["x"]}, "failed: the logs for that time had not"
         " arrived yet"),
        ("source_expired", {}, "failed: the logs for that time are no longer kept"),
        ("unsupported_value", {}, "failed: the value is too long to search for"),
    ],
)  # fmt: skip
def test_a_request_without_an_answer_says_why(status: str, coverage: Any, words: str) -> None:
    p = fx.provenance(request("proxy.host", 4), row("proxy.host", status, coverage=coverage))
    assert p.line == (
        f"E4 · proxy.host@1 · about 10.20.3.4 · squid, 09 Oct 10:00\u201313:00 UTC · {words}"
    )


def test_a_request_with_nothing_stored_and_a_retired_template() -> None:
    p = fx.provenance(request("proxy.host", 2), None)
    assert p.line == "E2 · proxy.host@1 · not run: nothing was stored for it"
    assert (p.status, p.family, p.window_start) == ("missing", "log", None)
    old = fx.provenance(request("proxy.host", 5, template_version=99), None)
    assert (old.family, old.from_logs) == ("unknown", True)  # unsure: hidden like logs
    assert fx.query_of("proxy.host", 1, {"ip": "x"}) == fx.Query("log", None, None, None)
    assert fx.query_of("nope", 1, {}) == fx.Query("unknown", None, None, None)


def test_spans_across_midnight_and_to_its_end() -> None:
    a = T0.replace(hour=23)
    assert fx.span(a, a + timedelta(hours=1)) == "09 Oct 23:00\u201324:00 UTC"
    assert fx.span(a, a + timedelta(hours=3)) == "09 Oct 23:00 \u2013 10 Oct 02:00 UTC"
    assert fx.span(None, a) == ""


# ----------------------------------------------------------------------------- outcomes


def test_nothing_found_only_from_the_templates_own_known_zero() -> None:
    k = keys("ti.lookup", "web.followups")
    empty_ti = row("ti.lookup", "empty")
    zero = signal("ti.listed_remote", 0, evidence=(key_of("ti.lookup"),))
    assert fx.outcome_of(empty_ti, [zero], False, "ti.lookup", k, True) == ("nothing_found", None)
    assert fx.outcome_of(empty_ti, [zero], False, "ti.lookup", k, False) == (
        "could_not_tell",
        fx.REASONS["source_stale"],
    )
    assert fx.outcome_of(empty_ti, [zero], False, "ti.lookup", k, None) == (
        "could_not_tell",
        fx.REASONS["source_not_checked"],
    )
    # another known signal citing it says nothing about this answer
    other = signal("ti.listed", 1, evidence=(key_of("ti.lookup"),))
    assert fx.outcome_of(empty_ti, [other], False, "ti.lookup", k, True)[0] == "could_not_tell"
    # a log zero is not known until ingest is measured (evidence.from_logs)
    log_zero = signal("web.successes_after", status="unknown", reason="ingest_not_verified",
                      evidence=(key_of("web.followups"),))  # fmt: skip
    got = fx.outcome_of(row("web.followups", "empty"), [log_zero], True, "web.followups", k)
    assert got == ("could_not_tell", fx.REASONS["ingest_not_verified"])
    assert fx.outcome_of(row("web.followups", "empty"), [], True, "web.followups", k) == (
        "could_not_tell",
        fx.REASONS["ingest_not_verified"],
    )
    assert fx.outcome_of(row("ti.lookup", "empty"), [], False, "ti.lookup", k)[1] == (
        "no signal reads it"
    )
    assert fx.outcome_of(row("ti.lookup", "ok"), [], False, "ti.lookup", k) == ("found", None)


@pytest.mark.parametrize("status", sorted(STATUS_RANK))
def test_every_status_has_an_outcome_and_failures_are_never_negative(status: str) -> None:
    k = keys("proxy.host")
    zero = signal("proxy.destinations", 0, evidence=(key_of("proxy.host"),))
    outcome, why = fx.outcome_of(row("proxy.host", status), [zero], True, "proxy.host", k)
    if status not in ("ok", "empty"):
        assert outcome in ("failed", "not_run", "could_not_tell")
        assert why
    expected = {"ok": "found", "empty": "nothing_found", "timeout": "failed", "failed": "failed",
                "skipped_budget": "not_run", "deferred": "not_run"}  # fmt: skip
    assert outcome == expected.get(status, "could_not_tell")
    assert fx.outcome_of(None, [zero], True, "proxy.host", k) == ("not_run", fx.REASONS["missing"])


STATUSES = st.sampled_from(sorted(STATUS_RANK))
SIGNALS = st.lists(
    st.builds(
        signal,
        st.sampled_from(["ti.listed_remote", "proxy.destinations", "web.successes_after",
                         "proxy.hosts_to_destination", "ti.listed", "other"]),
        st.one_of(st.none(), st.integers(0, 3)),
        status=st.sampled_from(["known", "unknown"]),
        reason=st.sampled_from(["ingest_not_verified", "timeout", "partial_coverage"]),
    ),
    max_size=4,
)  # fmt: skip


CHECKED = st.sampled_from(["proxy.host", "proxy.destination", "web.followups", "ti.lookup"])


@given(STATUSES, SIGNALS, CHECKED, st.sampled_from([True, False, None]))
def test_a_check_that_did_not_complete_is_never_negative(
    status: str, citing: list[dict[str, Any]], template: str, fresh: bool | None
) -> None:
    k = keys(template)
    r = row(template, status)
    outcome, why = fx.outcome_of(r, citing, fx.is_log(template, 1), template, k, fresh)
    if status not in ("ok", "empty"):
        assert outcome in ("failed", "not_run", "could_not_tell")
        assert why
    if outcome == "nothing_found":  # only a complete, empty answer with its own count known 0
        assert status == "empty"
        own = [s for s in citing if s["name"] == fx.NEGATIVE[template]]
        assert own
        assert own[0]["status"] == "known"
        assert template != "ti.lookup" or fresh is True
        assert not fx.is_log(template, 1) or own[0]["status"] == "known"


def test_a_check_sentence_per_outcome() -> None:
    k = keys("proxy.host", "ti.lookup")
    p = fx.provenance(request("proxy.host", 1), row("proxy.host"))
    aggs = row("proxy.host", snapshot={"aggregations": AGGS})
    assert fx.check(request("proxy.host", 1), aggs, [], p, k).sentence == (
        "Checked the host's proxy traffic: found an answer."
    )
    found = row("ti.lookup", row_count=2, snapshot={"rows": [{}, {}]})
    tp = fx.provenance(request("ti.lookup", 2), found)
    assert fx.check(request("ti.lookup", 2), found, [], tp, k).sentence == (
        "Checked the indicators on acme-threat-intel: found 2 rows."
    )
    failed = fx.check(request("proxy.host", 1), row("proxy.host", "timeout"), [], p, k)
    assert (failed.outcome, failed.sentence) == (
        "failed",
        "Could not check the host's proxy traffic: the SIEM did not answer in time.",
    )
    skipped = fx.check(request("proxy.host", 1), row("proxy.host", "skipped_budget"), [], p, k)
    assert skipped.sentence == ("Did not check the host's proxy traffic: ARGUS's SIEM budget"
                                " for it was used up.")  # fmt: skip
    lag = fx.check(request("proxy.host", 1), row("proxy.host", "source_lag"), [], p, k)
    assert lag.sentence == ("Checked the host's proxy traffic: could not tell, because the"
                            " logs for that time had not arrived yet.")  # fmt: skip
    zero = signal("proxy.destinations", 0, evidence=(key_of("proxy.host"),))
    none = fx.check(request("proxy.host", 1), row("proxy.host", "empty"), [zero], p, k)
    assert none.sentence == "Checked the host's proxy traffic: nothing found."
    odd = fx.check(request("proxy.host", 1, template="custom.x"), None, [], p, k)
    assert odd.sentence == "Did not check the custom.x check: nothing was stored for it."


# ----------------------------------------------------------------------------- facts


def test_intel_signals_cite_only_what_they_read() -> None:
    every = (key_of("proxy.host"), key_of("ti.lookup"), key_of("web.followups"))
    k = keys("proxy.host", "ti.lookup", "web.followups")
    listed = fx.signal_fact(signal("ti.listed", 1, evidence=every), k)
    # a hit from ARGUS's stored answers alone: no lookup found it (review F3)
    assert (listed.eids, listed.source, listed.leaning) == ((), None, "suspicious")
    found = fx.Keys(
        eid=k.eid,
        template=k.template,
        logs=k.logs,
        holds={key_of("ti.lookup"): frozenset({"45.9.9.9"})},
        local=("abuse-ioc",),
    )
    listed = fx.signal_fact(signal("ti.listed", 2, evidence=every), found)
    assert (listed.eids, listed.from_logs, listed.leaning) == (("E2",), False, "suspicious")
    assert listed.source == "ARGUS's stored threat-list answers (abuse-ioc)"
    remote = fx.signal_fact(signal("ti.listed_remote", 1, evidence=every), found)
    assert (remote.eids, remote.source) == (("E2",), None)
    none = fx.signal_fact(signal("ti.listed_remote", 0, evidence=every), k)
    assert none.eids == ("E2",)  # a known 0: the complete lookups say so
    count = fx.signal_fact(signal("proxy.destinations", 3, evidence=every[:1]), k)
    assert (count.eids, count.from_logs) == (("E1",), True)
    assert fx.reads(signal("ti.values", 2, evidence=every), k) == []
    assert fx.reads(signal("proxy.bytes", 2, evidence=every), k) == list(every)


def test_an_unknown_reading_blames_the_check_that_failed() -> None:
    every = (key_of("proxy.host"), key_of("ti.lookup"))
    k = keys("proxy.host", "ti.lookup", status={"proxy.host": "timeout", "ti.lookup": "empty"})
    got = fx.signal_fact(signal("ti.listed_remote", status="unknown", reason="timeout",
                                evidence=every), k)  # fmt: skip
    assert got.sentence == "On acme-threat-intel: could not tell."
    assert got.why == ("the SIEM did not answer in time for E1, and this reading waits for every"
                       " check of the investigation")  # fmt: skip
    assert (got.eids, got.from_logs, got.status) == (("E1", "E2"), False, "unknown")
    own = fx.signal_fact(signal("proxy.bytes", status="unknown", reason="timeout",
                                evidence=every[:1]), k)  # fmt: skip
    assert (own.why, own.eids) == ("the SIEM did not answer in time", ("E1",))
    plain = fx.signal_fact(signal("proxy.bytes", status="unknown", reason="partial_coverage",
                                  evidence=every[:1]), k)  # fmt: skip
    assert plain.why == fx.REASONS["partial_coverage"]
    gap = fx.signal_gap(signal("ti.listed_remote", status="unknown", reason="timeout",
                               evidence=every), got)  # fmt: skip
    assert gap is not None
    assert (gap.why, gap.who, gap.floor) == (got.why, "ARGUS, by checking again", True)
    assert fx.signal_gap(signal("proxy.bytes", 3), fx.signal_fact(signal("proxy.bytes", 3), k)) \
        is None  # fmt: skip


@pytest.mark.parametrize(
    ("name", "value", "completeness", "leaning"),
    [
        ("ti.listed", 1, "exact", "suspicious"), ("ti.listed", 0, "exact", "reassuring"),
        ("ti.listed", 0, "lower_bound", "neutral"), ("ports.risky", 0, "exact", "reassuring"),
        ("ti.listed_remote", 0, "exact", "neutral"), ("ti.listed_remote", 2, "exact", "suspicious"),
        ("web.successes_after", 2, "exact", "suspicious"),
        ("web.successes_after", 0, "exact", "neutral"),
        ("same_ioc.investigations", 1, "exact", "suspicious"),
        ("proxy.regularity", 0.29, "exact", "suspicious"),
        ("proxy.regularity", 0.3, "exact", "reassuring"),
        ("proxy.hosts_to_destination", 1, "exact", "suspicious"),
        ("proxy.hosts_to_destination", 2, "exact", "reassuring"),
        ("proxy.bytes", 10, "exact", "neutral"), ("nat.hint", True, "exact", "neutral"),
    ],
)  # fmt: skip
def test_how_each_signal_leans(name: str, value: Any, completeness: str, leaning: str) -> None:
    assert fx.leaning(signal(name, value, completeness=completeness)) == leaning
    assert fx.leaning(signal(name, status="unknown", reason="timeout")) == "neutral"


def test_a_step_takes_the_eids_of_the_signals_that_answer_it() -> None:
    k = keys("proxy.destination")
    hosts = fx.signal_fact(signal("proxy.hosts_to_destination", 1,
                                  evidence=(key_of("proxy.destination"),)), k)  # fmt: skip
    step = {"number": 3, "text": "How many internal hosts reach `destination.ip`?",
            "status": "answered", "sentence": "Proxy logs: 1 internal hosts reached it.",
            "needs": []}  # fmt: skip
    got = fx.step_fact(step, {"proxy.hosts_to_destination": hosts})
    assert (got.key, got.status, got.eids, got.from_logs) == ("step:3", "known", ("E1",), True)
    assert got.sentence == "Step 3, answered: Proxy logs: 1 internal hosts reached it."
    assert got.text == step["text"]
    waiting = {**step, "status": "deferred", "needs": ["prevalence"],
               "sentence": "Not checked yet: needs proxy-log statistics."}  # fmt: skip
    gap = fx.step_gap(waiting, fx.step_fact(waiting, {}))
    assert gap is not None
    assert (gap.why, gap.who) == ("it needs proxy-log statistics",
                                  "ARGUS, once it can make proxy-log statistics")  # fmt: skip
    nodata = {**step, "status": "unknown", "sentence": "Could not check: no alert has x."}
    assert fx.step_gap(nodata, fx.step_fact(nodata, {})).who == fx.PERSON  # type: ignore[union-attr]
    manual = {**step, "status": "manual", "sentence": "For a person to decide or do."}
    assert fx.step_gap(manual, fx.step_fact(manual, {})) is None
    assert fx.step_fact(manual, {}).why == "for a person"


def test_the_alerts_own_facts() -> None:
    (high,) = fx.alert_facts({"severity": "High"})
    assert (high.sentence, high.leaning, high.eids) == ("The rule rates it high.", "suspicious", ())
    assert fx.alert_facts({"severity": "low"})[0].leaning == "neutral"
    assert fx.alert_facts({}) == []


# ----------------------------------------------------------------------------- observations

HOSTILE = '<script>x</script>‮"; DROP'


def test_observations_keep_untrusted_values_beside_the_sentence() -> None:
    aggs = {**AGGS, "destinations": {"buckets": [{"key": HOSTILE, "doc_count": 3}]},
            "actions": {"buckets": [{"key": "TCP_MISS" * 40, "doc_count": 1}]}}  # fmt: skip
    got = fx.observations(request("proxy.host", 1), row("proxy.host", snapshot={
        "aggregations": aggs}))  # fmt: skip
    by = {f.key: f for f in got}
    assert set(by) == {"obs:E1:destinations", "obs:E1:answers", "obs:E1:activity"}
    for f in got:
        assert HOSTILE not in f.sentence
        assert "TCP_MISS" not in f.sentence
        assert (f.eids, f.from_logs, f.status) == (("E1",), True, "known")
    assert by["obs:E1:destinations"].values[0].text == HOSTILE
    assert len(by["obs:E1:answers"].values[1].text) == fx.VALUE_CHARS
    activity = by["obs:E1:activity"]
    assert activity.sentence == ("The host's proxy traffic ran in 6 ten-minute periods;"
                                 " timing very regular, like a beacon (100/100).")  # fmt: skip
    assert (activity.at, activity.until) == (T0, T0 + timedelta(minutes=160))


def test_observations_of_each_template() -> None:
    dest = {"host_count": {"value": 3}, "hosts": {"buckets": [{"key": "10.0.0.1", "doc_count": 9}]},
            "urls": {"buckets": [{"key": "http://x/" + HOSTILE, "doc_count": 9}]}}  # fmt: skip
    got = fx.observations(request("proxy.destination", 2),
                          row("proxy.destination", snapshot={"aggregations": dest}))  # fmt: skip
    assert [f.sentence for f in got] == [
        "The 3 campus hosts that reached the destination through the proxy (1 shown).",
        "The most requested addresses at the destination (1 shown).",
    ]
    rows = [{"_source": {"@timestamp": "2026-10-09T11:30:00Z", "url": {"domain": "a.example",
             "path": HOSTILE}, "http": {"response": {"status_code": 200},
             "request": {"method": "GET"}}}}, {"_source": {"@timestamp": "bad"}}]  # fmt: skip
    (succ,) = fx.observations(request("web.followups", 3),
                              row("web.followups", snapshot={"rows": rows}))  # fmt: skip
    assert succ.sentence == ("The client got 2 successful (2xx) answers after the first alert"
                             " (2 shown).")  # fmt: skip
    assert succ.values[0].label == "answer"  # never an untrusted value (review F6)
    assert succ.values[0].text.startswith("200 GET a.example ")
    assert HOSTILE in succ.values[0].text
    assert succ.values[1].label == "answer"
    assert (succ.at, succ.until) == (T0.replace(hour=11, minute=30), T0.replace(hour=11, minute=30))
    ti = [{"_source": {"ioc_type": "ip", "ioc_value": "45.9.9.9", "intel_source": "feodo",
                       "@timestamp": "2026-10-08T10:00:00Z"}}]  # fmt: skip
    (listed,) = fx.observations(request("ti.lookup", 4), row("ti.lookup", snapshot={"rows": ti}))
    assert (listed.sentence, listed.from_logs, listed.leaning) == (
        "acme-threat-intel lists 1 of the indicators looked up.",
        False,
        "suspicious",
    )
    assert listed.values[0].text == "45.9.9.9 (feodo)"


def test_no_observation_without_a_complete_answer_or_the_registered_version() -> None:
    snap = {"aggregations": AGGS}
    assert fx.observations(request("proxy.host", 1), row("proxy.host", "timeout",
                                                         snapshot=snap)) == []  # fmt: skip
    assert fx.observations(request("proxy.host", 1, template_version=2),
                           row("proxy.host", snapshot=snap)) == []  # fmt: skip
    assert fx.observations(request("proxy.host", 1, template="custom.x"),
                           row("proxy.host", snapshot=snap)) == []  # fmt: skip
    assert fx.observations(request("proxy.host", 1), row("proxy.host", snapshot=None)) == []
    assert fx.observations(request("proxy.host", 1), row("proxy.host", snapshot={
        "aggregations": None})) == []  # fmt: skip
    empty = {"destinations": {"buckets": "x"}, "timeline": {"buckets": [{"doc_count": 0}]}}
    assert fx.observations(request("proxy.host", 1), row("proxy.host", snapshot={
        "aggregations": empty})) == []  # fmt: skip


@given(st.text(max_size=300).map(lambda t: "\u00a7" + t))  # § is in no sentence of ARGUS
def test_a_value_never_reaches_a_sentence(value: str) -> None:
    aggs = {"destinations": {"buckets": [{"key": value, "doc_count": 1}]},
            "hosts": {"buckets": [{"key": value, "doc_count": 1}]},
            "urls": {"buckets": [{"key": value, "doc_count": 1}]}}  # fmt: skip
    found = [*fx.observations(request("proxy.host", 1), row("proxy.host", snapshot={
                 "aggregations": aggs})),
             *fx.observations(request("proxy.destination", 2), row("proxy.destination",
                 snapshot={"aggregations": aggs}))]  # fmt: skip
    assert found
    for f in found:
        assert "\u00a7" not in f.sentence
        assert all(len(v.text) <= fx.VALUE_CHARS for v in f.values)
        assert any(v.text.startswith("\u00a7") for v in f.values)


# ----------------------------------------------------------------------------- as of


def test_the_evidence_as_an_assessment_had_it() -> None:
    later = row("proxy.host", collected_at=T1 + timedelta(hours=5), result_hash="n" * 64,
                snapshot={"aggregations": AGGS})  # fmt: skip
    early = row("ti.lookup", "empty", collected_at=T1)
    ref = {"task_key": key_of("proxy.host"), "template": "proxy.host@1", "status": "timeout",
           "coverage": {"timed_out": True}, "row_count": None, "truncated": False,
           "result_hash": None}  # fmt: skip
    got = fx.as_of([later, early], [ref], 1, T1 + timedelta(hours=1))
    by = {r.template: r for r in got}
    assert by["ti.lookup"] == early
    old = by["proxy.host"]
    assert (old.status, old.coverage, old.snapshot, old.took_ms) == (
        "timeout",
        {"timed_out": True},
        None,
        None,
    )
    assert old.params == later.params
    every = sorted([later, early], key=lambda r: r.task_key)
    assert fx.as_of([later, early], [ref], 1, None) == every
    same = {**ref, "status": "ok", "result_hash": "n" * 64, "coverage": {}}
    kept = fx.as_of([later], [same], 1, T1)
    assert kept[0].snapshot == later.snapshot
    assert kept[0].took_ms == later.took_ms
    gone = fx.as_of([], [{**ref, "template": "custom"}], 3, T1)
    assert (gone[0].template, gone[0].template_version, gone[0].version) == ("", 0, 3)


def test_plain_words_and_resolvers() -> None:
    assert fx.plain("nope") == "it could not be told"
    assert fx.who("nope") == fx.PERSON
    assert fx.who("source_expired") == "nobody: the logs are gone"
    assert fx.rows(1) == "1 row"
    assert fx.rows(0) == "0 rows"
    assert (fx.seconds(999), fx.seconds(1000)) == ("999 ms", "1.0 s")
    assert fx.cap("x" * 300, 10) == "x" * 9 + "…"
    assert HIDDEN.startswith("Hidden")
