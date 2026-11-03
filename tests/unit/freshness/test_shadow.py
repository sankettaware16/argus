"""The shadow's pure parts (Q-F1): which signals are log zeros, the search's own completeness,
the window rebuilt from the evidence row, each reason a row can be refused for, a signal
verified only when every row is, and the body an assessor would read with the zeros known.
Also the probe passing the lanes' lags to the health machine (the trip wire, DQ19)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from argus.context.evidence import SignalValue, derived, from_logs, local
from argus.freshness.model import OK, Reading
from argus.freshness.report import nights, source_report, verdict_counts, with_zeros
from argus.freshness.shadow import (
    Policy,
    complete_search,
    judge,
    judge_ref,
    known_zero,
    log_zeros,
    window_of,
)
from argus.freshness.template import Watermark

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
MIN = timedelta(minutes=1)
POLICY = Policy(mode="shadow", margins={"squid": 3 * MIN})


def zero(name: str = "proxy.bytes", keys: tuple[str, ...] = ("k1",)) -> SignalValue:
    refs = [{"task_key": k, "status": "empty", "coverage": {}, "truncated": False} for k in keys]
    return from_logs(derived(name, 1, refs, lambda: 0, counts=True))


def row(start: datetime, end: datetime, **kw: Any) -> dict[str, Any]:
    """An evidence row of the watermark template (a registered log template) over a window
    ending at ``end``: its plan's window is [end - 15 min, end]."""
    del start
    base = {
        "template": Watermark.name,
        "template_version": Watermark.version,
        "params": {"source": "squid", "now": end.isoformat()},
        "status": "empty",
        "coverage": {},
        "truncated": False,
        "asked_at": end + 30 * MIN,
    }
    return {**base, **kw}


def flowing(start: datetime, end: datetime) -> dict[str, list[Reading]]:
    out, t = [], start
    while t <= end:
        out.append(Reading("squid", t, OK, t, t - timedelta(seconds=5)))
        t += 5 * MIN
    return {"squid": out}


READINGS = flowing(NOW - 60 * MIN, NOW + 60 * MIN)


def test_log_zeros_are_exactly_the_unverified_log_counts() -> None:
    plain = local("web.scanner_agents", 1, 0)
    positive = from_logs(
        derived(
            "dns.lookups",
            1,
            [{"task_key": "k", "status": "ok", "coverage": {}}],
            lambda: 3,
            counts=True,
        )
    )
    failed = derived(
        "dns.names", 1, [{"task_key": "k", "status": "timeout", "coverage": {}}], lambda: 0
    )
    assert log_zeros([plain, positive, failed, zero()]) == [zero()]
    known = known_zero(zero())
    assert (known.value, known.status, known.unknown_reason, known.completeness) == (
        0,
        "known",
        None,
        "exact",
    )
    assert known.evidence == ("k1",)


def test_the_search_must_be_complete() -> None:
    good = row(NOW, NOW)
    assert complete_search(good)
    for bad in (
        {"status": "timeout"},
        {"truncated": True},
        {"coverage": {"total": "lower_bound"}},
        {"status": "skipped_budget"},
    ):
        assert not complete_search({**good, **bad})


def test_the_window_is_rebuilt_from_the_row() -> None:
    window = window_of(row(NOW, NOW))
    assert window is not None
    assert (window.source, window.start, window.end) == ("squid", NOW - 15 * MIN, NOW)
    for bad in (
        {"template": "nope"},
        {"template_version": 2},
        {"params": {"source": "x"}},
        {"template": "alerts.ids", "template_version": 1},
    ):
        assert window_of({**row(NOW, NOW), **bad}) is None


@pytest.mark.parametrize(
    ("given", "reason"),
    [
        (None, "not_log_search"),
        ({"template": "alerts.ids", "template_version": 1}, "not_log_search"),
        ({"status": "failed"}, "search_incomplete"),
        ({"asked_at": None}, "not_asked"),
        ({"asked_at": NOW + 2 * MIN}, "not_past_end"),
    ],
)
def test_each_reason_a_row_is_refused_for(given: dict[str, Any] | None, reason: str) -> None:
    got = judge_ref(
        "k1", None if given is None else row(NOW, NOW, **given), READINGS, POLICY, "none"
    )
    assert (got.check.known, got.check.reason) == (False, reason)


def test_a_signal_is_verified_only_when_every_row_is() -> None:
    rows = {"k1": row(NOW, NOW), "k2": row(NOW, NOW + 20 * MIN)}
    both = judge(zero(keys=("k1", "k2")), rows, READINGS, POLICY, "none")
    assert both.known
    assert both.reason == "complete"
    assert both.complete_to == min(r.check.complete_to for r in both.refs)  # type: ignore[type-var]
    one_bad = {**rows, "k2": row(NOW, NOW, status="timeout")}
    got = judge(zero(keys=("k1", "k2")), one_bad, READINGS, POLICY, "none")
    assert (got.known, got.reason, got.complete_to) == (False, "search_incomplete", None)
    nothing = judge(zero(keys=()), rows, READINGS, POLICY, "none")
    assert (nothing.known, nothing.reason) == (False, "not_log_search")
    no_margin = judge(zero(), rows, READINGS, Policy(mode="shadow"), "none")
    assert no_margin.reason == "no_margin"
    as_dict = both.refs[0].as_dict()
    assert as_dict["source"] == "squid"
    assert as_dict["known"]
    assert as_dict["reason"] == "complete"


def test_the_policy_refuses_what_it_cannot_mean() -> None:
    with pytest.raises(ValueError, match=r"\w"):
        Policy(mode="sometimes")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=r"\w"):
        Policy(margins={"squid": -MIN})
    assert Policy(margins={"squid": 3 * MIN}).margins_s() == {"squid": 180}


def test_the_body_with_the_zeros_known() -> None:
    body = {
        "signals": [
            zero().as_dict(),
            zero("dns.names").as_dict(),
            local("web.scanner_agents", 1, 0).as_dict(),
        ],
        "facts": {},
    }
    got = with_zeros(body, ["proxy.bytes", "web.scanner_agents"])
    by = {s["name"]: s for s in got["signals"]}
    assert (by["proxy.bytes"]["status"], by["proxy.bytes"]["value"]) == ("known", 0)
    assert by["dns.names"]["status"] == "unknown"  # not named
    assert by["web.scanner_agents"] == body["signals"][2]  # not a log zero
    assert body["signals"][0]["status"] == "unknown"  # the original is untouched


def test_the_report_per_source_and_nights() -> None:
    day = datetime(2026, 10, 20, 2, 0, tzinfo=UTC)
    readings, t = [], day
    while t < day + timedelta(days=4):
        if not (t.hour == 0 or (t.hour == 1 and t.minute < 30)):
            readings.append(Reading("squid", t, OK, t, t - timedelta(seconds=5)))
        t += 5 * MIN
    assert nights(readings, 3 * MIN, 10 * MIN) == (4, 4)  # 10-21 to 10-24
    assert nights(readings, None, 10 * MIN) == (0, 0)
    assert nights([], 3 * MIN, 10 * MIN) == (0, 0)
    got = source_report("squid", readings, POLICY)
    assert got["readings"] == len(readings)
    assert got["within_margin"] == len(readings)
    assert got["lag"]["p50_s"] == 5.0
    assert got["margin_s"] == 180
    assert got["windows_72h"]["pass_strict"] == 0
    assert got["windows_72h"]["pass_bridged"] > 0
    assert source_report("dns", [], POLICY)["lag"] is None
    counts = verdict_counts(
        [
            {"verdict": "known_zero", "bridged_verdict": "known_zero", "reason": "complete"},
            {"verdict": "could_not_tell", "bridged_verdict": "known_zero", "reason": "quiet_hours"},
        ]
    )
    assert counts == {
        "signals": 2,
        "known_zero": 1,
        "known_zero_bridged": 2,
        "reasons": {"complete": 1, "quiet_hours": 1},
    }


async def test_the_probe_passes_the_lanes_lags_to_the_health_machine() -> None:
    from argus.config.settings import SiemSettings
    from argus.gateway.health import HealthState
    from argus.gateway.service import probe
    from tests.unit.gateway.fakes import FakeTransport, make, ok

    stats = {
        "_nodes": {"failed": 0},
        "nodes": {
            "n": {
                "fs": {"total": {"total_in_bytes": 100, "available_in_bytes": 50}},
                "jvm": {"mem": {"heap_used_percent": 40}},
                "os": {"cpu": {"load_average": {"1m": 1.0}}},
                "thread_pool": {"search": {"queue": 0, "rejected": 0}},
            }
        },
    }
    blocks = {".internal.alerts-security.alerts-acme-soc-000001": {}}
    transport = FakeTransport().on("_nodes", ok(stats)).on("_settings", ok(blocks))
    gateway, _, store, clock = make(transport)
    lags = {"squid": 20 * MIN, "dns": 20 * MIN}
    memory = await probe(gateway, store, SiemSettings(), clock.now, ingest_lag=lags)
    assert memory.state is HealthState.DEGRADED
    assert memory.reasons == ("ingest_lag:dns", "ingest_lag:squid")
    one = await probe(gateway, store, SiemSettings(), clock.now, ingest_lag={"squid": 20 * MIN})
    assert one.state is HealthState.NORMAL  # one late source alone: its own zeros only
    none = await probe(gateway, store, SiemSettings(), clock.now)
    assert none.state is HealthState.NORMAL
    assert store.probes[-1][0].ingest_lag == {}


def test_the_audit_sheet_and_its_score(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import csv

    from typer.testing import CliRunner

    from argus.cli import app
    from argus.freshness.report import SHEET, score, sheet

    inv = "00000000-0000-0000-0000-000000000001"
    proposals = [
        {
            "investigation_id": inv,
            "version": 1,
            "pack": "p",
            "outcome": "benign_expected",
            "actual": None,
            "signals": ["proxy.bytes"],
            "bridged": False,
        },
        {
            "investigation_id": inv,
            "version": 1,
            "pack": "p",
            "outcome": None,
            "actual": None,
            "signals": ["proxy.bytes"],
            "bridged": False,
        },
        {
            "investigation_id": inv,
            "version": 1,
            "pack": "p",
            "outcome": "rule_false_positive",
            "actual": "inconclusive",
            "signals": ["a", "b"],
            "bridged": True,
        },
        {  # the engine proposed benign on its own: not the shadow's work, not audited (F4)
            "investigation_id": inv,
            "version": 2,
            "pack": "p",
            "outcome": "benign_expected",
            "actual": "benign_expected",
            "signals": ["proxy.bytes"],
            "bridged": False,
        },
    ]
    rows = sheet(proposals, bridged=False)
    assert [r["would_propose"] for r in rows] == ["benign_expected"]
    assert tuple(rows[0]) == SHEET
    assert rows[0]["correct"] == ""
    assert rows[0]["proposed"] == ""
    (edge,) = sheet(proposals, bridged=True)
    assert edge["signals"] == "a b"
    assert edge["proposed"] == "inconclusive"

    def answered(n: int, correct: int, tp: int = 0, blank: int = 0) -> list[dict[str, str]]:
        out = [
            {"correct": "yes" if i < correct else "no", "true_positive": "yes" if i < tp else "no"}
            for i in range(n)
        ]
        return out + [{"correct": "", "true_positive": ""}] * blank

    assert score(answered(37, 37))["passes"]  # 1/(1 + z^2/37) = 0.906
    assert not score(answered(36, 36))["passes"]  # too few
    assert not score(answered(40, 37))["passes"]  # the bound falls below 90 %
    assert not score(answered(37, 37, tp=1))["passes"]  # a true positive proposed benign
    assert not score(answered(37, 37, blank=1))["passes"]  # every item is answered
    got = score(answered(37, 37))
    assert got["lower_bound"] > 0.9
    assert got["answered"] == 37
    assert got["true_positives"] == 0
    assert score([])["lower_bound"] is None

    path = tmp_path / "audit.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=SHEET)
        writer.writeheader()
        for row in answered(37, 37):
            writer.writerow({**dict.fromkeys(SHEET, ""), **row})
    monkeypatch.chdir(tmp_path)
    # audit-score checks the CSV against the stored proposals (F4): here the store is a stand-in
    import argus.freshness.cli as fcli

    with path.open(encoding="utf-8", newline="") as fh:
        stored = list(csv.DictReader(fh))
    monkeypatch.setattr(fcli, "load", lambda config=None: None)
    monkeypatch.setattr(fcli, "_stored_sheet", lambda settings, bridged: stored)
    runner = CliRunner()
    assert runner.invoke(app, ["freshness", "audit-score", str(path)]).exit_code == 0
    with path.open("a", newline="", encoding="utf-8") as fh:  # a row the store does not hold
        csv.DictWriter(fh, fieldnames=SHEET).writerow(
            {**dict.fromkeys(SHEET, ""), "investigation_id": "x", "correct": "no"}
        )
    assert runner.invoke(app, ["freshness", "audit-score", str(path)]).exit_code == 2
    rows_now = [*stored[:-1], {**stored[-1], "correct": "no", "true_positive": "yes"}]
    with path.open("w", newline="", encoding="utf-8") as fh:  # a true positive among them
        writer = csv.DictWriter(fh, fieldnames=SHEET)
        writer.writeheader()
        writer.writerows(rows_now)
    assert runner.invoke(app, ["freshness", "audit-score", str(path)]).exit_code == 1
    with path.open("w", newline="", encoding="utf-8") as fh:  # a row left out
        writer = csv.DictWriter(fh, fieldnames=SHEET)
        writer.writeheader()
        writer.writerows(stored[:-1])
    assert runner.invoke(app, ["freshness", "audit-score", str(path)]).exit_code == 2
