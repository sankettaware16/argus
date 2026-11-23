"""R16: soak samples (local SQL only) and the exit report's verdicts, with their boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import soak

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 13, 10, tzinfo=UTC)
GOOD: dict[str, Any] = {
    "last_reconcile_mismatched": 0,
    "took_today_ms": 1000,
    "overloads_last_hour": 0,
    "jobs_due": 0,
    "jobs_queued": 0,
    "jobs_failed": 0,
    "with_dossier": 10,
    "investigations": 10,
}


def hourly(hours: int, **change: Any) -> list[tuple[datetime, dict[str, Any]]]:
    return [(T0 + timedelta(hours=h), {**GOOD, **change}) for h in range(hours + 1)]


def verdicts(samples: list[tuple[datetime, dict[str, Any]]]) -> dict[str, tuple[str, str]]:
    return {c["criterion"]: (c["result"], c["why"]) for c in soak.judge(samples, T0)}


def test_no_samples_is_pending() -> None:
    assert soak.judge([], T0) == [
        {"criterion": "soak", "result": "PENDING", "why": "no samples yet"}
    ]


def test_a_clean_72_hours_passes_what_argus_can_judge() -> None:
    out = verdicts(hourly(72))
    assert out["72 h soak"] == ("PASS", "72.0 h of samples since 2026-10-13 10:00 UTC")
    judged = [k for k, (r, _) in out.items() if r not in ("PENDING", "INFO")]
    assert len(judged) == 7
    assert all(out[k][0] == "PASS" for k in judged)
    pending = [k for k, (r, _) in out.items() if r == "PENDING"]
    assert len(pending) == 2
    assert out["every investigation has a dossier"] == ("PASS", "10 of 10 at their current"
                                                        " version (0 queued)")  # fmt: skip
    assert out["the queue returns to 0 daily"] == ("PASS", "due jobs reached 0 on 4 of 4 days")
    assert out["SIEM budget held (≤ 60 min server time a day)"][1] == (
        "the busiest day used 0.0 min"
    )


def test_the_soak_span_boundary() -> None:
    assert verdicts(hourly(71))["72 h soak"][0] == "PASS"  # one hour short is allowed
    short = hourly(70)
    short.append((T0 + timedelta(hours=70, minutes=59, seconds=59), GOOD))
    assert verdicts(short)["72 h soak"][0] == "PENDING"
    assert verdicts(hourly(70))["72 h soak"] == (
        "PENDING", "70.0 h of samples since 2026-10-13 10:00 UTC"
    )  # fmt: skip


def test_one_mismatched_reconciliation_fails() -> None:
    samples = hourly(3)
    samples[1][1]["last_reconcile_mismatched"] = 2
    result = verdicts(samples)["0 lost / duplicated alerts (reconciliation per hour and rule)"]
    assert result == ("FAIL", "the worst reconciliation in the soak found 2 hours that differed")
    samples[1][1]["last_reconcile_mismatched"] = None
    assert verdicts(samples)[
        "0 lost / duplicated alerts (reconciliation per hour and rule)"
    ][0] == "PASS"  # fmt: skip


def test_the_budget_is_judged_per_day_at_its_peak() -> None:
    name = "SIEM budget held (≤ 60 min server time a day)"
    samples = hourly(30)
    samples[5][1]["took_today_ms"] = soak.DAY_CAP_MS
    samples[6][1]["took_today_ms"] = 10  # a later, smaller sample of the same day
    assert verdicts(samples)[name] == ("PASS", "the busiest day used 60.0 min")
    samples[20][1]["took_today_ms"] = soak.DAY_CAP_MS + 1
    assert verdicts(samples)[name][0] == "FAIL"
    samples[20][1]["took_today_ms"] = None
    assert verdicts(samples)[name][0] == "PASS"


def test_overloads_sum_over_the_soak() -> None:
    name = "no overload responses attributable to ARGUS"
    samples = hourly(3)
    samples[0][1]["overloads_last_hour"] = 1
    samples[2][1]["overloads_last_hour"] = 2
    assert verdicts(samples)[name] == ("FAIL", "3 overload or breaker responses in the soak")
    samples[0][1]["overloads_last_hour"] = None
    samples[2][1]["overloads_last_hour"] = 0
    assert verdicts(samples)[name] == ("PASS", "0 overload or breaker responses in the soak")


def test_the_queue_must_reach_zero_every_day() -> None:
    name = "the queue returns to 0 daily"
    samples = hourly(30)  # 10:00 day 1 .. 16:00 day 2
    for _, m in samples[14:]:  # never 0 on day 2
        m["jobs_due"] = 3
    assert verdicts(samples)[name] == ("FAIL", "due jobs reached 0 on 1 of 2 days")
    samples[-1][1]["jobs_due"] = None
    assert verdicts(samples)[name][0] == "PASS"


def test_dossiers_count_queued_work_and_need_investigations() -> None:
    name = "every investigation has a dossier"
    samples = hourly(1, with_dossier=7, investigations=10, jobs_queued=3)
    assert verdicts(samples)[name] == ("PASS", "7 of 10 at their current version (3 queued)")
    samples = hourly(1, with_dossier=6, investigations=10, jobs_queued=3)
    assert verdicts(samples)[name][0] == "FAIL"
    samples = hourly(1, with_dossier=0, investigations=0, jobs_queued=0)
    assert verdicts(samples)[name][0] == "FAIL"  # nothing collected is not a pass
    first_bad = hourly(1)
    first_bad[0][1]["with_dossier"] = 0  # only the last sample counts
    assert verdicts(first_bad)[name][0] == "PASS"
    missing = [(T0, {})]
    assert verdicts(missing)[name] == ("FAIL", "0 of 0 at their current version (None queued)")


def test_a_failed_job_fails() -> None:
    samples = hourly(1, jobs_failed=1)
    assert verdicts(samples)["no job given up"] == ("FAIL", "1 failed jobs")
    early = hourly(1)
    early[0][1]["jobs_failed"] = 4  # only the last sample counts
    assert verdicts(early)["no job given up"] == ("PASS", "0 failed jobs")


def test_the_person_criteria_stay_pending() -> None:
    out = soak.judge(hourly(72), T0)
    assert [c["criterion"] for c in out[-3:]] == [
        "detection-rule durations within +10% of the pre-ARGUS baseline",
        "review task test with a real reviewer",
        "write-back, not an exit criterion",
    ]
    assert [c["result"] for c in out[-3:]] == ["PENDING", "PENDING", "INFO"]
    assert out[-1]["why"] == "built and off; switched on with the user present (D-061)"


async def test_a_sample_reads_the_store_and_is_kept_once(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    now = datetime.now(UTC)
    async with migrated_engine.begin() as conn:
        for outcome, took, at in (
            ("ok", 1200, now - timedelta(minutes=5)),
            ("overloaded", 30, now - timedelta(minutes=10)),
            ("breaker_open", 0, now - timedelta(minutes=20)),
            ("ok", 999_999, now - timedelta(days=2)),  # another day: not today
            ("overloaded", 0, now - timedelta(hours=3)),  # earlier: not the last hour
        ):
            await conn.execute(
                text(
                    "INSERT INTO siem_requests (at, component, purpose, template, version,"
                    " indices, outcome, took_ms, elapsed_ms, response_bytes, attempts)"
                    " VALUES (:at, 'test', 'test', 't', 1, ARRAY['x'], :o, :t, 0, 0, 1)"
                ),
                {"at": at, "o": outcome, "t": took},
            )
    async with app_engine.begin() as conn:
        metrics = await soak.sample(conn, T0)
        again = await soak.sample(conn, T0)  # same hour: kept once
    assert metrics == again
    assert metrics["overloads_last_hour"] == 2
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    expected = sum(t for t, at in ((1200, 5), (30, 10), (0, 20), (0, 180))
                   if now - timedelta(minutes=at) >= today)  # fmt: skip
    assert metrics["took_today_ms"] == expected
    assert metrics["alerts"] == metrics["investigations"] == metrics["jobs_failed"] == 0
    assert metrics["with_dossier"] == 0
    async with app_engine.connect() as conn:
        rows = (await conn.execute(text("SELECT at, metrics FROM soak_samples"))).all()
        assert [(r.at, r.metrics) for r in rows] == [(T0, metrics)]
        report = await soak.report(conn, T0 + timedelta(hours=1))
        assert report == [*soak.judge([(T0, metrics)], T0), await soak.labels(conn),
                          *await soak.measurements(conn)]  # fmt: skip
        assert report[-2]["why"] == "no investigations yet"
        assert report[-1]["why"] == "no dossiers yet"
        assert await soak.report(conn, T0 + soak.SOAK + timedelta(hours=2)) == soak.judge([], T0)


# ----------------------------------------------------------------- exact (mutation testing)
from types import SimpleNamespace  # noqa: E402


def test_the_limits_and_wording() -> None:
    assert soak.DAY_CAP_MS == 3_600_000
    assert timedelta(hours=72) == soak.SOAK
    assert soak.TOKEN_CHARS == 4
    out = verdicts(hourly(36))
    assert out["72 h soak"][1] == "36.0 h of samples since 2026-10-13 10:00 UTC"
    budget = hourly(1, took_today_ms=90_000)
    assert verdicts(budget)["SIEM budget held (≤ 60 min server time a day)"][1] == (
        "the busiest day used 1.5 min")  # fmt: skip
    pending = {c["criterion"]: c["why"] for c in soak.judge(hourly(1), T0)}
    assert pending["detection-rule durations within +10% of the pre-ARGUS baseline"] == (
        "needs Kibana's rule execution data (no Kibana read yet)")  # fmt: skip
    assert pending["review task test with a real reviewer"] == "needs a reviewer and 15 minutes"
    exact = hourly(1)
    exact[0][1]["jobs_due"] = 0
    exact[1][1]["jobs_due"] = 1  # the last sample of the day not at zero: still a zero day
    assert verdicts(exact)["the queue returns to 0 daily"][0] == "PASS"


def row(rule: str, day: int, signals: list[dict[str, Any]], dest: str = "1.1.1.1",
        note: str = "x" * 400) -> SimpleNamespace:  # fmt: skip
    body = {
        "facts": {"rule_name": note},
        "report": {"steps": [{"number": 1, "status": "deferred", "text": "t", "sentence": "s",
                              "fields": ["destination.ip"]}]},
        "context": {"pack": {"fields": {"destination.ip": {"distinct": 1, "top": [[dest, 1]]}}}},
        "signals": signals, "local_signals": [],
    }  # fmt: skip
    return SimpleNamespace(rule_id=rule, group_key='[["source.ip","10.0.0.1"]]', rule=rule,
                           bucket_start=T0 + timedelta(days=day), body=body)  # fmt: skip


def test_the_phase_2_measurements_exactly() -> None:
    known = [{"name": "a", "status": "known", "value": 1}]
    unknown = [{"name": "a", "status": "unknown"}]
    rows = [
        row("r1", 0, known),
        row("r1", 0, unknown),
        row("r1", 0, known, dest="2.2.2.2"),
        row("r1", 0, known, dest="2.2.2.2"),  # 2 patterns on day 0 (4 investigations)
        row("r2", 1, unknown),
        row("r2", 1, unknown),  # 1 pattern on day 1
        row("r3", 1, known),
    ]
    share, patterns, model = soak.measure(rows)
    assert share["criterion"] == "share of investigations with every signal known (lowest rules)"
    assert (share["result"], share["why"]) == ("INFO", "r2 0%, r1 75%, r3 100%")
    assert patterns["why"] == "at most 2 patterns on a day with up to 4 investigations (2 days)"
    assert patterns["criterion"] == "decision patterns per day vs investigations per day"
    assert model["criterion"] == "digest size and projected Phase 2 model use"
    tokens = int(model["why"].split("p95 ")[1].split(" ")[0])
    assert 100 < tokens < 200  # a 400-character name in each digest, 4 characters a token
    expected = (f"digest p95 {tokens} tokens; at most 2 model requests and {2 * tokens:,} input"
                " tokens a day (one per undecided pattern)")  # fmt: skip
    assert model["why"] == expected
    long = [row("r1", 0, known, note="y" * 4000)] + [row("r1", 0, known) for _ in range(39)]
    (_, _, top) = soak.measure(long)
    small = int(top["why"].split("p95 ")[1].split(" ")[0])
    assert small < 200  # the 95th percentile of 40: the 39th smallest, not the one long digest
    (_, _, all_long) = soak.measure([row("r1", 0, known, note="y" * 4000)])
    assert int(all_long["why"].split("p95 ")[1].split(" ")[0]) > 900
    assert soak.measure([]) == [{"criterion": "Phase 2 measurements", "result": "INFO",
                                 "why": "no dossiers yet"}]  # fmt: skip


def labelled(rule: str, n: int, have: int, people: int) -> SimpleNamespace:
    return SimpleNamespace(rule=rule, investigations=n, labelled=have, by_people=people)


def test_the_labels_judgement_exactly() -> None:
    name = "≥ 30 reviewer labels per rule (or all of a rule's investigations)"
    assert soak.judge_labels([]) == {"criterion": name, "result": "PENDING",
                                     "why": "no investigations yet"}  # fmt: skip
    rows = [labelled("big", 900, 29, 4), labelled("small", 5, 5, 0), labelled("mid", 40, 31, 1),
            labelled("none", 100, 0, 0), labelled("tiny", 3, 2, 2)]  # fmt: skip
    got = soak.judge_labels(rows)
    assert got == {"criterion": name, "result": "PENDING",
                   "why": "2 of 5 rules done; furthest behind: none 0/30, big 29/30, tiny 2/3;"
                          " 7 by people, 60 by the assistant (D-071)"}  # fmt: skip
    done = soak.judge_labels([labelled("a", 30, 30, 30), labelled("b", 2, 2, 0)])
    assert done == {"criterion": name, "result": "PASS",
                    "why": "all 2 rules have their labels; 30 by people, 2 by the assistant"
                           " (D-071)"}  # fmt: skip
    edge = soak.judge_labels([labelled("e", 31, 30, 0)])
    assert edge["result"] == "PASS"  # 30 of 31 is enough


async def test_the_report_window_is_now_minus_the_soak_and_an_hour(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    start = datetime.now(UTC) - soak.SOAK - timedelta(minutes=30)
    async with migrated_engine.begin() as conn:
        for at in (start, start - timedelta(hours=1)):
            await conn.execute(text("INSERT INTO soak_samples (at, metrics) VALUES (:a, '{}')"),
                               {"a": at})  # fmt: skip
    async with app_engine.connect() as conn:
        out = await soak.report(conn)  # "now" by default
    assert out[0]["why"].startswith("0.0 h of samples since")  # the older sample is outside


async def test_labels_count_a_recreated_rule_as_one(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """A rule recreated in Kibana keeps its name but gets a new id: one rule for the labels."""
    from argus.web import auth

    async with app_engine.begin() as conn:
        person = await auth.add_user(conn, "asha", "Asha", "a long pass phrase 1")
        assistant = await auth.add_user(conn, soak.ASSISTANT, "Assistant", "a long pass phrase 2")
    rows = [("old-id", "Scan", 3), ("new-id", "Scan", 2), ("x-id", None, 1)]
    async with migrated_engine.begin() as conn:
        n = 0
        for rule_id, name, count in rows:
            for _ in range(count):
                n += 1
                await conn.execute(
                    text(
                        "INSERT INTO investigations (id, grouping_version, rule_id, rule_name,"
                        " group_key, bucket_start, bucket_end, previous_id, alert_count,"
                        " first_event_at, last_event_at, severity, version) VALUES (:id, '1',"
                        " :rule, :name, '[]', :t, :end, :id, 1, :t, :t, 'low', 1)"
                    ),
                    {"id": f"00000000-0000-0000-0000-{n:012d}", "rule": rule_id, "name": name,
                     "t": T0, "end": T0 + timedelta(days=1)},
                )  # fmt: skip
        for n, user, outcome in ((1, person, "true_positive"), (4, assistant, "benign_expected"),
                                 (5, person, None)):  # fmt: skip
            await conn.execute(
                text(
                    "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                    " action, outcome) VALUES (:id, 1, 1, :u, :a, :o)"
                ),
                {"id": f"00000000-0000-0000-0000-{n:012d}", "u": user,
                 "a": "reviewed" if outcome else "note", "o": outcome},
            )  # fmt: skip
    async with app_engine.connect() as conn:
        result = await soak.labels(conn)
    assert result["result"] == "PENDING"
    assert result["why"] == (
        "0 of 2 rules done; furthest behind: Scan 2/5, x-id 0/1;"
        " 1 by people, 1 by the assistant (D-071)"
    )
