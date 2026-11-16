"""A collector gap's reading (D-321, ``argus.collector.lateness``): late, caught up and nothing
missed only when it closed within the hour and the first reconciliation after the close that
covered its hours (and every one before it touching them) found nothing; else late but not
checked yet, or an outage. The SQL against the reporter oracle's own definition, on cases and
on many random ones."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.collector.lateness import LATE_KIND, LATE_WITHIN, reading_sql
from tests.integration.reporter.oracle import caught_up

pytestmark = pytest.mark.integration

H = timedelta(hours=1)
M = timedelta(minutes=1)
T = datetime(2026, 11, 13, 18, 0, tzinfo=UTC)  # the evening of production's longest gap


def gap(start: datetime, end: datetime | None, kind: str = LATE_KIND) -> dict[str, Any]:
    return {"kind": kind, "start_at": start, "end_at": end}


def run(started: datetime, *, differed: int = 0, recovered: int = 0, outcome: str = "ok",
        span: timedelta = 24 * H) -> dict[str, Any]:  # fmt: skip
    """An hourly reconciliation begun at ``started``: the whole hours of ``span`` before it."""
    last = started.replace(minute=0, second=0, microsecond=0)
    return {"started_at": started, "window_start": last - span, "window_end": last,
            "differed": differed, "recovered": recovered, "outcome": outcome}  # fmt: skip


async def readings(
    engine: AsyncEngine, gaps: list[dict[str, Any]], runs: list[dict[str, Any]],
    asof: datetime | None = None,
) -> list[str]:  # fmt: skip
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM coverage_gaps"))
        await conn.execute(text("DELETE FROM reconciliation_runs"))
        for n, g in enumerate(gaps):
            await conn.execute(
                text("INSERT INTO coverage_gaps (kind, subject, start_at, end_at)"
                     " VALUES (:kind, :subject, :start_at, :end_at)"),
                {**g, "subject": f"s{n}"},
            )  # fmt: skip
        for r in runs:
            await conn.execute(
                text("INSERT INTO reconciliation_runs (started_at, finished_at, window_start,"
                     " window_end, hours, hours_mismatched, recovered, missing_in_es, outcome)"
                     " VALUES (:started_at, :started_at, :window_start, :window_end, 24,"
                     " :differed, :recovered, 0, :outcome)"),
                r,
            )  # fmt: skip
        where = None if asof is None else "CAST(:asof AS timestamptz)"
        rows = await conn.execute(
            text(f"SELECT {reading_sql('g', where)} FROM coverage_gaps g ORDER BY subject"),  # noqa: S608 - a constant fragment
            {} if asof is None else {"asof": asof},
        )
        return [r[0] for r in rows]


async def test_the_readings(migrated_engine: AsyncEngine) -> None:
    short = gap(T + 19 * M, T + 59 * M)  # 40 minutes, inside one hour
    cases: list[tuple[str, dict[str, Any], list[dict[str, Any]]]] = [
        ("late", short, [run(T + 59 * M), run(T + H + 59 * M)]),
        # the run right after the close does not cover the hour it ended in
        ("late_unchecked", short, [run(T + 59 * M)]),
        ("late_unchecked", short, []),
        ("outage", short, [run(T + H + 59 * M, differed=1)]),
        ("outage", short, [run(T + H + 59 * M, recovered=3)]),
        # a difference found by a run after the close, before the covering one, in the
        # gap's first hour; and one in hours before the gap, which says nothing of it
        (
            "outage",
            gap(T + 50 * M, T + H + 10 * M),
            [run(T + H + 15 * M, differed=1), run(T + 2 * H + 5 * M)],
        ),
        ("late", short, [run(T + 59 * M, differed=1, span=H), run(T + H + 59 * M)]),
        # one found later than the first covering run is another gap's business
        ("late", short, [run(T + H + 59 * M), run(T + 2 * H + 59 * M, differed=1)]),
        # a run during the gap (the poll was behind) is not a miss
        ("late", short, [run(T + 30 * M, recovered=5), run(T + H + 59 * M)]),
        # a failed run does not check, and what it found before failing counts
        ("late_unchecked", short, [run(T + H + 59 * M, outcome="timed_out")]),
        (
            "outage",
            short,
            [run(T + H + 1 * M, outcome="timed_out", recovered=1), run(T + 2 * H + 1 * M)],
        ),
        # a run that does not reach back to the gap's first hour does not cover it
        ("late_unchecked", gap(T + 50 * M, T + H + 10 * M), [run(T + 2 * H + 5 * M, span=H)]),
        ("late", gap(T + 50 * M, T + H + 10 * M), [run(T + 2 * H + 5 * M)]),  # two hours
        ("outage", gap(T, T + LATE_WITHIN), [run(T + 2 * H + 5 * M)]),  # an hour: not late
        ("late", gap(T, T + LATE_WITHIN - M), [run(T + H + 5 * M)]),
        ("outage", gap(T + 19 * M, None), [run(T + 2 * H)]),  # still open
        ("outage", gap(T + 19 * M, T + 59 * M, "breaker_open"), [run(T + 2 * H)]),
        # closed at once: the hour it is in is reconciled from the next hour on
        ("late_unchecked", gap(T + 19 * M, T + 19 * M), [run(T + 19 * M)]),
        ("late", gap(T + 19 * M, T + 19 * M), [run(T + H + 19 * M)]),
    ]
    got = await readings(migrated_engine, [c[1] for c in cases[:1]], cases[0][2])
    assert got == ["late"]
    for want, g, runs in cases:
        assert await readings(migrated_engine, [g], runs) == [want], (want, g, runs)


async def test_a_report_reads_as_at_its_making(migrated_engine: AsyncEngine) -> None:
    short = gap(T + 19 * M, T + 59 * M)
    runs = [run(T + H + 59 * M)]
    assert await readings(migrated_engine, [short], runs, asof=T + 3 * H) == ["late"]
    assert await readings(migrated_engine, [short], runs, asof=T + H + 30 * M) == ["late_unchecked"]
    assert await readings(migrated_engine, [short], runs, asof=T + 30 * M) == ["outage"]  # open


def _random_world(rng: random.Random) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    gaps = []
    for _ in range(rng.randint(1, 4)):
        start = T + rng.randint(0, 300) * M
        end = None if rng.random() < 0.1 else start + rng.randint(0, 100) * M
        kind = LATE_KIND if rng.random() < 0.9 else "breaker_open"
        gaps.append(gap(start, end, kind))
    runs = []
    for _ in range(rng.randint(0, 5)):
        started = T + rng.randint(0, 480) * M
        outcome = rng.choice(["ok", "ok", "ok", "timed_out"])
        span = rng.choice([H, 3 * H, 24 * H])
        runs.append(run(
            started, differed=rng.choice([0, 0, 0, 1]), recovered=rng.choice([0, 0, 0, 2]),
            outcome=outcome, span=span,
        ))  # fmt: skip
    return gaps, runs


async def test_the_sql_agrees_with_the_definition(migrated_engine: AsyncEngine) -> None:
    rng = random.Random(321)
    seen: set[str] = set()
    for _ in range(150):
        gaps, runs = _random_world(rng)
        asof = T + rng.randint(0, 600) * M
        got = await readings(migrated_engine, gaps, runs, asof=asof)
        oracle_runs = [
            SimpleNamespace(started_at=r["started_at"], window_start=r["window_start"],
                            window_end=r["window_end"], hours_mismatched=r["differed"],
                            recovered=r["recovered"], outcome=r["outcome"])
            for r in runs
        ]  # fmt: skip
        seen.update(got)
        for g, reading in zip(gaps, got, strict=True):
            late = caught_up(SimpleNamespace(**g), oracle_runs, asof)
            assert (reading == "late") == late, (g, runs, asof, reading)
            short = (
                g["kind"] == LATE_KIND and g["end_at"] is not None and g["end_at"] <= asof
                and g["end_at"] - g["start_at"] < LATE_WITHIN
            )  # fmt: skip
            if not short:
                assert reading == "outage"
    assert seen == {"late", "late_unchecked", "outage"}  # every reading was exercised
