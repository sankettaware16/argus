# ruff: noqa: S608 - the f-strings put fixed fragments (GOOD_RUN, state lists) in the SQL; values are bound
"""The ramp: how many units a run of a class may write, and what must be true before it writes more.

A class starts at step 1 (its canary: one case, change or closure, with a person present). It
moves to 5 and then to at most 10 only after at least 3 runs on 3 different days at its step (or
5 working days), every write read back as sent, no reconciliation alarm since the step began (one
a person explained, ``argus kibana sync explain``, does not count), and a person's check in
Kibana. Only a run that sent something and stopped for no reason counts.
Nothing is raised while a writer finding waits for a person, the class is paused in the lane, or
a write is in doubt, in conflict or paused. The classes go in order (W2 after W1's canary and one
more run, W3 after W2's) and the service runs a class only after a clean canary at a terminal and
a step above 1."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.gateway.kibana import writes
from argus.writer import store

STEPS = (1, 5, 10)
BEFORE = {"W2": "W1", "W3": "W2"}  # the order the classes are first used in
MIN_RUNS, MIN_DAYS, MIN_WORKING_DAYS = 3, 3, 5
# a run that counts: it sent, every write it sent was read back as sent, and nothing stopped it
GOOD_RUN = (
    "finished_at IS NOT NULL AND sent >= 1 AND verified = sent AND mismatches = 0"
    " AND ambiguous = 0 AND stopped IS NULL"
)
WRITER_FINDINGS = "('duplicate_case', 'answer_unexpected')"
IN_DOUBT = "('ambiguous', 'conflict', 'paused')"


@dataclass(frozen=True)
class Evidence:
    step: int
    since: datetime | None
    runs: int = 0
    days: int = 0
    clean: bool = True
    alarms: int = 0
    first: datetime | None = None
    why_not: list[str] = field(default_factory=list)
    unresolved: int = 0  # writer findings waiting for a person
    in_doubt: int = 0  # this class's writes ambiguous, in conflict or paused
    paused: str | None = None  # why the lane has the class paused

    @property
    def ready(self) -> bool:
        return not self.why_not


def working_days(start: datetime, end: datetime) -> int:
    """Monday to Friday dates from ``start``'s to ``end``'s, both counted."""
    day, count = start.date(), 0
    while day <= end.date():
        count += day.weekday() < 5
        day += timedelta(days=1)
    return count


async def since(conn: AsyncConnection, write_class: str) -> datetime | None:
    found: datetime | None = (
        await conn.execute(
            text("SELECT since FROM kibana_writer_ramp WHERE write_class = :c"), {"c": write_class}
        )
    ).scalar_one_or_none()
    return found


async def evidence(conn: AsyncConnection, write_class: str, now: datetime) -> Evidence:
    """What the class's runs at its current step show, and what is still missing."""
    step = await store.ramp_step(conn, write_class)
    began = await since(conn, write_class)
    row = (
        await conn.execute(
            text(
                f"SELECT count(*) FILTER (WHERE {GOOD_RUN}) AS runs,"
                f" count(DISTINCT (started_at AT TIME ZONE 'UTC')::date)"
                f" FILTER (WHERE {GOOD_RUN}) AS days,"
                f" coalesce(bool_and({GOOD_RUN}) FILTER (WHERE sent >= 1), true) AS clean,"
                f" min(started_at) FILTER (WHERE {GOOD_RUN}) AS first FROM kibana_writer_runs"
                " WHERE write_class = :c AND step = :s AND finished_at IS NOT NULL"
                " AND (CAST(:t AS timestamptz) IS NULL OR started_at >= :t)"
            ),
            {"c": write_class, "s": step, "t": began},
        )
    ).one()
    unresolved = (
        await conn.execute(
            text(
                f"SELECT count(*) FROM kibana_findings WHERE resolved_at IS NULL"
                f" AND kind IN {WRITER_FINDINGS}"
            )
        )
    ).scalar_one()
    in_doubt = (
        await conn.execute(
            text(
                f"SELECT (SELECT count(*) FROM kibana_outbox WHERE write_class = :c"
                f" AND state IN {IN_DOUBT}) + (SELECT count(*) FROM kibana_steps"
                f" WHERE write_class = :c AND state IN {IN_DOUBT})"
            ),
            {"c": write_class},
        )
    ).scalar_one()
    paused = await lane_paused(conn, write_class)
    alarms = (
        await conn.execute(
            text(
                "SELECT count(*) FROM kibana_findings WHERE severity = 'alarm'"
                " AND resolved_at IS NULL"  # an alarm a person explained holds no step back
                " AND (CAST(:t AS timestamptz) IS NULL OR found_at >= :t)"
            ),
            {"t": began},
        )
    ).scalar_one()
    why: list[str] = []
    if step == STEPS[-1]:
        why.append("it is at the last step (10 a run)")
    enough = row.runs >= MIN_RUNS and row.days >= MIN_DAYS
    waited = (
        row.runs >= 1
        and row.first is not None
        and working_days(row.first, now) >= (MIN_WORKING_DAYS)
    )
    if not (enough or waited):
        why.append(
            f"{row.runs} runs on {row.days} days at step {step}: needs {MIN_RUNS} runs on"
            f" {MIN_DAYS} days (or {MIN_WORKING_DAYS} working days after a clean run)"
        )
    if not row.clean:
        why.append("a run at this step did not read every write back as sent")
    if alarms:
        why.append(f"{alarms} reconciliation alarms since this step began")
    if unresolved:
        why.append(f"{unresolved} findings of the writer wait for a person (Needs attention)")
    if in_doubt:
        why.append(f"{in_doubt} writes of {write_class} are in doubt, in conflict or paused")
    if paused:
        why.append(f"{write_class} is paused in the lane ({paused})")
    return Evidence(
        step, began, row.runs, row.days, bool(row.clean), alarms, row.first, why,
        unresolved, in_doubt, paused,
    )  # fmt: skip


async def lane_paused(conn: AsyncConnection, write_class: str) -> str | None:
    """Why the Kibana lane has the class paused (a wrong answer, a 403, a mismatching
    read-back, a landing twice), or None. The lane's state is one row the services share."""
    state = (
        await conn.execute(text("SELECT state FROM siem_state WHERE name = 'kibana'"))
    ).scalar_one_or_none()
    if not isinstance(state, dict):
        return None
    paused = writes.from_json(state).paused
    return paused.get(write_class)


async def canary_done(conn: AsyncConnection, write_class: str) -> bool:
    """A canary run of the class at a terminal sent something and read every write back."""
    done = (
        await conn.execute(
            text(
                f"SELECT count(*) FROM kibana_writer_runs WHERE write_class = :c"
                f" AND kind = 'canary' AND {GOOD_RUN}"
            ),
            {"c": write_class},
        )
    ).scalar_one()
    return bool(done)


async def scheduled_problem(conn: AsyncConnection, write_class: str) -> str | None:
    """Why the service may not run the class on its own: a person has to run its canary at a
    terminal first (one case, one change or one closure, checked in Kibana's UI), and raise it
    above step 1. The service is never a class's first writer."""
    if not await canary_done(conn, write_class):
        return (
            f"{write_class} has no clean canary run: a person runs `argus kibana run --class"
            f" {write_class}` at a terminal first"
        )
    if await store.ramp_step(conn, write_class) <= STEPS[0]:
        return (
            f"{write_class} is still at its canary step: a person raises it (`argus kibana"
            " ramp`) before the service runs it"
        )
    return None


async def first_use_problem(conn: AsyncConnection, write_class: str) -> str | None:
    """Why the class may not be used yet: the one before it has not had its canary and one more
    clean run (the order is W1, W2, W3)."""
    before = BEFORE.get(write_class)
    if before is None:
        return None
    done = (
        await conn.execute(
            text(f"SELECT count(*) FROM kibana_writer_runs WHERE write_class = :c AND {GOOD_RUN}"),
            {"c": before},
        )
    ).scalar_one()
    if done < 2:
        return (
            f"{write_class} begins after {before}'s canary and one more run"
            f" ({before} has {done} clean runs)"
        )
    return None


async def raise_step(
    conn: AsyncConnection, write_class: str, to: int, by: str, note: str, now: datetime
) -> None:
    """Record the next step (the caller has checked the evidence and the person)."""
    await conn.execute(
        text(
            "INSERT INTO kibana_writer_ramp (write_class, step, since, changed_by, note)"
            " VALUES (:c, :s, :now, :by, :n) ON CONFLICT (write_class) DO UPDATE SET"
            " step = :s, since = :now, changed_by = :by, note = :n"
        ),
        {"c": write_class, "s": to, "now": now, "by": by, "n": note[:500]},
    )
    await store.audit(
        conn,
        "kibana.ramp.raised",
        write_class,
        {"class": write_class, "step": to, "by": by, "note": note[:200]},
        target_type="writer",
    )
