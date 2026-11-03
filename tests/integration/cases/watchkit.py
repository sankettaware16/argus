"""A small world for the still-active watch (Q-C2): investigations with alerts at chosen times,
cases opened at a fake time, Q-F1's readings, the collector's cursor, and a fake gateway that
answers ``proxy.contact`` from a table. Time is always passed in, never read: the watch takes
``now``, and the case service is built with the fake time."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable, Sequence
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.cases import membership, watchrun
from argus.cases.machine import Contain, Open
from argus.cases.model import Indicator, Member, QuietWindow
from argus.cases.service import Applied, CaseService
from argus.context import beacon
from argus.context.packs import TaskSpec
from argus.freshness.shadow import Policy
from tests.integration.cases.conftest import KIBANA, Person

C2 = "77.221.155.150"
H1, H2, H3 = "10.8.235.157", "10.198.50.62", "10.9.1.7"
D0 = date(2026, 10, 14)
MARGIN = timedelta(minutes=2)
HISTORY = timedelta(days=5)


def at(day: int, hour: int = 0, minute: int = 0) -> datetime:
    """``hour:minute`` UTC, ``day`` days after D0."""
    return datetime.combine(D0 + timedelta(days=day), time(hour, minute), UTC)


def policy(mode: str = "on", bridge: str = "none") -> Policy:
    return Policy(mode=mode, margins={"squid": MARGIN}, bridge=bridge)  # type: ignore[arg-type]


class FakeAsker:
    """A gateway with fixture answers: ``contacts[day]`` is (requests per host, the newest
    contact); a day not in the table has no contact. ``refuse`` makes every question a refusal
    (``stopped``, ``deferred``, ...); ``now`` is when it is asked."""

    def __init__(self) -> None:
        self.now = at(0)
        self.contacts: dict[date, tuple[dict[str, int], datetime]] = {}
        self.refuse: str | None = None
        self.only: set[str] | None = None  # the addresses with contact (default: all)
        self.asked: list[tuple[str, date, str]] = []
        self.failing = False

    def beacon(self, days: Iterable[int], hosts: Sequence[str], hour: int = 12) -> None:
        for day in days:
            self.contacts[D0 + timedelta(days=day)] = (dict.fromkeys(hosts, 288), at(day, hour, 30))

    async def ask(self, task: TaskSpec) -> watchrun.Answer:
        params = task.params
        name = type(task.template).name
        day = params.start.date()
        self.asked.append((name, day, params.destination))  # type: ignore[attr-defined]
        if self.refuse is not None:
            return watchrun.Answer(self.now, refused=self.refuse)
        if self.failing:
            return watchrun.Answer(self.now, refused="failed", sent=True)
        if isinstance(params, beacon.ContactParams):
            seen, last = self.contacts.get(day, ({}, None))
            if self.only is not None and params.destination not in self.only:
                seen = {}
            seen = {h: n for h, n in seen.items() if not params.hosts or h in params.hosts}
            aggs: dict[str, Any] = {
                "requests": {"value": sum(seen.values())},
                "hosts": {
                    "buckets": [
                        {"key": h, "doc_count": n, "first": {"value": 1}, "last": {"value": 2}}
                        for h, n in sorted(seen.items())
                    ]
                },
            }
            if seen and last is not None:
                aggs["last"] = {"value": int(last.timestamp() * 1000)}
            body = {"timed_out": False, "_shards": {"failed": 0}, "aggregations": aggs}
            return watchrun.Answer(self.now, body=body, sent=True)
        assert isinstance(params, beacon.PairParams)
        seen, last = self.contacts.get(day, ({}, None))
        first = int(params.start.timestamp() * 1000)
        beats = (
            int((params.end - params.start).total_seconds()) // 360 if params.host in seen else 0
        )
        body = {  # a beat every 6 minutes
            "aggregations": {
                "beats": {"buckets": [{"key": first + n * 360_000, "doc_count": 1}
                                      for n in range(beats)]},
                "requests": {"value": beats},
                "first": {"value": first},
                "last": {"value": first + max(beats - 1, 0) * 360_000},
            }
        }  # fmt: skip
        return watchrun.Answer(self.now, body=body, sent=True)


def context(asker: FakeAsker | None, *, fresh: str = "on", pair: bool = False) -> watchrun.Context:
    """A run's context; no asker is mode ``local``. ``fresh``: Q-F1's mode."""
    return watchrun.Context(
        IpClassifier(None), membership.load_shared(), policy(fresh), HISTORY, asker, pair
    )


class World:
    def __init__(self, owner: AsyncEngine, runtime: AsyncEngine) -> None:
        self.owner = owner
        self.runtime = runtime
        self.read_until = at(0, 1, 30)  # readings exist up to here

    # ------------------------------------------------------------------ the data

    async def investigation(
        self,
        host: str,
        alerts: Sequence[datetime],
        *,
        entities: Sequence[tuple[str, str]] = (("ip", C2),),
        rule: str = "c2",
        severity: str = "high",
    ) -> uuid.UUID:
        """An investigation of ``host`` (its actor) with one alert at each time."""
        inv = uuid.uuid4()
        first, last = min(alerts), max(alerts)
        key = json.dumps([["source.ip", host]], separators=(",", ":"))
        async with self.owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO investigations (id, grouping_version, rule_id, rule_name,"
                    " group_key, bucket_start, bucket_end, previous_id, severity, alert_count,"
                    " first_event_at, last_event_at, version) VALUES (:id, '2', :rule, :name,"
                    " :key, :bs, :be, :prev, :sev, :n, :first, :last, 1)"
                ),
                {"id": inv, "rule": rule, "name": f"Rule {rule}", "key": key,
                 "bs": first - timedelta(hours=1), "be": last + timedelta(hours=23),
                 "prev": uuid.uuid4(), "sev": severity, "n": len(alerts), "first": first,
                 "last": last},
            )  # fmt: skip
            for kind, value in sorted({("ip", host), *entities}):
                await conn.execute(
                    text(
                        "INSERT INTO investigation_entities (investigation_id, kind, value)"
                        " VALUES (:i, :k, :v) ON CONFLICT DO NOTHING"
                    ),
                    {"i": inv, "k": kind, "v": value},
                )
        for when in alerts:
            await self._alert(inv, when)
        return inv

    async def _alert(self, inv: uuid.UUID, when: datetime) -> None:
        alert_id = f"{inv.hex}-{int(when.timestamp())}"
        async with self.owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO alert_records (alert_id, index, status, normalizer_version, raw,"
                    " content_hash, state_hash, recovered_by, detected_at, event_time)"
                    " VALUES (:a, 'alerts', 'normalized', 'test', '{}', 'h', 'h', 'live', :at,"
                    " :at) ON CONFLICT DO NOTHING"
                ),
                {"a": alert_id, "at": when},
            )
            await conn.execute(
                text(
                    "INSERT INTO investigation_alerts (alert_id, investigation_id)"
                    " VALUES (:a, :i) ON CONFLICT DO NOTHING"
                ),
                {"a": alert_id, "i": inv},
            )
            await conn.execute(
                text(
                    "UPDATE investigations SET last_event_at = greatest(last_event_at, :at),"
                    " alert_count = alert_count + 1 WHERE id = :i"
                ),
                {"at": when, "i": inv},
            )

    async def add_alert(self, inv: uuid.UUID, when: datetime) -> None:
        await self._alert(inv, when)

    async def open_case(
        self,
        person: Person,
        members: Sequence[uuid.UUID],
        hosts: Sequence[str],
        now: datetime,
        *,
        c2: str | Sequence[str] | None = C2,
        mirrored: bool = True,
    ) -> uuid.UUID:
        """A confirmed case opened at ``now`` with its hosts as actors and its C2 address(es)."""
        marks = [Indicator("ip", h, "actor") for h in hosts]
        for value in [c2] if isinstance(c2, str) else list(c2 or ()):
            marks.append(Indicator("ip", value, "c2", "threat_intel"))
        actor = person.actor(kibana=KIBANA, checked_at=now) if mirrored else person.actor()
        async with self.runtime.begin() as conn:
            service = CaseService(conn, now)
            applied = await service.open(actor, Open(
                "Regular beaconing from campus hosts", "high", "person",
                tuple(Member(i, "person") for i in members), tuple(marks)))  # fmt: skip
        return applied.case.id

    # ------------------------------------------------------------------ the freshness lane

    async def readings(self, until: datetime) -> None:
        """Q-F1's readings of squid every 5 minutes from where they stopped to ``until``, none
        in the nightly pause (00:00 to 01:30 UTC), each with a lag of 20 seconds."""
        rows = []
        moment = self.read_until
        while moment <= until:
            if not time(0, 0) <= moment.time() < time(1, 30):
                rows.append({"at": moment, "event": moment - timedelta(seconds=20),
                             "ingested": moment - timedelta(seconds=5)})  # fmt: skip
            moment += timedelta(minutes=5)
        self.read_until = moment
        if rows:
            async with self.owner.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO freshness_readings (source, sent_at, at, outcome, ingested,"
                        " event_at) VALUES ('squid', :at, :at, 'ok', :ingested, :event)"
                    ),
                    rows,
                )

    def skip_readings(self, until: datetime) -> None:
        """No readings until ``until``: STOP, a switch, an outage."""
        self.read_until = until

    async def cursor(self, when: datetime) -> None:
        async with self.owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO collector_cursors (name, at) VALUES ('live', :at)"
                    " ON CONFLICT (name) DO UPDATE SET at = EXCLUDED.at"
                ),
                {"at": when},
            )

    async def gap(self, start: datetime, end: datetime | None) -> None:
        async with self.owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO coverage_gaps (kind, subject, start_at, end_at)"
                    " VALUES ('source_stalled', 'squid', :s, :e)"
                ),
                {"s": start, "e": end},
            )

    # ------------------------------------------------------------------ the watch

    async def run(
        self, ctx: watchrun.Context, now: datetime, *, live: bool = True, apply: bool = True
    ) -> watchrun.Report:
        """One run of the watch at ``now`` (freshness readings and the collector's cursor are
        brought up to date first, unless ``live`` is false: an outage)."""
        if isinstance(ctx.asker, FakeAsker):
            ctx.asker.now = now
        if live:
            await self.readings(now)
            await self.cursor(now)
        return await watchrun.run(self.runtime, ctx, now=now, apply=apply)

    async def rows(self, case_id: uuid.UUID) -> dict[tuple[date, str, str, int], str]:
        async with self.owner.connect() as conn:
            found = await conn.execute(
                text(
                    "SELECT day, source, subject, part, outcome FROM case_watch_checks"
                    " WHERE case_id = :c ORDER BY day, source, subject, part"
                ),
                {"c": case_id},
            )
            return {(r.day, r.source, r.subject, r.part): r.outcome for r in found}

    async def finder_window(self, ctx: watchrun.Context, case_id: uuid.UUID, now: datetime) -> Any:
        async with self.runtime.begin() as conn:
            service = CaseService(conn, now)
            case = await service.get(case_id)
            assert case is not None
            return await watchrun.Finder(conn, ctx, lambda: now)(case)

    async def contain(
        self, ctx: watchrun.Context, person: Person, case_id: uuid.UUID, now: datetime
    ) -> Applied:
        """A person contains the case at ``now``: the service asks the watch, never the caller."""
        async with self.runtime.begin() as conn:
            service = CaseService(conn, now, watchrun.Finder(conn, ctx, lambda: now))
            return await service.apply(
                person.actor(), case_id,
                Contain("the three hosts were cleaned", QuietWindow(False, "the service decides")),
                expected_version=None,
            )  # fmt: skip

    async def case(self, case_id: uuid.UUID) -> Any:
        async with self.owner.connect() as conn:
            return (
                await conn.execute(
                    text(
                        "SELECT id, number, state, attention, version, owner_user_id, closed_at"
                        " FROM cases WHERE id = :c"
                    ),
                    {"c": case_id},
                )
            ).one()

    async def members(self, case_id: uuid.UUID) -> set[uuid.UUID]:
        async with self.owner.connect() as conn:
            found = await conn.execute(
                text(
                    "SELECT investigation_id FROM case_members WHERE case_id = :c"
                    " AND removed_at IS NULL"
                ),
                {"c": case_id},
            )
            return set(found.scalars())

    async def actors(self, case_id: uuid.UUID) -> set[str]:
        async with self.owner.connect() as conn:
            found = await conn.execute(
                text("SELECT value FROM case_indicators WHERE case_id = :c AND role = 'actor'"),
                {"c": case_id},
            )
            return set(found.scalars())

    async def events(self, case_id: uuid.UUID) -> list[str]:
        async with self.owner.connect() as conn:
            found = await conn.execute(
                text("SELECT kind FROM case_events WHERE case_id = :c ORDER BY case_version"),
                {"c": case_id},
            )
            return list(found.scalars())

    async def outbox(self, case_id: uuid.UUID) -> list[tuple[str, str]]:
        async with self.owner.connect() as conn:
            found = await conn.execute(
                text("SELECT write_class, op FROM kibana_outbox WHERE case_id = :c ORDER BY id"),
                {"c": case_id},
            )
            return [(r.write_class, r.op) for r in found]

    async def case_ids(self) -> list[uuid.UUID]:
        async with self.owner.connect() as conn:
            found = await conn.execute(text("SELECT id FROM cases ORDER BY number"))
            return list(found.scalars())
