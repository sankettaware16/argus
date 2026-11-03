"""What the read-back keeps: the mirror, its state, cycles, findings and people's cases.
``PgSyncStore`` (as the runtime role) and ``MemorySyncStore`` (tests and simulations) behave alike;
each case's change is one transaction, so a crash mid-cycle loses at most the case being read,
and findings are kept once each (their key)."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.kibana_sync.model import (
    AlertState,
    Finding,
    KCase,
    Mirror,
    SentWrite,
    TeamPost,
    clean,
)

# The case team's step kinds and the operation each one's request is (``classify.capacity``).
TEAM_OPS = {
    "open": "create",
    "comment": "comment",
    "file": "comment",  # a file is a comment of type externalReference
    "attach": "attach",
    "retitle": "title",
    "redescribe": "description",
    "edit_comment": "edit_comment",
}
SENT_STATES = ("sending", "sent", "verified", "ambiguous", "conflict", "paused", "skipped")


@dataclass(frozen=True)
class SyncState:
    changes_from: datetime | None = None
    last_cycle_at: datetime | None = None
    last_complete_at: datetime | None = None
    last_status_at: datetime | None = None
    last_discovery_at: datetime | None = None
    last_closed_listing_at: datetime | None = None
    discovery_cursor: str | None = None
    diff_cursor: str | None = None  # where the alert-status diff stopped (``cycle`` reads it)
    alerts_checked_to: datetime | None = None
    clock_offset_ms: int | None = None
    clock_checked_at: datetime | None = None


@dataclass(frozen=True)
class CycleRecord:
    started_at: datetime
    finished_at: datetime
    outcome: str  # complete, partial, failed
    reason: str | None
    health: str | None
    reads: int
    changed: int
    findings: int
    oldest_read_s: int | None
    stale: bool
    clock_offset_ms: int | None
    detail: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PeopleCase:
    kibana_case_id: str
    title: str
    status: str
    created_by: str
    tags: tuple[str, ...]
    known_alerts: tuple[str, ...]
    kibana_updated_at: datetime | None
    read_at: datetime


class SyncStore(Protocol):
    async def state(self) -> SyncState: ...
    async def save_state(self, state: SyncState) -> None: ...
    async def mirrors(self) -> dict[str, Mirror]: ...  # by Kibana case id, deleted included
    async def sent_writes(
        self, case_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, list[SentWrite]]: ...
    async def sent_creates(self, case_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, int]: ...
    async def team_posts(
        self, kibana_case_ids: Sequence[str], incident_ids: Sequence[str]
    ) -> list[TeamPost]: ...  # the case team's posts holding one of these Kibana ids or incidents
    async def apply(
        self, mirror: Mirror, findings: Sequence[Finding], *, new: bool, found_at: datetime
    ) -> int: ...
    async def touch(self, kibana_case_ids: Sequence[str], at: datetime) -> None: ...
    async def add_findings(self, findings: Sequence[Finding], found_at: datetime) -> int: ...
    async def unseen_keys(self, keys: Sequence[str]) -> frozenset[str]: ...  # not yet a finding
    async def people_cases(self) -> dict[str, PeopleCase]: ...
    async def save_people_case(self, case: PeopleCase, found_at: datetime) -> None: ...
    async def known_alerts(
        self, after: str | None, since: datetime, limit: int
    ) -> list[tuple[str, str]]: ...
    async def explained_alerts(self, alert_ids: Sequence[str]) -> frozenset[str]: ...
    async def alert_states(self, alert_ids: Sequence[str]) -> dict[str, AlertState]: ...
    async def save_alert_states(self, states: Sequence[AlertState]) -> None: ...
    async def record_alerts(
        self, states: Sequence[AlertState], findings: Sequence[Finding], found_at: datetime
    ) -> int: ...  # the baselines and the findings found against the old ones: one transaction
    async def record_cycle(self, record: CycleRecord) -> None: ...


def finding_key(finding: Finding) -> str:
    """The key a finding is kept under (the column holds 400 characters)."""
    return clean(finding.dedupe_key)[:400]


def clean_json(value: Any) -> Any:
    """A finding's details without a character the database refuses, in any string, key
    or nesting."""
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, Mapping):
        return {clean(str(k)): clean_json(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [clean_json(v) for v in value]
    return value


def cursor_of(first_seen: datetime, alert_id: str) -> str:
    return f"{first_seen.isoformat()}|{alert_id}"


def _split(cursor: str | None) -> tuple[datetime, str] | None:
    if not cursor or "|" not in cursor:
        return None
    at, _, alert = cursor.partition("|")
    try:
        return datetime.fromisoformat(at), alert
    except ValueError:
        return None


@dataclass
class MemorySyncStore:
    """In memory, as Postgres keeps it (the tests hold both to the same behaviour)."""

    sync: SyncState = field(default_factory=SyncState)
    mirror: dict[str, Mirror] = field(default_factory=dict)
    sent: dict[uuid.UUID, list[SentWrite]] = field(default_factory=dict)
    posts: dict[uuid.UUID, TeamPost] = field(default_factory=dict)  # the case team's posts
    findings: dict[str, tuple[datetime, Finding]] = field(default_factory=dict)
    people: dict[str, PeopleCase] = field(default_factory=dict)
    alerts: list[tuple[datetime, str]] = field(default_factory=list)  # (first seen, id)
    wa_sent: set[str] = field(default_factory=set)
    alert_state: dict[str, AlertState] = field(default_factory=dict)
    cycles: list[CycleRecord] = field(default_factory=list)
    crash_after: int | None = None  # tests: fail the n-th apply from now (a crash mid-cycle)

    async def state(self) -> SyncState:
        return self.sync

    async def save_state(self, state: SyncState) -> None:
        self.sync = state

    async def mirrors(self) -> dict[str, Mirror]:
        return dict(self.mirror)

    async def sent_writes(self, case_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, list[SentWrite]]:
        return {c: list(self.sent.get(c, [])) for c in case_ids}

    async def sent_creates(self, case_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, int]:
        found = {}
        for c in case_ids:
            if c in self.sent:
                found[c] = sum(w.sent_count for w in self.sent[c] if w.op == "create")
        return found

    async def team_posts(
        self, kibana_case_ids: Sequence[str], incident_ids: Sequence[str]
    ) -> list[TeamPost]:
        return [
            p
            for p in self.posts.values()
            if p.kibana_case_id in kibana_case_ids or p.incident_id in incident_ids
        ]

    async def apply(
        self, mirror: Mirror, findings: Sequence[Finding], *, new: bool, found_at: datetime
    ) -> int:
        if self.crash_after is not None:
            if self.crash_after <= 0:
                self.crash_after = None
                raise RuntimeError("crash (test)")
            self.crash_after -= 1
        old = self.mirror.get(mirror.kibana_case_id)
        if new and old is not None:
            raise ValueError("the mirror exists")
        if new:  # a recreated case takes over its deleted predecessor's row (one per case)
            for kid, before in list(self.mirror.items()):
                if before.case_id == mirror.case_id:
                    if before.deleted_at is None:
                        raise ValueError("the case has a live mirror")
                    del self.mirror[kid]
                    old = before
        if old is not None and old.paused_reason and mirror.paused_reason != old.paused_reason:
            mirror = replace(mirror, paused_reason=old.paused_reason)  # only the owner lifts it
        self.mirror[mirror.kibana_case_id] = mirror
        return self._add(findings, found_at)

    async def touch(self, kibana_case_ids: Sequence[str], at: datetime) -> None:
        for kid in kibana_case_ids:
            if kid in self.mirror:
                self.mirror[kid] = replace(self.mirror[kid], read_at=at)

    def _add(self, findings: Sequence[Finding], found_at: datetime) -> int:
        added = 0
        for finding in findings:
            key = finding_key(finding)
            if key not in self.findings:
                self.findings[key] = (found_at, finding)
                added += 1
        return added

    async def add_findings(self, findings: Sequence[Finding], found_at: datetime) -> int:
        return self._add(findings, found_at)

    async def unseen_keys(self, keys: Sequence[str]) -> frozenset[str]:
        return frozenset(k for k in keys if k not in self.findings)

    async def people_cases(self) -> dict[str, PeopleCase]:
        return dict(self.people)

    async def save_people_case(self, case: PeopleCase, found_at: datetime) -> None:
        self.people[case.kibana_case_id] = case

    async def known_alerts(
        self, after: str | None, since: datetime, limit: int
    ) -> list[tuple[str, str]]:
        start = _split(after)
        rows = sorted(a for a in self.alerts if a[0] >= since)
        if start is not None:
            rows = [r for r in rows if r > start]
        return [(alert, cursor_of(at, alert)) for at, alert in rows[:limit]]

    async def explained_alerts(self, alert_ids: Sequence[str]) -> frozenset[str]:
        return frozenset(a for a in alert_ids if a in self.wa_sent)

    async def alert_states(self, alert_ids: Sequence[str]) -> dict[str, AlertState]:
        return {a: self.alert_state[a] for a in alert_ids if a in self.alert_state}

    async def save_alert_states(self, states: Sequence[AlertState]) -> None:
        for state in states:
            self.alert_state[state.alert_id] = state

    async def record_alerts(
        self, states: Sequence[AlertState], findings: Sequence[Finding], found_at: datetime
    ) -> int:
        for state in states:
            self.alert_state[state.alert_id] = state
        return self._add(findings, found_at)

    async def record_cycle(self, record: CycleRecord) -> None:
        self.cycles.append(record)


def _mirror(row: Any) -> Mirror:
    return Mirror(
        case_id=row.case_id,
        kibana_case_id=row.kibana_case_id,
        kibana_version=row.kibana_version,
        status=row.status,
        title=row.title,
        severity=row.severity,
        tags=tuple(row.tags),
        created_by=row.created_by,
        sync_alerts=row.sync_alerts,
        kibana_created_at=row.kibana_created_at,
        kibana_updated_at=row.kibana_updated_at,
        read_at=row.read_at,
        unmanaged=frozenset(row.unmanaged),
        deleted_at=row.deleted_at,
        actions_seen=row.actions_seen,
        argus_actions=dict(row.argus_actions or {}),
        paused_reason=row.paused_reason,
        unexplained=dict(row.unexplained or {}),
    )


def _payload_fields(payload: Any) -> frozenset[str]:
    if not isinstance(payload, Mapping):
        return frozenset()
    return frozenset(k for k in ("status", "severity", "argus_tags") if k in payload)


def _finding_params(finding: Finding, found_at: datetime) -> dict[str, Any]:
    return {
        "at": found_at,
        "kind": finding.kind.value,
        "severity": finding.severity.value,
        "kid": finding.kibana_case_id,
        "cid": finding.case_id,
        "key": finding_key(finding),
        "lag": finding.lag_s,
        "details": json.dumps(clean_json(finding.details), default=str, ensure_ascii=True),
    }


INSERT_FINDING = text(
    "INSERT INTO kibana_findings (found_at, kind, severity, kibana_case_id, case_id,"
    " dedupe_key, lag_s, details) VALUES (:at, :kind, :severity, :kid, :cid, :key, :lag,"
    " CAST(:details AS jsonb)) ON CONFLICT (dedupe_key) DO NOTHING"
)
MIRROR_SET = (
    "kibana_version = :version, status = :status, title = :title, severity = :severity,"
    " tags = :tags, created_by = :created_by, sync_alerts = :sync_alerts,"
    " unmanaged = :unmanaged, kibana_created_at = :created_at,"
    " kibana_updated_at = :updated_at, read_at = :read_at, deleted_at = :deleted_at,"
    " actions_seen = :actions_seen, argus_actions = CAST(:argus_actions AS jsonb),"
    " unexplained = CAST(:unexplained AS jsonb)"
)


@dataclass
class PgSyncStore:
    engine: AsyncEngine

    async def state(self) -> SyncState:
        async with self.engine.connect() as conn:
            row = (await conn.execute(text("SELECT * FROM kibana_sync_state WHERE id = 1"))).first()
        if row is None:
            return SyncState()
        m = row._mapping
        return SyncState(**{k: m[k] for k in SyncState.__dataclass_fields__})

    async def save_state(self, state: SyncState) -> None:
        names = list(SyncState.__dataclass_fields__)
        sets = ", ".join(f"{n} = :{n}" for n in names)
        async with self.engine.begin() as conn:
            await conn.execute(
                text(f"UPDATE kibana_sync_state SET {sets}, updated_at = now() WHERE id = 1"),  # noqa: S608 - fixed column names
                {n: getattr(state, n) for n in names},
            )

    async def mirrors(self) -> dict[str, Mirror]:
        async with self.engine.connect() as conn:
            rows = (await conn.execute(text("SELECT * FROM kibana_mirror"))).all()
        return {row.kibana_case_id: _mirror(row) for row in rows}

    async def sent_writes(self, case_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, list[SentWrite]]:
        found: dict[uuid.UUID, list[SentWrite]] = {c: [] for c in case_ids}
        if not case_ids:
            return found
        async with self.engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT case_id, op, payload, sent_count FROM kibana_outbox"
                    " WHERE case_id = ANY(:ids) AND sent_count > 0 ORDER BY id"
                ),
                {"ids": list(case_ids)},
            )
            for row in rows:
                found[row.case_id].append(
                    SentWrite(row.op, _payload_fields(row.payload), row.sent_count)
                )
            # the writer's own steps: a created case's opening comment and attachments,
            # and an approved compensating write's change and comment
            steps = await conn.execute(
                text(
                    "SELECT case_id, kind, payload, sent_count FROM kibana_steps"
                    " WHERE case_id = ANY(:ids) AND sent_count > 0 ORDER BY id"
                ),
                {"ids": list(case_ids)},
            )
            for step in steps:
                op = {"compensate_update": "update", "compensate_comment": "comment"}.get(
                    step.kind, step.kind
                )
                fields = _payload_fields(step.payload) if op == "update" else frozenset()
                found[step.case_id].append(SentWrite(op, fields, step.sent_count))
            # the case team's steps: each explains an action of its own author. A tag
            # step tags alerts, which is no action on the case.
            team = await conn.execute(
                text(
                    "SELECT case_id, kind, author, sent_count FROM case_team_steps"
                    " WHERE case_id = ANY(:ids) AND sent_count > 0 AND kind <> 'tag' ORDER BY id"
                ),
                {"ids": list(case_ids)},
            )
            for row in team:
                team_op = TEAM_OPS.get(row.kind)
                if team_op is not None:
                    found[row.case_id].append(
                        SentWrite(team_op, frozenset(), row.sent_count, by=row.author)
                    )
        return found

    async def team_posts(
        self, kibana_case_ids: Sequence[str], incident_ids: Sequence[str]
    ) -> list[TeamPost]:
        if not kibana_case_ids and not incident_ids:
            return []
        async with self.engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT p.case_id, p.incident_id, p.kibana_case_id,"
                    " coalesce(sum(s.sent_count) FILTER (WHERE s.kind = 'open'), 0) AS opens,"
                    " coalesce(max(s.author) FILTER (WHERE s.kind = 'open'), '') AS opener"
                    " FROM case_team_posts p LEFT JOIN case_team_steps s ON s.case_id = p.case_id"
                    " WHERE p.kibana_case_id = ANY(:kids) OR p.incident_id = ANY(:incidents)"
                    " GROUP BY p.case_id, p.incident_id, p.kibana_case_id"
                ),
                {"kids": list(kibana_case_ids), "incidents": list(incident_ids)},
            )
            return [
                TeamPost(r.case_id, r.incident_id, r.kibana_case_id, int(r.opens), r.opener)
                for r in rows
            ]

    async def sent_creates(self, case_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, int]:
        if not case_ids:
            return {}
        async with self.engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT c.id, coalesce(sum(o.sent_count) FILTER (WHERE o.op = 'create'), 0)"
                    " AS n FROM cases c LEFT JOIN kibana_outbox o ON o.case_id = c.id"
                    " WHERE c.id = ANY(:ids) GROUP BY c.id"
                ),
                {"ids": list(case_ids)},
            )
            return {row.id: int(row.n) for row in rows}

    @staticmethod
    def _mirror_params(mirror: Mirror) -> dict[str, Any]:
        return {
            "case_id": mirror.case_id,
            "kid": mirror.kibana_case_id,
            "version": mirror.kibana_version,
            "status": mirror.status,
            "title": clean(mirror.title),
            "severity": mirror.severity,
            "tags": [clean(t) for t in mirror.tags],
            "created_by": clean(mirror.created_by),
            "sync_alerts": mirror.sync_alerts,
            "unmanaged": sorted(clean(u) for u in mirror.unmanaged),
            "created_at": mirror.kibana_created_at,
            "updated_at": mirror.kibana_updated_at,
            "read_at": mirror.read_at,
            "deleted_at": mirror.deleted_at,
            "actions_seen": mirror.actions_seen,
            "argus_actions": json.dumps(dict(mirror.argus_actions), sort_keys=True),
            "unexplained": json.dumps(dict(mirror.unexplained), sort_keys=True),
            "paused": clean(mirror.paused_reason) if mirror.paused_reason else None,
        }

    async def apply(
        self, mirror: Mirror, findings: Sequence[Finding], *, new: bool, found_at: datetime
    ) -> int:
        params = self._mirror_params(mirror)
        async with self.engine.begin() as conn:
            # a recreated case takes over its deleted predecessor's row (one per ARGUS case;
            # the database trigger allows the new Kibana id only after the deletion)
            taken = (
                new
                and (
                    await conn.execute(
                        text(
                            f"UPDATE kibana_mirror SET kibana_case_id = :kid, {MIRROR_SET},"  # noqa: S608 - a constant
                            " paused_reason = coalesce(paused_reason, :paused)"
                            " WHERE case_id = :case_id AND deleted_at IS NOT NULL"
                        ),
                        params,
                    )
                ).rowcount
                == 1
            )
            if new and not taken:
                await conn.execute(
                    text(
                        "INSERT INTO kibana_mirror (case_id, kibana_case_id, kibana_version,"
                        " status, title, severity, tags, created_by, sync_alerts, unmanaged,"
                        " kibana_created_at, kibana_updated_at, read_at, deleted_at,"
                        " actions_seen, argus_actions, paused_reason, unexplained) VALUES"
                        " (:case_id, :kid, :version, :status, :title, :severity, :tags,"
                        " :created_by, :sync_alerts, :unmanaged, :created_at, :updated_at,"
                        " :read_at, :deleted_at, :actions_seen, CAST(:argus_actions AS jsonb),"
                        " :paused, CAST(:unexplained AS jsonb))"
                    ),
                    params,
                )
            elif not new:
                # a pause is set here, never lifted (only the owner lifts it)
                await conn.execute(
                    text(
                        f"UPDATE kibana_mirror SET {MIRROR_SET},"  # noqa: S608 - a constant
                        " paused_reason = coalesce(paused_reason, :paused)"
                        " WHERE kibana_case_id = :kid"
                    ),
                    params,
                )
            return await self._insert(conn, findings, found_at)

    @staticmethod
    async def _insert(conn: Any, findings: Sequence[Finding], found_at: datetime) -> int:
        added = 0
        for finding in findings:
            result = await conn.execute(INSERT_FINDING, _finding_params(finding, found_at))
            added += result.rowcount or 0
        return added

    async def touch(self, kibana_case_ids: Sequence[str], at: datetime) -> None:
        if not kibana_case_ids:
            return
        async with self.engine.begin() as conn:
            await conn.execute(
                text("UPDATE kibana_mirror SET read_at = :at WHERE kibana_case_id = ANY(:ids)"),
                {"at": at, "ids": list(kibana_case_ids)},
            )

    async def add_findings(self, findings: Sequence[Finding], found_at: datetime) -> int:
        async with self.engine.begin() as conn:
            return await self._insert(conn, findings, found_at)

    async def unseen_keys(self, keys: Sequence[str]) -> frozenset[str]:
        if not keys:
            return frozenset()
        async with self.engine.connect() as conn:
            rows = await conn.execute(
                text("SELECT dedupe_key FROM kibana_findings WHERE dedupe_key = ANY(:keys)"),
                {"keys": [clean(k)[:400] for k in keys]},
            )
            known = {r[0] for r in rows}
        return frozenset(k for k in keys if clean(k)[:400] not in known)

    async def people_cases(self) -> dict[str, PeopleCase]:
        async with self.engine.connect() as conn:
            rows = (await conn.execute(text("SELECT * FROM kibana_people_cases"))).all()
        return {
            r.kibana_case_id: PeopleCase(
                r.kibana_case_id,
                r.title,
                r.status,
                r.created_by,
                tuple(r.tags),
                tuple(r.known_alerts),
                r.kibana_updated_at,
                r.read_at,
            )
            for r in rows
        }

    async def save_people_case(self, case: PeopleCase, found_at: datetime) -> None:
        async with self.engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO kibana_people_cases (kibana_case_id, title, status, created_by,"
                    " tags, known_alerts, kibana_updated_at, first_seen_at, read_at) VALUES"
                    " (:kid, :title, :status, :by, :tags, :alerts, :updated, :found, :read)"
                    " ON CONFLICT (kibana_case_id) DO UPDATE SET title = EXCLUDED.title,"
                    " status = EXCLUDED.status, created_by = EXCLUDED.created_by,"
                    " tags = EXCLUDED.tags, known_alerts = EXCLUDED.known_alerts,"
                    " kibana_updated_at = EXCLUDED.kibana_updated_at, read_at = EXCLUDED.read_at"
                ),
                {
                    "kid": case.kibana_case_id,
                    "title": clean(case.title),
                    "status": case.status,
                    "by": clean(case.created_by),
                    "tags": [clean(t) for t in case.tags],
                    "alerts": list(case.known_alerts),
                    "updated": case.kibana_updated_at,
                    "found": found_at,
                    "read": case.read_at,
                },
            )

    async def known_alerts(
        self, after: str | None, since: datetime, limit: int
    ) -> list[tuple[str, str]]:
        start = _split(after)
        query = "SELECT alert_id, first_seen_at FROM alert_records WHERE first_seen_at >= :since"
        params: dict[str, Any] = {"since": since, "limit": limit}
        if start is not None:
            query += " AND (first_seen_at, alert_id) > (:at, :alert)"
            params |= {"at": start[0], "alert": start[1]}
        query += " ORDER BY first_seen_at, alert_id LIMIT :limit"
        async with self.engine.connect() as conn:
            rows = (await conn.execute(text(query), params)).all()
        return [(r.alert_id, cursor_of(r.first_seen_at, r.alert_id)) for r in rows]

    async def explained_alerts(self, alert_ids: Sequence[str]) -> frozenset[str]:
        if not alert_ids:
            return frozenset()
        async with self.engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT DISTINCT a FROM writeback_outbox, unnest(alert_ids) AS a"
                    " WHERE sent_count > 0 AND a = ANY(:ids)"
                ),
                {"ids": list(alert_ids)},
            )
            return frozenset(r[0] for r in rows)

    async def alert_states(self, alert_ids: Sequence[str]) -> dict[str, AlertState]:
        if not alert_ids:
            return {}
        async with self.engine.connect() as conn:
            rows = await conn.execute(
                text("SELECT * FROM kibana_alert_states WHERE alert_id = ANY(:ids)"),
                {"ids": list(alert_ids)},
            )
            return {
                r.alert_id: AlertState(
                    r.alert_id, r.status, r.workflow_user, r.status_updated_at, r.seen_at
                )
                for r in rows
            }

    @staticmethod
    async def _upsert_states(conn: Any, states: Sequence[AlertState]) -> None:
        for st in states:
            await conn.execute(
                text(
                    "INSERT INTO kibana_alert_states (alert_id, status, workflow_user,"
                    " status_updated_at, seen_at) VALUES (:a, :s, :u, :t, :seen)"
                    " ON CONFLICT (alert_id) DO UPDATE SET status = EXCLUDED.status,"
                    " workflow_user = EXCLUDED.workflow_user,"
                    " status_updated_at = EXCLUDED.status_updated_at,"
                    " seen_at = EXCLUDED.seen_at"
                ),
                {
                    "a": st.alert_id,
                    "s": st.status,
                    "u": clean(st.user) if st.user else None,
                    "t": st.status_updated_at,
                    "seen": st.seen_at,
                },
            )

    async def save_alert_states(self, states: Sequence[AlertState]) -> None:
        if not states:
            return
        async with self.engine.begin() as conn:
            await self._upsert_states(conn, states)

    async def record_alerts(
        self, states: Sequence[AlertState], findings: Sequence[Finding], found_at: datetime
    ) -> int:
        async with self.engine.begin() as conn:
            await self._upsert_states(conn, states)
            return await self._insert(conn, findings, found_at)

    async def record_cycle(self, record: CycleRecord) -> None:
        async with self.engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO kibana_sync_cycles (started_at, finished_at, outcome, reason,"
                    " health, reads, changed, findings, oldest_read_s, stale, clock_offset_ms,"
                    " detail) VALUES (:started, :finished, :outcome, :reason, :health, :reads,"
                    " :changed, :findings, :oldest, :stale, :offset, CAST(:detail AS jsonb))"
                ),
                {
                    "started": record.started_at,
                    "finished": record.finished_at,
                    "outcome": record.outcome,
                    "reason": record.reason,
                    "health": record.health,
                    "reads": record.reads,
                    "changed": record.changed,
                    "findings": record.findings,
                    "oldest": record.oldest_read_s,
                    "stale": record.stale,
                    "offset": record.clock_offset_ms,
                    "detail": json.dumps(dict(record.detail), default=str, sort_keys=True),
                },
            )


def mirrored_by_case(mirrors: Iterable[Mirror]) -> dict[uuid.UUID, str]:
    """Each ARGUS case's live mirror (its Kibana id)."""
    return {m.case_id: m.kibana_case_id for m in mirrors if m.active}


def kcase_mirror_case(case: KCase) -> uuid.UUID | None:
    ids = case.argus_case_ids()
    return ids[0] if len(ids) == 1 else None
