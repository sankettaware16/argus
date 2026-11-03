"""A small world for the responder (Q-H2): the still-active watch's world (cases, alerts, the
fake gateway), plus the stored web answers an exposed file and an attack leave, and alerts that
record a failed sign-in. Time is always passed in, never read."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.responder import store
from tests.integration.cases.conftest import Person
from tests.integration.cases.watchkit import C2, D0, H1, H2, H3, FakeAsker, World, at, context

__all__ = ["C2", "D0", "H1", "H2", "H3", "FakeAsker", "Scene", "at", "context"]

SITE = "app.univ.example"
ATTACKER = "203.0.113.9"
ENV = "/.env"
GIT = "/.git/config"


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def snapshot(rows: dict[str, tuple[int, int | None]]) -> dict[str, Any]:
    """A ``web.path_outcomes`` answer: per path, (requests, the size of its 2xx answers or None
    when none was 2xx). The 2xx sizes make ``success``; requests without one are ``refused``."""
    aggs: dict[str, Any] = {"paths": {"buckets": []}}
    for i, (path, (requests, size)) in enumerate(sorted(rows.items())):
        status = 200 if size is not None else 404
        aggs["paths"]["buckets"].append(
            {
                "key": path,
                "doc_count": requests,
                "statuses": {"buckets": [{"key": status, "doc_count": requests}]},
            }
        )
        sizes = {"buckets": [{"key": size, "doc_count": requests}] if size is not None else []}
        aggs[f"ok_{i}"] = {"doc_count": requests if size is not None else 0, "sizes": sizes}
    aggs["requests"] = {"value": sum(r for r, _ in rows.values())}
    aggs["answered"] = {"value": sum(r for r, _ in rows.values())}
    return {"aggregations": aggs}


class Scene(World):
    """The watch's world and the case actions' own helpers."""

    def __init__(self, owner: AsyncEngine, runtime: AsyncEngine) -> None:
        super().__init__(owner, runtime)
        self.eids: dict[uuid.UUID, int] = {}

    async def web_answer(
        self,
        inv: uuid.UUID,
        paths: Sequence[str],
        rows: dict[str, tuple[int, int | None]],
        *,
        start: datetime,
        asked: datetime,
        status: str = "ok",
    ) -> None:
        """A stored ``web.path_outcomes`` answer for ``inv``: window from ``start`` for an hour,
        asked at ``asked``; ``rows`` as in :func:`snapshot` (empty: no request was logged)."""
        eid = self.eids[inv] = self.eids.get(inv, 0) + 1
        params = {
            "ip": ATTACKER,
            "site": SITE,
            "paths": sorted(paths),
            "start": start.isoformat(),
            "end": (start + timedelta(hours=1)).isoformat(),
        }
        key = sha(f"{inv}-{eid}")
        body = snapshot(rows) if rows else {"aggregations": {}}
        async with self.owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO evidence_requests (investigation_id, eid, task_key, template,"
                    " template_version, origin, first_version, created_at) VALUES (:i, :e, :k,"
                    " 'web.path_outcomes', 1, 'person', 1, :t)"
                ),
                {"i": inv, "e": eid, "k": key, "t": asked},
            )
            await conn.execute(
                text(
                    "INSERT INTO evidence (investigation_id, version, task_key, template,"
                    " template_version, params, status, coverage, snapshot, result_hash,"
                    " collected_at, asked_at) VALUES (:i, 1, :k, 'web.path_outcomes', 1,"
                    " CAST(:p AS jsonb), :s, '{}', CAST(:b AS jsonb), :h, :t, :t)"
                ),
                {
                    "i": inv,
                    "k": key,
                    "p": json.dumps(params),
                    "s": status,
                    "b": json.dumps(body),
                    "h": sha(key),
                    "t": asked,
                },
            )

    async def raw(self, inv: uuid.UUID, raw: dict[str, Any]) -> None:
        """Every alert of ``inv`` carries ``raw``."""
        async with self.owner.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE alert_records SET raw = CAST(:r AS jsonb) WHERE alert_id IN"
                    " (SELECT alert_id FROM investigation_alerts WHERE investigation_id = :i)"
                ),
                {"r": json.dumps(raw), "i": inv},
            )

    async def exposed_env_case(self, person: Person, now: datetime) -> tuple[uuid.UUID, uuid.UUID]:
        """A case about an outside client that was served ``/.env`` (a stored answer showing it);
        returns (case id, investigation id)."""
        inv = await self.investigation(
            ATTACKER, [at(0, 9)], entities=[("ip", ATTACKER)], rule="web"
        )
        case_id = await self.open_case(person, [inv], [ATTACKER], now, c2=None)
        await self.web_answer(
            inv, [ENV, GIT], {ENV: (3, 1523), GIT: (2, None)}, start=at(0, 9), asked=at(0, 11)
        )
        return case_id, inv

    async def brute_force_case(self, person: Person, now: datetime) -> tuple[uuid.UUID, uuid.UUID]:
        """A case about an outside client whose alerts record failed sign-ins."""
        inv = await self.investigation(
            ATTACKER, [at(0, 9), at(0, 9, 5)], entities=[("ip", ATTACKER)], rule="ssh"
        )
        await self.raw(inv, {"event.category": ["authentication"], "event.outcome": "failure"})
        case_id = await self.open_case(person, [inv], [ATTACKER], now, c2=None)
        return case_id, inv

    async def beacon_case(self, person: Person, now: datetime) -> tuple[uuid.UUID, uuid.UUID]:
        """PS1Bot: three campus hosts and one C2 address; returns (case id, first investigation)."""
        inv = await self.investigation(H1, [at(0, 9), at(0, 9, 5)])
        case_id = await self.open_case(person, [inv], [H1, H2, H3], now)
        return case_id, inv

    async def views(self, case_id: uuid.UUID, now: datetime, ctx: Any = None) -> dict[str, Any]:
        async with self.runtime.connect() as conn:
            found = await store.actions_for(conn, case_id, ctx=ctx, now=now)
        return {v.action: v for v in found}

    async def do(self, case_id: uuid.UUID, now: datetime, ctx: Any = None) -> list[Any]:
        """Record the advice and the verdicts, as ``argus case actions --recommend`` does."""
        async with self.runtime.begin() as conn:
            new = await store.recommend(conn, case_id, now)
            moved = await store.refresh(conn, case_id, now, ctx=ctx)
        return [new, moved]

    async def stored(self, case_id: uuid.UUID) -> Any:
        async with self.owner.connect() as conn:
            found = await conn.execute(
                text(
                    "SELECT action, state, requested_by, reported_by, attestation, verdict,"
                    " last_beat FROM case_actions WHERE case_id = :c ORDER BY id"
                ),
                {"c": case_id},
            )
            return {r.action: r for r in found}
