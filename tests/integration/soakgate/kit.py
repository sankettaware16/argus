"""A world for the soak gate's integration tests: rows written as the schema owner (every table, any
column), read back by the gate as the runtime login. Times are always passed in, never read, except
where the database stamps its own (a case event)."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import Settings
from argus.soakgate.model import Window
from tests.integration.cases import knownkit
from tests.integration.cases.conftest import Person, investigation

# a day of the soak, well inside the write window; the window below spans it and today
DAY = datetime(2026, 10, 30, 8, 0, tzinfo=UTC)
SINCE = datetime(2026, 10, 30, 0, 0, tzinfo=UTC)


def window(*, live: bool = False) -> Window:
    """A fixed window around the seeded rows (so the tests read the same on any day), or with
    ``live`` one that reaches a day past the real now: case events carry the database's clock."""
    if live:
        return Window(SINCE, max(datetime.now(UTC), DAY) + timedelta(days=1))
    return Window(SINCE, datetime(2026, 11, 2, 6, 30, tzinfo=UTC))


def settings(tmp: Any) -> Settings:
    """Settings whose files (the soak folder, the backups) are in ``tmp``, not in a checkout."""
    return Settings(soak={"dir": tmp / "gate" / "soak"}, backup={"dir": tmp / "backups"})  # type: ignore[arg-type]


def digest(*parts: object) -> str:
    return hashlib.sha256(json.dumps(parts, default=str).encode()).hexdigest()


async def case(
    owner: AsyncEngine, app: AsyncEngine, person: Person, host: str
) -> tuple[uuid.UUID, int]:
    """A real, open ARGUS case (made through the case service) and its number."""
    inv = await investigation(owner, actor=(("source.ip", host),), alerts=1)
    case_id = await knownkit.open_case(app, person, [inv], host=host, servers=())
    async with owner.connect() as conn:
        number = (
            await conn.execute(text("SELECT number FROM cases WHERE id = :c"), {"c": case_id})
        ).scalar_one()
    return case_id, int(number)


async def run(owner: AsyncEngine, sql: str, **params: Any) -> Any:
    async with owner.begin() as conn:
        result = await conn.execute(text(sql), params)
        return result.first() if result.returns_rows else None


async def report(
    owner: AsyncEngine,
    case_id: uuid.UUID,
    *,
    version: int = 1,
    outcome: str = "true_positive",
    at: datetime = DAY,
) -> int:
    row = await run(
        owner,
        "INSERT INTO incident_reports (case_id, version, schema_version, writer, content_hash,"
        " case_version, verdict_outcome, body, as_at, core_hash, generated_at) VALUES (:c, :v,"
        " 'incident-report@1', 'test', :h, 1, :o, '{}', :t, :h, :t) RETURNING id",
        c=case_id, v=version, h=digest(case_id, version), o=outcome, t=at,
    )  # fmt: skip
    return int(row.id)


async def decide(
    owner: AsyncEngine,
    report_id: int,
    user_id: int,
    *,
    decision: str = "confirmed",
    outcome: str | None = "true_positive",
    at: datetime = DAY,
) -> None:
    reason = "it is the backup tool" if decision == "rejected" else None
    await run(
        owner,
        "INSERT INTO incident_report_decisions (report_id, decision, outcome, reason, by_user_id,"
        " decided_at) VALUES (:r, :d, :o, :why, :u, :t)",
        r=report_id, d=decision, o=outcome, why=reason, u=user_id, t=at,
    )  # fmt: skip


async def post(
    owner: AsyncEngine,
    case_id: uuid.UUID,
    number: int,
    *,
    kibana: str | None,
    opened_at: datetime | None,
    created_at: datetime = DAY,
) -> None:
    await run(
        owner,
        "INSERT INTO case_team_posts (case_id, incident_id, kibana_case_id, opened_at,"
        " last_version, created_at) VALUES (:c, :i, :k, :o, 1, :t)",
        c=case_id, i=f"ACME-IR-2026-1030-{number:02d}", k=kibana, o=opened_at, t=created_at,
    )  # fmt: skip


async def step(
    owner: AsyncEngine,
    case_id: uuid.UUID,
    seq: int,
    *,
    kind: str = "comment",
    state: str = "verified",
    sent_count: int = 1,
    sent_at: datetime | None = DAY,
    verified_at: datetime | None = None,
    kibana_ids: dict[str, Any] | None = None,
    created_at: datetime = DAY,
    gen: int = 1,
) -> int:
    lead = ("open", "attach", "tag", "retitle", "redescribe")  # 0061: the lead alone edits a case
    author = "argus-lead" if kind in lead else "argus-evidence"
    row = await run(
        owner,
        "INSERT INTO case_team_steps (case_id, gen, seq, key, kind, author, part, report_version,"
        " text_body, request_hash, state, sent_count, sent_at, verified_at, kibana_ids, created_at)"
        " VALUES (:c, :g, :n, :k, :kind, :a, 'evidence', 1, :body, :h, :s, :sc, :sa, :va,"
        " CAST(:ids AS jsonb), :ca) RETURNING id",
        c=case_id, g=gen, n=seq, k=f"{kind}:{seq}", kind=kind, a=author,
        body="x" if kind in ("open", "comment") else None, h=digest(case_id, seq, gen),
        s=state, sc=sent_count, sa=sent_at, va=verified_at, ids=json.dumps(kibana_ids or {}),
        ca=created_at,
    )  # fmt: skip
    return int(row.id)


async def request(
    owner: AsyncEngine,
    at: datetime,
    *,
    template: str = "team.comment",
    purpose: str = "kibana_write",
    lane: str | None = "kibana_write",
    target: str = "kibana",
    outcome: str = "ok",
    took_ms: int = 50,
    write_class: str | None = "WC",
    outbox_id: str | None = None,
    health: str | None = "normal",
) -> None:
    await run(
        owner,
        "INSERT INTO siem_requests (at, component, purpose, template, version, indices, outcome,"
        " http_status, took_ms, elapsed_ms, response_bytes, attempts, lane, target, outbox_id,"
        " write_class, health) VALUES (:at, 'caseteam', :p, :t, 1, '{}', :o, 200, :took, :took, 10,"
        " 1, :lane, :target, :outbox, :wc, :health)",
        at=at, p=purpose, t=template, o=outcome, took=took_ms, lane=lane, target=target,
        outbox=outbox_id, wc=write_class, health=health,
    )  # fmt: skip


async def probe(owner: AsyncEngine, at: datetime, state: str = "normal") -> None:
    await run(
        owner,
        "INSERT INTO siem_probes (at, state, reasons, probe_ok, auth_failed, blocked_indices)"
        " VALUES (:at, :s, '{}', true, false, '{}')",
        at=at, s=state,
    )  # fmt: skip


async def cycle(owner: AsyncEngine, at: datetime, *, outcome: str = "complete",
                health: str = "normal") -> None:  # fmt: skip
    await run(
        owner,
        "INSERT INTO kibana_sync_cycles (started_at, finished_at, outcome, health, reads, changed,"
        " findings, stale) VALUES (:at, :at, :o, :h, 1, 0, 0, false)",
        at=at, o=outcome, h=health,
    )  # fmt: skip


async def finding(
    owner: AsyncEngine,
    kind: str,
    at: datetime,
    *,
    lag_s: int | None = None,
    case_id: uuid.UUID | None = None,
    resolved: bool = False,
) -> None:
    await run(
        owner,
        "INSERT INTO kibana_findings (found_at, kind, severity, case_id, dedupe_key, lag_s,"
        " resolved_at) VALUES (:at, :k, 'attention', :c, :key, :lag, :res)",
        at=at, k=kind, c=case_id, key=f"{kind}:{uuid.uuid4()}", lag=lag_s,
        res=at if resolved else None,
    )  # fmt: skip


async def mirror(owner: AsyncEngine, case_id: uuid.UUID, kibana: str) -> None:
    await run(
        owner,
        "INSERT INTO kibana_mirror (case_id, kibana_case_id, kibana_version, status, title,"
        " severity, tags, created_by, sync_alerts, kibana_created_at, read_at)"
        " VALUES (:c, :k, 'v1', 'open', 't', 'high', '{}', 'argus-lead', false, :t, :t)",
        c=case_id, k=kibana, t=DAY,
    )  # fmt: skip


async def lookup(
    owner: AsyncEngine,
    address: str,
    day: date,
    looked_at: datetime,
    *,
    reason: str | None = None,
    store_failures: int = 0,
) -> None:
    complete = reason is None
    await run(
        owner,
        "INSERT INTO signin_lookups (address, day, looked_at, complete, reason, store_failures)"
        " VALUES (CAST(:a AS inet), :d, :t, :c, :r, :f)",
        a=address, d=day, t=looked_at, c=complete, r=reason, f=store_failures,
    )  # fmt: skip


async def sample(owner: AsyncEngine, at: datetime) -> None:
    await run(
        owner, "INSERT INTO soak_samples (at, metrics) VALUES (:at, CAST('{}' AS jsonb))", at=at
    )


async def llm_call(owner: AsyncEngine, at: datetime, cost: float) -> None:
    await run(
        owner,
        "INSERT INTO llm_calls (at, call_id, attempt, provider, model, tier, purpose, priority,"
        " outcome, input_tokens, output_tokens, cost_usd, latency_ms, request_bytes,"
        " request_sha256) VALUES (:at, :id, 1, 'p', 'm', 'high', 'assess', 'normal', 'ok', 10, 10,"
        " :c, 100, 100, '')",
        at=at, id=uuid.uuid4(), c=cost,
    )  # fmt: skip


async def dismissal_by_argus(owner: AsyncEngine) -> int:
    """A suspected case ARGUS opened and, with no person's hand in it, dismissed: the closure the
    machine refuses to make and the gate must still catch. Written as the owner, through the case
    guard's own rules (a suspected case closes without an approval). Returns its number."""
    case_id = uuid.uuid4()
    async with owner.begin() as conn:
        number = (
            await conn.execute(
                text(
                    "INSERT INTO cases (id, title, state, severity, version, cause) VALUES (:c,"
                    " 'A suspected case', 'suspected', 'high', 1, 'person') RETURNING number"
                ),
                {"c": case_id},
            )
        ).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO case_events (case_id, case_version, kind, actor, actor_user_id,"
                " from_state, to_state) VALUES (:c, 1, 'suspected', 'argus:test', NULL, NULL,"
                " 'suspected')"
            ),
            {"c": case_id},
        )
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE cases SET state = 'closed', version = 2, closed_at = now(),"
                " closure_reason = 'benign_expected' WHERE id = :c"
            ),
            {"c": case_id},
        )
        await conn.execute(
            text(
                "INSERT INTO case_events (case_id, case_version, kind, actor, actor_user_id,"
                " from_state, to_state) VALUES (:c, 2, 'dismissed', 'argus:test', NULL,"
                " 'suspected', 'closed')"
            ),
            {"c": case_id},
        )
    return int(number)
