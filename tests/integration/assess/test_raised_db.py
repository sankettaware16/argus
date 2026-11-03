"""AR2b (D-154, D-160) against the database: an investigation whose newest dossier carries a strong
generic flag is in Needs attention whatever its severity, with "ARGUS raised it: ..." as a reason;
one that nobody flagged, or somebody reviewed, is not; the home page, the Inbox and the dashboard
count it the same way."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import raised
from argus.web import dashboard, queries
from tests.integration.cases.conftest import investigation, make_person, rows

pytestmark = pytest.mark.integration
NOW = datetime.now(UTC)
BEACON = {"name": "proxy.regularity", "status": "known", "value": 0.0}
LISTED = {"name": "ti.listed", "status": "known", "value": 2}


async def make(
    owner: AsyncEngine, *, severity: str = "low", signals: tuple[dict[str, Any], ...] = (),
    host: int = 1, version: int = 1, hours: float = 1.0, rule: str | None = None,
) -> uuid.UUID:  # fmt: skip
    inv = await investigation(
        owner, rule=rule or f"r{host}", actor=(("source.ip", f"10.1.1.{host}"),), severity=severity
    )
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET first_event_at = :t, last_event_at = :t WHERE id = :i"),
            {"t": NOW - timedelta(hours=hours), "i": inv},
        )
    await dossier(owner, inv, 1, signals)
    return inv


async def dossier(owner: AsyncEngine, inv: uuid.UUID, version: int, signals: Any) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                " VALUES (:i, :v, 'generic@12', :v, 1, 'collect', 'proxy', 'evidence_ready',"
                " :h, CAST(:b AS jsonb), 0, now())"
            ),
            {
                "i": inv,
                "v": version,
                "h": f"{version}{inv.hex}".ljust(64, "0")[:64],
                "b": json.dumps({"local_signals": list(signals), "signals": []}),
            },
        )


async def read(engine: AsyncEngine, **more: Any) -> Any:
    async with engine.begin() as conn:
        return await raised.evaluate(conn, NOW, **more)


async def in_attention(engine: AsyncEngine) -> dict[uuid.UUID, queries.Summary]:
    async with engine.connect() as conn:
        return {s.id: s for s in await queries.inbox(conn, "attention", limit=100)}


async def test_a_flagged_low_severity_investigation_is_raised_into_needs_attention(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    beacon = await make(migrated_engine, severity="low", signals=(BEACON,), host=1)
    listed = await make(migrated_engine, severity="medium", signals=(LISTED,), host=2)
    both = await make(migrated_engine, severity="low", signals=(BEACON, LISTED), host=3)
    quiet = await make(migrated_engine, severity="low", host=4)
    plain_high = await make(migrated_engine, severity="critical", host=5)
    assert await rows(app_engine, "SELECT * FROM investigation_raises") == []
    before = await in_attention(app_engine)
    assert set(before) == {plain_high}  # before the read, only the rule's severity decides

    assert await read(app_engine) == {"read": 5, "raised": 3}  # flagged: first in the AI queue
    shown = await in_attention(app_engine)
    # a threat-list hit with another flag raises it; one flag alone does not (D-164)
    assert set(shown) == {both, plain_high}
    assert not {beacon, listed, quiet} & set(shown)
    assert shown[both].reasons == [
        "ARGUS raised it: on a threat list; regular traffic, like a beacon."
    ]  # fmt: skip
    assert shown[plain_high].reasons == ["The rule rates it critical."]
    async with app_engine.connect() as conn:
        counts = await queries.counts(conn, NOW)
        assert counts["attention"] == 2
        assert [s.id for s in await queries.inbox(conn, "attention", limit=2)] == [plain_high, both]
        assert {s.id for s in await queries.inbox(conn, "open", limit=100)} >= {quiet, beacon}
        one = await queries.investigation(conn, beacon)
    assert one is not None
    assert one.reasons == []


async def test_a_dossier_is_read_once_and_a_newer_one_replaces_the_flags(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await make(migrated_engine, signals=(BEACON, LISTED))
    assert await read(app_engine) == {"read": 1, "raised": 1}
    assert await read(app_engine) == {"read": 0, "raised": 0}  # once
    assert set(await in_attention(app_engine)) == {inv}
    async with migrated_engine.begin() as conn:  # more alerts: version 2, no flag now
        await conn.execute(text("UPDATE investigations SET version = 2 WHERE id = :i"), {"i": inv})
    assert set(await in_attention(app_engine)) == set()  # a stale read is not shown
    await dossier(migrated_engine, inv, 2, ())
    assert await read(app_engine) == {"read": 1, "raised": 0}
    (row,) = await rows(app_engine, "SELECT version, flags FROM investigation_raises")
    assert (row.version, row.flags) == (2, [])
    assert set(await in_attention(app_engine)) == set()
    async with migrated_engine.begin() as conn:  # and flagged again in version 3
        await conn.execute(text("UPDATE investigations SET version = 3 WHERE id = :i"), {"i": inv})
    await dossier(migrated_engine, inv, 3, (BEACON, LISTED))
    await read(app_engine)
    assert set(await in_attention(app_engine)) == {inv}
    assert len(await rows(app_engine, "SELECT * FROM investigation_raises")) == 1


async def test_a_reviewed_or_old_investigation_is_not_read(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    done = await make(migrated_engine, signals=(BEACON, LISTED), host=1)
    await make(
        migrated_engine, signals=(BEACON, LISTED), host=2, hours=24 * 5
    )  # last alert 5 days ago
    fresh = await make(migrated_engine, signals=(BEACON, LISTED), host=3)
    asha = await make_person(app_engine, "asha")
    async with app_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome) VALUES (:i, 1, 2, :u, 'reviewed', 'benign_expected')"
            ),
            {"i": done, "u": asha.user_id},
        )
    assert await read(app_engine) == {"read": 1, "raised": 1}
    assert set(await in_attention(app_engine)) == {fresh}
    assert await read(app_engine, horizon=timedelta(days=9)) == {"read": 1, "raised": 1}


async def test_the_batch_is_the_newest_first_and_the_rest_wait(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    older = await make(migrated_engine, signals=(BEACON, LISTED), host=1, hours=5)
    newer = await make(migrated_engine, signals=(BEACON, LISTED), host=2, hours=1)
    assert await read(app_engine, limit=1) == {"read": 1, "raised": 1}
    assert set(await in_attention(app_engine)) == {newer}
    assert await read(app_engine, limit=1) == {"read": 1, "raised": 1}
    assert set(await in_attention(app_engine)) == {older, newer}


async def test_one_malformed_dossier_is_said_and_skipped_and_the_others_are_read(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:  # fmt: skip
    good = await make(migrated_engine, signals=(BEACON, LISTED), host=1, hours=1)
    bad = await make(migrated_engine, signals=(BEACON, LISTED), host=2, hours=2)
    later = await make(migrated_engine, signals=(BEACON, LISTED), host=3, hours=3)
    real = raised.flags_of
    marker = {"name": "poison", "status": "known", "value": 1}

    def flags_of(local_signals: Any, signals: Any) -> tuple[str, ...]:
        if marker in (local_signals or []):
            raise RecursionError("a dossier nobody can read")
        return real(local_signals, signals)

    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE dossiers SET body = jsonb_set(body, '{local_signals}', CAST(:s AS jsonb))"
                 " WHERE investigation_id = :i"),
            {"s": json.dumps([marker]), "i": bad},
        )  # fmt: skip
    monkeypatch.setattr(raised, "flags_of", flags_of)
    with caplog.at_level(logging.WARNING, logger="argus.raised"):
        assert await read(app_engine) == {"read": 3, "raised": 2, "skipped": 1}
    assert str(bad) in caplog.text
    assert "RecursionError" in caplog.text
    assert "a dossier nobody can read" not in caplog.text  # the type, never the content
    assert set(await in_attention(app_engine)) == {good, later}
    # the bad one is stored as read, with no flags: it is not read and said again every pass
    assert await read(app_engine) == {"read": 0, "raised": 0}
    (row,) = await rows(app_engine, "SELECT flags FROM investigation_raises WHERE"
                                    " investigation_id = :i", i=bad)  # fmt: skip
    assert row.flags == []


async def test_the_dashboard_counts_needs_attention_as_the_inbox_does(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await make(migrated_engine, severity="low", signals=(BEACON, LISTED), host=1)
    await make(migrated_engine, severity="low", host=2)
    await make(migrated_engine, severity="high", host=3)
    await read(app_engine)
    async with app_engine.connect() as conn:
        shown = await dashboard.build(conn, dashboard.Filters(), NOW + timedelta(hours=1))
        counts = await queries.counts(conn, NOW)
    assert shown.kpis["attention"] == counts["attention"] == 2
