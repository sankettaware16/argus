"""The retention purge (Q-A4, D-028) against the real database: over generated timelines exactly
the expired, unheld rows go, the dry run's counts equal what a run changes, a second run changes
nothing, and the purge role can touch nothing else."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.collector.store import ingest
from argus.config.settings import Settings
from argus.context.cli import queue_rederive
from argus.context.store import reusable
from argus.db import roles
from argus.ops import purge
from argus.web import auth

pytestmark = pytest.mark.integration

DAY = 86400
AT = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
SETTINGS = Settings()  # defaults: raw 30d, quarantine 30d, evidence 90d, memory 90d, history 5d
CUT = purge.cutoffs(SETTINGS, AT)


def _s(seconds: int) -> datetime:
    return AT + timedelta(seconds=seconds)


def _hex(*parts: object) -> str:
    return hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest()


# --------------------------------------------------------------------------- generated worlds
# Times are seconds from AT; the bases sit on the cutoffs, the deltas on either side by a second.
BASES = (-30 * DAY, -90 * DAY, -5 * DAY, -200 * DAY)
DELTAS = (-3600, -1, 0, 1, 3600)
TIME = st.builds(lambda b, d: b + d, st.sampled_from(BASES), st.sampled_from(DELTAS))


@dataclass
class Alert:
    detected: int | None
    first_seen: int
    quarantined: bool = False


@dataclass
class Inv:
    bucket_end: int
    alerts: list[Alert]
    reviews: list[tuple[str, int]]  # (action, created_at), in insertion order
    snapshots: list[bool]  # per evidence row: holds a snapshot (else JSON null)
    gold: bool
    job_active: bool
    assessment_active: bool
    entities: list[str]
    continues: int | None  # index of the investigation it continues
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    changed: bool = False  # version 2 since its reviews (made at version 1): open work
    writeback: str = "sent"  # its write-back row's state


@dataclass
class World:
    investigations: list[Inv]
    loose: list[Alert]  # alerts in no investigation (quarantined ones among them)
    lookups: list[int]  # ti_lookups' checked_at
    reports: list[int] = field(default_factory=list)  # tuning reports' week_end


ALERT = st.builds(Alert, st.one_of(st.none(), TIME), TIME, st.just(False))
LOOSE = st.builds(Alert, st.one_of(st.none(), TIME), TIME, st.booleans())
REVIEW = st.tuples(st.sampled_from(["reviewed", "follow_up", "note"]), TIME)
# Case holds are not generated: the case tables' triggers (ENABLE ALWAYS: the case machine's
# guard, its event chain, append-only rows) admit only cases the case machine makes. They are
# tested with real cases in tests/integration/cases/test_purge_holds.py.
INV = st.builds(
    Inv,
    TIME,
    st.lists(ALERT, max_size=3),
    st.lists(REVIEW, max_size=2),
    st.lists(st.booleans(), max_size=2),
    st.booleans(),
    st.booleans(),
    st.booleans(),
    st.lists(st.sampled_from(["10.0.0.1", "10.0.0.2", "10.0.0.3"]), max_size=2, unique=True),
    st.one_of(st.none(), st.integers(0, 4)),
    changed=st.booleans(),
    writeback=st.sampled_from(["sent", "sent", "skipped", "planned", "paused"]),
)
WORLD = st.builds(
    World,
    st.lists(INV, max_size=5),
    st.lists(LOOSE, max_size=3),
    st.lists(TIME, max_size=2),
    st.lists(TIME, max_size=2),
)


def _age(alert: Alert) -> int:
    return alert.first_seen if alert.detected is None else min(alert.detected, alert.first_seen)


def _cut(name: str) -> int:
    return int((getattr(CUT, name) - AT).total_seconds())


def held(inv: Inv) -> bool:
    return inv.gold


def continues(world: World, n: int) -> int | None:
    """The index of the investigation ``n`` continues, as ``write`` links them."""
    target = world.investigations[n].continues
    return target if target is not None and target < len(world.investigations) else None


def expected(world: World) -> dict[str, Any]:
    """The model: what the purge must change, by D-028's rules as the module states them."""
    raw, quarantine, evidence = set(), set(), set()
    victims, waiting, kept = set(), set(), set()
    invs = world.investigations
    for n, inv in enumerate(invs):
        decision = [r for r in inv.reviews if r[0] != "note"]
        expired = (
            inv.bucket_end <= _cut("memory")
            and all(_age(a) < _cut("memory") for a in inv.alerts)
            and all(created < _cut("memory") for _, created in inv.reviews)
        )
        busy = inv.job_active or inv.assessment_active or inv.writeback in ("planned", "paused")
        keeps = held(inv) or any(held(m) and continues(world, k) == n for k, m in enumerate(invs))
        if expired and not busy:
            (kept if keeps else victims).add(n)
        elif expired and not keeps:
            waiting.add(n)
        if held(inv):
            continue
        for k, alert in enumerate(inv.alerts):
            if _age(alert) < _cut("raw_source"):
                raw.add(("inv", n, k))
        if (
            decision
            and decision[-1][0] == "reviewed"
            and decision[-1][1] < _cut("evidence")
            and not inv.changed
        ):
            evidence |= {(n, k) for k, snap in enumerate(inv.snapshots) if snap}
    loose_gone = set()
    for k, alert in enumerate(world.loose):
        cut = _cut("quarantine") if alert.quarantined else _cut("raw_source")
        if _age(alert) < cut:
            (quarantine if alert.quarantined else raw).add(("loose", k))
        if _age(alert) < _cut("memory"):
            loose_gone.add(k)
    return {
        "raw": raw,
        "quarantine": quarantine,
        "evidence": evidence,
        "victims": victims,
        "waiting": waiting,
        "kept": kept,
        "loose_gone": loose_gone,
        "lookups_gone": sum(1 for t in world.lookups if t < _cut("memory")),
        "reports_gone": sum(1 for t in world.reports if t < _cut("memory")),
    }


def _alert_id(where: str, n: int, k: int) -> str:
    return f"{where}-{n}-{k}"


async def write(conn: AsyncConnection, world: World, user: int) -> None:
    """The world as rows, written as the owner (who may set every time)."""
    for n, inv in enumerate(world.investigations):
        end = _s(inv.bucket_end)
        await conn.execute(
            text(
                "INSERT INTO investigations (id, grouping_version, rule_id, group_key,"
                " bucket_start, bucket_end, previous_id, version)"
                " VALUES (:id, '2', 'r', :key, :start, :end, :prev, :v)"
            ),
            {"id": inv.id, "key": f"k{n}", "start": end - timedelta(days=1), "end": end,
             "prev": uuid.uuid4(), "v": 2 if inv.changed else 1},
        )  # fmt: skip
        for k, alert in enumerate(inv.alerts):
            await _write_alert(conn, _alert_id("inv", n, k), alert)
            await conn.execute(
                text(
                    "INSERT INTO investigation_alerts (alert_id, investigation_id) VALUES (:a, :i)"
                ),
                {"a": _alert_id("inv", n, k), "i": inv.id},
            )
        for value in inv.entities:
            await conn.execute(
                text(
                    "INSERT INTO investigation_entities (investigation_id, kind, value)"
                    " VALUES (:i, 'ip', :v)"
                ),
                {"i": inv.id, "v": value},
            )
        for action, created in inv.reviews:
            await conn.execute(
                text(
                    "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                    " action, outcome, note, created_at) VALUES (:i, 1, 1, :u, :a, :o, :note, :t)"
                ),
                {"i": inv.id, "u": user, "a": action,
                 "o": None if action == "note" else "benign_expected",
                 "note": "a note" if action == "note" else None, "t": _s(created)},
            )  # fmt: skip
        for k, snap in enumerate(inv.snapshots):
            key = _hex(inv.id, k)
            await conn.execute(
                text(
                    "INSERT INTO evidence_requests (investigation_id, eid, task_key, template,"
                    " template_version, origin, first_version, created_at)"
                    " VALUES (:i, :e, :k, 'proxy.pair', 1, 'pack', 1, :t)"
                ),
                {"i": inv.id, "e": k + 1, "k": key, "t": AT},
            )
            await conn.execute(
                text(
                    "INSERT INTO evidence (investigation_id, version, task_key, template,"
                    " template_version, params, status, coverage, snapshot, result_hash,"
                    " collected_at) VALUES (:i, 1, :k, 'proxy.pair', 1, '{}', 'ok', '{}',"
                    " CAST(:snap AS jsonb), :h, :t)"
                ),
                {"i": inv.id, "k": key, "snap": '{"rows": [1]}' if snap else "null",
                 "h": _hex("r", k), "t": AT},
            )  # fmt: skip
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                " VALUES (:i, 1, 'p@1', 1, 1, 'collect', 'proxy', 'evidence_ready', :h, '{}',"
                " 0, :t)"
            ),
            {"i": inv.id, "h": _hex("d", inv.id), "t": AT},
        )
        await conn.execute(
            text(
                "INSERT INTO signals (investigation_id, version, pack, name, value, status,"
                " completeness, evidence, definition_version) VALUES (:i, 1, 'p@1', 's',"
                " '1', 'known', 'exact', '{}', 1)"
            ),
            {"i": inv.id},
        )
        await conn.execute(
            text(
                "INSERT INTO jobs (investigation_id, status, trigger, run_after)"
                " VALUES (:i, :s, 'new', :t)"
            ),
            {"i": inv.id, "s": "queued" if inv.job_active else "done", "t": AT},
        )
        await conn.execute(
            text(
                "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                " view_hash, assessor, run_after, status) VALUES (:i, 1, 'p@1', :h, :h,"
                " 'engine', :t, :s)"
            ),
            {"i": inv.id, "h": _hex("a", inv.id), "t": AT,
             "s": "queued" if inv.assessment_active else "no_decision"},
        )  # fmt: skip
        await conn.execute(
            text(
                "INSERT INTO writeback_outbox (review_id, investigation_id, status, alert_ids,"
                " state) VALUES (:r, :i, 'closed', '{}', :s)"
            ),
            {"r": n + 1 + 1000 * user, "i": inv.id, "s": inv.writeback},
        )
        if inv.gold:
            await conn.execute(
                text(
                    "INSERT INTO gold_items (set_name, investigation_id, version, pack,"
                    " dossier_hash, rule_name, split, why, suggestion)"
                    " VALUES ('g', :i, 1, 'p@1', :h, 'r', 'dev', '{}', '{}')"
                ),
                {"i": inv.id, "h": _hex("d", inv.id)},
            )
    ids = [inv.id for inv in world.investigations]
    for inv in world.investigations:
        if inv.continues is not None and inv.continues < len(ids):
            await conn.execute(
                text("UPDATE investigations SET continues_id = :c WHERE id = :i"),
                {"c": ids[inv.continues], "i": inv.id},
            )
    await conn.execute(
        text(
            "INSERT INTO entities (kind, value, investigations) SELECT kind, value, count(*)"
            " FROM investigation_entities GROUP BY kind, value"
        )
    )
    for k, alert in enumerate(world.loose):
        await _write_alert(conn, _alert_id("loose", 0, k), alert)
    for k, checked in enumerate(world.lookups):
        await conn.execute(
            text(
                "INSERT INTO ti_lookups (source, value, indicators, checked_at)"
                " VALUES ('acme-threat-intel', :v, '[]', :t)"
            ),
            {"v": f"v{k}", "t": _s(checked)},
        )
    for k, week_end in enumerate(world.reports):
        await conn.execute(
            text(
                "INSERT INTO tuning_reports (rule, week_end, report, suggestions, dropped, model,"
                " cost_usd) VALUES (:r, :t, '{}', '[]', '[]', 'none', 0)"
            ),
            {"r": f"rule {k}", "t": _s(week_end)},
        )


async def _write_alert(conn: AsyncConnection, alert_id: str, alert: Alert) -> None:
    quarantined = alert.quarantined
    await conn.execute(
        text(
            "INSERT INTO alert_records (alert_id, index, status, quarantine_reason,"
            " normalizer_version, raw, content_hash, state_hash, recovered_by, detected_at,"
            " first_seen_at) VALUES (:a, 'alerts', :st, :q, 't', '{\"x\": 1}', 'h', 'h', 'live',"
            " :d, :f)"
        ),
        {"a": alert_id, "st": "quarantined" if quarantined else "normalized",
         "q": "missing_field" if quarantined else None,
         "d": None if alert.detected is None else _s(alert.detected), "f": _s(alert.first_seen)},
    )  # fmt: skip


CLEAR = (
    "signals", "dossiers", "evidence", "evidence_requests", "jobs", "review_state",
    "review_events", "assessments", "writeback_outbox", "llm_shadow", "gold_items",
    "investigation_entities", "entities", "investigation_alerts", "alert_records",
    "investigations", "ti_lookups", "tuning_reports",
)  # fmt: skip


async def clear(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        for table in CLEAR:
            await conn.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - constant names


@pytest.fixture
async def user(migrated_engine: AsyncEngine) -> int:
    async with migrated_engine.begin() as conn:
        return await auth.add_user(conn, "purger", "Purger", "correct horse battery")


async def _scalars(engine: AsyncEngine, query: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(query), params)).scalars())


async def _all(engine: AsyncEngine, query: str) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(query))).all())


async def _links(engine: AsyncEngine) -> dict[Any, Any]:
    return dict(await _all(engine, "SELECT id, continues_id FROM investigations"))


async def check(engine: AsyncEngine, world: World) -> None:
    model = expected(world)
    links = await _links(engine)
    planned = await purge.plan(engine, CUT)
    outcome = await purge.run(engine, CUT)
    assert outcome.planned.as_json() == planned.as_json()
    assert purge.differences(outcome.planned, outcome.done) == []
    assert outcome.holds_intact, outcome.holds_changed
    assert outcome.done.waiting == len(model["waiting"])
    assert outcome.done.held["memory"] == len(model["kept"])
    # a held investigation's row is as it was, its link to the one it continues too
    after = await _links(engine)
    for inv in world.investigations:
        if held(inv):
            assert after[inv.id] == links[inv.id]
    done = outcome.done.changed
    assert done["raw_source"]["alert_records.raw"] == len(model["raw"])
    assert done["quarantine"]["alert_records.raw"] == len(model["quarantine"])
    assert done["evidence"]["evidence.snapshot"] == len(model["evidence"])
    memory = done["memory"]
    assert memory["investigations"] == len(model["victims"])
    assert memory["alert_records.unlinked"] == len(model["loose_gone"])
    assert memory["ti_lookups"] == model["lookups_gone"]
    assert memory["tuning_reports"] == model["reports_gone"]
    gone = {world.investigations[n].id for n in model["victims"]}
    left = set(await _scalars(engine, "SELECT id FROM investigations"))
    assert left == {inv.id for inv in world.investigations} - gone
    victims_alerts = sum(len(world.investigations[n].alerts) for n in model["victims"])
    assert memory["alert_records"] == memory["investigation_alerts"] == victims_alerts
    # raw purged exactly as the model says, for the alerts that stay
    purged = set(
        await _scalars(
            engine,
            "SELECT alert_id FROM alert_records WHERE raw_purged_at IS NOT NULL AND raw = '{}'",
        )
    )
    kept_raw = set(
        await _scalars(
            engine,
            "SELECT alert_id FROM alert_records WHERE raw_purged_at IS NULL AND raw = '{\"x\": 1}'",
        )
    )
    should = {
        _alert_id(w, n if w == "inv" else 0, k)
        for (w, n, k) in {(*x,) if x[0] == "inv" else ("loose", 0, x[1]) for x in model["raw"]}
        | {("loose", 0, x[1]) for x in model["quarantine"]}
    }
    remaining = set(await _scalars(engine, "SELECT alert_id FROM alert_records"))
    assert purged == should & remaining
    assert kept_raw == remaining - purged
    # evidence snapshots
    emptied = {
        (r[0], r[1])
        for r in await _all(engine, "SELECT investigation_id, task_key FROM evidence"
                            " WHERE snapshot_purged_at IS NOT NULL AND snapshot IS NULL")
    }  # fmt: skip
    wanted = {
        (world.investigations[n].id, _hex(world.investigations[n].id, k))
        for n, k in model["evidence"]
        if n not in model["victims"]
    }
    assert emptied == wanted
    # entity counts are what the entity index says
    stored_rows = await _all(engine, "SELECT kind, value, investigations FROM entities")
    derived_rows = await _all(
        engine, "SELECT kind, value, count(*) FROM investigation_entities GROUP BY 1, 2"
    )
    stored = {(k, v): n for k, v, n in stored_rows}
    derived = {(k, v): n for k, v, n in derived_rows}
    assert stored == derived
    # no investigation continues one that is gone
    dangling = await _scalars(
        engine,
        "SELECT n.id FROM investigations n WHERE n.continues_id IS NOT NULL AND NOT EXISTS"
        " (SELECT 1 FROM investigations o WHERE o.id = n.continues_id)",
    )
    assert dangling == []
    # a second run at the same time changes nothing
    again = await purge.run(engine, CUT)
    assert again.done.total() == 0
    assert again.planned.total() == 0


@settings(
    # the profile's (dev 30, ci 100, gate 1,000): about 0.45 s each, two runs over a database
    max_examples=max(30, settings().max_examples // 10),
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(world=WORLD)
async def test_exactly_the_expired_unheld_rows_go(
    migrated_engine: AsyncEngine, user: int, world: World
) -> None:
    await clear(migrated_engine)
    async with migrated_engine.begin() as conn:
        await write(conn, world, user)
    await check(migrated_engine, world)


async def test_a_world_with_every_kind_of_row(migrated_engine: AsyncEngine, user: int) -> None:
    """One example of each rule, by hand: the generated property's anchor."""
    old, new = -200 * DAY, -1 * DAY
    world = World(
        investigations=[
            Inv(old, [Alert(old, old)], [("reviewed", old)], [True, False], False, False, False,
                ["10.0.0.1"], None),  # gone whole
            Inv(old, [Alert(old, old)], [("reviewed", old)], [True], True, False, False,
                ["10.0.0.1"], 6),  # the gold set: everything kept, and the one it continues
            Inv(old, [Alert(old, old)], [("reviewed", -1 * DAY)], [True], False, False, False,
                [], 0),  # reviewed yesterday: kept, raw emptied, evidence kept
            Inv(-60 * DAY, [Alert(-60 * DAY, -60 * DAY)], [("reviewed", -95 * DAY)], [True],
                False, False, False, ["10.0.0.2"], None),  # raw and evidence emptied
            Inv(old, [Alert(old, old)], [("follow_up", old)], [True], False, True, False,
                [], None),  # a job waits: kept; a follow-up keeps its evidence
            Inv(new, [Alert(new, new)], [], [True], False, False, False, ["10.0.0.2"], None),
            Inv(old, [Alert(old, old)], [("reviewed", old)], [True], False, False, False,
                [], None),  # past every period, but the gold one continues it: its row stays
            Inv(old, [Alert(old, old), Alert(-10 * DAY, -10 * DAY)], [("reviewed", -95 * DAY)],
                [True], False, False, False, [], None, changed=True),  # changed since review
            Inv(old, [Alert(old, old)], [("reviewed", old)], [True], False, False, False,
                [], None, writeback="paused"),  # a paused write-back: waits, kept whole
        ],
        loose=[Alert(None, old, True), Alert(-40 * DAY, -40 * DAY, False), Alert(new, new, True)],
        lookups=[old, new],
        reports=[old, new],
    )  # fmt: skip
    async with migrated_engine.begin() as conn:
        await write(conn, world, user)
    model = expected(world)
    assert model["victims"] == {0}
    assert model["kept"] == {1, 6}
    assert model["waiting"] == {4, 8}
    assert model["evidence"] == {(0, 0), (3, 0), (6, 0), (8, 0)}
    await check(migrated_engine, world)


# --------------------------------------------------------------------------- the role


async def test_the_purge_role_holds_exactly_its_grants(migrated_engine: AsyncEngine) -> None:
    assert await roles.purge_role_problems(migrated_engine) == []
    await purge.preflight(migrated_engine)


async def test_an_extra_grant_is_reported_and_stops_the_purge(
    migrated_engine: AsyncEngine,
) -> None:
    async with migrated_engine.begin() as conn:
        await conn.execute(text("GRANT DELETE ON audit_events TO argus_purge"))
        await conn.execute(text("GRANT SELECT ON users TO argus_purge"))
    problems = await roles.purge_role_problems(migrated_engine)
    assert "can DELETE audit_events" in problems
    assert "can read users" in problems
    with pytest.raises(purge.PurgeError, match="not as migration 0031 grants it"):
        await purge.run(migrated_engine, CUT)


async def test_a_missing_grant_is_reported(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        await conn.execute(text("REVOKE DELETE ON investigations FROM argus_purge"))
    assert "cannot DELETE investigations" in await roles.purge_role_problems(migrated_engine)


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        ("DELETE FROM audit_events", "permission denied"),
        ("DELETE FROM case_events", "permission denied"),
        ("DELETE FROM cases", "permission denied"),
        ("UPDATE alert_records SET normalized = NULL", "permission denied"),
        ("TRUNCATE alert_records", "permission denied"),
        ("ALTER TABLE audit_events DISABLE TRIGGER ALL", "must be owner"),
        ("ALTER TABLE alert_records DISABLE TRIGGER ALL", "must be owner"),
        ("SET session_replication_role = replica", "permission denied"),
        ("DELETE FROM users", "permission denied"),
    ],
)
async def test_the_purge_role_can_touch_nothing_else(
    migrated_engine: AsyncEngine, statement: str, message: str
) -> None:
    async with migrated_engine.connect() as conn:
        await conn.execute(text("SET LOCAL ROLE argus_purge"))
        with pytest.raises(DBAPIError, match=message):
            await conn.execute(text(statement))


async def test_the_runtime_role_is_no_member_of_the_purge_role(app_engine: AsyncEngine) -> None:
    async with app_engine.connect() as conn:
        with pytest.raises(DBAPIError, match="permission denied"):
            await conn.execute(text("SET ROLE argus_purge"))
    assert await roles.runtime_role_problems(app_engine) == []


async def test_a_purged_value_cannot_come_back(migrated_engine: AsyncEngine) -> None:
    world = World([], [Alert(-200 * DAY, -200 * DAY)], [])
    async with migrated_engine.begin() as conn:
        await write(conn, world, 0)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE alert_records SET raw = '{}', raw_purged_at = now()"))
    with pytest.raises(DBAPIError, match="purged_raw_is_empty"):
        async with migrated_engine.begin() as conn:
            await conn.execute(text("UPDATE alert_records SET raw = '{\"x\": 2}'"))


# --------------------------------------------------------------------------- the rest of ARGUS


def _doc(alert_id: str, status: str) -> dict[str, Any]:
    return {
        "_id": alert_id,
        "_index": ".alerts-security.alerts-acme-soc",
        "found": True,
        "_source": {"@timestamp": "2026-03-01T00:00:00Z", "kibana.alert.workflow_status": status},
    }


async def test_reingesting_keeps_the_purged_raw_empty(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    async with app_engine.begin() as conn:
        await ingest(conn, [_doc("a1", "open")], "live", AT)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("SET LOCAL ROLE argus_purge"))
        await conn.execute(text("UPDATE alert_records SET raw = '{}', raw_purged_at = now()"))
    async with app_engine.begin() as conn:  # the state changed in the SIEM: read again
        await ingest(conn, [_doc("a1", "closed")], "live", AT)
    async with app_engine.connect() as conn:
        raw, purged_at, status = (
            await conn.execute(
                text("SELECT raw, raw_purged_at, workflow_status FROM alert_records")
            )
        ).one()
    assert raw == {}
    assert purged_at is not None
    assert status == "closed"  # the rest of the row is kept up to date


async def test_purged_evidence_is_never_reused_or_rederived(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, user: int
) -> None:
    old = -200 * DAY
    keep = Inv(-10 * DAY, [Alert(-10 * DAY, -10 * DAY)], [], [True], False, False, False, [], None)
    emptied = Inv(old, [Alert(old, old)], [("reviewed", -100 * DAY), ("note", -1 * DAY)], [True],
                  False, False, False, [], None)  # fmt: skip
    world = World([keep, emptied], [], [])
    async with migrated_engine.begin() as conn:
        await write(conn, world, user)
    outcome = await purge.run(migrated_engine, CUT)
    assert outcome.done.changed["evidence"]["evidence.snapshot"] == 1
    assert outcome.done.changed["memory"]["investigations"] == 0  # a review note from yesterday
    async with app_engine.connect() as conn:
        assert await reusable(conn, emptied.id, [_hex(emptied.id, 0)]) == {}
        assert await reusable(conn, keep.id, [_hex(keep.id, 0)]) == {_hex(keep.id, 0): 1}
    # a new pack: only the investigation whose data is all there is derived again
    assert await queue_rederive(app_engine, "p@2") == 1
    jobs = await _scalars(
        app_engine, "SELECT investigation_id FROM jobs WHERE trigger = 'rederive'"
    )
    assert jobs == [keep.id]
