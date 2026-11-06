"""E3 against the database, as the runtime role: an inbound group's site from its stored web
evidence, the checking lane's pass with a fake gateway (a soft-404 site stays in the digest, a
served file presents its site; a lookup places a thin group), what the checks change read again
by the engine, the keep period, and the grants. Made-up sites and addresses (ACME)."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.gateway.gateway import Result
from argus.gateway.health import HealthMemory
from argus.gateway.templates import Purpose
from argus.risk import checking, exposure_db, run
from argus.risk.config import Exposure
from tests.integration.risk.conftest import NOW, all_rows, group, rule, scalar, setup

pytestmark = pytest.mark.integration
SITE, SOFT = "dept.example.edu", "www.example.edu"
SCOUT, SCANNER, THIN = "45.138.13.7", "45.138.13.8", "45.138.13.9"
WHEN = NOW.replace(hour=11)  # the checks run inside the day's index, outside the quiet hours
ON = Exposure.model_validate({**setup().config.exposure.model_dump(),
                              "templates": sorted(checking.TEMPLATES)})  # fmt: skip


async def followups(owner: AsyncEngine, gid: uuid.UUID, rows: list[tuple[str, str]]) -> None:
    """The group's stored ``web.followups`` answer: its client's 2xx answers (site, path)."""
    key = hashlib.sha256(gid.bytes).hexdigest()
    snapshot = {"rows": [{"_index": "acme-logs-nginx-2026.10.20", "_id": str(i), "_source": {
        "url": {"domain": site, "path": path}, "http": {"response": {"status_code": 200}}}}
        for i, (site, path) in enumerate(rows)]}  # fmt: skip
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO evidence_requests (investigation_id, eid, task_key, template,"
                " template_version, origin, first_version, created_at) VALUES (:i, 1, :k,"
                " 'web.followups', 1, 'pack', 1, :t)"
            ),
            {"i": gid, "k": key, "t": NOW},
        )
        await conn.execute(
            text(
                "INSERT INTO evidence (investigation_id, version, task_key, template,"
                " template_version, params, status, coverage, row_count, snapshot, result_hash,"
                " took_ms, collected_at) VALUES (:i, 1, :k, 'web.followups', 1, '{}'::jsonb, 'ok',"
                " '{}'::jsonb, :n, CAST(:s AS jsonb), :h, 5, :t)"
            ),
            {"i": gid, "k": key, "n": len(rows), "s": json.dumps(snapshot), "h": key, "t": NOW},
        )


def sizes(found: dict[int, int]) -> dict[str, Any]:
    return {"buckets": [{"key": k, "doc_count": v} for k, v in found.items()],
            "sum_other_doc_count": 0}  # fmt: skip


class Fake:
    """A gateway answering each template as a site would: ``SOFT`` answers every path with one
    page; ``SITE`` serves its ``/.env``."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def run(self, template: Any, params: Any, *, purpose: Purpose, component: str,
                  deadline: datetime) -> Result:  # fmt: skip
        assert purpose is Purpose.CHECK
        assert component == "checking"
        name = type(template).name
        self.sent.append(name)
        aggs: dict[str, Any]
        if name == "web.source_sites":
            aggs = {"sources": {"buckets": [{"key": THIN, "sites": sizes({}) | {
                "buckets": [{"key": SOFT, "doc_count": 4}]}}]},
                "ok_sources": {"sources": {"buckets": []}},
                "ok_sites": {"sites": {"buckets": []}}}  # fmt: skip
        elif name == "web.catchall":
            page = 5_120 if params.site == SOFT else None
            aggs = {"requests": {"value": 40}, "not_found": {"sizes": sizes({731: 9})}}
            for i, p in enumerate(params.paths):
                size = page or (2_400 if p == "/.env" else 731)
                aggs[f"ok_{i}"] = {"doc_count": 1, "sizes": sizes({size: 1})}
        elif name == "web.path_outcomes":
            page = 5_120 if params.site == SOFT else None
            aggs = {"requests": {"value": 3}, "answered": {"value": 3}, "paths": {"buckets": [
                {"key": p, "doc_count": 1, "statuses": {"buckets": [{"key": 200, "doc_count": 1}]}}
                for p in params.paths]}}  # fmt: skip
            for i, p in enumerate(params.paths):
                size = page or (2_400 if p == "/.env" else 731)
                aggs[f"ok_{i}"] = {"doc_count": 1, "sizes": sizes({size: 1})}
        else:
            aggs = {"paths": {"value": 2}, "sizes": {"value": 1}, "bytes": {"value": 9},
                    "top": {"buckets": []}}  # fmt: skip
        return Result({"aggregations": aggs}, 700, ("acme-logs-nginx-2026.10.20",))


async def normal() -> HealthMemory:
    return HealthMemory(probed_at=WHEN)


async def world(owner: AsyncEngine) -> dict[str, uuid.UUID]:
    await rule(owner, "r-web", "Web rule", severity="high", indices=("acme-logs-nginx-*",))
    made = {
        "scout": await group(owner, "r-web", actor=SCOUT, severity="high", hours_ago=3,
                             signals={"web.successes_after": 2}),
        "scanner": await group(owner, "r-web", actor=SCANNER, severity="high", hours_ago=3,
                               signals={"web.successes_after": 2}),
        "thin": await group(owner, "r-web", actor=THIN, severity="high", hours_ago=2),
    }  # fmt: skip
    # SITE serves its /.env and answers /.git/config with its not-found page: two files compared
    await followups(owner, made["scout"].id, [(SITE, "/.env"), (SITE, "/.git/config"), (SITE, "/")])
    await followups(owner, made["scanner"].id, [(SOFT, "/.env"), (SOFT, "/.git/config")])
    return {k: v.id for k, v in made.items()}


async def lanes(engine: AsyncEngine) -> dict[str, tuple[str, ...]]:
    rows = await all_rows(engine, "SELECT key, lanes FROM risk_objects WHERE kind = 'site'")
    return {r.key: tuple(r.lanes) for r in rows}


async def test_the_checks_present_a_served_file_and_leave_a_soft_404_site_in_the_digest(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    made = await world(migrated_engine)
    config = setup()
    await run.step(app_engine, config, WHEN)
    # the sites come from the stored web evidence; nothing is checked yet: no lane
    assert await lanes(migrated_engine) == {f"domain:{SITE}": (), f"domain:{SOFT}": ()}
    fake = Fake()
    report = await checking.run_pass(app_engine, fake, normal, now=WHEN, config=ON,
                                     clock=lambda: WHEN)  # fmt: skip
    assert report.stopped is None
    assert report.sent == len(fake.sent) > 0
    assert set(fake.sent) == {"web.source_sites", "web.catchall", "web.path_outcomes"}
    assert report.touched >= 2
    await run.step(app_engine, config, WHEN + timedelta(minutes=2))
    assert await lanes(migrated_engine) == {f"domain:{SITE}": ("exposure",), f"domain:{SOFT}": ()}
    category = {r.investigation_id: r.category for r in await all_rows(
        migrated_engine, "SELECT investigation_id, category FROM risk_groups")}  # fmt: skip
    assert category[made["scout"]] == "presented"
    assert category[made["scanner"]] == "inbound_success"  # its 2xx was the catch-all page
    crossing = await all_rows(
        migrated_engine,
        "SELECT c.lane, c.breakdown FROM risk_crossings c JOIN risk_objects b ON b.id ="
        " c.object_id WHERE b.key = :k", k=f"domain:{SITE}",
    )  # fmt: skip
    assert [r.lane for r in crossing] == ["exposure"]
    assert "ev:served" in {w["source"] for w in crossing[0].breakdown}
    # the thin group's site came from the lookup: it is a plain scanned site now
    obs = await all_rows(
        migrated_engine,
        "SELECT b.key FROM risk_observations o JOIN risk_objects b ON b.id = o.object_id"
        " WHERE o.investigation_id = :i", i=made["thin"],
    )  # fmt: skip
    assert {r.key for r in obs} == {f"domain:{SOFT}"}
    # a second pass asks nothing it already knows
    again = Fake()
    await checking.run_pass(app_engine, again, normal, now=WHEN + timedelta(minutes=5), config=ON,
                            clock=lambda: WHEN)  # fmt: skip
    assert again.sent == []
    stored = await all_rows(migrated_engine, "SELECT kind, verdict FROM exposure_checks")
    assert ("catchall", "soft_404") in {(r.kind, r.verdict) for r in stored}


async def test_one_outside_address_that_took_files_from_two_sites_is_one_new_item(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """Both sites enter L5 through the same outside address: the rescore folds the second, as
    the replay does (one item; the incident joins its sites in E2)."""
    other = "lab.example.edu"
    await rule(migrated_engine, "r-web", "Web rule", severity="high",
               indices=("acme-logs-nginx-*",))  # fmt: skip
    made = await group(migrated_engine, "r-web", actor=SCOUT, severity="high", hours_ago=3,
                       signals={"web.successes_after": 2})  # fmt: skip
    await followups(migrated_engine, made.id, [(s, p) for s in (SITE, other)
                                               for p in ("/.env", "/.git/config")])  # fmt: skip
    config = setup()
    await run.step(app_engine, config, WHEN)
    await checking.run_pass(app_engine, Fake(), normal, now=WHEN, config=ON, clock=lambda: WHEN)
    report = await run.step(app_engine, config, WHEN + timedelta(minutes=2))
    assert await lanes(migrated_engine) == {f"domain:{SITE}": ("exposure",),
                                            f"domain:{other}": ("exposure",)}  # fmt: skip
    assert report.new_items == 1
    assert report.folded == 1
    assert "1 folded into another site's" in report.line()
    crossed = await all_rows(migrated_engine, "SELECT lane, new_item FROM risk_crossings")
    assert sorted((r.lane, r.new_item) for r in crossed) == [("exposure", False),
                                                             ("exposure", True)]  # fmt: skip
    again = await run.step(app_engine, config, WHEN + timedelta(minutes=4))
    assert (again.new_items, again.folded) == (0, 0)


async def test_nothing_is_sent_while_the_checks_are_off_in_caution_or_in_the_quiet_hours(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, setup(), WHEN)
    fake = Fake()
    off = await checking.run_pass(app_engine, fake, normal, now=WHEN,
                                  config=setup().config.exposure, clock=lambda: WHEN)  # fmt: skip
    assert "switched on" in str(off.stopped)

    async def caution() -> HealthMemory:
        from argus.gateway.health import HealthState

        return HealthMemory(HealthState.CAUTION, since=WHEN, probed_at=WHEN)

    held = await checking.run_pass(app_engine, fake, caution, now=WHEN, config=ON,
                                   clock=lambda: WHEN)  # fmt: skip
    assert "NORMAL only" in str(held.stopped)
    night = WHEN.replace(hour=0, minute=40)
    quiet = await checking.run_pass(app_engine, fake, normal, now=night, config=ON,
                                    clock=lambda: night)  # fmt: skip
    assert "quiet hours" in str(quiet.stopped)
    assert fake.sent == []


async def test_the_checks_are_kept_180_days_and_the_web_may_read_them(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    old = NOW - timedelta(days=181)
    async with app_engine.begin() as conn:
        await exposure_db.save(
            conn,
            [
                exposure_db.Found(
                    "catchall", None, SITE, old.date(), "web.catchall", 1, None, "plain", {}, 5
                )
            ],
            old,
        )
        await exposure_db.save(conn, [exposure_db.Found(
            "sites", SCOUT, None, NOW.date(), "web.source_sites", 1, None, "none",
            {"sites": []}, 5)], NOW)  # fmt: skip
        assert await exposure_db.prune(conn, NOW, Exposure()) == 1
    assert await scalar(migrated_engine, "SELECT count(*) FROM exposure_checks") == 1
    assert await scalar(
        migrated_engine, "SELECT has_table_privilege('argus_web', 'exposure_checks', 'SELECT')"
    )
    assert not await scalar(
        migrated_engine, "SELECT has_table_privilege('argus_web', 'exposure_checks', 'INSERT')"
    )
    assert (
        await scalar(
            migrated_engine, "SELECT count(*) FROM siem_switches WHERE component = 'checking'"
        )
        == 1
    )
    async with migrated_engine.begin() as conn:  # the ledger takes the checking lane
        await conn.execute(
            text(
                "INSERT INTO siem_requests (at, component, purpose, template, version, indices,"
                " outcome, took_ms, elapsed_ms, response_bytes, attempts, lane) VALUES (now(),"
                " 'checking', 'check', 'web.catchall', 1, '{}', 'ok', 5, 5, 10, 1, 'checking')"
            )
        )
    async with app_engine.connect() as conn:
        assert await checking.spent_today(conn, datetime.now(UTC)) == 5
