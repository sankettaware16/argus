"""The shadow store (Q-G2): live items answered by a model for one helper task, stored by the
runtime role, never changed or deleted by it, never readable by the web's role (never shown);
resumable; the fallback only on small-tier items without a floor signal; the ladder's
measure from the rows and the runners' files."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.evaluation import ladder, measures, robustness, shadow, tasks
from argus.llm.gateway import Call, Completion, NoCapacity
from argus.llm.privacy import Privacy
from argus.llm.providers import LlmConfig
from tests.unit.agent.test_agent import body

pytestmark = pytest.mark.integration
NOW = datetime.now(UTC)


def local(**over: Any) -> LlmConfig:
    provider = {"name": "local", "trust": "campus", "base_url": "https://127.0.0.1:28443/v1",
                "keys": ["K"], "ca_file": "/x.crt", "timeout_s": 900, "concurrency": 1,
                "tasks": ["evaluate", "ping"], "schema_output": True, "schema_required": True,
                "models": {"small": {"name": "cp", "context_tokens": 16384,
                                     "thinking_tokens": 2048, "max_output": 6144,
                                     "max_prompt_tokens": 12000, "read_tps": 45,
                                     "write_tps": 11}},
                "limits": {"rpd": 375}, "licence": "D-121", **over}  # fmt: skip
    return LlmConfig.model_validate({"providers": [provider]})


class Fake:
    def __init__(self, *replies: str | Exception) -> None:
        self.replies = list(replies)
        self.calls: list[Call] = []

    async def __call__(self, call: Call) -> Completion:
        self.calls.append(call)
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return Completion(reply, "local", "cp", 300, 40, 0.0, 9_000, uuid.uuid4())


async def seed(owner: AsyncEngine, n: int, **over: Any) -> list[uuid.UUID]:
    ids = [uuid.uuid4() for _ in range(n)]
    async with owner.begin() as conn:
        for k, iid in enumerate(ids):
            await conn.execute(text(
                "INSERT INTO investigations (id, grouping_version, rule_id, group_key,"
                " bucket_start, bucket_end, previous_id, alert_count, first_event_at,"
                " last_event_at, severity, version) VALUES (:i, '1', 'r', :k, :s, :e,"
                " gen_random_uuid(), 1, :s, :s, 'low', 1)"
            ), {"i": iid, "k": f"k{k}", "s": NOW, "e": NOW + timedelta(hours=1)})  # fmt: skip
            await conn.execute(text(
                "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                " VALUES (:i, 1, 'generic@1', 1, 1, 'collect', 'generic', 'evidence_ready', :h,"
                " CAST(:b AS jsonb), 0, :at)"
            ), {"i": iid, "h": f"{k:064x}", "b": json.dumps(body(**over)),
                "at": NOW - timedelta(minutes=k)})  # fmt: skip
    return ids


TRIAGE = json.dumps({"urgency": "today", "reason": "r"})


async def test_live_items_are_answered_in_shadow_once_and_measured(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, privacy: Privacy
) -> None:
    await seed(migrated_engine, 3)
    spec = tasks.SPECS[tasks.TRIAGE]
    fake = Fake(TRIAGE, "not json", TRIAGE)
    since = NOW - timedelta(hours=24)
    done = await shadow.run(app_engine, spec, privacy, fake, local(), "local", "cp", since, 10)
    assert (done.stored, done.usable, done.skipped, done.stopped) == (3, 2, 0, None)
    assert all(c.purpose == "evaluate" and c.schema == spec.schema for c in fake.calls)
    again = Fake(RuntimeError("must not be called"))
    resumed = await shadow.run(app_engine, spec, privacy, again, local(), "local", "cp", since, 10)
    assert (resumed.stored, again.calls) == (0, [])
    other = Fake(TRIAGE)  # another model: its own shadow
    assert (await shadow.run(app_engine, spec, privacy, other, local(), "local", "cp2", since,
                             10)).stored == 3  # fmt: skip
    async with app_engine.connect() as conn:
        measured = await shadow.measure(conn, "triage", "local", "cp")
        rows = (await conn.execute(text(
            "SELECT usable, ok, outcome, answer, lease_ms, latency_ms >= 0 FROM llm_shadow"
            " WHERE model = 'cp' ORDER BY usable, id"))).all()  # fmt: skip
        assert await shadow.measure(conn, "extract", "local", "cp") is None
    assert measured == ladder.Shadow(items=3, calls=ladder.Count(hits=2, total=3), failed=0,
                                     latency=measured.latency)  # fmt: skip
    assert len(measured.latency) == 3  # every call that reached the model (F1)
    unusable, *usable = rows
    assert unusable[:4] == (False, None, None, None)  # nothing kept of an unusable answer
    assert [r[2] for r in usable] == ["today", "today"]
    assert all(r[3] == {"reason": "r", "urgency": "today"} and r[4] > 60_000 for r in usable)


async def test_a_long_deferral_stops_the_shadow_until_next_time(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, privacy: Privacy
) -> None:
    await seed(migrated_engine, 2)
    fake = Fake(TRIAGE, NoCapacity(datetime.now(UTC) + timedelta(hours=5), "overnight only"))
    done = await shadow.run(app_engine, tasks.SPECS["triage"], privacy, fake, local(), "local",
                            "cp", NOW - timedelta(hours=1), 10)  # fmt: skip
    assert done.stored == 1
    assert done.stopped is not None
    assert done.stopped.startswith("no capacity until")


async def test_the_fallback_shadows_only_small_tier_items_without_a_floor_signal(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, privacy: Privacy
) -> None:
    """DQ22 (ii): the dossiers here have a floor signal (the threat lists were not checked),
    so the fallback asks nothing; triage asks them all, and never takes "later" for them."""
    await seed(migrated_engine, 2)
    fake = Fake(json.dumps({"outcome": "benign_expected", "confidence": 1, "reason": "r",
                            "missing": []}))  # fmt: skip
    since = NOW - timedelta(hours=1)
    done = await shadow.run(app_engine, tasks.SPECS["fallback"], privacy, fake, local(), "local",
                            "cp", since, 10)  # fmt: skip
    assert (done.stored, done.skipped, fake.calls) == (0, 2, [])
    later = Fake(json.dumps({"urgency": "later", "reason": "r"}))
    await shadow.run(app_engine, tasks.SPECS["triage"], privacy, later, local(), "local", "cp",
                     since, 10)  # fmt: skip
    async with app_engine.connect() as conn:
        measured = await shadow.measure(conn, "triage", "local", "cp")
    assert measured is not None
    assert measured.failed == 2  # a floor item triaged "later" fails its check


async def test_the_runtime_role_adds_rows_but_never_changes_or_deletes_them(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, privacy: Privacy
) -> None:
    await seed(migrated_engine, 1)
    await shadow.run(app_engine, tasks.SPECS["triage"], privacy, Fake(TRIAGE), local(), "local",
                     "cp", NOW - timedelta(hours=1), 10)  # fmt: skip
    for statement in ("UPDATE llm_shadow SET ok = false", "DELETE FROM llm_shadow",
                      "TRUNCATE llm_shadow"):  # fmt: skip
        with pytest.raises(DBAPIError, match="permission denied"):
            async with app_engine.begin() as conn:
                await conn.execute(text(statement))


async def test_the_web_can_never_read_the_shadow(web_engine: AsyncEngine) -> None:
    """Plan §3 rule 12: shadow output is never shown. The web's role has no grant on it."""
    with pytest.raises(DBAPIError, match="permission denied"):
        async with web_engine.connect() as conn:
            await conn.execute(text("SELECT count(*) FROM llm_shadow"))


async def test_the_ladder_reads_the_runners_files_and_the_shadow(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, privacy: Privacy, tmp_path: Path
) -> None:
    llm = local()
    here = measures.folder(tmp_path, "local")
    cases = {"control": {"outcome": "answered"}, "off": {"outcome": "deferred", "wait_s": 300}}
    hardening = dict.fromkeys(ladder.HARDENING, True)
    measures.write(here / "drill.json", {"provider": "local", "model": "cp",
                                         "setup": robustness.setup_of(llm.providers[0]),
                                         "hardening": hardening, "cases": cases})  # fmt: skip
    triage = {"calls": {"hits": 30, "total": 30}, "items": 30, "right": 25, "baseline_right": 20}
    measures.write(here / "task-triage.json", measures.wrapped(llm, triage))
    other = local(models={"small": {"name": "other", "context_tokens": 16384}})
    measures.write(here / "task-extract.json", measures.wrapped(other, {
        "calls": {"hits": 1, "total": 1}, "items": 1}))  # fmt: skip
    await seed(migrated_engine, 2)
    await shadow.run(app_engine, tasks.SPECS["summary"], privacy,
                     Fake(json.dumps({"summary": "An alert."})), llm, "local", "cp",
                     NOW - timedelta(hours=1), 10)  # fmt: skip
    async with app_engine.connect() as conn:
        built, notes = await measures.build(conn, llm, tmp_path)
    assert built.licence == "D-121"
    assert built.robustness is not None
    assert built.robustness["off"].outcome == "deferred"
    assert set(built.tasks) == {"triage"}  # another model's extraction is not used
    assert any("task-extract.json" in n for n in notes)
    assert built.shadow["summary"].items == 2
    assert built.gold is None  # no gold run: no promotion
    result = ladder.judge("triage", built)
    assert not result.ready
    rung = next(r for r in result.rungs if r.name == "robustness")
    assert any(line.startswith("slow: not run") for line in rung.lines)


async def test_items_it_cannot_ask_never_take_a_runs_places(
    migrated_engine: AsyncEngine,
    app_engine: AsyncEngine,
    privacy: Privacy,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fallback skips floor items without storing them: a run looks past them, so a newer
    batch of floor items never starves the older items it can ask; its limit counts items
    asked, not items looked at."""
    from argus.assess import engine
    from argus.evaluation import taskrun

    await seed(migrated_engine, 3)  # the newest: floor items
    old = await seed(migrated_engine, 2, clear=True)  # older: without a floor signal
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE dossiers SET created_at = :at"
                                " WHERE investigation_id = ANY(:i)"),
                           {"at": NOW - timedelta(hours=2), "i": old})  # fmt: skip
    monkeypatch.setattr(engine, "floor", lambda b, f, s: [] if b.get("clear") else ["a floor"])
    monkeypatch.setattr(taskrun, "small_tier", lambda b, f, r: True)
    asked = Fake(json.dumps({"outcome": "inconclusive", "confidence": 0.5, "reason": "r",
                             "missing": []}))  # fmt: skip
    done = await shadow.run(app_engine, tasks.SPECS["fallback"], privacy, asked, local(), "local",
                            "cp", NOW - timedelta(hours=24), 1)  # fmt: skip
    assert (done.stored, done.skipped, len(asked.calls)) == (1, 3, 1)
    again = await shadow.run(app_engine, tasks.SPECS["fallback"], privacy, asked, local(),
                             "local", "cp", NOW - timedelta(hours=24), 5)  # fmt: skip
    assert (again.stored, again.skipped) == (1, 3)  # the other one; the floor items again


async def test_a_regroup_empties_the_shadow_with_the_investigations(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, privacy: Privacy
) -> None:
    """Shadow answers are about the old investigations: a regroup (D-053) drops them with the
    rest of the derived tables, and is not stopped by them."""
    from argus.grouping.regroup import regroup

    await seed(migrated_engine, 1)
    await shadow.run(app_engine, tasks.SPECS["triage"], privacy, Fake(TRIAGE), local(), "local",
                     "cp", NOW - timedelta(hours=1), 10)  # fmt: skip
    await regroup(migrated_engine, NOW)
    async with app_engine.connect() as conn:
        assert await shadow.measure(conn, "triage", "local", "cp") is None


async def test_a_call_the_model_failed_is_stored_unusable_and_counted(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, privacy: Privacy
) -> None:
    """F1 (review): a call that reached the model and gave nothing (timed out, a server error)
    is a stored, unusable row with its time and lease; the run waits the gateway's short wait
    and goes on, or stops at a long one."""
    await seed(migrated_engine, 3)
    soon = NoCapacity(datetime.now(UTC) + timedelta(seconds=30), "local: no answer", failed=1)
    waited: list[float] = []

    async def sleep(s: float) -> None:
        waited.append(s)

    fake = Fake(soon, TRIAGE)
    done = await shadow.run(app_engine, tasks.SPECS["triage"], privacy, fake, local(), "local",
                            "cp", NOW - timedelta(hours=1), 10, sleep=sleep)  # fmt: skip
    assert (done.stored, done.usable, done.stopped, len(fake.calls)) == (3, 2, None, 3)
    assert len(waited) == 1
    assert waited[0] <= 30
    async with app_engine.connect() as conn:
        measured = await shadow.measure(conn, "triage", "local", "cp")
    assert measured is not None
    assert measured.calls == ladder.Count(hits=2, total=3)
    assert len(measured.latency) == 3
    assert all(lease > 60 for _, lease in measured.latency)
    later = NoCapacity(datetime.now(UTC) + timedelta(hours=1), "local: no answer", failed=1)
    stopped = await shadow.run(app_engine, tasks.SPECS["summary"], privacy, Fake(later),
                               local(), "local", "cp", NOW - timedelta(hours=1), 10)  # fmt: skip
    assert (stopped.stored, stopped.usable) == (1, 0)
    assert stopped.stopped is not None
    assert stopped.stopped.startswith("no capacity until")


async def test_doctor_fails_while_the_web_could_read_shadow_rows(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, privacy: Privacy
) -> None:
    """F8 (review): the runtime login may read llm_shadow, and the web uses it until
    web.database_role: api (Q-A2): doctor fails while there are rows and the web uses it."""
    from argus.config.settings import Settings, WebSettings
    from argus.doctor import shadow_check

    app, api = Settings(), Settings(web=WebSettings(database_role="api"))
    assert (await shadow_check(app_engine, app)).ok  # empty
    await seed(migrated_engine, 1)
    await shadow.run(app_engine, tasks.SPECS["triage"], privacy, Fake(TRIAGE), local(), "local",
                     "cp", NOW - timedelta(hours=1), 10)  # fmt: skip
    failed = await shadow_check(app_engine, app)
    assert not failed.ok
    assert "web.database_role: api" in failed.detail
    assert (await shadow_check(app_engine, api)).ok
