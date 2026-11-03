"""The review's findings that only Postgres shows (Q-D3, gate report "Review"): a person's
text the database refuses (R1), a recreated case against the mirror's primary key (R2), the
alert baseline and its finding in one transaction (R4), a stray action counted once (R7), the
alert diff's place kept (R8)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.kibana_sync.cycle import SyncConfig
from argus.kibana_sync.model import AlertState, Finding, Kind
from argus.kibana_sync.store import PgSyncStore
from tests.integration.cases.conftest import make_person
from tests.integration.kibana_sync.test_pg_sync import (
    _case_with_a_sent_create,
    _findings,
    _pg_rig,
)

PERSON = "ra-anita"


async def test_r2_a_recreated_case_takes_over_the_deleted_ones_row(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    asha = await make_person(app_engine, "asha")
    case_id = await _case_with_a_sent_create(app_engine, migrated_engine, asha)
    r = _pg_rig(app_engine)
    first = r.kibana.create(argus_case=case_id)
    assert (await r.cycle()).outcome == "complete"
    r.kibana.delete(first)
    assert (await r.cycle()).outcome == "complete"
    assert Kind.DELETED_IN_KIBANA in await _findings(app_engine)
    async with migrated_engine.begin() as conn:  # the approved recreate: the create sent again
        # (Q-D4's approved resend, with its approval request, is not built: the guard that
        # wants one is switched off for this one update on the throwaway database)
        await conn.execute(text("ALTER TABLE kibana_outbox DISABLE TRIGGER kibana_outbox_guard"))
        await conn.execute(
            text(
                "UPDATE kibana_outbox SET resends = 1, sent_count = 2"
                " WHERE case_id = :c AND op = 'create'"
            ),
            {"c": case_id},
        )
    second = r.kibana.create(argus_case=case_id)
    for _ in range(3):
        record = await r.cycle()
        assert record.outcome == "complete", (record.outcome, record.reason)
    async with app_engine.connect() as conn:
        rows = (await conn.execute(text("SELECT * FROM kibana_mirror"))).all()
    assert [(row.kibana_case_id, row.deleted_at, row.actions_seen) for row in rows] == [
        (second, None, 1)
    ]
    assert rows[0].case_id == case_id
    assert Kind.DUPLICATE_CASE not in await _findings(app_engine)


async def test_r2_the_runtime_moves_a_mirror_only_after_its_case_was_deleted(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    asha = await make_person(app_engine, "asha")
    case_id = await _case_with_a_sent_create(app_engine, migrated_engine, asha)
    r = _pg_rig(app_engine)
    kid = r.kibana.create(argus_case=case_id)
    assert (await r.cycle()).outcome == "complete"
    with pytest.raises(DBAPIError, match="only after its own was deleted"):
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE kibana_mirror SET kibana_case_id = 'elsewhere'"))
    async with app_engine.begin() as conn:  # a deleted one may be pointed at the new case
        await conn.execute(text("UPDATE kibana_mirror SET deleted_at = now()"))
        await conn.execute(text("UPDATE kibana_mirror SET kibana_case_id = 'elsewhere'"))
    assert "elsewhere" in await PgSyncStore(app_engine).mirrors()
    assert kid not in await PgSyncStore(app_engine).mirrors()


@pytest.mark.parametrize(
    "where", ["comment", "title", "tag", "surrogate", "author_title", "people"]
)
async def test_r1_a_persons_text_the_database_refuses_wedges_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, where: str
) -> None:
    asha = await make_person(app_engine, "asha")
    case_id = await _case_with_a_sent_create(app_engine, migrated_engine, asha)
    r = _pg_rig(app_engine)
    kid = r.kibana.create(argus_case=case_id)
    assert (await r.cycle()).outcome == "complete"
    other = r.kibana.create(by=PERSON, tags=("x\u0000y",), title="a\u0000b")
    if where == "comment":
        r.kibana.comment(kid, PERSON, "hello \u0000 world")
    elif where == "title":
        r.kibana.set_field(kid, PERSON, "title", "my \u0000 title")
    elif where == "tag":
        r.kibana.add_tags(kid, PERSON, "x\u0000y")
    elif where == "surrogate":
        r.kibana.comment(kid, PERSON, "lone \ud800 surrogate")
        r.kibana.set_field(kid, PERSON, "title", "lone \udfff title")
    elif where == "author_title":
        r.kibana.set_field(kid, "ra\u0000anita", "title", "t")
    else:
        async with migrated_engine.begin() as conn:  # a known alert, on the person's case
            await conn.execute(
                text(
                    "INSERT INTO alert_records (alert_id, index, status, normalizer_version,"
                    " raw, content_hash, state_hash, recovered_by, first_seen_at) VALUES"
                    " ('alert-7', 'alerts', 'normalized', 't', '{}', 'h', 'h', 'live', now())"
                )
            )
        r.kibana.attach(other, PERSON, "alert-7")
    for _ in range(3):
        record = await r.cycle(advance=timedelta(hours=1, minutes=1))
        assert record.outcome == "complete", (record.outcome, record.reason)
    async with app_engine.connect() as conn:
        mirror = (await conn.execute(text("SELECT title, tags FROM kibana_mirror"))).one()
        details = (await conn.execute(text("SELECT details::text FROM kibana_findings"))).all()
    assert "\u0000" not in mirror.title
    assert all("\u0000" not in t for t in mirror.tags)
    assert not any("\\u0000" in row[0] or "\\ud8" in row[0] for row in details)
    if where in ("title", "surrogate"):
        assert mirror.title in ("my  title", "lone  title")
    if where == "people":
        async with app_engine.connect() as conn:
            kept = (await conn.execute(text("SELECT title, tags FROM kibana_people_cases"))).one()
        assert (kept.title, kept.tags) == ("ab", ["xy"])


async def test_r1_a_case_the_database_refuses_for_another_reason_is_a_finding(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Whatever else Postgres might refuse in one case: that case is a finding, the other
    goes on, and the case is kept the cycle after it can be."""
    asha = await make_person(app_engine, "asha")
    case_id = await _case_with_a_sent_create(app_engine, migrated_engine, asha)
    r = _pg_rig(app_engine)
    kid = r.kibana.create(argus_case=case_id)
    assert (await r.cycle()).outcome == "complete"
    r.kibana.comment(kid, PERSON, "a comment")
    real = r.store.apply  # type: ignore[attr-defined]

    async def refuse(*a: object, **k: object) -> int:
        raise DBAPIError("INSERT", {}, Exception("the database says no"))

    r.store.apply = refuse  # type: ignore[attr-defined,method-assign]
    record = await r.cycle()
    assert record.outcome == "partial"
    assert Kind.ANSWER_UNEXPECTED in await _findings(app_engine)
    r.store.apply = real  # type: ignore[attr-defined,method-assign]
    assert (await r.cycle()).outcome == "complete"
    assert Kind.PERSON_COMMENTED in await _findings(app_engine)


async def test_r4_the_baseline_and_its_finding_are_kept_together(app_engine: AsyncEngine) -> None:
    store = PgSyncStore(app_engine)
    now = datetime.now(UTC)
    state = AlertState("alert-1", "closed", None, None, now)
    good = Finding(Kind.ALERT_CHANGE_UNEXPLAINED, "alert-unexplained:one", None, None, {})
    assert await store.record_alerts([state], [good], now) == 1
    assert (await store.alert_states(["alert-1"]))["alert-1"].status == "closed"
    refused = Finding(Kind.ALERT_CHANGE_UNEXPLAINED, "", None, None, {})  # a key the table refuses
    with pytest.raises(DBAPIError):
        await store.record_alerts(
            [AlertState("alert-2", "closed", None, None, now)], [refused], now
        )
    assert await store.alert_states(["alert-2"]) == {}, "the baseline did not outlive its finding"


async def test_r4_unseen_keys_are_the_findings_not_yet_kept(app_engine: AsyncEngine) -> None:
    store = PgSyncStore(app_engine)
    now = datetime.now(UTC)
    await store.add_findings([Finding(Kind.CLOCK_OFFSET, "clock:kept", None, None, {})], now)
    assert await store.unseen_keys(["clock:kept", "clock:new"]) == {"clock:new"}
    assert await store.unseen_keys([]) == frozenset()


async def test_r7_a_stray_action_is_counted_once_in_the_mirror(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    asha = await make_person(app_engine, "asha")
    case_id = await _case_with_a_sent_create(app_engine, migrated_engine, asha)
    r = _pg_rig(app_engine)
    kid = r.kibana.create(argus_case=case_id)
    assert (await r.cycle()).outcome == "complete"
    r.kibana.comment(kid, "argus", "stray")
    for _ in range(2):
        await r.cycle()
    async with app_engine.connect() as conn:
        row = (
            await conn.execute(text("SELECT unexplained, argus_actions FROM kibana_mirror"))
        ).one()
    assert (row.unexplained, row.argus_actions) == ({"comment": 1}, {"create": 1, "comment": 1})
    assert await _findings(app_engine) == [Kind.UNEXPLAINED_ARGUS_ACTION]


async def test_r8_the_alert_diff_goes_on_from_where_it_stopped_after_a_restart(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    asha = await make_person(app_engine, "asha")
    case_id = await _case_with_a_sent_create(app_engine, migrated_engine, asha)
    r = _pg_rig(app_engine)
    r.syncer.config = SyncConfig(diff_calls=1)
    kid = r.kibana.create(argus_case=case_id)
    names = [f"alert-{i:03d}" for i in range(250)]
    for name in names:
        r.kibana.attach(kid, PERSON, name)
        r.kibana.alert_status(name, "open", None)
    long = timedelta(hours=3)
    await r.cycle(within=long)
    store = PgSyncStore(app_engine)
    assert (await store.state()).diff_cursor is not None
    assert len(await store.alert_states(names)) == 100, "one search of 100 alerts"
    # a new process: the place is in the database, not in the syncer
    again = _pg_rig(app_engine)
    again.syncer.config = SyncConfig(diff_calls=1)
    again.kibana.cases, again.kibana.actions = r.kibana.cases, r.kibana.actions
    again.kibana.alerts = r.kibana.alerts
    again.clock.now = r.clock.now
    await again.cycle(advance=timedelta(hours=1, minutes=1), within=long)
    assert len(await store.alert_states(names)) == 200, "the next hundred, not the same"
