"""The retention purge (Q-A4) against the review's findings (A4-R3 to R6, R10, and the merge with
Q-G2's shadow store): what the holds keep is checked row by row, a held row's link stays, open
work keeps its evidence and its investigation, and every table naming an investigation is
either purged with it or kept on purpose."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.ops import purge
from tests.integration.ops.test_purge import CUT, DAY, Alert, Inv, World, _hex, _s, write

pytestmark = pytest.mark.integration
OLD = -200 * DAY


async def one(engine: AsyncEngine, query: str, **params: Any) -> Any:
    async with engine.connect() as conn:
        return (await conn.execute(text(query), params)).scalar_one()


def _inv(bucket_end: int, *, gold: bool = False, **over: Any) -> Inv:
    age = bucket_end
    fields: dict[str, Any] = {
        "bucket_end": bucket_end, "alerts": [Alert(age, age)], "reviews": [], "snapshots": [],
        "gold": gold, "job_active": False, "assessment_active": False, "entities": [],
        "continues": None,
    }  # fmt: skip
    fields.update(over)
    return Inv(**fields)


def _between_passes(monkeypatch: pytest.MonkeyPatch, action: Any) -> None:
    """Run ``action`` (as another ARGUS process would) after the raw pass, before evidence."""
    original = purge._purge_evidence

    async def wrapped(engine: AsyncEngine, cut: Any, counts: Any) -> None:
        await action(engine)
        await original(engine, cut, counts)

    monkeypatch.setattr(purge, "_purge_evidence", wrapped)


async def _link_alert(engine: AsyncEngine, inv: Any, alert_id: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO alert_records (alert_id, index, status, normalizer_version, raw,"
                " content_hash, state_hash, recovered_by, detected_at)"
                " VALUES (:a, 'alerts', 'normalized', 't', '{\"x\": 2}', 'h', 'h', 'live', now())"
            ),
            {"a": alert_id},
        )
        await conn.execute(
            text("INSERT INTO investigation_alerts (alert_id, investigation_id) VALUES (:a, :i)"),
            {"a": alert_id, "i": inv},
        )


# --------------------------------------------------------------------------- A4-R3


async def test_a_new_alert_on_a_held_investigation_is_no_change_to_a_held_row(
    migrated_engine: AsyncEngine, user: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The collector links today's alert to a held investigation while the purge runs: no held
    row changed, so the run is not a failure."""
    held, gone = _inv(-1 * DAY, gold=True), _inv(OLD)
    async with migrated_engine.begin() as conn:
        await write(conn, World([held, gone], [], []), user)

    async def collector(engine: AsyncEngine) -> None:
        await _link_alert(engine, held.id, "new-alert")

    _between_passes(monkeypatch, collector)
    outcome = await purge.run(migrated_engine, CUT)
    assert purge.differences(outcome.planned, outcome.done) == []
    assert outcome.holds_after["alerts_with_raw"] == outcome.holds_before["alerts_with_raw"] + 1
    assert outcome.holds_intact, outcome.holds_changed


async def test_a_held_alert_that_lost_its_raw_is_seen_though_another_arrived(
    migrated_engine: AsyncEngine, user: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rows, not counts: one held alert loses its raw data while one new alert joins a held
    investigation; the counts are equal, the check still names the loss."""
    held = _inv(-1 * DAY, gold=True)
    async with migrated_engine.begin() as conn:
        await write(conn, World([held], [], []), user)

    async def both(engine: AsyncEngine) -> None:
        async with engine.begin() as conn:  # a held row loses its raw (a defect, or a writer)
            await conn.execute(
                text(
                    "UPDATE alert_records SET raw = '{}', raw_purged_at = now()"
                    " WHERE alert_id = 'inv-0-0'"
                )
            )
        await _link_alert(engine, held.id, "new-alert")

    _between_passes(monkeypatch, both)
    outcome = await purge.run(migrated_engine, CUT)
    assert outcome.holds_after == outcome.holds_before  # the counts alone would hide it
    assert not outcome.holds_intact
    assert outcome.holds_changed["alerts_lost_raw"] == 1


async def test_a_hold_that_ends_during_the_run_is_no_false_alarm(
    migrated_engine: AsyncEngine, user: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A gold item removed during the run: its investigation is no longer the holds' to keep."""
    held = _inv(OLD, gold=True, snapshots=[True], reviews=[("reviewed", OLD)])
    async with migrated_engine.begin() as conn:
        await write(conn, World([held], [], []), user)

    async def release(engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM gold_items"))

    _between_passes(monkeypatch, release)
    outcome = await purge.run(migrated_engine, CUT)
    assert outcome.holds_intact, outcome.holds_changed


# --------------------------------------------------------------------------- A4-R4


async def test_a_held_investigation_keeps_its_continues_link(
    migrated_engine: AsyncEngine, user: int
) -> None:
    """The investigation a held one continues keeps its row (memory counts it as kept), so the
    held row is not changed; its raw data still goes."""
    victim = _inv(OLD)
    gold = _inv(OLD + DAY, gold=True, continues=0)
    async with migrated_engine.begin() as conn:
        await write(conn, World([victim, gold], [], []), user)
    outcome = await purge.run(migrated_engine, CUT)
    assert outcome.done.changed["memory"]["investigations"] == 0
    assert outcome.done.held["memory"] == 2  # the gold one, and the one it continues
    assert outcome.holds_intact
    link = "SELECT continues_id FROM investigations WHERE id = :i"
    assert await one(migrated_engine, link, i=gold.id) == victim.id
    assert outcome.done.changed["raw_source"]["alert_records.raw"] == 1  # the victim's alert


async def test_a_changed_continues_link_of_a_held_row_is_seen(
    migrated_engine: AsyncEngine, user: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    gold = _inv(-1 * DAY, gold=True)
    other = _inv(-1 * DAY)
    async with migrated_engine.begin() as conn:
        await write(conn, World([gold, other], [], []), user)

    async def relink(engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await conn.execute(
                text("UPDATE investigations SET continues_id = :o WHERE id = :g"),
                {"o": other.id, "g": gold.id},
            )

    _between_passes(monkeypatch, relink)
    outcome = await purge.run(migrated_engine, CUT)
    assert outcome.holds_changed["continues_changed"] == 1


# --------------------------------------------------------------------------- A4-R5


async def test_evidence_of_a_version_changed_since_review_is_kept(
    migrated_engine: AsyncEngine, user: int
) -> None:
    """Reviewed 100 days ago at version 1; a late alert 10 days ago made version 2 (the Inbox
    shows 'changed since review'): open work, so no snapshot of it goes."""
    inv = _inv(OLD, alerts=[Alert(OLD, OLD), Alert(-10 * DAY, -10 * DAY)],
               reviews=[("reviewed", -100 * DAY)], snapshots=[True], changed=True)  # fmt: skip
    async with migrated_engine.begin() as conn:
        await write(conn, World([inv], [], []), user)
        await conn.execute(
            text(
                "INSERT INTO evidence (investigation_id, version, task_key, template,"
                " template_version, params, status, coverage, snapshot, result_hash,"
                " collected_at) VALUES (:i, 2, :k, 'proxy.pair', 1, '{}', 'ok', '{}',"
                " '{\"rows\": [2]}', :h, :t)"
            ),
            {"i": inv.id, "k": _hex(inv.id, 0), "h": _hex("r2"), "t": _s(-10 * DAY)},
        )
    planned = await purge.plan(migrated_engine, CUT)
    assert planned.changed["evidence"]["evidence.snapshot"] == 0
    outcome = await purge.run(migrated_engine, CUT)
    assert outcome.done.changed["evidence"]["evidence.snapshot"] == 0
    purged = "SELECT count(*) FROM evidence WHERE snapshot_purged_at IS NOT NULL"
    assert await one(migrated_engine, purged) == 0
    # once version 2 is reviewed (long enough ago), its snapshots go like any others
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome, created_at) VALUES (:i, 2, 2, :u, 'reviewed',"
                " 'benign_expected', :t)"
            ),
            {"i": inv.id, "u": user, "t": _s(-95 * DAY)},
        )
    again = await purge.run(migrated_engine, CUT)
    assert again.done.changed["evidence"]["evidence.snapshot"] == 2


# --------------------------------------------------------------------------- A4-R6


@pytest.mark.parametrize("state", ["planned", "paused"])
async def test_an_unsent_write_back_keeps_its_investigation(
    migrated_engine: AsyncEngine, user: int, state: str
) -> None:
    """A paused write-back may be the only record of a partial write to Kibana; a planned one is
    a reviewer's decision not delivered yet. Either keeps the investigation, as a queued job
    does, and the plan says how many wait."""
    inv = _inv(OLD, reviews=[("reviewed", OLD)], writeback=state)
    sent = _inv(OLD, reviews=[("reviewed", OLD)], writeback="sent")
    async with migrated_engine.begin() as conn:
        await write(conn, World([inv, sent], [], []), user)
    planned = await purge.plan(migrated_engine, CUT)
    assert planned.waiting == 1
    outcome = await purge.run(migrated_engine, CUT)
    assert outcome.done.changed["memory"]["investigations"] == 1  # the sent one only
    assert outcome.done.changed["memory"]["writeback_outbox"] == 1
    left = "SELECT investigation_id FROM writeback_outbox WHERE state = :s"
    assert await one(migrated_engine, left, s=state) == inv.id
    lines = purge.lines(planned, CUT, CUT.periods["memory"])
    assert "waiting on unfinished work (jobs, assessments, write-backs): 1" in lines[4]


# --------------------------------------------------------------------------- A4-R10 (decided)


async def test_entity_notes_are_kept_after_their_entity_goes(
    migrated_engine: AsyncEngine, user: int
) -> None:
    """Decided (review A4-R10): entity notes are people's knowledge, written on purpose and
    append-only (D-025), kept like a case's notes; the plan says so on every run."""
    inv = _inv(OLD, entities=["10.0.0.9"])
    async with migrated_engine.begin() as conn:
        await write(conn, World([inv], [], []), user)
        await conn.execute(
            text(
                "INSERT INTO entity_notes (kind, value, author_user_id, body, created_at)"
                " VALUES ('ip', '10.0.0.9', :u, 'the print server', :t)"
            ),
            {"u": user, "t": _s(OLD)},
        )
    outcome = await purge.run(migrated_engine, CUT)
    assert outcome.done.changed["memory"]["entities"] == 1
    assert await one(migrated_engine, "SELECT count(*) FROM entity_notes") == 1
    shown = purge.lines(outcome.done, CUT, CUT.periods["memory"])
    assert "entity notes" in shown[6]


# --------------------------------------------------------------------------- the merge (Q-G2)


async def test_the_local_models_shadow_answers_go_with_their_investigation(
    migrated_engine: AsyncEngine, user: int
) -> None:
    """Q-G2's shadow store names its investigation (a foreign key) and holds prompts built from
    its dossier: memory.window removes them with it; the gold set keeps them."""
    gone, gold = _inv(OLD), _inv(OLD, gold=True)
    async with migrated_engine.begin() as conn:
        await write(conn, World([gone, gold], [], []), user)
        for inv in (gone, gold):
            await conn.execute(
                text(
                    "INSERT INTO llm_shadow (investigation_id, version, pack, dossier_hash, task,"
                    " prompt, provider, model, usable, floor, latency_ms, lease_ms,"
                    " input_tokens, output_tokens) VALUES (:i, 1, 'p@1', :h, 'triage', 't@1',"
                    " 'local', 'm', false, false, 1, 1, 1, 1)"
                ),
                {"i": inv.id, "h": _hex("d", inv.id)},
            )
    planned = await purge.plan(migrated_engine, CUT)
    assert planned.changed["memory"]["llm_shadow"] == 1
    outcome = await purge.run(migrated_engine, CUT)
    assert purge.differences(outcome.planned, outcome.done) == []
    assert outcome.done.changed["memory"]["llm_shadow"] == 1
    left = "SELECT investigation_id FROM llm_shadow"
    assert await one(migrated_engine, left) == gold.id


# Tables that name an investigation and stay: the holds' and the case records (never purged in
# Phase 3; an investigation they name keeps its row), and the gold set's labels.
KEPT_ON_PURPOSE = {"gold_items", "gold_labels", "case_members", "case_openings"}
PURGED_WITH_IT = {
    *purge._BY_INVESTIGATION,
    *purge._CASCADES,
    "investigation_alerts",
    "investigation_entities",
}


async def test_every_table_naming_an_investigation_is_purged_with_it_or_kept_on_purpose(
    migrated_engine: AsyncEngine,
) -> None:
    """A new table that names an investigation (Q-G2's llm_shadow did) must be purged with it,
    or be kept on purpose: else memory.window leaves its personal data, or fails on its key."""
    async with migrated_engine.connect() as conn:
        naming = set(
            (
                await conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.columns"
                        " WHERE table_schema = 'public' AND column_name = 'investigation_id'"
                    )
                )
            ).scalars()
        )
        referencing = set(
            (
                await conn.execute(
                    text(
                        "SELECT conrelid::regclass::text FROM pg_constraint WHERE contype = 'f'"
                        " AND confrelid = 'investigations'::regclass"
                    )
                )
            ).scalars()
        )
    assert naming == PURGED_WITH_IT | KEPT_ON_PURPOSE
    assert referencing <= PURGED_WITH_IT | KEPT_ON_PURPOSE | {"investigations"}


@pytest.fixture
async def user(migrated_engine: AsyncEngine) -> int:
    from argus.web import auth

    async with migrated_engine.begin() as conn:
        return await auth.add_user(conn, "purger", "Purger", "correct horse battery")
