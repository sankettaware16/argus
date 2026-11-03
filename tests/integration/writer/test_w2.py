"""Q-D4, W2: tags, severity and status with a comment; a person's work in Kibana is kept, what a
person edited is left alone, and Sync alerts on or a pause sends nothing."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Release, Take
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _apply
from tests.integration.writer.kit import created, mirror, rig

pytestmark = pytest.mark.integration


async def test_taking_a_case_changes_status_and_owner_tag_and_keeps_peoples_tags(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id, kid = await created(r, people)
    r.kibana.cases[kid]["tags"].append("team-blue")  # a person's tag
    await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)
    assert [(c, o) for c, o, _ in await r.outbox(case_id)] == [
        ("W1", "create"), ("W2", "update"), ("W2", "comment"),
    ]  # fmt: skip

    report = await r.run("W2", limit=1)

    assert report.stopped is None, report.lines()
    assert (report.units, report.sent, report.verified) == (1, 2, 2)
    case = r.kibana.cases[kid]
    assert case["status"] == "in-progress"
    assert f"argus:owner:user-{people['ravi'].user_id}" in case["tags"]
    assert "argus:owner:argus" not in case["tags"]
    assert "argus:state:assigned" in case["tags"]
    assert "team-blue" in case["tags"]  # a person's tag stays
    assert case["totalComment"] == 2
    last = r.kibana.comments[kid][-1]["comment"]
    assert last.startswith("Taken in ARGUS by Ravi (` user:")
    assert "ARGUS reference:" in last
    assert [s for _, _, s in await r.outbox(case_id)] == ["verified"] * 3


async def test_what_a_person_edited_or_changed_is_not_overwritten(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id, kid = await created(r, people)
    await mirror(migrated_engine, case_id, kid, unmanaged=("severity",))
    r.kibana.cases[kid]["status"] = "closed"  # a person closed it in Kibana
    r.kibana.cases[kid]["severity"] = "low"  # and edited the severity
    await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)

    report = await r.run("W2", limit=1)

    case = r.kibana.cases[kid]
    assert case["status"] == "closed"
    assert case["severity"] == "low"
    assert f"argus:owner:user-{people['ravi'].user_id}" in case["tags"]  # ARGUS's own tags follow
    assert report.stopped is None, report.lines()
    assert report.mismatches == 0
    assert [s for _, _, s in await r.outbox(case_id)] == ["verified", "verified", "verified"]


async def test_sync_alerts_on_sends_nothing_and_needs_attention(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id, kid = await created(r, people)
    r.kibana.cases[kid]["settings"] = {"syncAlerts": True}  # anyone can switch it on in Kibana
    await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)
    before = r.kibana.count("PATCH") + r.kibana.count("POST")

    report = await r.run("W2", limit=5)

    assert r.kibana.count("PATCH") + r.kibana.count("POST") == before  # nothing was sent
    assert any("Sync alerts is on" in h for h in report.held)
    assert [s for _, _, s in await r.outbox(case_id)][1:] == ["planned", "planned"]
    findings = await r.sql("SELECT kind, severity FROM kibana_findings")
    assert [(f.kind, f.severity) for f in findings] == [("settings_changed", "attention")]
    r.kibana.cases[kid]["settings"] = {"syncAlerts": False}  # switched off again: it goes
    assert (await r.run("W2", limit=5)).verified == 2


async def test_a_paused_case_or_one_not_made_by_argus_is_not_written_to(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id, kid = await created(r, people)
    await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)
    await mirror(migrated_engine, case_id, kid, paused="a person changed ARGUS's tags in Kibana")
    report = await r.run("W2", limit=5)
    assert r.kibana.count("PATCH") == 0
    assert any("paused" in h for h in report.held)
    await mirror(migrated_engine, case_id, kid)  # the owner lifted the pause
    r.kibana.cases[kid]["created_by"] = {"username": "someone"}
    report = await r.run("W2", limit=5)
    assert r.kibana.count("PATCH") == 0
    assert [s for _, _, s in await r.outbox(case_id)][1] == "paused"  # a person must look


async def test_a_release_back_to_argus_reverts_the_owner_tag(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id, kid = await created(r, people)
    await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)
    await r.run("W2", limit=1)
    await _apply(app_engine, people["ravi"].actor(), case_id, Release(), 2)
    report = await r.run("W2", limit=1)
    assert report.verified == 2, report.lines()
    case = r.kibana.cases[kid]
    assert case["status"] == "open"
    assert "argus:owner:argus" in case["tags"]
