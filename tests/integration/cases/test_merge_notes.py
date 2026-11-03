"""Merges (an approved one for confirmed cases), notes for people only, and doctor's view of
the chains (Q-C1)."""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import CaseRefused, Open, replay
from argus.cases.model import Actor, Member
from argus.cases.service import CaseService
from tests.integration.cases.conftest import (
    APPROVER,
    Person,
    asking,
    investigation,
    rows,
    signed_for,
)
from tests.integration.cases.test_service import _open

SRC = Path(__file__).resolve().parents[3] / "src" / "argus"


async def _two_cases(
    api: AsyncEngine, owner: AsyncEngine, person: Person
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
    a = await investigation(owner, actor=(("source.ip", "10.4.0.1"),))
    b = await investigation(owner, actor=(("source.ip", "10.4.0.2"),))
    return await _open(api, person.actor(), [a]), await _open(api, person.actor(), [b]), a, b


async def test_an_approved_merge_moves_everything_into_the_target(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha, ravi = people["asha"], people["ravi"]
    source, target, a, b = await _two_cases(api_engine, migrated_engine, asha)
    async with api_engine.begin() as conn:
        service = await CaseService.start(conn)
        _, request = await service.request_merge(
            asha.actor(), source, target, expected_version=1, session_token=asha.session_token,
            check=await asking(conn, asha),
        )  # fmt: skip
    req = (await rows(api_engine, "SELECT kind, reason, target_case_id FROM approval_requests"))[0]
    assert (req.kind, req.reason, req.target_case_id) == ("merge", "duplicate", target)
    async with api_engine.begin() as conn:
        service = await CaseService.start(conn)
        signed = await signed_for(conn, ravi, request)
        status, applied = await service.decide(ravi.actor(APPROVER), request,
                                               session_token=ravi.session_token,
                                               decision="approved", signed=signed)  # fmt: skip
    assert status == "approved"
    left, joined = applied
    assert (left.case.state, left.case.closure_reason, left.case.merged_into_id) == (
        "closed", "duplicate", target,
    )  # fmt: skip
    assert left.case.members == frozenset()
    assert joined.case.members == {a, b}
    members = await rows(api_engine, "SELECT case_id, investigation_id, link, removed_at"
                                     " FROM case_members ORDER BY added_at")  # fmt: skip
    active = {(m.case_id, m.investigation_id, m.link) for m in members if m.removed_at is None}
    assert active == {(target, a, "merge"), (target, b, "person")}
    async with api_engine.connect() as conn:
        service = await CaseService.start(conn)
        for case_id in (source, target):
            assert replay(await service.events(case_id)) == await service.get(case_id)


async def test_a_suspected_case_merges_without_an_approval_and_a_confirmed_one_never(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha = people["asha"]
    source, target, _, _ = await _two_cases(api_engine, migrated_engine, asha)
    async with api_engine.begin() as conn:
        with pytest.raises(CaseRefused, match="needs an approval"):
            await (await CaseService.start(conn)).merge(asha.actor(APPROVER), source, target)
    inv = await investigation(migrated_engine, actor=(("source.ip", "10.4.0.3"),))
    async with migrated_engine.begin() as conn:
        assessment = (
            await conn.execute(
                text(
                    "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                    " view_hash, assessor, run_after, status, outcome) VALUES (:i, 1, 'p',"
                    " repeat('a', 64), repeat('b', 64), 'agent', now(), 'proposed',"
                    " 'true_positive') RETURNING id"
                ),
                {"i": inv},
            )
        ).scalar_one()
    async with api_engine.begin() as conn:
        service = await CaseService.start(conn)
        suspected = (
            await service.open(
                Actor.argus("opener"),
                Open(
                    "Proposed",
                    "low",
                    "proposal",
                    (Member(inv, "proposal"),),
                    suspected=True,
                    cause_assessment_id=assessment,
                ),
            )
        ).case.id
        left, joined = await service.merge(asha.actor(), suspected, target)
    assert (left.case.state, left.case.closure_request_id) == ("closed", None)
    assert inv in joined.case.members


async def test_notes_are_for_people_and_never_change_the_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, people["asha"].actor(), [inv])
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.add_note(people["asha"].actor(), case_id, "  called the lab admin  ")
        await service.add_entity_note(people["ravi"].actor(), "ip", "10.0.0.1", "lab printer")
        for bad, message in (("", "needs text"), ("x" * 4001, "at most 4000")):
            with pytest.raises(CaseRefused, match=message):
                await service.add_note(people["asha"].actor(), case_id, bad)
        with pytest.raises(CaseRefused, match="a person's"):
            await service.add_note(Actor.argus("opener"), case_id, "ARGUS has no notes")
        with pytest.raises(CaseRefused, match="an ip, domain, host or user"):
            await service.add_entity_note(people["ravi"].actor(), "url", "x", "no")
    notes = await rows(app_engine, "SELECT body, author_user_id FROM case_notes")
    assert [tuple(n) for n in notes] == [("called the lab admin", people["asha"].user_id)]
    version = await rows(app_engine, "SELECT version FROM cases")
    assert version[0].version == 1  # a note is not a change of the case
    audit = await rows(app_engine, "SELECT action FROM audit_events ORDER BY id")
    assert [a.action for a in audit] == ["case.opened", "case.note", "entity.note"]
    with pytest.raises(DBAPIError, match="permission denied"):
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE case_notes SET body = 'rewritten'"))


def test_notes_never_reach_a_model() -> None:
    """No module that builds what a model sees (the agent, assessments, the LLM gateway and its
    privacy layer, tuning) reads the notes tables (plan Q-B3: people only)."""
    model_side = [p for area in ("agent", "assess", "llm", "tuning", "context")
                  for p in (SRC / area).rglob("*.py")]  # fmt: skip
    assert model_side
    for path in model_side:
        source = path.read_text()
        tree = ast.parse(source)
        strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
                   and isinstance(n.value, str)]  # fmt: skip
        for table in ("case_notes", "entity_notes"):
            assert not any(table in s for s in strings), f"{path} names {table}"
        assert "argus.cases" not in source, f"{path} imports the case record"


async def test_doctor_verifies_the_chains(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person],
    db_settings: object, test_database: str, monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    from argus.config import load_settings
    from argus.doctor import database_checks
    from tests.conftest import REPO_ROOT

    inv = await investigation(migrated_engine)
    await _open(app_engine, people["asha"].actor(), [inv])
    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)
    settings = load_settings(REPO_ROOT / "config" / "argus.yaml", env_file=REPO_ROOT / ".env")
    results = {r.name: r for r in await database_checks(settings)}
    assert results["audit chain (audit_events)"].ok
    assert results["audit chain (case_events)"].detail.startswith("1 rows chained; head 1 ")
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("ALTER TABLE case_events DISABLE TRIGGER case_events_append_only_rows")
        )
        await conn.execute(text("UPDATE case_events SET actor = 'mallory'"))
        await conn.execute(
            text("ALTER TABLE case_events ENABLE ALWAYS TRIGGER case_events_append_only_rows")
        )
    results = {r.name: r for r in await database_checks(settings)}
    assert not results["audit chain (case_events)"].ok
    assert "was changed after it was written" in results["audit chain (case_events)"].detail
    assert results["runtime role"].ok
