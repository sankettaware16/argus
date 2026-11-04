"""Migration 0052 (AR7, D-190): what the database holds for the incident report and refuses: a
version is never changed, a decision is a record, the runtime login writes the reports and the
checks, the web's login reads them and writes only a person's decision, and a downgrade that would
lose a decision (a label was written from it) is refused."""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate
from tests.integration.cases.conftest import Person
from tests.integration.incident import kit

pytestmark = pytest.mark.integration

REPORT = (
    "INSERT INTO incident_reports (case_id, version, schema_version, writer, content_hash,"
    " case_version, verdict_outcome, verdict_confidence, body, generated_by, as_at) VALUES (:c, :v,"
    " :s, 'w@1', :h, 1, :o, :f, CAST(:b AS jsonb), 'argus:incident', now())"
)


def params(case: uuid.UUID, **more: object) -> dict[str, object]:
    values: dict[str, object] = {
        "c": case, "v": 1, "s": "incident-report@1", "h": "a" * 64, "o": "true_positive",
        "f": 0.8, "b": json.dumps({"x": 1}),
    }  # fmt: skip
    values.update(more)
    return values


async def a_case(owner: AsyncEngine, app: AsyncEngine, people: dict[str, Person]) -> uuid.UUID:
    case, _ = await kit.amadey(owner, app, people["asha"])
    return case


async def test_the_database_refuses_a_report_that_is_not_shaped_right(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await a_case(migrated_engine, app_engine, people)
    async with app_engine.begin() as conn:
        await conn.execute(text(REPORT), params(case))
    for bad, why in (
        ({"v": 0}, "version_valid"),
        ({"s": "incident-report@2"}, "schema_valid"),
        ({"h": "xyz"}, "hash_valid"),
        ({"o": "maybe"}, "outcome_valid"),
        ({"f": 1.5}, "confidence_valid"),
        ({"b": json.dumps([1])}, "body_is_object"),
    ):
        with pytest.raises(DBAPIError, match=why):
            async with app_engine.begin() as conn:
                await conn.execute(
                    text(REPORT), params(case, **bad, **({"v": 2} if "v" not in bad else {}))
                )
    with pytest.raises(DBAPIError, match=r"uq_incident_reports_case_id_version"):
        async with app_engine.begin() as conn:
            await conn.execute(text(REPORT), params(case))  # the version is taken
    with pytest.raises(DBAPIError, match="prose_complete"):  # prose says who wrote it
        async with app_engine.begin() as conn:
            await conn.execute(
                text(
                    REPORT.replace("body, generated_by", "body, prose, generated_by").replace(
                        "CAST(:b AS jsonb), 'argus", "CAST(:b AS jsonb), true, 'argus"
                    )
                ),
                params(case, v=5),
            )


async def test_a_report_and_a_decision_are_records_nobody_edits_or_deletes(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await a_case(migrated_engine, app_engine, people)
    async with app_engine.begin() as conn:
        report = (await conn.execute(text(REPORT + " RETURNING id"), params(case))).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO incident_report_decisions (report_id, decision, by_user_id) VALUES"
                " (:r, 'confirmed', :u)"
            ),
            {"r": report, "u": people["asha"].user_id},
        )
    for sql in (
        "UPDATE incident_reports SET writer = 'x'",
        "DELETE FROM incident_reports",
        "UPDATE incident_report_decisions SET decision = 'rejected'",
        "DELETE FROM incident_report_decisions",
        "TRUNCATE incident_report_decisions, incident_report_checks, incident_reports",
    ):
        with pytest.raises(DBAPIError, match=r"append-only|not empty"):
            async with migrated_engine.begin() as conn:
                await conn.execute(text(sql))
    assert await migrate.missing_guard_triggers(migrated_engine) == []


async def test_a_decision_is_complete_and_a_rejection_has_its_reason_and_outcome(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await a_case(migrated_engine, app_engine, people)
    async with app_engine.begin() as conn:
        report = (await conn.execute(text(REPORT + " RETURNING id"), params(case))).scalar_one()
    insert = (
        "INSERT INTO incident_report_decisions (report_id, decision, outcome, reason, by_user_id)"
        " VALUES (:r, :d, :o, :why, :u)"
    )
    base = {"r": report, "u": people["asha"].user_id}
    async with app_engine.begin() as conn:
        await conn.execute(
            text(insert),
            base | {"d": "rejected", "o": "benign_expected", "why": "it is the backup tool"},
        )
        await conn.execute(
            text(insert), base | {"d": "confirmed", "o": "true_positive", "why": None}
        )
    for bad, why in (
        ({"d": "rejected", "o": "benign_expected", "why": None}, "rejection_complete"),
        ({"d": "rejected", "o": None, "why": "a reason"}, "rejection_complete"),
        (
            {"d": "confirmed", "o": "true_positive", "why": "reason on a confirm"},
            "rejection_complete",
        ),
        ({"d": "rejected", "o": "benign_expected", "why": "  x "}, "reason_length"),
        ({"d": "maybe", "o": None, "why": None}, "decision_valid"),
        ({"d": "rejected", "o": "wrong", "why": "a reason"}, "outcome_valid"),
    ):
        with pytest.raises(DBAPIError, match=why):
            async with app_engine.begin() as conn:
                await conn.execute(text(insert), base | bad)


async def test_each_login_writes_only_what_it_may(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    web_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    case = await a_case(migrated_engine, app_engine, people)
    async with app_engine.begin() as conn:
        report = (await conn.execute(text(REPORT + " RETURNING id"), params(case))).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO incident_report_checks (case_id, signal, checked_at, report_id)"
                " VALUES (:c, 's', now(), :r)"
            ),
            {"c": case, "r": report},
        )
        await conn.execute(
            text(
                "UPDATE incident_report_checks SET signal = 't', failure = 'x', failed_at = now()"
                " WHERE case_id = :c"
            ),
            {"c": case},
        )
    async with web_engine.connect() as conn:  # the web reads all three
        for table in ("incident_reports", "incident_report_decisions", "incident_report_checks"):
            assert await conn.scalar(text(f"SELECT count(*) FROM {table}")) >= 0  # noqa: S608
    for who, sql in (
        (web_engine, REPORT),
        (
            web_engine,
            "INSERT INTO incident_report_checks (case_id, signal, checked_at)"
            " VALUES (:c, 's', now())",
        ),
        (web_engine, "UPDATE incident_report_checks SET signal = 'z'"),
        (app_engine, "UPDATE incident_reports SET writer = 'z'"),
        (app_engine, "DELETE FROM incident_report_checks"),
    ):
        with pytest.raises(DBAPIError, match="permission denied"):
            async with who.begin() as conn:
                await conn.execute(text(sql), params(case) | {"c": case})
    async with web_engine.begin() as conn:  # and records a person's decision
        await conn.execute(
            text(
                "INSERT INTO incident_report_decisions (report_id, decision, by_user_id)"
                " VALUES (:r, 'confirmed', :u)"
            ),
            {"r": report, "u": people["asha"].user_id},
        )


async def test_a_downgrade_that_would_lose_a_decision_is_refused_and_a_clean_one_round_trips(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await a_case(migrated_engine, app_engine, people)
    async with app_engine.begin() as conn:
        report = (await conn.execute(text(REPORT + " RETURNING id"), params(case))).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO incident_report_decisions (report_id, decision, by_user_id)"
                " VALUES (:r, 'confirmed', :u)"
            ),
            {"r": report, "u": people["asha"].user_id},
        )
    with pytest.raises(DBAPIError, match="labels were written"):
        await migrate.downgrade(migrated_engine, "0051")
    assert await migrate.current_revision(migrated_engine) == "0065"
    # the decision is the record: the owner removes it the one way there is (the guard is the point)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "ALTER TABLE incident_report_decisions DISABLE TRIGGER"
                " incident_report_decisions_append_only_rows"
            )
        )
        await conn.execute(text("DELETE FROM incident_report_decisions"))
    await migrate.downgrade(migrated_engine, "0051")
    async with migrated_engine.connect() as conn:
        found = await conn.scalar(
            text(
                "SELECT count(*) FROM information_schema.tables"
                " WHERE table_name LIKE 'incident_report%'"
            )
        )
    assert found == 0
    await migrate.upgrade(migrated_engine)
    assert await migrate.schema_drift(migrated_engine) == []
    assert await migrate.missing_guard_triggers(migrated_engine) == []
