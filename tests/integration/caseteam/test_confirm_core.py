"""A person's confirm and the report's accounts (AR6 review, D-225): with ``case_team.auto`` off the
only way a case opens is a person's confirm of the newest report, and every account or lookup the
sign-ins add makes a new version. The confirm holds across versions that differ only in the
accounts, and not across a version whose evidence changed."""

from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam import store
from argus.incident import model as m
from tests.integration.cases.conftest import Person
from tests.integration.caseteam.kit import CONFIG, a_case, rig, save_version

pytestmark = pytest.mark.integration
MANUAL = replace(CONFIG, auto=False)  # D-214: only a person's confirm opens a case


def more_accounts(report: Any) -> Any:
    """The report with two accounts (a sentence that writes no number, so it cites F1 soundly)."""
    accounts = tuple(
        m.ReportAccount(
            name=n, device="10.0.0.7", first_seen=report.meta.as_at, last_seen=report.meta.as_at,
            signins=3, failed=0, days=1, browsers=("Chrome on Windows",),
        )
        for n in ("user-ar6-alpha", "user-ar6-beta")
    )  # fmt: skip
    sentence = m.ReportSentence(text="Two accounts signed in from the device.", cites=("F1",))
    device = m.ReportDeviceUsers(
        device="10.0.0.7", state="possible", sentence=sentence, accounts=accounts,
        account_count=2, at_least=False,
    )  # fmt: skip
    return report.model_copy(update={"users": m.ReportUsers(lead="A lead.", devices=(device,))})


def more_evidence(report: Any) -> Any:
    line = report.evidence[-1].model_copy(update={"id": "E99", "title": "A newer check"})
    return report.model_copy(update={"evidence": (*report.evidence, line)})


async def candidates(writer: AsyncEngine, minimum: float | None = None) -> list[uuid.UUID]:
    async with writer.connect() as conn:
        return await store.candidates(conn, 40, minimum)


async def test_a_confirm_survives_a_new_version_that_only_adds_an_account(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine, config=MANUAL)
    case = await a_case(migrated_engine, app_engine, people["asha"], confirmed=True, confidence=0.5)
    assert await candidates(writer_engine) == [case]
    stored = await save_version(app_engine, case, more_accounts)  # v2: the sign-ins found accounts
    assert stored.version == 2
    assert await candidates(writer_engine) == [case]  # the confirm of v1 still qualifies it
    done = await r.run(case)
    assert done.stopped is None, done.lines()
    assert done.decision.route == "a person confirmed the report"
    assert len(r.kibana.team_cases()) == 1  # and it opened


async def test_a_confirm_survives_new_evidence_and_stops_when_the_verdict_turns(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """D-229: new evidence after a confirm is an update for Kibana, not a reason to confirm again;
    a newest verdict that is no longer a true positive needs a person again."""
    r = rig(migrated_engine, writer_engine, config=MANUAL)
    case = await a_case(migrated_engine, app_engine, people["asha"], confirmed=True, confidence=0.5)
    await save_version(app_engine, case, more_evidence)
    assert await candidates(writer_engine) == [case]

    def turned(report: Any) -> Any:
        return report.model_copy(
            update={"verdict": report.verdict.model_copy(update={"outcome": "inconclusive"})}
        )

    await save_version(app_engine, case, turned)
    assert await candidates(writer_engine) == []
    done = await r.run(case)
    assert done.decision.action == "none"
    assert "no longer says true positive" in done.decision.why
    assert r.kibana.team_cases() == []


async def test_a_rejection_after_a_confirm_stops_it(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    from tests.integration.caseteam.kit import decide

    r = rig(migrated_engine, writer_engine, config=MANUAL)
    case = await a_case(migrated_engine, app_engine, people["asha"], confirmed=True, confidence=0.5)
    await save_version(app_engine, case, more_evidence)
    await decide(migrated_engine, case, people["ravi"], "rejected")
    assert await candidates(writer_engine) == []
    assert (await r.run(case)).decision.action == "none"
    assert r.kibana.team_cases() == []


async def test_a_confirm_made_before_the_core_hash_existed_is_judged_by_the_policy(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """A report stored by 0056's writer has no ``core_hash``: the SQL lets its confirm through and
    the policy decides from the stored body, so the confirm is not lost to the new column."""
    from sqlalchemy import text

    r = rig(migrated_engine, writer_engine, config=MANUAL)
    case = await a_case(migrated_engine, app_engine, people["asha"], confirmed=True, confidence=0.5)
    async with migrated_engine.begin() as conn:  # as if v1 had been written before 0057
        trigger = "incident_reports_append_only_rows"
        await conn.execute(text(f"ALTER TABLE incident_reports DISABLE TRIGGER {trigger}"))
        await conn.execute(text("UPDATE incident_reports SET core_hash = NULL"))
        await conn.execute(text(f"ALTER TABLE incident_reports ENABLE ALWAYS TRIGGER {trigger}"))
    await save_version(app_engine, case, more_accounts)
    assert await candidates(writer_engine) == [case]
    done = await r.run(case)
    assert done.stopped is None, done.lines()
    assert len(r.kibana.team_cases()) == 1


async def test_every_new_version_stores_the_hash_without_its_accounts(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    from sqlalchemy import text

    case = await a_case(migrated_engine, app_engine, people["asha"])
    await save_version(app_engine, case, more_accounts)
    async with app_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT version, content_hash, core_hash FROM incident_reports"
                    " WHERE case_id = :c ORDER BY version"
                ),
                {"c": case},
            )
        ).all()
    assert [r.version for r in rows] == [1, 2]
    assert rows[0].core_hash == rows[1].core_hash  # only the accounts differ
    assert rows[0].content_hash != rows[1].content_hash
    # naming v2: the core leaves out the case's title too, so it is not the content hash
    assert rows[0].core_hash != rows[0].content_hash
    assert m.core_hash is not None


def renamed(report: Any) -> Any:
    """The report with the case renamed by ARGUS (naming v2): only the title and the headline."""
    header = report.header.model_copy(
        update={"title": f"{report.header.incident_id} · Likely a clearer name",
                "certainty": "Likely"}
    )  # fmt: skip
    summary = report.summary.model_copy(
        update={"headline": "A new headline: Likely a clearer name"}
    )
    return report.model_copy(update={"header": header, "summary": summary})


async def test_a_confirm_survives_a_version_that_only_renames_the_case(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """A retitle renames what a person confirmed; it does not undo the confirm."""
    from argus.incident import store as incident_store

    case = await a_case(migrated_engine, app_engine, people["asha"], confirmed=True)
    stored = await save_version(app_engine, case, renamed)
    assert stored.version == 2
    async with app_engine.connect() as conn:
        first = await incident_store.version(conn, case, 1)
        assert first is not None
        assert m.core_hash(first.report) == m.core_hash(stored.report)
        held = await incident_store.holding(conn, stored)
    assert held is not None
    assert (held.decision.decision, held.held_from) == ("confirmed", 1)
    assert await candidates(writer_engine) == [case]
