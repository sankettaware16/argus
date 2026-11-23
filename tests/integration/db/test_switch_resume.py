"""Q-A5: services may stop a kill switch, only the owner resumes one (migration 0027)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate
from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration

FALSY = [False, None, 0, 0.0, "", [], {}]
TRUTHY = [True, 1, "true", "no", [0], {"a": 1}, 2.5]


async def _sql(engine: AsyncEngine, statement: str, **params: object) -> None:
    async with engine.begin() as conn:
        await conn.execute(text(statement), params)


def _refused(exc: pytest.ExceptionInfo[DBAPIError]) -> bool:
    return getattr(exc.value.orig, "sqlstate", None) == "42501"


async def _stopped(engine: AsyncEngine) -> tuple[bool, object]:
    async with engine.connect() as conn:
        switch = await conn.scalar(
            text("SELECT stopped FROM siem_switches WHERE component = 'global'")
        )
        llm = await conn.scalar(text("SELECT state -> 'stopped' FROM llm_state"))
    return bool(switch), llm


async def test_the_runtime_stops_but_cannot_resume_an_siem_switch(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    resume = "UPDATE siem_switches SET stopped = false WHERE component = 'global'"
    await _sql(app_engine, resume)  # running -> running: nothing to guard
    await _sql(app_engine, "UPDATE siem_switches SET stopped = true WHERE component = 'global'")
    with pytest.raises(DBAPIError) as refused:
        await _sql(app_engine, resume)
    assert _refused(refused)
    assert "only the owner resumes a stopped switch (siem_switches)" in str(refused.value)
    # the other columns stay the runtime's to change while stopped
    await _sql(app_engine, "UPDATE siem_switches SET reason = 'still stopped', changed_by = 'x'")
    assert (await _stopped(app_engine))[0]
    await _sql(migrated_engine, resume)  # the owner
    assert not (await _stopped(app_engine))[0]


async def test_the_runtime_stops_but_cannot_resume_the_llm_gateway(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    stop = "UPDATE llm_state SET state = jsonb_set(state, '{stopped}', 'true')"
    await _sql(app_engine, stop)
    # its budget updates keep working while stopped (they keep the flag)
    await _sql(app_engine, "UPDATE llm_state SET state = state || '{\"spent\": 1}'")
    for change in (
        "jsonb_set(state, '{stopped}', 'false')",
        "state - 'stopped'",
        "jsonb_set(state, '{stopped}', 'null')",
        "'{}'::jsonb",
    ):
        with pytest.raises(DBAPIError) as refused:
            await _sql(app_engine, f"UPDATE llm_state SET state = {change}")  # noqa: S608
        assert _refused(refused), change
    assert (await _stopped(app_engine))[1] is True
    await _sql(migrated_engine, "UPDATE llm_state SET state = state - 'stopped'")  # the owner
    assert (await _stopped(app_engine))[1] is None


async def test_the_llm_flag_is_read_as_the_gateway_reads_it(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Every pair of JSON values (exhaustive): the runtime is refused exactly when a truthy
    flag (budget.from_json reads Python's bool of it) would become falsy or vanish."""
    set_flag = "UPDATE llm_state SET state = jsonb_set(state, '{stopped}', CAST(:v AS jsonb))"
    for before in TRUTHY + FALSY:
        for after in [*TRUTHY, *FALSY, "absent"]:
            await _sql(migrated_engine, set_flag, v=json.dumps(before))
            change = (
                "UPDATE llm_state SET state = state - 'stopped'" if after == "absent" else set_flag
            )
            resumes = bool(before) and (after == "absent" or not bool(after))
            if resumes:
                with pytest.raises(DBAPIError) as refused:
                    await _sql(app_engine, change, v=json.dumps(after))
                assert _refused(refused), (before, after)
            else:
                await _sql(app_engine, change, v=json.dumps(after))


async def test_doctor_reports_a_disabled_resume_guard(migrated_engine: AsyncEngine) -> None:
    assert await migrate.missing_resume_triggers(migrated_engine) == []
    await _sql(
        migrated_engine,
        "ALTER TABLE llm_state ENABLE TRIGGER llm_state_resume_needs_owner",  # origin only
    )
    assert await migrate.missing_resume_triggers(migrated_engine) == [
        "llm_state.llm_state_resume_needs_owner"
    ]
    await _sql(migrated_engine, "DROP TRIGGER siem_switches_resume_needs_owner ON siem_switches")
    assert len(await migrate.missing_resume_triggers(migrated_engine)) == 2


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER TABLE siem_switches DISABLE TRIGGER siem_switches_resume_needs_owner",
        "ALTER TABLE llm_state DISABLE TRIGGER ALL",
        "DROP TRIGGER llm_state_resume_needs_owner ON llm_state",
        "DROP FUNCTION argus_resume_needs_owner()",
        "CREATE OR REPLACE FUNCTION argus_resume_needs_owner() RETURNS trigger"
        " LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
        "SET session_replication_role = replica",
        "DELETE FROM siem_switches",
        "INSERT INTO siem_switches (component) VALUES ('global')",
        "UPDATE llm_state SET name = 'other'",
        "SET ROLE argus",
    ],
)
async def test_the_runtime_cannot_remove_the_guard(app_engine: AsyncEngine, statement: str) -> None:
    with pytest.raises(DBAPIError):
        await _sql(app_engine, statement)


async def test_the_function_is_not_executable_by_public(app_engine: AsyncEngine) -> None:
    async with app_engine.connect() as conn:
        allowed = await conn.scalar(
            text("SELECT has_function_privilege('argus_resume_needs_owner()', 'EXECUTE')")
        )
    assert allowed is False


async def test_downgrade_removes_the_guard_and_upgrade_restores_it(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await migrate.downgrade(migrated_engine, "0022")
    await _sql(app_engine, "UPDATE siem_switches SET stopped = true")
    await _sql(app_engine, "UPDATE siem_switches SET stopped = false")  # as before Q-A5
    await migrate.upgrade(migrated_engine)
    await _sql(app_engine, "UPDATE siem_switches SET stopped = true")
    with pytest.raises(DBAPIError):
        await _sql(app_engine, "UPDATE siem_switches SET stopped = false")


def test_resume_commands_log_in_as_the_owner(
    cli_env: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = ("-c", str(cli_env))
    assert _invoke("db", "upgrade", *config)[0] == 0
    assert _invoke("siem", "stop", "--component", "collector", *config)[0] == 0
    assert _invoke("llm", "stop", *config)[0] == 0
    with monkeypatch.context() as without:
        without.setenv("ARGUS_DATABASE__OWNER_PASSWORD", "")
        for command in (("siem", "resume", "--component", "collector"), ("llm", "resume")):
            code, out = _invoke(*command, *config)
            assert code == 2, out
            assert "resuming needs the database owner" in out
            assert f"sudo argus-owner {' '.join(command)}" in out
        # stopping still works without it
        assert _invoke("siem", "stop", "--component", "global", *config)[0] == 0
    assert _invoke("siem", "resume", "--component", "collector", *config) == (
        0,
        "collector: resumed\n",
    )
    assert _invoke("llm", "resume", *config) == (0, "LLM calls resumed\n")
    assert _invoke("siem", "resume", *config) == (0, "global: resumed\n")
