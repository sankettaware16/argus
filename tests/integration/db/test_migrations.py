from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest
from alembic import command as alembic_command
from alembic.config import Config
from alembic.util import CommandError
from sqlalchemy import inspect, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate


async def _tables(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as conn:
        return set(await conn.run_sync(lambda c: inspect(c).get_table_names()))


async def _function_exists(engine: AsyncEngine, name: str) -> bool:
    async with engine.connect() as conn:
        found = await conn.execute(text("SELECT 1 FROM pg_proc WHERE proname = :n"), {"n": name})
        return found.first() is not None


def test_single_head() -> None:
    assert migrate.head_revision() == "0110"


async def test_upgrade_from_empty(empty_engine: AsyncEngine) -> None:
    assert await migrate.current_revision(empty_engine) is None
    await migrate.upgrade(empty_engine)
    assert await migrate.current_revision(empty_engine) == migrate.head_revision()
    assert {"audit_events", "alembic_version"} <= await _tables(empty_engine)
    assert await migrate.missing_guard_triggers(empty_engine) == []
    assert await _function_exists(empty_engine, "argus_reject_mutation")


async def test_models_match_schema_after_upgrade(migrated_engine: AsyncEngine) -> None:
    assert await migrate.schema_drift(migrated_engine) == []


async def test_upgrade_is_idempotent(migrated_engine: AsyncEngine) -> None:
    await migrate.upgrade(migrated_engine)
    assert await migrate.current_revision(migrated_engine) == migrate.head_revision()


async def test_full_down_up_cycle(migrated_engine: AsyncEngine) -> None:
    await migrate.downgrade(migrated_engine, "base")
    assert await migrate.current_revision(migrated_engine) is None
    assert "audit_events" not in await _tables(migrated_engine)
    assert not await _function_exists(migrated_engine, "argus_reject_mutation")

    await migrate.upgrade(migrated_engine)
    assert await migrate.schema_drift(migrated_engine) == []
    assert await migrate.missing_guard_triggers(migrated_engine) == []


async def test_failed_migration_leaves_no_partial_state(empty_engine: AsyncEngine) -> None:
    """Transactional DDL: if the migration fails halfway, nothing it did survives."""
    async with empty_engine.begin() as conn:
        await conn.execute(
            text("CREATE FUNCTION argus_reject_mutation() RETURNS int LANGUAGE sql AS 'SELECT 1'")
        )

    with pytest.raises(ProgrammingError):
        await migrate.upgrade(empty_engine)

    assert await migrate.current_revision(empty_engine) is None
    assert "audit_events" not in await _tables(empty_engine)


async def test_disabled_trigger_is_reported(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only_rows")
        )
    assert await migrate.missing_guard_triggers(migrated_engine) == [
        "audit_events.audit_events_append_only_rows"
    ]


# a migration whose downgrade has nothing to undo, with the reason
EMPTY_DOWNGRADE = {"0064_siem_names.py": "D-291: the earlier migrations create the new names"}


def test_every_migration_has_a_real_downgrade() -> None:
    versions = Path(migrate.MIGRATIONS_DIR) / "versions"
    files = sorted(versions.glob("*.py"))
    assert files, "no migrations found"
    for path in files:
        tree = ast.parse(path.read_text())
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        assert "upgrade" in functions, path.name
        assert "downgrade" in functions, path.name
        body = functions["downgrade"].body
        if path.name in EMPTY_DOWNGRADE:
            continue
        assert not (len(body) == 1 and isinstance(body[0], ast.Pass)), (
            f"{path.name}: empty downgrade"
        )


# --------------------------------------------------------------------------- revision targets

CHAIN = migrate.revision_chain()
FIRST, HEAD = CHAIN[0], CHAIN[-1]


def test_revision_chain_runs_from_the_first_migration_to_head() -> None:
    assert len(CHAIN) >= 2  # several cases below need a step between two migrations
    assert migrate.head_revision() == HEAD
    assert len(set(CHAIN)) == len(CHAIN)


@pytest.mark.parametrize(
    ("revision", "target"),
    [
        ("head", "head"),
        ("heads", "heads"),
        ("base", "base"),
        (FIRST, FIRST),
        (HEAD, HEAD),
        ("+1", "+1"),
        ("-1", "-1"),
        (f"+{len(CHAIN)}", f"+{len(CHAIN)}"),
        ("+01", "+1"),
        ("head-1", CHAIN[-2]),
        ("heads-1", CHAIN[-2]),
        ("head+0", HEAD),
        (f"head-{len(CHAIN)}", "base"),  # Alembic's own upgrade asserts on a step that lands here
        ("base+1", FIRST),
        (f"base+{len(CHAIN)}", HEAD),
        ("base+0", "base"),
        (f"{FIRST}+1", CHAIN[1]),
        (f"{FIRST}-1", "base"),
        (f"{HEAD}-1", CHAIN[-2]),
    ],
)
def test_targets_on_the_chain_resolve_to_what_alembic_handles(revision: str, target: str) -> None:
    assert migrate.resolve_revision(revision) == target


@pytest.mark.parametrize(
    "revision",
    [
        "head+1",  # Alembic: bare AssertionError (a traceback in the CLI)
        "heads+1",
        f"head-{len(CHAIN) + 1}",
        f"{HEAD}+1",
        f"{FIRST}+{len(CHAIN)}",
        f"{FIRST}-2",
        f"base+{len(CHAIN) + 1}",
        "base-1",
        "+0",
        "-0",
        f"+{len(CHAIN) + 1}",
        f"-{len(CHAIN) + 1}",
        "head+9999999",
        "head+" + "9" * 5000,
        "no-such-revision",
        "",
        " ",
        "HEAD",
        " head",
        "head ",
        "head\n",
        "head+1abc",
        "head+\u0661",  # ARABIC-INDIC DIGIT ONE: Alembic would read it as 1
        # Steps that would be on the chain if any Unicode digit counted (as \d does): ASCII only.
        "head-\u0661",
        "base+\u0661",
        "+\u0661",
        "-\u0661",
        "+\uff11",  # FULLWIDTH DIGIT ONE
        FIRST[:-1],  # a prefix of several ids
        f"{FIRST}@head",  # no branch labels in ARGUS
        "@head",
        f"{FIRST},{HEAD}",
    ],
)
def test_targets_off_the_chain_are_unknown(revision: str) -> None:
    with pytest.raises(migrate.UnknownRevisionError, match="unknown revision"):
        migrate.resolve_revision(revision)


@pytest.mark.parametrize(
    ("revision", "direction", "target"),
    [
        ("+1", "upgrade", "+1"),
        (f"+{len(CHAIN)}", "upgrade", f"+{len(CHAIN)}"),
        ("-1", "downgrade", "-1"),
        (f"-{len(CHAIN)}", "downgrade", f"-{len(CHAIN)}"),
        # A step from a named point is a fixed target: the database's revision decides the way.
        ("head-1", "upgrade", CHAIN[-2]),
        ("head-1", "downgrade", CHAIN[-2]),
        ("base+1", "downgrade", FIRST),
        ("head", "downgrade", "head"),
        ("base", "upgrade", "base"),
    ],
)
def test_a_step_from_the_database_may_go_the_commands_way(
    revision: str, direction: migrate.Direction, target: str
) -> None:
    assert migrate.resolve_revision(revision, direction=direction) == target


@pytest.mark.parametrize(
    ("revision", "direction"),
    [
        ("-1", "upgrade"),
        (f"-{len(CHAIN)}", "upgrade"),
        ("+1", "downgrade"),
        (f"+{len(CHAIN)}", "downgrade"),
    ],
)
def test_a_step_from_the_database_the_other_way_is_unknown(
    revision: str, direction: migrate.Direction
) -> None:
    """Alembic refuses ``upgrade -N`` and ``downgrade +N`` whatever the database's revision."""
    sign = "+" if direction == "upgrade" else "-"
    expected = (
        f"unknown revision {revision!r}: {direction} takes only {sign}N steps from the "
        "database's revision"
    )
    with pytest.raises(migrate.UnknownRevisionError) as info:
        migrate.resolve_revision(revision, direction=direction)
    assert str(info.value) == expected
    assert migrate.resolve_revision(revision) == revision  # a point of the chain, without a way


async def test_a_step_that_lands_on_base_is_a_no_op_upgrade(migrated_engine: AsyncEngine) -> None:
    """Alembic's own resolution of ``head-N`` (= base) for an upgrade is a bare AssertionError."""
    await migrate.upgrade(migrated_engine, f"head-{len(CHAIN)}")
    assert await migrate.current_revision(migrated_engine) == HEAD


async def test_off_chain_target_is_refused_before_alembic_runs(
    migrated_engine: AsyncEngine,
) -> None:
    with pytest.raises(migrate.UnknownRevisionError):
        await migrate.upgrade(migrated_engine, "head+1")
    with pytest.raises(migrate.UnknownRevisionError):
        await migrate.downgrade(migrated_engine, f"head-{len(CHAIN) + 1}")
    assert await migrate.current_revision(migrated_engine) == HEAD


async def test_a_step_the_other_way_is_refused_before_alembic_runs(
    migrated_engine: AsyncEngine,
) -> None:
    """Alembic's own error for these is a CommandError ("Relative revision -1 didn't produce 1
    migrations") that does not say what is wrong."""
    with pytest.raises(migrate.UnknownRevisionError, match=r"upgrade takes only \+N steps"):
        await migrate.upgrade(migrated_engine, "-1")
    with pytest.raises(migrate.UnknownRevisionError, match="downgrade takes only -N steps"):
        await migrate.downgrade(migrated_engine, "+1")
    assert await migrate.current_revision(migrated_engine) == HEAD


async def test_alembic_assertion_while_resolving_a_target_becomes_a_command_error(
    migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Backstop for targets the static check might miss: Alembic's revision map asserts instead of
    raising RevisionError, which the CLI would show as a traceback."""
    monkeypatch.setattr(migrate, "resolve_revision", lambda revision, **_: revision)
    with pytest.raises(CommandError, match="cannot resolve revision 'head\\+1'"):
        await migrate.upgrade(migrated_engine, "head+1")
    assert await migrate.current_revision(migrated_engine) == HEAD


async def test_other_assertion_errors_are_not_disguised(
    migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_upgrade(_cfg: Config, _revision: str) -> None:
        raise AssertionError("raised by a migration, not by Alembic's revision map")

    monkeypatch.setattr(alembic_command, "upgrade", failing_upgrade)
    with pytest.raises(AssertionError, match="raised by a migration"):
        await migrate.upgrade(migrated_engine)


# --------------------------------------------------------------------------- in-process lock


@pytest.mark.timeout(30)
async def test_migrating_inside_a_migration_fails_fast_instead_of_waiting_for_itself(
    migrated_engine: AsyncEngine,
) -> None:
    async with migrate.migration_transaction(migrated_engine) as conn:
        with pytest.raises(RuntimeError, match="already in progress"):
            await asyncio.wait_for(migrate.upgrade(migrated_engine), timeout=5)
        started_meanwhile = asyncio.ensure_future(migrate.downgrade(migrated_engine, "base"))
        with pytest.raises(RuntimeError, match="already in progress"):
            await asyncio.wait_for(started_meanwhile, timeout=5)
        assert await migrate.current_revision(conn) == HEAD  # the outer migration carries on
    await asyncio.wait_for(migrate.downgrade(migrated_engine, "base"), timeout=10)  # lock is free
    assert await migrate.current_revision(migrated_engine) is None


@pytest.mark.timeout(30)
async def test_a_task_started_during_a_migration_may_migrate_once_it_has_ended(
    migrated_engine: AsyncEngine,
) -> None:
    """Fail-fast lasts as long as the migration, not as long as the tasks started during it (a
    background job started while the application migrates at startup, say)."""
    ended = asyncio.Event()

    async def background_job() -> str | None:
        await ended.wait()
        await migrate.downgrade(migrated_engine, "base")
        return await migrate.current_revision(migrated_engine)

    async with migrate.migration_transaction(migrated_engine):
        job = asyncio.create_task(background_job())
        meanwhile = asyncio.create_task(migrate.upgrade(migrated_engine))
        with pytest.raises(RuntimeError, match="already in progress"):  # still fails fast
            await asyncio.wait_for(meanwhile, timeout=5)
    ended.set()
    assert await asyncio.wait_for(job, timeout=10) is None


class _MigrationAbandonedError(Exception):
    pass


async def _abandoned_migration(
    engine: AsyncEngine, started: list[asyncio.Task[str | None]]
) -> None:
    """A migration that fails after starting a background job (which waits for it to end)."""
    async with migrate.migration_transaction(engine):
        started.append(asyncio.create_task(_downgrade_when_free(engine)))
        await asyncio.sleep(0)
        raise _MigrationAbandonedError


async def _downgrade_when_free(engine: AsyncEngine) -> str | None:
    await asyncio.sleep(0.2)  # the migration that started this task has ended by now
    await migrate.downgrade(engine, "base")
    return await migrate.current_revision(engine)


@pytest.mark.timeout(30)
async def test_a_task_started_during_a_failed_migration_may_migrate_once_it_has_ended(
    migrated_engine: AsyncEngine,
) -> None:
    """The marker is cleared however the migration ends: a failed one too (round-3 verification:
    clearing it only after a successful yield passed every other test)."""
    started: list[asyncio.Task[str | None]] = []
    with pytest.raises(_MigrationAbandonedError):
        await _abandoned_migration(migrated_engine, started)
    assert await asyncio.wait_for(started[0], timeout=10) is None


@pytest.mark.timeout(30)
async def test_sibling_tasks_still_queue_for_the_lock(migrated_engine: AsyncEngine) -> None:
    """Fail-fast is only for re-entry: tasks started outside a migration wait their turn."""
    await asyncio.wait_for(
        asyncio.gather(
            migrate.downgrade(migrated_engine, "base"), migrate.upgrade(migrated_engine)
        ),
        timeout=20,
    )
    assert await migrate.current_revision(migrated_engine) in (None, HEAD)
