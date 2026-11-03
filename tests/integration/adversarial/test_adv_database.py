"""Adversarial tests for C1's database layer: migrations, engine/pool behaviour and the audit trail.

Every database used here is a throwaway one from ``tests/integration/conftest.py`` (names start with
``argus_test_``); ``_connect`` refuses any other name. Nothing here touches the developer's
``argus`` database, runs migrations outside a throwaway database, or contacts the production SIEM.

A docstring starting with **DEFECT** marks a test that fails on the current code on purpose: it
proves the defect and passes once it is fixed. **LOCK-IN** tests pass today and pin down behaviour
that held up under attack.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import UTC, date, datetime, timedelta
from datetime import time as clock_time
from decimal import Decimal
from enum import Enum
from pathlib import PurePosixPath
from typing import Any

import psycopg
import pytest
from sqlalchemy import event, inspect, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner, Result

from argus.cli import app
from argus.config import ConfigError, DatabaseSettings, load_settings
from argus.db import migrate
from argus.db.audit import MAX_DETAILS_BYTES, AuditError, record_audit
from argus.db.engine import APPLICATION_NAME, create_engine, session_factory
from tests.conftest import REPO_ROOT
from tests.integration.conftest import TEST_DB_PREFIX, admin_connect, owner_password

CONFIG_PATH = REPO_ROOT / "config" / "argus.yaml"
runner = CliRunner()

# --------------------------------------------------------------------------- helpers


def _connect(
    settings: DatabaseSettings, database: str, *, autocommit: bool = True
) -> psycopg.Connection[tuple[Any, ...]]:
    """Plain psycopg connection to a THROWAWAY database (any other name is refused), as the
    owner: it sees every session's wait events and may lock any table."""
    if not database.startswith(TEST_DB_PREFIX):
        raise AssertionError(f"refusing to connect to non-test database {database!r}")
    return psycopg.connect(
        host=settings.host,
        port=settings.port,
        user=settings.owner_user,
        password=owner_password(settings),
        dbname=database,
        autocommit=autocommit,
        connect_timeout=5,
        application_name="argus-adversarial-probe",
    )


def _fast(settings: DatabaseSettings) -> DatabaseSettings:
    """1 s statement timeout (hence 1 s lock timeout) so blocked work fails quickly."""
    return settings.model_copy(update={"statement_timeout": timedelta(seconds=1)})


def _first_line(exc: BaseException) -> str:
    lines = str(exc).strip().splitlines()
    return f"{type(exc).__name__}: {lines[0] if lines else ''}"


async def _write(engine: AsyncEngine, **kwargs: Any) -> int:
    async with session_factory(engine)() as session, session.begin():
        audit = await record_audit(session, **{"actor": "adv", "action": "adv.test", **kwargs})
        return audit.id


async def _rows(engine: AsyncEngine) -> list[tuple[Any, ...]]:
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT id, occurred_at, actor, action, outcome, target_type, target_id, "
                "correlation_id, details FROM audit_events ORDER BY id"
            )
        )
        return [tuple(row) for row in result]


async def _actions(engine: AsyncEngine) -> list[str]:
    return [row[3] for row in await _rows(engine)]


async def _details(engine: AsyncEngine, event_id: int) -> Any:
    async with engine.connect() as conn:
        result = await conn.execute(
            text("SELECT details FROM audit_events WHERE id = :i"), {"i": event_id}
        )
        return result.scalar_one()


async def _show(engine: AsyncEngine, *names: str) -> dict[str, str]:
    async with engine.connect() as conn:
        return {
            name: str((await conn.execute(text(f"SHOW {name}"))).scalar_one()) for name in names
        }


_SESSION_GUC = (
    "statement_timeout",
    "lock_timeout",
    "idle_in_transaction_session_timeout",
    "TimeZone",
)


async def _schema_objects(engine: AsyncEngine) -> dict[str, Any]:
    """Everything migration 0001 owns, counted, so residue or loss would show up."""
    async with engine.connect() as conn:
        tables = sorted(await conn.run_sync(lambda c: inspect(c).get_table_names()))
        functions = (
            await conn.execute(
                text("SELECT count(*) FROM pg_proc WHERE proname = 'argus_reject_mutation'")
            )
        ).scalar_one()
        triggers = sorted(
            row[0]
            for row in await conn.execute(
                text(
                    "SELECT t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
                    "WHERE c.relname = 'audit_events' AND NOT t.tgisinternal"
                )
            )
        )
        indexes = sorted(
            row[0]
            for row in await conn.execute(
                text("SELECT indexname FROM pg_indexes WHERE tablename = 'audit_events'")
            )
        )
        versions = (
            [row[0] for row in await conn.execute(text("SELECT version_num FROM alembic_version"))]
            if "alembic_version" in tables
            else None
        )
    return {
        "tables": tables,
        "functions": functions,
        "triggers": triggers,
        "indexes": indexes,
        "versions": versions,
    }


def _terminate_argus_backends(
    settings: DatabaseSettings, database: str, pid: int | None = None
) -> set[int]:
    """pg_terminate_backend on ARGUS connections inside one throwaway database."""
    assert database.startswith(TEST_DB_PREFIX), database
    with admin_connect(settings) as conn:
        rows = conn.execute(
            "SELECT pid, pg_terminate_backend(pid, 3000) FROM pg_stat_activity "
            "WHERE datname = %s AND application_name = %s AND pid <> pg_backend_pid() "
            "AND (%s::int IS NULL OR pid = %s::int)",
            (database, APPLICATION_NAME, pid, pid),
        ).fetchall()
    return {int(row[0]) for row in rows if row[1]}


async def _wait_for_lock_waiter(settings: DatabaseSettings, database: str) -> int:
    """pid of the ARGUS backend that is blocked on a lock in ``database`` (polls up to 5 s)."""
    deadline = time.monotonic() + 5
    with _connect(settings, database) as probe:
        while time.monotonic() < deadline:
            row = probe.execute(
                "SELECT pid FROM pg_stat_activity WHERE datname = current_database() "
                "AND application_name = %s AND wait_event_type = 'Lock'",
                (APPLICATION_NAME,),
            ).fetchone()
            if row is not None:
                return int(row[0])
            await asyncio.sleep(0.02)
    raise AssertionError("precondition: no ARGUS backend ever blocked on a lock")


@pytest.fixture
def cli_env(test_database: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Point the real CLI at the throwaway database (env beats .env) with 1 s DB timeouts."""
    monkeypatch.chdir(REPO_ROOT)  # the repo .env supplies the password
    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)
    monkeypatch.setenv("ARGUS_DATABASE__STATEMENT_TIMEOUT", "1s")
    monkeypatch.setenv("ARGUS_LOGGING__LEVEL", "WARNING")
    effective = load_settings(CONFIG_PATH).database.name
    assert effective == test_database, effective
    assert effective.startswith(TEST_DB_PREFIX), effective
    return dict(os.environ)


def _cli(*args: str) -> Result:
    return runner.invoke(app, [*args, "-c", str(CONFIG_PATH)])


# =========================================================================== migrations


@pytest.mark.timeout(30)
async def test_concurrent_upgrades_in_one_process_both_succeed(
    db_settings: DatabaseSettings, test_database: str
) -> None:
    """DEFECT: two concurrent ``migrate.upgrade`` calls in one process both fail.

    Alembic keeps its ``context``/``op`` proxies in module globals. The second call installs its
    environment while the first is still running, so one call dies inside Alembic with a bare
    ``KeyError`` ('config'/'script') and the other stalls on catalog rows the first left
    uncommitted until the lock/statement timeout. Both callers asked for head; the database stays
    empty.
    """
    engine = create_engine(_fast(db_settings), database=test_database, role="owner")
    try:
        results = await asyncio.gather(
            migrate.upgrade(engine), migrate.upgrade(engine), return_exceptions=True
        )
        failures = [_first_line(r) for r in results if isinstance(r, BaseException)]
        assert failures == [], failures
        assert await migrate.current_revision(engine) == migrate.head_revision()
        assert await migrate.missing_guard_triggers(engine) == []
    finally:
        await engine.dispose()


_LOCK_WAITERS = (
    "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
    "WHERE NOT l.granted AND a.datname = current_database()"
)


@pytest.mark.timeout(60)
async def test_second_upgrade_process_waits_for_the_first_instead_of_failing(
    db_settings: DatabaseSettings, test_database: str, cli_env: dict[str, str]
) -> None:
    """DEFECT: migrations take no lock, so two ``argus db upgrade`` processes race.

    Runner A (this process) is held just before COMMIT; runner B (``argus db upgrade`` in a
    subprocess) then blocks on A's uncommitted ``alembic_version`` catalog row and, as soon as A
    commits, dies with ``duplicate key value violates unique constraint
    "pg_type_typname_nsp_index"`` (exit 1, printed as "cannot connect"). With a migration lock
    (``pg_advisory_xact_lock`` taken before Alembic runs) B would wait and find the database at
    head.
    """
    state: dict[str, Any] = {}

    def hold_commit_until_runner_b_waits(_conn: object) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-c", "from argus.cli import main; main()", "db", "upgrade"],
            cwd=REPO_ROOT,
            env=cli_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        state["proc"] = proc
        deadline = time.monotonic() + 15
        with _connect(db_settings, test_database) as probe:
            while proc.poll() is None and time.monotonic() < deadline:
                row = probe.execute(_LOCK_WAITERS).fetchone()
                if row is not None and row[0]:
                    state["b_blocked"] = True
                    return
                time.sleep(0.02)

    engine = create_engine(db_settings, database=test_database, role="owner")
    event.listen(engine.sync_engine, "commit", hold_commit_until_runner_b_waits, once=True)
    try:
        await migrate.upgrade(engine)
        proc = state["proc"]
        _, stderr = proc.communicate(timeout=30)
        assert state.get("b_blocked"), "precondition: runner B never reached the database"
        assert proc.returncode == 0, stderr.strip().splitlines()[-1:]
        assert (await _schema_objects(engine))["versions"] == [migrate.head_revision()]
        assert await migrate.schema_drift(engine) == []
    finally:
        leftover = state.get("proc")
        if leftover is not None and leftover.poll() is None:
            leftover.kill()
            leftover.communicate()
        await engine.dispose()


async def test_upgrade_and_downgrade_leave_unrelated_objects_alone(
    empty_engine: AsyncEngine,
) -> None:
    """LOCK-IN: unrelated objects (a table with its own trigger and trigger function, and an
    ``argus_reject_mutation(text)`` overload) neither block the migration nor get dropped by it."""
    async with empty_engine.begin() as conn:
        await conn.execute(text("CREATE TABLE operator_notes (id int PRIMARY KEY, body text)"))
        await conn.execute(
            text(
                "CREATE FUNCTION operator_touch() RETURNS trigger LANGUAGE plpgsql "
                "AS $$ BEGIN RETURN NEW; END $$"
            )
        )
        await conn.execute(
            text(
                "CREATE TRIGGER operator_notes_touch BEFORE UPDATE ON operator_notes "
                "FOR EACH ROW EXECUTE FUNCTION operator_touch()"
            )
        )
        await conn.execute(
            text(
                "CREATE FUNCTION argus_reject_mutation(reason text) RETURNS text "
                "LANGUAGE sql AS 'SELECT reason'"
            )
        )

    await migrate.upgrade(empty_engine)
    assert await migrate.current_revision(empty_engine) == migrate.head_revision()
    assert await migrate.missing_guard_triggers(empty_engine) == []
    await _write(empty_engine)

    await migrate.downgrade(empty_engine, "base")
    async with empty_engine.connect() as conn:
        survivors = (
            await conn.execute(
                text(
                    "SELECT (SELECT count(*) FROM pg_class WHERE relname = 'operator_notes'),"
                    " (SELECT count(*) FROM pg_trigger WHERE tgname = 'operator_notes_touch'),"
                    " (SELECT count(*) FROM pg_proc WHERE proname = 'operator_touch'),"
                    " (SELECT count(*) FROM pg_proc WHERE proname = 'argus_reject_mutation'"
                    "   AND pg_get_function_identity_arguments(oid) = 'reason text')"
                )
            )
        ).one()
    assert tuple(survivors) == (1, 1, 1, 1)
    assert "audit_events" not in (await _schema_objects(empty_engine))["tables"]


async def test_unrelated_table_is_not_reported_as_model_drift(migrated_engine: AsyncEngine) -> None:
    """DEFECT: ``schema_drift`` compares the models with *every* table in the database.

    D-009 puts LangGraph's checkpoint tables in the same database. Any table ARGUS's models do not
    declare (here a ``checkpoints`` table) is reported as ``remove_table`` drift, so
    ``argus db check`` and ``doctor`` fail permanently. An Alembic autogenerate run would also
    emit ``DROP TABLE`` for it.
    """
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("CREATE TABLE checkpoints (thread_id text PRIMARY KEY, checkpoint jsonb)")
        )
    assert await migrate.schema_drift(migrated_engine) == []


@pytest.mark.timeout(60)
async def test_twenty_down_up_cycles_leave_no_residue(migrated_engine: AsyncEngine) -> None:
    """LOCK-IN: repeated full downgrade/upgrade cycles converge on exactly the same schema."""
    baseline = await _schema_objects(migrated_engine)
    assert baseline["functions"] == 1
    assert baseline["versions"] == [migrate.head_revision()]
    for _ in range(20):
        await migrate.downgrade(migrated_engine, "base")
        await migrate.upgrade(migrated_engine)
    assert await _schema_objects(migrated_engine) == baseline
    assert await migrate.schema_drift(migrated_engine) == []
    await _write(migrated_engine)
    with pytest.raises(DBAPIError, match="append-only"):
        async with migrated_engine.begin() as conn:
            await conn.execute(text("DELETE FROM audit_events"))


@pytest.mark.timeout(30)
async def test_migration_blocked_past_the_timeout_fails_fast_and_rolls_back(
    db_settings: DatabaseSettings, test_database: str
) -> None:
    """LOCK-IN: a migration step that cannot get its lock (a reader holds audit_events) fails within
    the configured timeout instead of hanging, and the schema is exactly as before."""
    engine = create_engine(_fast(db_settings), database=test_database, role="owner")
    try:
        await migrate.upgrade(engine)
        before = await _schema_objects(engine)
        with _connect(db_settings, test_database, autocommit=False) as reader:
            reader.execute("LOCK TABLE audit_events IN ACCESS SHARE MODE")
            started = time.monotonic()
            with pytest.raises(DBAPIError, match="timeout"):
                await migrate.downgrade(engine, "base")
            elapsed = time.monotonic() - started
            reader.rollback()
        assert elapsed < 4
        assert await _schema_objects(engine) == before
        assert await migrate.missing_guard_triggers(engine) == []
    finally:
        await engine.dispose()


@pytest.mark.timeout(30)
async def test_migration_killed_midway_leaves_nothing_behind_and_can_be_retried(
    db_settings: DatabaseSettings, test_database: str, empty_engine: AsyncEngine
) -> None:
    """LOCK-IN: pg_terminate_backend on the migrating connection (after it created alembic_version,
    audit_events and its indexes) rolls everything back; a retry then succeeds cleanly."""
    with _connect(db_settings, test_database, autocommit=False) as other:
        # Uncommitted twin of the trigger function: the migration blocks right before creating it.
        other.execute(
            "CREATE FUNCTION argus_reject_mutation() RETURNS trigger LANGUAGE plpgsql "
            "AS $$ BEGIN RETURN NULL; END $$"
        )
        task = asyncio.ensure_future(migrate.upgrade(empty_engine))
        try:
            pid = await _wait_for_lock_waiter(db_settings, test_database)
            assert _terminate_argus_backends(db_settings, test_database, pid=pid) == {pid}
            with pytest.raises(DBAPIError):
                await task
        finally:
            other.rollback()
            if not task.done():  # only on a failed precondition: never leave the task behind
                task.cancel()
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await task

    leftovers = await _schema_objects(empty_engine)
    assert leftovers["tables"] == []
    assert leftovers["functions"] == 0
    await migrate.upgrade(empty_engine)
    assert await migrate.current_revision(empty_engine) == migrate.head_revision()
    assert await migrate.schema_drift(empty_engine) == []
    assert await migrate.missing_guard_triggers(empty_engine) == []


# --------------------------------------------------------------------------- CLI migration paths


def _downgrade_while_a_reader_holds_audit_events(
    settings: DatabaseSettings, database: str
) -> Result:
    assert _cli("db", "upgrade").exit_code == 0
    with _connect(settings, database, autocommit=False) as reader:
        reader.execute("LOCK TABLE audit_events IN ACCESS SHARE MODE")
        result = _cli("db", "downgrade", "base", "--yes")
        reader.rollback()
    return result


def test_cli_failed_downgrade_does_not_record_a_successful_downgrade(
    cli_env: dict[str, str], db_settings: DatabaseSettings, test_database: str
) -> None:
    """DEFECT: ``_db_downgrade`` commits a ``db.downgrade`` audit event with outcome ``success``
    *before* it runs the downgrade. When the downgrade then fails (here: lock timeout), the database
    is still at 0001 but the audit trail claims it was downgraded."""
    result = _downgrade_while_a_reader_holds_audit_events(db_settings, test_database)
    assert result.exit_code == 1, result.output  # precondition: the downgrade really failed
    with _connect(db_settings, test_database) as conn:
        version = conn.execute("SELECT version_num FROM alembic_version").fetchall()
        claims = conn.execute(
            "SELECT outcome, details FROM audit_events WHERE action = 'db.downgrade'"
        ).fetchall()
    assert version == [(migrate.head_revision(),)]
    assert [c for c in claims if c[0] == "success"] == []


def test_cli_migration_timeout_is_not_reported_as_a_connection_failure(
    cli_env: dict[str, str], db_settings: DatabaseSettings, test_database: str
) -> None:
    """DEFECT: ``_short_db_error`` prefixes every database error with "cannot connect", so a
    migration that connected fine but hit a lock/statement timeout (or a failed DDL statement) is
    reported as a connection problem, which sends the operator to check network and credentials."""
    result = _downgrade_while_a_reader_holds_audit_events(db_settings, test_database)
    assert result.exit_code == 1, result.output  # precondition: the downgrade really failed
    assert "timeout" in result.output
    assert "cannot connect" not in result.output


# =========================================================================== append-only trail

_INDIRECT_MUTATIONS: dict[str, list[str]] = {
    "writable-cte-update": [
        "WITH changed AS (UPDATE audit_events SET actor = 'mallory' RETURNING id) "
        "SELECT count(*) FROM changed"
    ],
    "writable-cte-delete-and-reinsert": [
        "WITH gone AS (DELETE FROM audit_events RETURNING action, details) "
        "INSERT INTO audit_events (actor, action, details) "
        "SELECT 'mallory', action, details FROM gone"
    ],
    "delete-using": ["DELETE FROM audit_events a USING (SELECT 1 AS one) s WHERE s.one = 1"],
    "upsert-on-conflict-do-update": [
        "INSERT INTO audit_events (id, actor, action) OVERRIDING SYSTEM VALUE "
        "SELECT id, 'mallory', 'forged' FROM audit_events "
        "ON CONFLICT (id) DO UPDATE SET actor = EXCLUDED.actor"
    ],
    "merge-update": [
        "MERGE INTO audit_events t USING (SELECT 1 AS one) s ON true "
        "WHEN MATCHED THEN UPDATE SET actor = 'mallory'"
    ],
    "merge-delete": [
        "MERGE INTO audit_events t USING (SELECT 1 AS one) s ON true WHEN MATCHED THEN DELETE"
    ],
    "update-through-view": [
        "CREATE TEMP VIEW audit_view AS SELECT * FROM audit_events",
        "UPDATE audit_view SET actor = 'mallory'",
    ],
    "jsonb-patch": [
        "UPDATE audit_events SET details = details || jsonb_build_object('tampered', true)"
    ],
    "truncate-only": ["TRUNCATE ONLY audit_events"],
    "truncate-restart-identity-cascade": ["TRUNCATE audit_events RESTART IDENTITY CASCADE"],
}


@pytest.mark.parametrize(
    "statements", list(_INDIRECT_MUTATIONS.values()), ids=list(_INDIRECT_MUTATIONS)
)
async def test_append_only_holds_against_indirect_mutation(
    migrated_engine: AsyncEngine, statements: list[str]
) -> None:
    """LOCK-IN: every DML route to UPDATE/DELETE/TRUNCATE (writable CTEs, USING, upsert, MERGE,
    auto-updatable views, TRUNCATE variants) still hits the append-only triggers."""
    await _write(migrated_engine, details={"k": "v"})
    before = await _rows(migrated_engine)
    with pytest.raises(DBAPIError, match="append-only"):  # noqa: PT012 - one transaction
        async with migrated_engine.begin() as conn:
            for statement in statements:
                await conn.execute(text(statement))
    assert await _rows(migrated_engine) == before


async def test_copy_bulk_load_only_appends_rows_that_pass_the_constraints(
    migrated_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    """LOCK-IN: COPY is an append path only; it cannot alter existing rows or skip CHECKs."""
    await _write(migrated_engine)
    before = await _rows(migrated_engine)
    copy_sql = "COPY audit_events (actor, action, outcome) FROM STDIN"
    with _connect(db_settings, test_database) as conn:
        with conn.cursor() as cur, cur.copy(copy_sql) as copy:
            copy.write_row(("bulk", "bulk.load", "success"))
        with (
            pytest.raises(psycopg.errors.CheckViolation),
            conn.cursor() as cur,
            cur.copy(copy_sql) as copy,
        ):
            copy.write_row(("bulk", "bulk.load", "maybe"))
    after = await _rows(migrated_engine)
    assert after[: len(before)] == before
    assert [row[2:5] for row in after[len(before) :]] == [("bulk", "bulk.load", "success")]


async def test_session_replication_role_cannot_bypass_append_only(
    migrated_engine: AsyncEngine,
) -> None:
    """DEFECT: the guard triggers are ordinary (``tgenabled = 'O'``) triggers, which do not fire
    when ``session_replication_role = replica``. ARGUS connects as a superuser that owns the table
    (docker-compose default), so one ``SET`` with no DDL silently makes the audit trail
    mutable, and ``missing_guard_triggers``/doctor see nothing wrong. Fix: ``ENABLE ALWAYS
    TRIGGER`` (and a non-superuser runtime role)."""
    await _write(migrated_engine)
    before = await _rows(migrated_engine)
    with contextlib.suppress(DBAPIError):  # rejected (either way) is the desired outcome
        async with migrated_engine.begin() as conn:
            await conn.execute(text("SET LOCAL session_replication_role = replica"))
            await conn.execute(text("UPDATE audit_events SET actor = 'mallory'"))
    assert await _rows(migrated_engine) == before


async def test_replica_only_guard_triggers_are_reported_missing(
    migrated_engine: AsyncEngine,
) -> None:
    """DEFECT: ``missing_guard_triggers`` only flags ``tgenabled = 'D'``. A guard switched to
    ``ENABLE REPLICA`` (``'R'``) never fires in normal sessions (DELETE succeeds), yet doctor still
    reports "audit trail append-only: triggers present"."""
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("ALTER TABLE audit_events ENABLE REPLICA TRIGGER audit_events_append_only_rows")
        )
    assert await migrate.missing_guard_triggers(migrated_engine) == [
        "audit_events.audit_events_append_only_rows"
    ]


# =========================================================================== record_audit input

_UNSTORABLE: dict[str, dict[str, Any]] = {
    "nul-in-detail-value": {"details": {"user_agent": "curl\x00/8.0"}},
    "nul-in-detail-key": {"details": {"hdr\x00x": "1"}},
    "nul-in-raw-bytes": {"details": {"raw": b"GET /\x00 HTTP/1.1"}},
    # what ``b"caf\xe9".decode("utf-8", "surrogateescape")`` produces for a Latin-1 log line
    "lone-surrogate-in-detail-value": {"details": {"query": "caf\udce9"}},
    "lone-surrogate-in-detail-key": {"details": {"\ud800": 1}},
    "nul-in-actor": {"actor": "collector\x00"},
    "nul-in-target-id": {"target_id": "alert-1\x00"},
    "lone-surrogate-in-target-id": {"target_id": "host-\udcff"},
    "nul-in-correlation-id": {"correlation_id": "corr\x00"},
}


@pytest.mark.parametrize("hostile", list(_UNSTORABLE.values()), ids=list(_UNSTORABLE))
async def test_unstorable_text_is_rejected_or_sanitised_without_killing_the_transaction(
    migrated_engine: AsyncEngine, hostile: dict[str, Any]
) -> None:
    """DEFECT: NUL characters and lone surrogates (both arrive in SIEM data: raw log bytes,
    ``surrogateescape`` decoding, JSON ``\\ud800`` escapes) pass ``record_audit``'s validation and
    only fail at flush time with a raw ``DataError``/``UnicodeEncodeError``, not ``AuditError``. The
    caller's whole transaction is then dead (``PendingRollbackError``), so one hostile log line can
    stop the work being audited. Either sanitise or raise ``AuditError`` before touching the
    session."""
    async with session_factory(migrated_engine)() as session, session.begin():
        with contextlib.suppress(AuditError):  # rejecting cleanly is acceptable
            await record_audit(session, **{"actor": "adv", "action": "adv.hostile", **hostile})
        await record_audit(session, actor="adv", action="adv.after")  # caller carries on
    assert "adv.after" in await _actions(migrated_engine)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("actor", "\x01\x02"),
        ("actor", "\x1b"),
        ("actor", "\u200b"),
        ("action", "\x7f"),
        ("action", "\ufeff"),
        ("action", "\u200b\u2060"),
    ],
    ids=[
        "actor-c0-controls",
        "actor-escape",
        "actor-zero-width-space",
        "action-delete",
        "action-byte-order-mark",
        "action-zero-width-space-and-word-joiner",
    ],
)
async def test_actor_and_action_made_only_of_invisible_characters_are_rejected(
    migrated_engine: AsyncEngine, field: str, value: str
) -> None:
    """DEFECT: the emptiness check is ``str.strip()``, which ignores control and format
    characters. An actor/action that renders as nothing (or as a terminal escape) is stored, which
    defeats the "must not be empty" rule and lets audit listings be spoofed."""
    with pytest.raises(AuditError, match=field):
        await _write(migrated_engine, **{field: value})
    assert await _rows(migrated_engine) == []


@pytest.mark.parametrize(
    ("char", "count"), [("क", 12_000), ("😀", 9_000)], ids=["devanagari-36KB", "emoji-36KB"]
)
async def test_size_limit_counts_utf8_bytes_not_ascii_escapes(
    migrated_engine: AsyncEngine, char: str, count: int
) -> None:
    """DEFECT: the 64 KiB limit is measured on ``json.dumps`` output with ``ensure_ascii=True``,
    where each non-ASCII character costs 6-12 bytes instead of its 2-4 UTF-8 bytes. 36 KB of
    Devanagari or emoji is rejected as "exceed 65536 bytes"."""
    details = {"note": char * count}
    utf8_size = len(json.dumps(details, ensure_ascii=False).encode("utf-8"))
    assert utf8_size < MAX_DETAILS_BYTES * 0.6  # precondition: comfortably under the limit
    event_id = await _write(migrated_engine, details=details)
    assert await _details(migrated_engine, event_id) == details


async def test_details_exactly_at_the_size_limit_are_stored_and_one_byte_more_is_rejected(
    migrated_engine: AsyncEngine,
) -> None:
    """LOCK-IN: the boundary is inclusive and exact (ASCII payload, default JSON separators)."""
    overhead = len(json.dumps({"blob": ""}).encode("utf-8"))
    at_limit = {"blob": "x" * (MAX_DETAILS_BYTES - overhead)}
    assert len(json.dumps(at_limit).encode("utf-8")) == MAX_DETAILS_BYTES
    event_id = await _write(migrated_engine, details=at_limit)
    assert await _details(migrated_engine, event_id) == at_limit

    with pytest.raises(AuditError, match="exceed"):
        await _write(migrated_engine, details={"blob": "x" * (MAX_DETAILS_BYTES - overhead + 1)})
    assert len(await _rows(migrated_engine)) == 1


class _Colour(Enum):
    RED = "red"


async def test_rich_python_values_are_stored_as_plain_json(migrated_engine: AsyncEngine) -> None:
    """LOCK-IN: datetimes, sets, bytes, Decimal, UUID, paths, enums and big ints become JSON."""
    details = {
        "aware": datetime(2026, 10, 10, 1, 2, 3, tzinfo=UTC),
        "naive": datetime(2026, 10, 10, 1, 2, 3),  # noqa: DTZ001 - deliberately naive input
        "day": date(2026, 10, 10),
        "clock": clock_time(1, 2, 3),
        "tags": {"b", "a"},
        "frozen": frozenset({3}),
        "pair": (1, "two"),
        "utf8_bytes": b"caf\xc3\xa9",
        "invalid_bytes": b"\xff\xfe",
        "amount": Decimal("1.10"),
        "not_a_number": Decimal("NaN"),
        "id": uuid.UUID("12345678-1234-5678-1234-567812345678"),
        "path": PurePosixPath("/var/log/squid/access.log"),
        "colour": _Colour.RED,
        "big": 10**30,
        "nothing": None,
        "flag": True,
        "ratio": 0.25,
    }
    stored = await _details(migrated_engine, await _write(migrated_engine, details=details))
    assert sorted(stored.pop("tags")) == ["a", "b"]
    assert stored == {
        "aware": "2026-10-10T01:02:03+00:00",
        "naive": "2026-10-10T01:02:03",
        "day": "2026-10-10",
        "clock": "01:02:03",
        "frozen": [3],
        "pair": [1, "two"],
        "utf8_bytes": "café",
        "invalid_bytes": "\ufffd\ufffd",
        "amount": "1.10",
        "not_a_number": "NaN",
        "id": "12345678-1234-5678-1234-567812345678",
        "path": "/var/log/squid/access.log",
        "colour": "red",
        "big": 10**30,
        "nothing": None,
        "flag": True,
        "ratio": 0.25,
    }


@pytest.mark.parametrize("bad", [float("inf"), float("-inf")], ids=["inf", "-inf"])
async def test_non_finite_floats_are_rejected_before_the_database(
    migrated_engine: AsyncEngine, bad: float
) -> None:
    """LOCK-IN: JSON has no infinity; the event is refused and nothing is written."""
    with pytest.raises(AuditError, match="JSON"):
        await _write(migrated_engine, details={"nested": [{"x": bad}]})
    assert await _rows(migrated_engine) == []


async def test_pathologically_deep_details_are_truncated_without_crashing_or_leaking(
    migrated_engine: AsyncEngine,
) -> None:
    """LOCK-IN: 5,000 levels of nesting are cut at the redaction depth cap; a secret buried below
    the cap is not stored."""
    deep: dict[str, Any] = {"password": "hunter2-deep", "note": "buried"}
    for _ in range(5_000):
        deep = {"n": deep}
    event_id = await _write(migrated_engine, details={"root": deep})
    async with migrated_engine.connect() as conn:
        raw = (
            await conn.execute(
                text("SELECT details::text FROM audit_events WHERE id = :i"), {"i": event_id}
            )
        ).scalar_one()
    assert "<max-depth>" in raw
    assert "hunter2-deep" not in raw


async def test_non_string_detail_keys_become_json_strings(migrated_engine: AsyncEngine) -> None:
    """LOCK-IN: int/float/bool/None keys are stringified the JSON way; unrepresentable keys are an
    AuditError with nothing written."""
    event_id = await _write(
        migrated_engine, details={7: "int", 2.5: "float", False: "bool", None: "none"}
    )
    assert await _details(migrated_engine, event_id) == {
        "7": "int",
        "2.5": "float",
        "false": "bool",
        "null": "none",
    }
    with pytest.raises(AuditError, match="JSON"):
        await _write(migrated_engine, details={("tuple", "key"): 1})
    assert len(await _rows(migrated_engine)) == 1


async def test_returned_event_has_server_defaults_loaded(migrated_engine: AsyncEngine) -> None:
    """LOCK-IN: the AuditEvent returned by record_audit is fully usable after the session closes
    (server defaults come back via RETURNING; no lazy load in async code)."""
    async with session_factory(migrated_engine)() as session, session.begin():
        audit = await record_audit(session, actor="adv", action="adv.defaults")
    assert audit.id > 0
    assert audit.occurred_at.utcoffset() == timedelta(0)
    assert audit.outcome == "success"
    assert audit.details == {}


# =========================================================================== engine and pool


async def test_session_settings_do_not_leak_between_pool_checkouts(
    db_settings: DatabaseSettings, test_database: str
) -> None:
    """DEFECT: the pool's reset-on-return is only ROLLBACK, so a committed session-level ``SET``
    (``SET statement_timeout = 0``, ``SET TimeZone``, or ``session_replication_role``) survives
    into the next, unrelated checkout for the connection's whole life (up to 30 min). The
    "conservative timeouts, UTC" guarantee of ``create_engine`` then silently stops holding. Fix:
    ``RESET ALL`` on checkin/reset (restores the startup ``-c`` options)."""
    engine = create_engine(
        db_settings.model_copy(update={"pool_size": 1, "max_overflow": 0}), database=test_database
    )
    try:
        baseline = await _show(engine, *_SESSION_GUC)
        async with engine.begin() as conn:
            first_pid = (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one()
            await conn.execute(text("SET statement_timeout = 0"))
            await conn.execute(text("SET lock_timeout = 0"))
            await conn.execute(text("SET idle_in_transaction_session_timeout = 0"))
            await conn.execute(text("SET TimeZone = 'Asia/Kolkata'"))
        async with engine.connect() as conn:
            second_pid = (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        assert second_pid == first_pid  # precondition: the same pooled connection came back
        assert await _show(engine, *_SESSION_GUC) == baseline
    finally:
        await engine.dispose()


async def test_uncommitted_session_settings_are_undone_by_the_pool_reset(
    db_settings: DatabaseSettings, test_database: str
) -> None:
    """LOCK-IN: a ``SET`` inside a transaction that is rolled back (the pool's reset) does not
    leak."""
    engine = create_engine(
        db_settings.model_copy(update={"pool_size": 1, "max_overflow": 0}), database=test_database
    )
    try:
        baseline = await _show(engine, *_SESSION_GUC)
        async with engine.connect() as conn:
            await conn.execute(text("SET statement_timeout = 0"))
            await conn.execute(text("SET TimeZone = 'Asia/Kolkata'"))
            # no commit: returning the connection rolls the transaction back
        assert await _show(engine, *_SESSION_GUC) == baseline
    finally:
        await engine.dispose()


@pytest.mark.timeout(30)
async def test_exhausted_pool_hands_over_a_connection_as_soon_as_one_is_returned(
    db_settings: DatabaseSettings, test_database: str
) -> None:
    """LOCK-IN: with the pool exhausted a caller waits (without blocking the event loop) and gets
    the returned connection immediately."""
    engine = create_engine(
        db_settings.model_copy(update={"pool_size": 1, "max_overflow": 0}), database=test_database
    )

    async def answer() -> int:
        async with engine.connect() as conn:
            return int((await conn.execute(text("SELECT 41 + 1"))).scalar_one())

    try:
        held = await engine.connect()
        try:
            waiter = asyncio.ensure_future(answer())
            await asyncio.sleep(0.3)
            assert not waiter.done()  # precondition: the pool really was exhausted
        finally:
            await held.close()
        assert await asyncio.wait_for(waiter, timeout=3) == 42
    finally:
        await engine.dispose()


@pytest.mark.timeout(30)
async def test_pooled_connections_terminated_by_the_server_are_replaced_transparently(
    db_settings: DatabaseSettings, test_database: str
) -> None:
    """LOCK-IN: after pg_terminate_backend (a DB restart, an admin kill) the next checkout gets a
    fresh connection via pre-ping, with UTC and the timeouts applied again."""
    engine = create_engine(db_settings, database=test_database)
    try:
        baseline = await _show(engine, *_SESSION_GUC)
        async with engine.connect() as conn:
            old_pid = (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        assert _terminate_argus_backends(db_settings, test_database) == {old_pid}
        async with engine.connect() as conn:
            new_pid = (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        assert new_pid != old_pid
        assert await _show(engine, *_SESSION_GUC) == baseline
    finally:
        await engine.dispose()


@pytest.mark.timeout(30)
async def test_connection_killed_mid_transaction_loses_only_that_transaction(
    migrated_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    """LOCK-IN: killing the backend mid-transaction fails that unit of work (nothing half-written)
    and the very next unit of work on the same engine succeeds."""
    with pytest.raises(DBAPIError):  # noqa: PT012 - the kill has to happen mid-transaction
        async with session_factory(migrated_engine)() as session, session.begin():
            await record_audit(session, actor="adv", action="adv.doomed")
            pid = (await session.execute(text("SELECT pg_backend_pid()"))).scalar_one()
            assert _terminate_argus_backends(db_settings, test_database, pid=pid) == {pid}
            await session.execute(text("SELECT 1"))
    await _write(migrated_engine, action="adv.after-kill")
    assert await _actions(migrated_engine) == ["adv.after-kill"]


async def test_connection_is_reusable_after_a_statement_timeout(
    db_settings: DatabaseSettings, test_database: str
) -> None:
    """LOCK-IN: a statement timeout aborts only the statement; the pooled connection is healthy."""
    engine = create_engine(
        _fast(db_settings).model_copy(update={"pool_size": 1, "max_overflow": 0}),
        database=test_database,
    )
    try:
        with pytest.raises(DBAPIError, match="statement timeout"):
            async with engine.connect() as conn:
                await conn.execute(text("SELECT pg_sleep(3)"))
        async with engine.connect() as conn:
            assert (await conn.execute(text("SELECT 41 + 1"))).scalar_one() == 42
        assert (await _show(engine, "statement_timeout"))["statement_timeout"] == "1s"
    finally:
        await engine.dispose()


def test_empty_database_override_is_rejected_not_redirected_to_the_configured_database(
    db_settings: DatabaseSettings,
) -> None:
    """DEFECT: ``create_engine(settings, database="")`` falls back to ``settings.name`` (the
    developer's real database) because ``url()`` uses ``database or self.name``. Even a bare ``""``
    in the URL would make libpq connect to the database named after the user, the same real
    database. A blank override (e.g. an unset env var) must be an error. No connection is made."""
    try:
        engine = create_engine(db_settings, database="")
    except (ConfigError, ValueError):
        return
    target = engine.url.database
    engine.sync_engine.dispose()  # never connected
    pytest.fail(f"database='' was accepted and resolved to {target!r}, not a throwaway database")
