"""Programmatic migrations (used by the CLI, ``doctor`` and tests).

Every migration runs in one transaction that first takes a PostgreSQL advisory lock, so concurrent
runners go one after the other and the later one finds the database already at its target:

* A runner in another process (a second ``argus db upgrade``, or plain ``alembic``) waits for the
  advisory lock for at most the engine's ``lock_timeout``, then fails.
* Another task in this process first queues on an in-process lock, because Alembic keeps its
  ``context``/``op`` proxies in module globals. That wait has no timeout of its own: it lasts until
  the earlier migration commits or rolls back (each of its statements is bounded by the statement
  and lock timeouts).
* While a migration is in progress, neither the task running it nor a task started meanwhile can
  start another one: it gets RuntimeError at once, because the migration may be waiting for that
  very task, and the two would then wait for each other for ever. Once the migration has ended,
  those tasks may migrate like any other.
"""

from __future__ import annotations

import asyncio
import itertools
import re
import weakref
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Literal

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.environment import NameFilterParentNames, NameFilterType
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util import CommandError
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.db.models import Base

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

Direction = Literal["upgrade", "downgrade"]

# Transaction-level advisory lock taken by every ARGUS migration runner (``argus db``, tests and
# the plain ``alembic`` command) before Alembic reads the version table.
MIGRATION_LOCK_KEY = int.from_bytes(b"ARGUSMIG", "big")

# Alembic keeps its ``context``/``op`` proxies in module globals, so two migrations must not
# interleave inside one process either. Tasks on the same event loop queue here first, without
# holding a database connection (asyncio locks belong to one loop, hence one lock per loop).
_LOOP_LOCKS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
    weakref.WeakKeyDictionary()
)


class _Migration:
    """A migration in progress. A task started during it copies the context, and so this object,
    for the task's whole life: the flag, not the context variable, says whether it has ended."""

    __slots__ = ("in_progress",)

    def __init__(self) -> None:
        self.in_progress = True


# Set by migration_transaction, in the task running it and so in every task started meanwhile.
_MIGRATION: ContextVar[_Migration | None] = ContextVar("argus_migration", default=None)

# A step: from the database's revision (+2, -1) or from a named point (head-1, base+2, 0001+1).
# ASCII digits only (Alembic would also read other Unicode digits); at most 6 of them.
_RELATIVE_REVISION = re.compile(r"(?P<anchor>[A-Za-z0-9_]*)(?P<sign>[+-])(?P<steps>[0-9]{1,6})")
_SYMBOLS = ("head", "heads", "base")
# The only sign Alembic takes, in each direction, for a step from the database's revision: it
# rejects the other one whatever that revision is ("didn't produce 1 migrations").
_STEP_SIGN: dict[Direction, str] = {"upgrade": "+", "downgrade": "-"}


class UnknownRevisionError(CommandError):
    """The target is not a point of this code's migration chain, or is a step the wrong way;
    nothing was touched."""


def alembic_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    return cfg


def head_revision() -> str:
    heads = ScriptDirectory.from_config(alembic_config()).get_heads()
    if len(heads) != 1:
        raise RuntimeError(f"expected exactly one migration head, found {heads}")
    return heads[0]


def revision_chain() -> tuple[str, ...]:
    """This code's revision ids from first to last; RuntimeError unless they form one chain."""
    script = ScriptDirectory.from_config(alembic_config())
    newest_first = list(script.walk_revisions("base", "heads"))
    linked = all(
        newer.down_revision == older.revision for newer, older in itertools.pairwise(newest_first)
    )
    chain = tuple(rev.revision for rev in reversed(newest_first))
    if not chain or not linked or newest_first[-1].down_revision is not None:
        raise RuntimeError(f"migrations must form one linear chain, found {chain}")
    return chain


def resolve_revision(revision: str, *, direction: Direction | None = None) -> str:
    """The target to hand Alembic for ``revision``, checked against this code's chain.

    Accepted: ``head``/``heads``, ``base``, a revision id or a unique prefix of one, a step from
    the database's revision (``+1``, ``-2``; at most the chain's length), and a step from a named
    point (``head-1``, ``base+2``, ``0001+1``). A step from a named point is resolved here, to an
    id or ``base``: Alembic itself fails with a bare AssertionError on such a step when it lands
    on base or walks off the chain. A step from the database's revision is checked by Alembic when
    it runs (a CommandError if it leaves the chain). Given the ``direction``, such a step must also
    go that way: ``+N`` for an upgrade, ``-N`` for a downgrade.

    Anything else raises UnknownRevisionError: a typo, an ambiguous prefix, a step that walks off
    the chain or goes the wrong way, or the ``branch@`` forms (ARGUS's migrations have no branch
    labels).
    """
    chain = revision_chain()
    relative = _RELATIVE_REVISION.fullmatch(revision)
    if relative is None:
        return revision if revision in _SYMBOLS else chain[_index(chain, revision, revision)]
    anchor, sign, steps = relative["anchor"], relative["sign"], int(relative["steps"])
    if not anchor:
        if not 1 <= steps <= len(chain):
            raise UnknownRevisionError(
                f"unknown revision {revision!r}: a step from the database's revision must be 1 to "
                f"{len(chain)} long"
            )
        if direction is not None and sign != _STEP_SIGN[direction]:
            raise UnknownRevisionError(
                f"unknown revision {revision!r}: {direction} takes only {_STEP_SIGN[direction]}N "
                "steps from the database's revision"
            )
        return f"{sign}{steps}"
    if anchor in ("head", "heads"):
        start = len(chain) - 1
    elif anchor == "base":
        start = -1
    else:
        start = _index(chain, anchor, revision)
    position = start + steps if sign == "+" else start - steps
    if not -1 <= position < len(chain):
        raise UnknownRevisionError(
            f"unknown revision {revision!r}: the step walks off the migration chain "
            f"(base, {', '.join(chain)})"
        )
    return "base" if position == -1 else chain[position]


def _index(chain: Sequence[str], name: str, revision: str) -> int:
    """Position of the id ``name`` (or the one id it is a prefix of, as Alembic allows)."""
    if name in chain:
        return chain.index(name)
    matches = [i for i, rev in enumerate(chain) if name and rev.startswith(name)]
    if len(matches) != 1:
        raise UnknownRevisionError(
            f"unknown revision {revision!r} (use a revision id, head, base, or a step such as +1, "
            "-1 or head-1)"
        )
    return matches[0]


def is_argus_table(
    name: str | None, type_: NameFilterType, parent_names: NameFilterParentNames
) -> bool:
    """Alembic ``include_name`` hook: compare only the tables ARGUS's models declare.

    Other tables share this database (LangGraph's checkpoint tables, D-009). They are not drift,
    and autogenerate must never emit DROP TABLE for them. The flip side: a table that ARGUS
    drops from its models must be dropped by a hand-written migration.
    """
    if type_ != "table":
        return True
    schema = parent_names.get("schema_name")
    return (f"{schema}.{name}" if schema else name) in Base.metadata.tables


def _process_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _LOOP_LOCKS.get(loop)
    if lock is None:
        lock = _LOOP_LOCKS[loop] = asyncio.Lock()
    return lock


async def lock_migrations(conn: AsyncConnection) -> None:
    """Take the migration lock for the rest of ``conn``'s transaction (waits up to lock_timeout)."""
    await conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_KEY})


@asynccontextmanager
async def migration_transaction(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    """One transaction holding the migration lock; commits on success, rolls back on any error.

    Whatever else runs on the yielded connection (e.g. the CLI's audit record) commits or rolls
    back together with the migration. Entering it again while that migration is in progress, from
    the same task or a task started meanwhile, raises RuntimeError instead of waiting for itself.
    """
    outer = _MIGRATION.get()
    if outer is not None and outer.in_progress:
        raise RuntimeError(
            "a migration is already in progress in this task (or in the task that started it)"
        )
    migration = _Migration()
    token = _MIGRATION.set(migration)
    try:
        async with _process_lock(), engine.begin() as conn:
            await lock_migrations(conn)
            yield conn
    finally:
        migration.in_progress = False
        _MIGRATION.reset(token)


def _run_command(connection: Connection, name: Direction, revision: str) -> None:
    cfg = alembic_config()
    cfg.attributes["connection"] = connection
    target = resolve_revision(revision, direction=name)
    try:
        getattr(command, name)(cfg, target)
    except AssertionError as exc:
        # Backstop: Alembic's revision map asserts, rather than raising RevisionError, on targets
        # it cannot resolve. resolve_revision() keeps every such target known today away from it.
        if _raised_in(exc, "alembic.script.revision"):
            raise CommandError(f"cannot resolve revision {revision!r}") from exc
        raise


def _raised_in(exc: BaseException, module: str) -> bool:
    """True if the innermost frame of ``exc``'s traceback is code in ``module``."""
    tb = exc.__traceback__
    while tb is not None and tb.tb_next is not None:
        tb = tb.tb_next
    return tb is not None and tb.tb_frame.f_globals.get("__name__") == module


async def run(conn: AsyncConnection, direction: Direction, revision: str) -> None:
    """Migrate inside ``conn``'s transaction (use :func:`migration_transaction` to get one)."""
    await conn.run_sync(_run_command, direction, revision)


async def upgrade(engine: AsyncEngine, revision: str = "head") -> None:
    async with migration_transaction(engine) as conn:
        await run(conn, "upgrade", revision)


async def downgrade(engine: AsyncEngine, revision: str) -> None:
    async with migration_transaction(engine) as conn:
        await run(conn, "downgrade", revision)


def _current_revision(sync_conn: Connection) -> str | None:
    return MigrationContext.configure(sync_conn).get_current_revision()


async def current_revision(bind: AsyncEngine | AsyncConnection) -> str | None:
    """The database's revision (None if empty); on a connection, as its transaction sees it."""
    if isinstance(bind, AsyncConnection):
        return await bind.run_sync(_current_revision)
    async with bind.connect() as conn:
        return await conn.run_sync(_current_revision)


async def schema_drift(engine: AsyncEngine) -> list[Any]:
    """Differences between the ORM models and the live schema (empty list = in sync)."""

    def _compare(sync_conn: Connection) -> list[Any]:
        context = MigrationContext.configure(
            sync_conn, opts={"compare_type": True, "include_name": is_argus_table}
        )
        return list(compare_metadata(context, Base.metadata))

    async with engine.connect() as conn:
        return await conn.run_sync(_compare)


# Triggers that make tables append-only, and the function they must call. Autogenerate cannot see
# triggers, so they are checked explicitly (doctor + tests).
GUARD_TRIGGERS: dict[str, tuple[str, ...]] = {
    "audit_events": ("audit_events_append_only_rows", "audit_events_append_only_truncate"),
    # 0026 (Q-C1): the case record's append-only tables (their TRUNCATE guard below); outbox
    # rows are never deleted.
    **{
        table: (f"{table}_append_only_rows",)
        for table in (
            "case_events",
            "case_notes",
            "entity_notes",
            "case_openings",
            "approval_requests",
            "approval_decisions",
            "action_ledger",
            "case_notices",  # 0050 (AR4b, D-181)
            "incident_reports",  # 0052 (AR7, D-190): a report version is never changed
            "incident_report_decisions",  # 0052: what a person decided is a record
            "case_team_approvals",  # 0053 (AR8): a signed approval is a record
            "case_team_seen",  # 0053: a verdict comment, read once, and what ARGUS did with it
        )
    },
    "kibana_outbox": ("kibana_outbox_no_delete",),
}
_CASE_APPEND_ONLY = (
    "case_events",
    "case_notes",
    "entity_notes",
    "case_openings",
    "approval_requests",
    "approval_decisions",
    "action_ledger",
    "case_notices",  # 0050 (AR4b): what a person told the owner, and the blocks they recorded
    "incident_reports",  # 0052 (AR7): the versions of a case's incident report
    "incident_report_decisions",  # 0052 (AR7): a person's confirm or reject of a version
    "case_team_approvals",  # 0053 (AR8): a person's approval of a first sequence (canary)
    "case_team_seen",  # 0053 (AR8): the verdict comments read, and what was done with them
)
GUARD_FUNCTION = "argus_reject_mutation"
# 0026 (Q-C1): the other triggers ARGUS's guarantees rest on, each with the function it calls:
# the hash chains, the case lifecycle guard and its commit-time checks, the outbox guard.
CHECK_TRIGGERS: dict[tuple[str, str], str] = {
    ("audit_events", "audit_events_chain"): "argus_chain_append",
    ("audit_events", "audit_events_chain_head"): "argus_chain_flush",
    ("case_events", "case_events_chain"): "argus_chain_append",
    ("case_events", "case_events_chain_head"): "argus_chain_flush",
    ("cases", "cases_guard"): "argus_case_guard",
    ("cases", "cases_have_events"): "argus_case_has_event",
    ("case_events", "case_events_follow_case"): "argus_case_event_follows",
    # 0036 (Q-E2's review): the web's login changes only the identity lane's state rows
    ("siem_state", "siem_state_web_rows"): "argus_web_state_rows",
    ("case_events", "case_events_have_outbox"): "argus_case_event_outbox",
    ("kibana_outbox", "kibana_outbox_guard"): "argus_outbox_guard",
    # 0042 (Q-B3 review): the web's login records a case only as the person who acted
    ("case_events", "case_events_web_writes"): "argus_web_case_writes",
    ("case_members", "case_members_web_writes"): "argus_web_case_writes",
    ("case_indicators", "case_indicators_web_writes"): "argus_web_case_writes",
    ("kibana_outbox", "kibana_outbox_web_writes"): "argus_web_case_writes",
    ("kibana_outbox", "kibana_outbox_no_truncate"): "argus_reject_truncate_unless_empty",
    # 0033 (Q-F1): a log source's watermark only advances
    ("freshness_watermarks", "freshness_watermarks_advance"): "argus_watermark_advance",
    # 0041 (Q-C2): a watch answer that was decided (anything but "not checked") is never replaced
    ("case_watch_checks", "case_watch_checks_decided_once"): "argus_watch_check_guard",
    # 0044 (Q-H2): a case action moves along its edges only; the web's login is a person's hands
    ("case_actions", "case_actions_guard"): "argus_case_action_guard",
    # 0035 (Q-D3's review): a mirror is pointed at another Kibana case only after the deletion
    ("kibana_mirror", "kibana_mirror_repoint_after_deletion"): (
        "argus_mirror_repoint_after_deletion"
    ),
    **{
        (table, f"{table}_append_only_truncate"): "argus_reject_truncate_unless_empty"
        for table in _CASE_APPEND_ONLY
    },
}


# 0027 (Q-A5): services may stop a kill switch, only the owner resumes one; each trigger and
# the function it must call.
RESUME_TRIGGERS: dict[tuple[str, str], str] = {
    ("siem_switches", "siem_switches_resume_needs_owner"): "argus_resume_needs_owner",
    ("llm_state", "llm_state_resume_needs_owner"): "argus_resume_needs_owner",
    # 0029 (Q-D2): the same rule for Kibana's stop and its paused write classes
    ("siem_state", "siem_state_kibana_resume_needs_owner"): "argus_kibana_resume_needs_owner",
    # 0034 (Q-D3): a paused Kibana case (a person changed ARGUS's tags or its settings)
    ("kibana_mirror", "kibana_mirror_resume_needs_owner"): "argus_mirror_resume_needs_owner",
}


async def missing_resume_triggers(engine: AsyncEngine) -> list[str]:
    """The resume guards (migration 0027) that would not fire in every session: missing,
    disabled, not ENABLE ALWAYS, or calling another function."""
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT c.relname, t.tgname, p.proname FROM pg_trigger t "
                "JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid "
                "WHERE NOT t.tgisinternal AND t.tgenabled = 'A'"
            )
        )
        present = {(r[0], r[1]): r[2] for r in rows}
    return sorted(
        f"{table}.{name}"
        for (table, name), function in RESUME_TRIGGERS.items()
        if present.get((table, name)) != function
    )


async def missing_guard_triggers(engine: AsyncEngine) -> list[str]:
    """Guard triggers that would not fire in every session: missing, disabled, replica-only or
    origin-only (``tgenabled`` must be 'A', ENABLE ALWAYS, so ``session_replication_role =
    replica`` cannot skip them), or calling a function other than their own (the append-only
    guard, or the one CHECK_TRIGGERS names)."""
    expected = {
        (table, name, GUARD_FUNCTION) for table, names in GUARD_TRIGGERS.items() for name in names
    } | {(table, name, function) for (table, name), function in CHECK_TRIGGERS.items()}
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT c.relname, t.tgname, p.proname FROM pg_trigger t "
                "JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE NOT t.tgisinternal AND t.tgenabled = 'A' AND n.nspname = 'public'"
            )
        )
        present = {(r[0], r[1], r[2]) for r in rows}
    return sorted(f"{table}.{name}" for table, name, _ in expected - present)
