"""Backups of ARGUS's database (Q-A2): a nightly dump, a weekly restore drill, a dump before
every migration (``argus db upgrade`` and ``downgrade``), all local: nothing reaches the SIEM.

A dump and its fingerprints come from one snapshot. A REPEATABLE READ transaction exports its
snapshot, fingerprints every table in it (a row count and an order-free hash of the rows), every
sequence and the schema (columns, constraints, indexes, triggers with their enabled state,
functions, privileges), and pg_dump reads that same snapshot (``--snapshot``). So the services
keep running, and the fingerprints describe exactly what the dump holds. The drill restores a
dump into a scratch database, fingerprints it the same way and compares: identical, or the
tables that differ.

Dumps hold production data (raw alerts, sessions' hashes): they stay under ``backup.dir`` as
mode 0600 files in mode 0700 folders, never committed (``data/`` is gitignored). Each dump has a
manifest next to it (its fingerprints, size, SHA-256, revision); drills are appended to
``drills.jsonl``. A file lock lets one dump or drill run at a time.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.config.settings import BackupSettings, DatabaseSettings, Settings
from argus.db.engine import create_engine
from argus.observability.redaction import redact_text
from argus.ops.units import REPO

Kind = Literal["nightly", "migration", "manual"]
KINDS: tuple[Kind, ...] = ("nightly", "migration", "manual")
FORMAT = 1
DUMP_SUFFIX = ".dump"
MANIFEST_SUFFIX = ".json"
DRILLS = "drills.jsonl"
SCRATCH_PREFIX = "argus_restore_"
# argus_restore_<UTC seconds>_<8 hex>: a drill's scratch database; nothing else is dropped
SCRATCH_PATTERN = re.compile(rf"{SCRATCH_PREFIX}(?P<at>[0-9]{{10}})_[0-9a-f]{{8}}")
STALE_SCRATCH = timedelta(hours=6)
NIGHTLY_STALE = timedelta(hours=26)  # a nightly dump is overdue after a day and two hours
DRILL_STALE = timedelta(days=8)  # a weekly drill, after eight days
TOOL_TIMEOUT = timedelta(hours=2)
LOCK_WAIT = timedelta(minutes=30)
_STDERR_KEPT = 4000
# Session settings that make a row's text form the same on every server and session, so the
# fingerprints of the same rows are equal (the engine already sets TimeZone=UTC).
_DETERMINISTIC = (
    "SET LOCAL TimeZone = 'UTC'",
    "SET LOCAL DateStyle = 'ISO, YMD'",
    "SET LOCAL IntervalStyle = 'postgres'",
    "SET LOCAL extra_float_digits = 1",
    "SET LOCAL bytea_output = 'hex'",
    "SET LOCAL statement_timeout = '30min'",
    "SET LOCAL idle_in_transaction_session_timeout = 0",
)
_SCHEMAS = "n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_%'"


class BackupError(Exception):
    """A dump or a drill did not complete; the message says why (no secret, no row)."""


# --------------------------------------------------------------------------- fingerprints


@dataclass(frozen=True)
class Fingerprints:
    tables: dict[str, tuple[int, str]]  # schema.table: (rows, md5 of the sorted row md5s)
    sequences: dict[str, tuple[int, bool]]  # schema.sequence: (last_value, is_called)
    schema: dict[str, str]  # part: md5 of its catalog description

    def as_json(self) -> dict[str, Any]:
        return {
            "tables": {k: list(v) for k, v in sorted(self.tables.items())},
            "sequences": {k: list(v) for k, v in sorted(self.sequences.items())},
            "schema": dict(sorted(self.schema.items())),
        }

    @staticmethod
    def from_json(data: Mapping[str, Any]) -> Fingerprints:
        return Fingerprints(
            tables={str(k): (int(v[0]), str(v[1])) for k, v in data["tables"].items()},
            sequences={str(k): (int(v[0]), bool(v[1])) for k, v in data["sequences"].items()},
            schema={str(k): str(v) for k, v in data["schema"].items()},
        )


def differences(expected: Fingerprints, got: Fingerprints) -> list[str]:
    """What differs between two fingerprints, one line each (names and counts, never rows).

    Sequences are compared by name only: they are not transactional, so a dump's snapshot does
    not hold their values (concurrent inserts move them on between the fingerprints and
    pg_dump's read). Whether a restored sequence can collide is :func:`sequence_problems`."""
    out: list[str] = []
    for part, kind in (("tables", "table"), ("sequences", "sequence"), ("schema", "schema")):
        want: Mapping[str, Any] = getattr(expected, part)
        have: Mapping[str, Any] = getattr(got, part)
        for name in sorted(set(want) | set(have)):
            if name not in have:
                out.append(f"{kind} {name}: missing from the restore")
            elif name not in want:
                out.append(f"{kind} {name}: only in the restore")
            elif kind != "sequence" and want[name] != have[name]:
                if kind == "table" and want[name][0] != have[name][0]:
                    dumped, restored = want[name][0], have[name][0]
                    out.append(f"table {name}: {dumped} rows dumped, {restored} restored")
                else:
                    out.append(f"{kind} {name}: differs")
    return out


# Every sequence a column owns (serial: 'a'uto, identity: 'i'nternal) and that column.
_OWNED_SEQUENCES = (
    "SELECT format('%I.%I', sn.nspname, s.relname), format('%I.%I', tn.nspname, t.relname),"
    " format('%I', a.attname), sn.nspname || '.' || s.relname"
    " FROM pg_depend d JOIN pg_class s ON s.oid = d.objid AND s.relkind = 'S'"
    " JOIN pg_namespace sn ON sn.oid = s.relnamespace"
    " JOIN pg_class t ON t.oid = d.refobjid JOIN pg_namespace tn ON tn.oid = t.relnamespace"
    " JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid"
    " WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass"
    " AND d.deptype IN ('a', 'i') ORDER BY 4"
)


async def sequence_problems(conn: AsyncConnection) -> list[str]:
    """The sequences that would hand out a value their column holds already: in a restore,
    the first insert would fail (or worse, for a column without a unique index)."""
    problems = []
    for seq, table, column, name in (await conn.execute(text(_OWNED_SEQUENCES))).all():
        last, called = (
            await conn.execute(text(f"SELECT last_value, is_called FROM {seq}"))  # noqa: S608 - server-quoted
        ).one()
        highest = (
            await conn.execute(text(f"SELECT max({column}) FROM {table}"))  # noqa: S608 - server-quoted
        ).scalar_one()
        if highest is not None and (highest > last or (highest == last and not called)):
            problems.append(f"sequence {name}: behind its column (next {last}, highest {highest})")
    return problems


_RELATIONS = (
    "SELECT n.nspname, c.relname, c.relkind FROM pg_class c"
    " JOIN pg_namespace n ON n.oid = c.relnamespace"
    " WHERE <schemas> AND c.relkind IN ('r', 'p', 'S') ORDER BY 1, 2"
).replace("<schemas>", _SCHEMAS)
_COUNT = "SELECT count(*), md5(coalesce(string_agg(h, '' ORDER BY h), ''))"
_ROW_HASHES = "SELECT md5(t::text) AS h FROM"
_DESCRIBED = "SELECT md5(coalesce(string_agg(r::text, '|' ORDER BY r::text), ''))"
_SCHEMA_QUERIES = {
    "columns": """
        SELECT n.nspname, c.relname, a.attnum, a.attname, format_type(a.atttypid, a.atttypmod),
               a.attnotnull, a.attidentity, a.attgenerated,
               coalesce(pg_get_expr(d.adbin, d.adrelid), '')
        FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
        WHERE <schemas> AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.attnum > 0
          AND NOT a.attisdropped""",
    "constraints": """
        SELECT n.nspname, c.relname, k.conname, pg_get_constraintdef(k.oid)
        FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace WHERE <schemas>""",
    "indexes": """
        SELECT n.nspname, i.relname, pg_get_indexdef(i.oid)
        FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid
        JOIN pg_namespace n ON n.oid = i.relnamespace WHERE <schemas>""",
    "triggers": """
        SELECT n.nspname, c.relname, t.tgname, t.tgenabled, pg_get_triggerdef(t.oid)
        FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace WHERE <schemas> AND NOT t.tgisinternal""",
    "functions": """
        SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid),
               pg_get_functiondef(p.oid), coalesce(p.proacl::text, '')
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE <schemas> AND p.prokind IN ('f', 'p')""",
    "privileges": """
        SELECT n.nspname, c.relname, coalesce(c.relacl::text, ''),
               coalesce((SELECT string_agg(a.attname || '=' || a.attacl::text, ','
                                           ORDER BY a.attname)
                         FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attacl IS NOT NULL),
                        '')
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE <schemas> AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')""",
    "schemas": """
        SELECT n.nspname, coalesce(n.nspacl::text, '') FROM pg_namespace n WHERE <schemas>""",
}
_SCHEMA_PARTS = {
    part: query.replace("<schemas>", _SCHEMAS) for part, query in _SCHEMA_QUERIES.items()
}


async def fingerprints(conn: AsyncConnection) -> Fingerprints:
    """Fingerprints of the database ``conn`` is connected to, in its current transaction (and
    snapshot). Must run as a role that may read every table (the owner)."""
    for statement in _DETERMINISTIC:
        await conn.execute(text(statement))
    rows = await conn.execute(text(_RELATIONS))
    tables: dict[str, tuple[int, str]] = {}
    sequences: dict[str, tuple[int, bool]] = {}
    for schema, name, kind in rows.all():
        qualified = await _quoted(conn, schema, name)
        key = f"{schema}.{name}"
        if kind == "S":
            query = f"SELECT last_value, is_called FROM {qualified}"  # noqa: S608 - server-quoted
            last, called = (await conn.execute(text(query))).one()
            sequences[key] = (int(last), bool(called))
        else:
            query = f"{_COUNT} FROM ({_ROW_HASHES} {qualified} t) s"
            count, digest = (await conn.execute(text(query))).one()
            tables[key] = (int(count), str(digest))
    schema_parts: dict[str, str] = {}
    for part, query in _SCHEMA_PARTS.items():
        described = await conn.execute(text(f"{_DESCRIBED} FROM ({query}) r"))
        schema_parts[part] = str(described.scalar_one())
    return Fingerprints(tables, sequences, schema_parts)


async def _quoted(conn: AsyncConnection, schema: str, name: str) -> str:
    """``schema.name`` quoted by the server (format %I), whatever characters the names hold."""
    quoted = await conn.execute(
        text("SELECT format('%I.%I', CAST(:s AS text), CAST(:n AS text))"),
        {"s": schema, "n": name},
    )
    return str(quoted.scalar_one())


# --------------------------------------------------------------------------- tools


@dataclass(frozen=True)
class Tools:
    """How pg_dump and pg_restore run (``backup.tools``): in the db container over its local
    socket (``compose``), or in a throwaway container of the pinned image on the host's network,
    with the owner's password in the environment (``image``)."""

    backup: BackupSettings
    database: DatabaseSettings
    compose_file: Path = REPO / "docker-compose.yml"

    def _prefix(self) -> list[str]:
        if self.backup.tools == "compose":
            return ["docker", "compose", "-f", str(self.compose_file), "exec", "-T", "db"]
        return ["docker", "run", "--rm", "-i", "--network", "host", "-e", "PGPASSWORD",
                self.backup.image]  # fmt: skip

    def _connection(self, database: str) -> list[str]:
        owner = ["-U", self.database.owner_user, "-d", database]
        if self.backup.tools == "compose":
            return owner
        return ["-h", self.database.host, "-p", str(self.database.port), *owner]

    def dump(self, database: str, snapshot: str) -> list[str]:
        return [*self._prefix(), "pg_dump", *self._connection(database), "--format=custom",
                f"--snapshot={snapshot}", "--no-password"]  # fmt: skip

    def restore(self, database: str) -> list[str]:
        return [*self._prefix(), "pg_restore", *self._connection(database), "--no-owner",
                "--exit-on-error", "--no-password"]  # fmt: skip

    def version(self) -> list[str]:
        return [*self._prefix(), "pg_dump", "--version"]

    def environment(self) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("PG")}
        env.setdefault("DOCKER_CONTEXT", "default")
        if self.backup.tools == "image":
            password = self.database.owner_password
            if password is None or not password.get_secret_value():
                raise BackupError(
                    "backup.tools is image, which needs the owner's password:"
                    " put ARGUS_DATABASE__OWNER_PASSWORD in .env"
                )
            env["PGPASSWORD"] = password.get_secret_value()
        return env


async def _run_tool(
    command: Sequence[str],
    env: Mapping[str, str],
    *,
    stdin: Path | None = None,
    stdout: Path | None = None,
    what: str,
) -> None:
    """Run a pg tool: its input from ``stdin``, its output to ``stdout``; BackupError naming
    ``what`` and the tool's last words (redacted) unless it exits 0 within TOOL_TIMEOUT."""
    with contextlib.ExitStack() as files:
        source = files.enter_context(stdin.open("rb")) if stdin is not None else None
        sink = files.enter_context(_private(stdout)) if stdout is not None else None
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=source if source is not None else asyncio.subprocess.DEVNULL,
                stdout=sink if sink is not None else asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                env=dict(env),
            )
        except OSError as exc:
            raise BackupError(f"{what}: cannot start {command[0]} ({exc.strerror})") from None
        try:
            async with asyncio.timeout(TOOL_TIMEOUT.total_seconds()):
                _, err = await process.communicate()
        except TimeoutError:
            process.kill()
            await process.wait()
            raise BackupError(f"{what}: gave up after {TOOL_TIMEOUT}") from None
    if process.returncode != 0:
        said = redact_text(err.decode("utf-8", "replace")[-_STDERR_KEPT:]).strip()
        raise BackupError(f"{what} failed (exit {process.returncode}): {said or 'no message'}")


@contextlib.contextmanager
def _private(path: Path) -> Iterator[Any]:
    """A new file only its owner may read (mode 0600), never one that exists already."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        yield handle


# --------------------------------------------------------------------------- files


@dataclass
class Manifest:
    kind: Kind
    database: str
    created_at: datetime
    file: str  # the dump's file name, in its kind's folder
    bytes: int
    sha256: str
    revision: str | None
    server_version: str
    took_s: float
    fingerprints: Fingerprints
    verified: dict[str, Any] | None = None  # the passing drill that restored it
    path: Path = field(default=Path(), compare=False)

    def as_json(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "kind": self.kind,
            "database": self.database,
            "created_at": self.created_at.isoformat(),
            "file": self.file,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "revision": self.revision,
            "server_version": self.server_version,
            "took_s": self.took_s,
            "fingerprints": self.fingerprints.as_json(),
            "verified": self.verified,
        }

    @property
    def dump_path(self) -> Path:
        return self.path.with_name(self.file)


def read_manifest(path: Path) -> Manifest:
    """A dump's manifest; BackupError if it cannot be read or is not one."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("format") != FORMAT or data.get("kind") not in KINDS:
            raise ValueError("not a manifest")
        file = str(data["file"])
        if Path(file).name != file or not file.endswith(DUMP_SUFFIX):
            raise ValueError("a dump file name with a folder in it")
        return Manifest(
            kind=data["kind"],
            database=str(data["database"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            file=file,
            bytes=int(data["bytes"]),
            sha256=str(data["sha256"]),
            revision=None if data["revision"] is None else str(data["revision"]),
            server_version=str(data["server_version"]),
            took_s=float(data["took_s"]),
            fingerprints=Fingerprints.from_json(data["fingerprints"]),
            verified=data.get("verified"),
            path=path,
        )
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise BackupError(f"{path.name} is not a readable backup manifest ({exc})") from None


def _write_json(path: Path, data: Mapping[str, Any]) -> None:
    """Replace ``path`` atomically with ``data`` (mode 0600)."""
    partial = path.with_name(f".{path.name}.{secrets.token_hex(4)}.partial")
    with _private(partial) as handle:
        handle.write(json.dumps(data, indent=1, sort_keys=True).encode())
    os.replace(partial, path)


def _folder(base: Path, kind: Kind) -> Path:
    folder = base / kind
    for directory in (base, folder):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    return folder


def manifests(base: Path) -> list[Manifest]:
    """Every readable manifest under ``base``, newest first."""
    found = []
    for kind in KINDS:
        folder = base / kind
        if not folder.is_dir():
            continue
        for path in folder.glob(f"*{MANIFEST_SUFFIX}"):
            with contextlib.suppress(BackupError):
                found.append(read_manifest(path))
    return sorted(found, key=lambda m: m.created_at, reverse=True)


def drills(base: Path) -> list[dict[str, Any]]:
    """The drill records, oldest first (unreadable lines are skipped)."""
    path = base / DRILLS
    if not path.is_file():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        with contextlib.suppress(ValueError):
            record = json.loads(line)
            if isinstance(record, dict):
                records.append(record)
    return records


def _append_drill(base: Path, record: Mapping[str, Any]) -> None:
    path = base / DRILLS
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


@contextlib.asynccontextmanager
async def _locked(base: Path) -> AsyncIterator[None]:
    """One dump or drill at a time (a file lock); BackupError after LOCK_WAIT."""
    descriptor = _lock_file(base)
    try:
        waited = timedelta(0)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if waited >= LOCK_WAIT:
                    raise BackupError(
                        f"another dump or drill has held {base}/.lock for {LOCK_WAIT}"
                    ) from None
                await asyncio.sleep(2)
                waited += timedelta(seconds=2)
        yield
    finally:
        os.close(descriptor)  # releases the lock


def _lock_file(base: Path) -> int:
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return os.open(base / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------- dump


async def dump(settings: Settings, kind: Kind, *, now: datetime | None = None) -> Manifest:
    """Dump ARGUS's database with its fingerprints, from one snapshot; then prune. The engine
    logs in as the owner (it reads every table). Returns the manifest."""
    tools = Tools(settings.backup, settings.database)
    env = tools.environment()  # before anything is written: a missing password stops here
    base = settings.backup.dir
    now = now or datetime.now(UTC)
    stamp = now.strftime("%Y%m%dT%H%M%S%fZ")
    async with _locked(base):
        folder = _folder(base, kind)
        name = f"{_file_safe(settings.database.name)}-{stamp}{DUMP_SUFFIX}"
        target = folder / name
        partial = folder / f".{name}.partial"
        engine = create_engine(settings.database, role="owner")
        started = asyncio.get_running_loop().time()
        try:
            conn = await engine.connect()
            try:
                conn = await conn.execution_options(isolation_level="REPEATABLE READ")
                async with conn.begin():
                    await conn.execute(text("SET TRANSACTION READ ONLY"))
                    snapshot = str(
                        (await conn.execute(text("SELECT pg_export_snapshot()"))).scalar_one()
                    )
                    marks = await fingerprints(conn)
                    revision = await _revision(conn)
                    server = str((await conn.execute(text("SHOW server_version"))).scalar_one())
                    await _run_tool(
                        tools.dump(settings.database.name, snapshot), env, stdout=partial,
                        what="pg_dump",
                    )  # fmt: skip
            finally:
                await conn.close()
        except BaseException:
            partial.unlink(missing_ok=True)
            raise
        finally:
            await engine.dispose()
        os.replace(partial, target)
        manifest = Manifest(
            kind=kind,
            database=settings.database.name,
            created_at=now,
            file=name,
            bytes=target.stat().st_size,
            sha256=_sha256(target),
            revision=revision,
            server_version=server,
            took_s=round(asyncio.get_running_loop().time() - started, 1),
            fingerprints=marks,
            path=target.with_suffix(MANIFEST_SUFFIX),
        )
        _write_json(manifest.path, manifest.as_json())
        prune(base, settings.backup, apply=True)
    return manifest


def _file_safe(name: str) -> str:
    """A database name as part of a file name: no folder, no hidden file, nothing a shell or a
    terminal would read twice."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name).lstrip(".")[:63] or "database"


async def _revision(conn: AsyncConnection) -> str | None:
    exists = await conn.execute(text("SELECT to_regclass('public.alembic_version') IS NOT NULL"))
    if not exists.scalar_one():
        return None
    row = (await conn.execute(text("SELECT version_num FROM alembic_version"))).first()
    return None if row is None else str(row[0])


# --------------------------------------------------------------------------- retention


def kept(
    found: Sequence[Manifest], backup: BackupSettings, now: datetime | None = None
) -> set[Path]:
    """The manifests retention keeps: per kind its newest (``keep_<kind>``), and the newest
    ``keep_verified`` that a drill restored; of those, none older than ``backup.max_age``
    (dumps hold what the retention purge removes, Q-A4), except the newest dump a drill
    restored, or the newest dump while none was: there is always one to restore from."""
    now = datetime.now(UTC) if now is None else now
    keep: set[Path] = set()
    limits = {
        "nightly": backup.keep_nightly,
        "migration": backup.keep_migration,
        "manual": backup.keep_manual,
    }
    newest_first = sorted(found, key=lambda m: m.created_at, reverse=True)
    for kind in KINDS:
        of_kind = [m for m in newest_first if m.kind == kind]
        keep.update(m.path for m in of_kind[: limits[kind]])
    verified = [m for m in newest_first if m.verified]
    keep.update(m.path for m in verified[: backup.keep_verified])
    oldest = now - backup.max_age
    keep = {m.path for m in newest_first if m.path in keep and m.created_at >= oldest}
    anchor = verified or newest_first
    if anchor:
        keep.add(anchor[0].path)
    return keep


def prune(
    base: Path, backup: BackupSettings, *, apply: bool, now: datetime | None = None
) -> list[Path]:
    """The dumps (and manifests) retention would remove, removed with ``apply``. A dump without
    a readable manifest is left alone; a ``.partial`` older than a day is removed."""
    found = manifests(base)
    keep = kept(found, backup, now)
    gone = [m for m in found if m.path not in keep]
    removed: list[Path] = []
    for manifest in gone:
        removed += [manifest.dump_path, manifest.path]
        if apply:
            manifest.dump_path.unlink(missing_ok=True)
            manifest.path.unlink(missing_ok=True)
    cutoff = datetime.now(UTC) - timedelta(days=1)
    for kind in KINDS:
        folder = base / kind
        if not folder.is_dir():
            continue
        for partial in folder.glob(".*.partial"):
            if datetime.fromtimestamp(partial.stat().st_mtime, UTC) < cutoff:
                removed.append(partial)
                if apply:
                    partial.unlink(missing_ok=True)
    return removed


# --------------------------------------------------------------------------- drill


@dataclass(frozen=True)
class DrillResult:
    dump: str  # kind/file
    passed: bool
    differences: tuple[str, ...]
    took_s: float
    at: datetime


async def drill(
    settings: Settings, manifest: Manifest | None = None, *, now: datetime | None = None
) -> DrillResult:
    """Restore a dump (the newest nightly one, else the newest of any kind) into a scratch
    database, compare its fingerprints with the dump's, drop the scratch database, record the
    result (``drills.jsonl``; the manifest is marked verified when it passed)."""
    base = settings.backup.dir
    tools = Tools(settings.backup, settings.database)
    env = tools.environment()
    async with _locked(base):
        if manifest is None:
            found = manifests(base)
            nightly = [m for m in found if m.kind == "nightly"]
            if not (nightly or found):
                raise BackupError(f"no dump to restore in {base}")
            manifest = (nightly or found)[0]
        now = now or datetime.now(UTC)
        started = asyncio.get_running_loop().time()
        label = f"{manifest.kind}/{manifest.file}"
        try:
            if not manifest.dump_path.is_file():
                raise BackupError(f"{label}: the dump file is missing")
            if _sha256(manifest.dump_path) != manifest.sha256:
                problems: list[str] = ["the dump file does not match its recorded SHA-256"]
            else:
                problems = await _restore_and_compare(settings, tools, env, manifest, now)
        except Exception as exc:  # recorded as a failed drill, so doctor never shows an older pass
            why = redact_text(f"{type(exc).__name__}: {exc}")[:300]
            _append_drill(
                base,
                {"at": now.isoformat(), "dump": label, "passed": False,
                 "differences": [f"the drill did not finish: {why}"],
                 "took_s": round(asyncio.get_running_loop().time() - started, 1)},
            )  # fmt: skip
            raise
        result = DrillResult(
            dump=label,
            passed=not problems,
            differences=tuple(problems),
            took_s=round(asyncio.get_running_loop().time() - started, 1),
            at=now,
        )
        _append_drill(
            base,
            {"at": now.isoformat(), "dump": label, "passed": result.passed,
             "differences": list(result.differences[:50]), "took_s": result.took_s},
        )  # fmt: skip
        if result.passed:
            manifest.verified = {"at": now.isoformat(), "took_s": result.took_s}
            _write_json(manifest.path, manifest.as_json())
    return result


async def _restore_and_compare(
    settings: Settings, tools: Tools, env: Mapping[str, str], manifest: Manifest, now: datetime
) -> list[str]:
    scratch = f"{SCRATCH_PREFIX}{int(now.timestamp()):010d}_{secrets.token_hex(4)}"
    admin = create_engine(settings.database, database="postgres", role="owner")
    try:
        await _drop_stale_scratch(admin, now)
        async with admin.connect() as conn:
            conn = await conn.execution_options(isolation_level="AUTOCOMMIT")
            await conn.execute(text(f'CREATE DATABASE "{scratch}"'))
        try:
            await _run_tool(
                tools.restore(scratch), env, stdin=manifest.dump_path, what="pg_restore"
            )
            restored = create_engine(settings.database, database=scratch, role="owner")
            try:
                async with restored.connect() as conn, conn.begin():
                    got = await fingerprints(conn)
                    behind = await sequence_problems(conn)
            finally:
                await restored.dispose()
        finally:
            async with admin.connect() as conn:
                conn = await conn.execution_options(isolation_level="AUTOCOMMIT")
                await conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
    finally:
        await admin.dispose()
    return differences(manifest.fingerprints, got) + behind


async def _drop_stale_scratch(admin: AsyncEngine, now: datetime) -> None:
    """Scratch databases an interrupted drill left (only names a drill makes, older than
    STALE_SCRATCH)."""
    async with admin.connect() as conn:
        conn = await conn.execution_options(isolation_level="AUTOCOMMIT")
        names = await conn.execute(text("SELECT datname FROM pg_database"))
        for (name,) in names.all():
            match = SCRATCH_PATTERN.fullmatch(str(name))
            if match is None:
                continue
            made = datetime.fromtimestamp(int(match["at"]), UTC)
            if now - made > STALE_SCRATCH:
                await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


# --------------------------------------------------------------------------- status


@dataclass(frozen=True)
class Status:
    newest_nightly: Manifest | None
    newest_any: Manifest | None
    last_drill: dict[str, Any] | None
    last_passed_drill: dict[str, Any] | None


def status(base: Path) -> Status:
    found = manifests(base)
    nightly = [m for m in found if m.kind == "nightly"]
    records = drills(base)
    passed = [r for r in records if r.get("passed") is True]
    return Status(
        newest_nightly=nightly[0] if nightly else None,
        newest_any=found[0] if found else None,
        last_drill=records[-1] if records else None,
        last_passed_drill=passed[-1] if passed else None,
    )
