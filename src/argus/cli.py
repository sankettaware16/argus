"""``argus`` command line.

Exit codes: 0 success · 1 operational failure (unreachable DB, failed migration or check) ·
2 bad config/usage (including a missing database password or an unknown revision).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Coroutine
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
import yaml
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession

from argus import __version__
from argus.admin.cli import admin_app
from argus.assess.cli import assess_app
from argus.assets import store as asset_store
from argus.assets.assetmap import AssetMap, AssetMapError, parse_asset_map
from argus.cases.cli import approvals_app, audit_app, case_app
from argus.collector.cli import collect_app
from argus.config.settings import (
    ConfigError,
    DatabaseRole,
    Settings,
    load_settings,
    resolve_config_path,
)
from argus.context.cli import worker_app
from argus.db import migrate, roles
from argus.db.audit import AuditError, record_audit
from argus.db.engine import create_engine
from argus.db.errors import DB_ERRORS, is_connection_failure, short_db_error
from argus.discover.cli import discover
from argus.doctor import run_checks
from argus.evaluation.cli import gold_app
from argus.freshness.cli import freshness_app
from argus.gateway import cli as gateway_cli
from argus.gateway.kibana import cli as kibana_cli
from argus.identity.cli import identity_app
from argus.install.cli import init as init_command
from argus.investigation.cli import investigation_app
from argus.llm.cli import llm_app
from argus.notices.cli import notices_app
from argus.observability.logs import configure_logging
from argus.observability.redaction import redact_text, register_secret
from argus.ops import backup
from argus.ops.backup import BackupError
from argus.ops.backup_cli import backup_app
from argus.ops.purge_cli import purge_app
from argus.ops.units_cli import units_app
from argus.reference.cli import knowledge_app, rules_app, ti_app
from argus.report.cli import report_app
from argus.reporter.cli import register as register_reporter
from argus.risk.cli import risk_app
from argus.signins.cli import signins_app
from argus.soak_cli import soak_app
from argus.tuning.cli import tune_app
from argus.web import cli as web_cli
from argus.web.cli import break_glass_app, sessions_app, user_app
from argus.writeback_cli import writeback_app
from argus.writer import cli as writer_cli

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="ARGUS — alert investigation for an Elastic SIEM.",
)
config_app = typer.Typer(no_args_is_help=True, help="Inspect and validate configuration.")
db_app = typer.Typer(
    no_args_is_help=True, help="Database roles and migrations (as the schema owner)."
)
app.add_typer(config_app, name="config")
app.add_typer(db_app, name="db")
assets_app = typer.Typer(no_args_is_help=True, help="Import and inspect the asset map.")
app.add_typer(assets_app, name="assets")
app.add_typer(gateway_cli.siem_app, name="siem")
app.add_typer(gateway_cli.live_app, name="live")
writer_cli.register(kibana_cli.kibana_app)
app.add_typer(kibana_cli.kibana_app, name="kibana")
app.add_typer(writer_cli.writer_app, name="writer")
app.add_typer(identity_app, name="identity")
app.add_typer(collect_app, name="collect")
app.add_typer(freshness_app, name="freshness")
app.add_typer(investigation_app, name="investigation")
app.add_typer(worker_app, name="worker")
app.add_typer(rules_app, name="rules")
app.add_typer(ti_app, name="ti")
app.add_typer(knowledge_app, name="knowledge")
app.add_typer(soak_app, name="soak")
app.add_typer(writeback_app, name="writeback")
app.add_typer(user_app, name="user")
app.add_typer(sessions_app, name="sessions")
app.add_typer(break_glass_app, name="break-glass")
app.add_typer(gold_app, name="gold")
app.add_typer(assess_app, name="assess")
app.add_typer(llm_app, name="llm")
app.add_typer(tune_app, name="tune")
register_reporter(report_app)  # `argus report daily|weekly`
app.add_typer(report_app, name="report")
app.add_typer(backup_app, name="backup")
app.add_typer(purge_app, name="purge")
app.add_typer(units_app, name="units")
app.add_typer(case_app, name="case")
app.add_typer(audit_app, name="audit")
app.add_typer(approvals_app, name="approvals")
app.add_typer(notices_app, name="notices")
app.add_typer(signins_app, name="signins")
app.add_typer(risk_app, name="risk")
app.add_typer(admin_app, name="admin")
app.command("web")(web_cli.web)
app.command("discover")(discover)
app.command("init")(init_command)
app.command("grade")(web_cli.grade)

ConfigOption = Annotated[
    Path | None,
    typer.Option(
        "--config", "-c", help="YAML config file (default: $ARGUS_CONFIG or config/argus.yaml)."
    ),
]


def _load(config: Path | None) -> Settings:
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    for secret in settings.secret_values():
        register_secret(secret)
    configure_logging(settings.logging.level, settings.logging.format)
    return settings


def _engine(settings: Settings, role: DatabaseRole) -> AsyncEngine:
    """An engine logging in as ``role``, or exit code 2 while the configuration is incomplete
    (that role's password is missing)."""
    try:
        return create_engine(settings.database, role=role)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None


def _fail(exc: BaseException, during: str | None = None) -> NoReturn:
    typer.echo(f"error: {short_db_error(exc, during)}", err=True)
    raise typer.Exit(1) from None


def _run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"argus {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """ARGUS command line."""


# --------------------------------------------------------------------------- config


@config_app.command("show")
def config_show(config: ConfigOption = None) -> None:
    """Print the effective configuration (secrets masked)."""
    settings = _load(config)
    path = redact_text(str(resolve_config_path(config)))
    typer.echo(f"# effective configuration — file: {path}; secrets masked")
    shown = _redact_strings(settings.model_dump(mode="json"))
    typer.echo(yaml.safe_dump(shown, sort_keys=False).rstrip())


def _redact_strings(value: Any) -> Any:
    """Redact every string value (a DSN pasted into a host field, say); keys are setting names."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: _redact_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_strings(item) for item in value]
    return value


@config_app.command("validate")
def config_validate(config: ConfigOption = None) -> None:
    """Validate configuration; exit code 2 if invalid."""
    settings = _load(config)
    typer.echo(
        f"configuration OK (history.window={settings.model_dump(mode='json')['history']['window']})"
    )


# --------------------------------------------------------------------------- db


@db_app.command("bootstrap")
def db_bootstrap(config: ConfigOption = None) -> None:
    """Create or repair ARGUS's roles and set the logins' passwords: the runtime login, and the
    web's own login once ARGUS_DATABASE__API_PASSWORD is set. Run before the first
    upgrade, and again after changing a login's name or password."""
    settings = _load(config)
    try:
        roles.check_bootstrap_settings(settings.database)
        if roles.api_login_configured(settings.database):
            roles.check_api_settings(settings.database)
        if roles.writer_login_configured(settings.database):
            roles.check_writer_settings(settings.database)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    _run(_bootstrap(settings, _engine(settings, "owner")))


async def _bootstrap(settings: Settings, engine: AsyncEngine) -> None:
    """Roles and the CONNECT grants in one transaction, audited in it if the audit table
    exists: the runtime roles, and the web's (its group always, its login once its password is
    set). Whatever had to be repaired is printed and recorded (names only)."""
    database = settings.database
    web_login = roles.api_login_configured(database)
    writer_login = roles.writer_login_configured(database)
    repaired: list[str] = []
    try:
        async with engine.begin() as conn:
            created = await roles.ensure_roles(conn, database, changes=repaired)
            created += await roles.ensure_approvals_role(conn, changes=repaired)
            created += await roles.ensure_purge_role(conn, changes=repaired)
            await roles.grant_connect(conn, database.name)
            web_created = await roles.ensure_api_roles(conn, database, changes=repaired)
            await roles.ensure_web_approvals(conn, database, changes=repaired)
            await roles.grant_connect(conn, database.name, role=roles.API_ROLE)
            writer_created = await roles.ensure_writer_roles(conn, database, changes=repaired)
            details: dict[str, Any] = {
                "login": database.user,
                "created": [*created, *web_created, *writer_created],
                "repaired": _capped(repaired),
            }
            if web_login:
                details["web_login"] = database.api_user
            if writer_login:
                details["writer_login"] = database.writer_user
            await _audit(conn, settings, "db.bootstrap", "success", details)
    except DB_ERRORS as exc:
        _fail(exc, "bootstrap")
    except (roles.BootstrapError, AuditError) as exc:
        typer.echo(f"error: {_printable(redact_text(str(exc)))}", err=True)
        raise typer.Exit(1) from None
    finally:
        await engine.dispose()
    made = f"created {', '.join(created)}" if created else "already present"
    typer.echo(
        f"roles ready: {database.user} (member of {roles.RUNTIME_ROLE}) may connect to"
        f" {_printable(database.name)}; {made}"
    )
    web_made = f"created {', '.join(web_created)}" if web_created else "already present"
    if web_login:
        typer.echo(
            f"web login ready: {database.api_user} (member of {roles.API_ROLE}) may connect to"
            f" {_printable(database.name)}; {web_made}"
        )
    elif web_created:
        typer.echo(
            f"web group ready: {roles.API_ROLE}, {web_made}; the web's login"
            f" ({database.api_user}) is made once ARGUS_DATABASE__API_PASSWORD is set"
        )
    if writer_login:
        made_writer = f"created {', '.join(writer_created)}" if writer_created else "present"
        typer.echo(
            f"writer login ready: {database.writer_user} (member of {roles.WRITER_ROLE} and"
            f" {roles.RUNTIME_ROLE}); {made_writer}"
        )
    for repair in repaired:
        typer.echo(f"repaired: {_printable(repair)}")


# A repair names roles and settings found on the server; any character but NUL may be in them.
_MAX_AUDITED_REPAIRS = 50
_MAX_REPAIR_CHARS = 300


def _printable(text: str) -> str:
    """``text`` on one line: control and other unprintable characters escaped (a role name with
    a carriage return or a terminal escape could otherwise forge or hide console lines)."""
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in text
    )


def _capped(repairs: list[str]) -> list[str]:
    """The repairs for the audit row: each shortened, at most 50, then how many more (an audit
    row holds at most 64 KiB, and failing to write it would roll every repair back)."""
    shown = [
        repair if len(repair) <= _MAX_REPAIR_CHARS else repair[: _MAX_REPAIR_CHARS - 3] + "..."
        for repair in repairs[:_MAX_AUDITED_REPAIRS]
    ]
    more = len(repairs) - len(shown)
    return [*shown, f"... and {more} more"] if more else shown


NoBackupOption = Annotated[
    bool,
    typer.Option(
        "--no-backup",
        help="Migrate without dumping the database first (backup.before_migration): only when a"
        " person decides so, e.g. with a fresh dump already taken.",
    ),
]


@db_app.command("upgrade")
def db_upgrade(
    revision: Annotated[
        str, typer.Argument(help="Target revision: an id, head, or a step such as +1 or head-1.")
    ] = "head",
    no_backup: NoBackupOption = False,
    config: ConfigOption = None,
) -> None:
    """Apply migrations up to REVISION (default: head); a dump first when backup.before_migration
    is on."""
    settings = _load(config)
    _check_revision("upgrade", revision)
    backup_first = settings.backup.before_migration and not no_backup
    _run(_migrate(settings, _engine(settings, "owner"), "upgrade", revision, backup_first))


@db_app.command("regroup")
def db_regroup(config: ConfigOption = None) -> None:
    """Rebuild all investigations from the stored alerts after a grouping change.
    Logs in as the schema owner; refused while reviews exist."""
    from datetime import UTC, datetime

    from argus.grouping.regroup import ReviewsExistError, regroup

    settings = _load(config)
    engine = _engine(settings, "owner")

    async def go() -> tuple[int, int]:
        try:
            return await regroup(engine, datetime.now(UTC))
        finally:
            await engine.dispose()

    try:
        grouped, investigations = _run(go())
    except ReviewsExistError as exc:
        typer.echo(f"error: {exc}; regrouping would orphan them", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"regrouped {grouped} alerts into {investigations} investigations")


@db_app.command("downgrade")
def db_downgrade(
    revision: Annotated[
        str,
        typer.Argument(
            help="Target revision: an id, base, or a step such as head-1 or -1 "
            "(put -- before a negative step: db downgrade --yes -- -1)."
        ),
    ],
    yes: Annotated[
        bool, typer.Option("--yes", help="Confirm: downgrading can drop tables and data.")
    ] = False,
    no_backup: NoBackupOption = False,
    config: ConfigOption = None,
) -> None:
    """Revert migrations down to REVISION (a dump first when backup.before_migration is on).
    Requires --yes."""
    settings = _load(config)
    if not yes:
        typer.echo("refusing to downgrade without --yes (this can drop tables and data)", err=True)
        raise typer.Exit(2)
    _check_revision("downgrade", revision)
    backup_first = settings.backup.before_migration and not no_backup
    _run(_migrate(settings, _engine(settings, "owner"), "downgrade", revision, backup_first))


def _check_revision(direction: migrate.Direction, revision: str) -> None:
    """A target that is not a point of this code's migration chain (a typo, or a step that walks
    off the chain) or a step the wrong way (``upgrade -1``, ``downgrade +1``: Alembic refuses
    these whatever the database's revision) is a usage error; nothing is touched."""
    try:
        migrate.resolve_revision(revision, direction=direction)
    except migrate.UnknownRevisionError as exc:
        typer.echo(f"error: {redact_text(str(exc))}", err=True)
        raise typer.Exit(2) from None


async def _migrate(
    settings: Settings,
    engine: AsyncEngine,
    direction: migrate.Direction,
    revision: str,
    backup_first: bool = False,
) -> None:
    """Migrate and audit it in one locked transaction, so the audit record commits only if the
    migration does. A failed attempt is then recorded as a failure (best effort), with details
    ``from`` (left out if the database's revision could not be read), ``target`` and ``error``.
    With ``backup_first`` the database is dumped first when the migration changes anything,
    and a failed dump stops it before anything is migrated."""
    action = f"db.{direction}"
    seen: dict[str, Any] = {}
    before: str | None = None
    after: str | None = None
    saved: str | None = None
    try:
        if backup_first:
            saved = await _backup_before(settings, engine, direction, revision)
        async with migrate.migration_transaction(engine) as conn:
            before = seen["from"] = await migrate.current_revision(conn)
            await migrate.run(conn, direction, revision)
            after = await migrate.current_revision(conn)
            done: dict[str, Any] = {"from": before, "to": after}
            if saved is not None:
                done["backup"] = saved
            await _audit(conn, settings, action, "success", done)
    except BackupError as exc:
        typer.echo(
            f"error: the dump before the {direction} failed, so nothing was migrated:"
            f" {_printable(redact_text(str(exc)))}",
            err=True,
        )
        typer.echo(
            f"(a person who decides to go on without it: argus db {direction} ... --no-backup)",
            err=True,
        )
        raise typer.Exit(1) from None
    except DB_ERRORS as exc:
        if not is_connection_failure(exc):
            error = short_db_error(exc, direction)
            await _audit_failure(
                engine, settings, action, {**seen, "target": revision, "error": error}
            )
        _fail(exc, direction)
    finally:
        await engine.dispose()
    if saved is not None:
        typer.echo(f"dumped first: {saved} (backup.dir)")
    typer.echo(f"database at revision {after or 'empty'} (was {before or 'empty'})")


async def _backup_before(
    settings: Settings, engine: AsyncEngine, direction: migrate.Direction, revision: str
) -> str | None:
    """The dump taken before a migration, as kind/file; None when there is nothing to keep (an
    empty database) or the migration would change nothing (upgrading at head)."""
    current = await migrate.current_revision(engine)
    if current is None:
        return None
    target = migrate.resolve_revision(revision, direction=direction)
    if target == current or (target in ("head", "heads") and current == migrate.head_revision()):
        return None
    made = await backup.dump(settings, "migration")
    return f"{made.kind}/{made.file}"


async def _audit(
    conn: AsyncConnection, settings: Settings, action: str, outcome: str, details: dict[str, Any]
) -> None:
    """Record a db command in ``conn``'s transaction, if the audit table exists at that point
    (after a downgrade to base it does not)."""
    if not await conn.run_sync(lambda sync_conn: inspect(sync_conn).has_table("audit_events")):
        return
    async with AsyncSession(bind=conn) as session:  # joins conn's transaction; never commits it
        await record_audit(
            session,
            actor="cli",
            action=action,
            outcome=outcome,
            target_type="database",
            target_id=settings.database.name,
            details=details,
        )


async def _audit_failure(
    engine: AsyncEngine, settings: Settings, action: str, details: dict[str, Any]
) -> None:
    """Best effort: recording the failed attempt must never hide the error that caused it."""
    with contextlib.suppress(*DB_ERRORS, AuditError):
        async with engine.begin() as conn:
            await _audit(conn, settings, action, "failure", details)


@db_app.command("current")
def db_current(config: ConfigOption = None) -> None:
    """Show the current and head revisions."""
    settings = _load(config)
    current = _run(_current(_engine(settings, "owner")))
    typer.echo(f"current={current or 'empty'} head={migrate.head_revision()}")


async def _current(engine: AsyncEngine) -> str | None:
    try:
        return await migrate.current_revision(engine)
    except DB_ERRORS as exc:
        _fail(exc)
    finally:
        await engine.dispose()


@db_app.command("check")
def db_check(config: ConfigOption = None) -> None:
    """Fail (exit 1) if the database is not at head or differs from the models."""
    settings = _load(config)
    problems = _run(_check(_engine(settings, "owner")))
    if problems:
        for problem in problems:
            typer.echo(f"problem: {problem}", err=True)
        raise typer.Exit(1)
    typer.echo("database schema OK")


async def _check(engine: AsyncEngine) -> list[str]:
    try:
        current = await migrate.current_revision(engine)
        head = migrate.head_revision()
        if current != head:
            return [f"database at {current or 'empty'}, head is {head}"]
        return [str(d) for d in await migrate.schema_drift(engine)]
    except DB_ERRORS as exc:
        return [short_db_error(exc)]
    finally:
        await engine.dispose()


# --------------------------------------------------------------------------- assets


def _summary(asset_map: AssetMap) -> str:
    return (
        f"{len(asset_map.entries)} entries, {asset_map.network_count} networks"
        f" ({asset_map.duplicate_networks} listed more than once), sha256 {asset_map.sha256}"
    )


@assets_app.command("import")
def assets_import(
    path: Annotated[Path, typer.Argument(help="The asset map file to import.")],
    config: ConfigOption = None,
) -> None:
    """Validate an asset map, record the import in the audit trail and install it (mode 0600)."""
    settings = _load(config)
    try:
        raw = asset_store.read_map_bytes(path)
        if raw is None:
            typer.echo("error: the file does not exist", err=True)
            raise typer.Exit(2)
        asset_map = parse_asset_map(raw)
    except AssetMapError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    destination = settings.assets.map_path
    try:
        previous = asset_store.load_asset_map(destination)
    except AssetMapError:
        previous = None
    staged = asset_store.stage_map(raw, destination)
    details: dict[str, Any] = {
        "sha256": asset_map.sha256,
        "entries": len(asset_map.entries),
        "networks": asset_map.network_count,
        "duplicate_networks": asset_map.duplicate_networks,
        "previous_sha256": None if previous is None else previous.sha256,
    }
    try:
        _run(_audit_assets(_engine(settings, "app"), "success", details))
    except BaseException:
        asset_store.discard_staged(staged)
        raise
    try:
        asset_store.commit_map(staged, destination)
    except OSError as exc:
        asset_store.discard_staged(staged)
        _run(_audit_assets(_engine(settings, "app"), "failure", {**details, "error": exc.strerror}))
        typer.echo(f"error: could not install the asset map: {exc.strerror}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"imported asset map: {_summary(asset_map)}")


async def _audit_assets(engine: AsyncEngine, outcome: str, details: dict[str, Any]) -> None:
    try:
        async with engine.begin() as conn, AsyncSession(bind=conn) as session:
            await record_audit(
                session,
                actor="cli",
                action="assets.import",
                outcome=outcome,
                target_type="asset_map",
                target_id=str(details["sha256"]),
                details=details,
            )
    except DB_ERRORS as exc:
        if outcome == "success":
            _fail(exc, "recording the import")
    finally:
        await engine.dispose()


@assets_app.command("status")
def assets_status(config: ConfigOption = None) -> None:
    """Show the imported asset map's size and hash (never its content)."""
    settings = _load(config)
    try:
        asset_map = asset_store.load_asset_map(settings.assets.map_path)
    except AssetMapError as exc:
        typer.echo(f"error: the imported asset map is invalid: {exc}", err=True)
        raise typer.Exit(1) from None
    if asset_map is None:
        typer.echo("no asset map imported (asset context will be 'no_map')")
        raise typer.Exit(1)
    typer.echo(f"asset map: {_summary(asset_map)}")


# --------------------------------------------------------------------------- doctor


@app.command()
def doctor(config: ConfigOption = None) -> None:
    """Run read-only health checks; exit 1 if any fails."""
    settings = _load(config)
    results = _run(run_checks(settings))
    width = max(len(r.name) for r in results)
    for r in results:
        # names and details can hold text from outside (a certificate's subject, a unit file's
        # name): control characters are escaped so they cannot forge or hide lines
        typer.echo(_printable(redact_text(f"{r.label}  {r.name.ljust(width)}  {r.detail}")))
    if not all(r.ok for r in results):
        raise typer.Exit(1)


def main() -> None:
    app()
