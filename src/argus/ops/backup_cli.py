"""``argus backup ...``: the nightly dump, the weekly restore drill, and what is kept.
Local only: nothing reaches the SIEM."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Any

import typer
from sqlalchemy.ext.asyncio import AsyncSession

from argus.db.audit import AuditError, record_audit
from argus.db.engine import create_engine
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, load
from argus.ops import backup
from argus.ops.backup import BackupError

_FAILURES: tuple[type[Exception], ...] = (BackupError, *DB_ERRORS)
_AUDIT_FAILURES: tuple[type[Exception], ...] = (AuditError, *DB_ERRORS)
backup_app = typer.Typer(
    no_args_is_help=True,
    help="Database backups: the nightly dump, the weekly restore drill.",
)


async def record(settings: Any, action: str, outcome: str, details: dict[str, Any]) -> None:
    """The backup's audit event in the live database (best effort: a dump that worked stays a
    dump that worked if the audit trail cannot be written)."""
    engine = create_engine(settings.database, role="owner")
    try:
        async with engine.begin() as conn, AsyncSession(bind=conn) as session:
            await record_audit(
                session,
                actor="cli",
                action=action,
                outcome=outcome,
                target_type="database",
                target_id=settings.database.name,
                details=details,
            )
    except _AUDIT_FAILURES as exc:
        typer.echo(f"note: the audit event was not recorded ({short_db_error(exc)})", err=True)
    finally:
        await engine.dispose()


@backup_app.command("dump")
def backup_dump(
    kind: Annotated[str, typer.Option(help="nightly, manual or migration")] = "manual",
    config: ConfigOption = None,
) -> None:
    """Dump the database with its fingerprints (one snapshot; the services keep running), then
    remove what retention no longer keeps."""
    if kind not in backup.KINDS:
        typer.echo(f"error: --kind is one of {', '.join(backup.KINDS)}", err=True)
        raise typer.Exit(2)
    settings = load(config)

    async def go() -> backup.Manifest:
        try:
            made = await backup.dump(settings, kind)
        except _FAILURES as exc:
            await record(settings, "backup.dump", "failure", {"kind": kind, "error": _why(exc)})
            raise
        await record(settings, "backup.dump", "success", _summary(made))
        return made

    try:
        made = asyncio.run(go())
    except _FAILURES as exc:
        typer.echo(f"error: {_why(exc)}", err=True)
        raise typer.Exit(1) from None
    typer.echo(
        f"dumped {made.database} at revision {made.revision or 'none'}: {made.kind}/{made.file},"
        f" {_size(made.bytes)}, {len(made.fingerprints.tables)} tables, {made.took_s} s"
    )


@backup_app.command("drill")
def backup_drill(
    latest: Annotated[
        bool, typer.Option("--latest", help="the newest nightly dump (the default)")
    ] = True,
    dump: Annotated[
        Path | None, typer.Option(help="a dump's manifest (.json) instead of the newest")
    ] = None,
    config: ConfigOption = None,
) -> None:
    """Restore a dump into a scratch database and compare every table's fingerprint with the
    dump's own; the scratch database is dropped afterwards."""
    settings = load(config)

    async def go() -> backup.DrillResult:
        chosen = backup.read_manifest(dump) if dump is not None else None
        try:
            result = await backup.drill(settings, chosen)
        except _FAILURES as exc:
            await record(settings, "backup.drill", "failure", {"error": _why(exc)})
            raise
        details = {
            "dump": result.dump,
            "passed": result.passed,
            "differences": list(result.differences[:20]),
            "took_s": result.took_s,
        }
        await record(settings, "backup.drill", "success" if result.passed else "failure", details)
        return result

    try:
        result = asyncio.run(go())
    except _FAILURES as exc:
        typer.echo(f"error: {_why(exc)}", err=True)
        raise typer.Exit(1) from None
    if not result.passed:
        typer.echo(f"RESTORE DIFFERS: {result.dump}", err=True)
        for line in result.differences[:20]:
            typer.echo(f"  {line}", err=True)
        raise typer.Exit(1)
    typer.echo(f"RESTORE IDENTICAL: {result.dump}, every table's fingerprint ({result.took_s} s)")


@backup_app.command("check")
def backup_check(config: ConfigOption = None) -> None:
    """A dump, then a restore drill of that very dump: what to run before applying
    migrations. Every service keeps running."""
    settings = load(config)

    async def go() -> tuple[backup.Manifest, backup.DrillResult]:
        try:
            made = await backup.dump(settings, "manual")
        except _FAILURES as exc:
            await record(settings, "backup.dump", "failure", {"kind": "manual", "error": _why(exc)})
            raise
        await record(settings, "backup.dump", "success", _summary(made))
        result = await backup.drill(settings, made)
        await record(settings, "backup.drill", "success" if result.passed else "failure",
                     {"dump": result.dump, "passed": result.passed,
                      "differences": list(result.differences[:20])})  # fmt: skip
        return made, result

    try:
        made, result = asyncio.run(go())
    except _FAILURES as exc:
        typer.echo(f"error: {_why(exc)}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"dumped {made.kind}/{made.file} ({_size(made.bytes)}, revision {made.revision})")
    if not result.passed:
        typer.echo("RESTORE DIFFERS", err=True)
        for line in result.differences[:20]:
            typer.echo(f"  {line}", err=True)
        raise typer.Exit(1)
    typer.echo(f"RESTORE IDENTICAL: every table's fingerprint ({result.took_s} s)")


@backup_app.command("list")
def backup_list(config: ConfigOption = None) -> None:
    """The dumps kept and the last drills (never their content)."""
    settings = load(config)
    base = settings.backup.dir
    found = backup.manifests(base)
    if not found:
        typer.echo(f"no dumps in {base}")
    for made in found:
        mark = " verified" if made.verified else ""
        typer.echo(
            f"{made.created_at:%Y-%m-%d %H:%M} UTC  {made.kind:<9} {made.file}"
            f"  {_size(made.bytes)}  revision {made.revision or 'none'}{mark}"
        )
    for record_ in backup.drills(base)[-5:]:
        outcome = "identical" if record_.get("passed") else "DIFFERS"
        typer.echo(f"drill {record_.get('at', '?')}: {record_.get('dump', '?')} {outcome}")


@backup_app.command("prune")
def backup_prune(
    apply: Annotated[bool, typer.Option("--apply", help="remove them (else: only list)")] = False,
    config: ConfigOption = None,
) -> None:
    """What retention removes (backup.keep_*); with --apply, remove it. Every dump also prunes."""
    settings = load(config)
    removed = backup.prune(settings.backup.dir, settings.backup, apply=apply)
    for path in removed:
        typer.echo(f"{'removed' if apply else 'would remove'}: {path.parent.name}/{path.name}")
    if not removed:
        typer.echo("nothing to remove")


def _summary(made: backup.Manifest) -> dict[str, Any]:
    return {"kind": made.kind, "file": made.file, "bytes": made.bytes, "sha256": made.sha256,
            "revision": made.revision, "tables": len(made.fingerprints.tables),
            "took_s": made.took_s}  # fmt: skip


def _why(exc: BaseException) -> str:
    return str(exc) if isinstance(exc, BackupError) else short_db_error(exc)


def _size(count: int) -> str:
    size = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"  # pragma: no cover - the loop returns
