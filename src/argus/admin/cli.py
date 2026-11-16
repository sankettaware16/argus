"""``argus admin``: ``run`` is ``argus-admin``, the service that applies what people change in the
app's Settings (D-327); ``status`` lists the latest changes and their outcome."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from sqlalchemy import text

from argus.gateway.cli import ConfigOption, engine_for, load

admin_app = typer.Typer(help="Settings changed in the app: the service that applies them.",
                        no_args_is_help=True)  # fmt: skip
RootOption = Annotated[Path, typer.Option("--root", help="The installation's folder.")]


@admin_app.command("run")
def admin_run(config: ConfigOption = None, root: RootOption = Path()) -> None:
    """Apply the settings people save in the app, as they arrive (the argus-admin service)."""
    from argus.admin.applier import Applier, Systemd
    from argus.ops.stopping import until_stopped

    settings = load(config)

    async def main() -> None:
        engine = engine_for(settings)
        stop = asyncio.Event()
        try:
            here = root.resolve()
            applier = Applier(
                engine, here, Systemd(here), custody=settings.custody.role is not None
            )
            await until_stopped(applier.run(stop), stop=stop)
        finally:
            await engine.dispose()

    asyncio.run(main())


@admin_app.command("status")
def admin_status(config: ConfigOption = None, last: int = 10) -> None:
    """The latest changes made in the app and what became of each (never a value)."""
    settings = load(config)

    async def main() -> None:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT c.id, c.key, c.state, c.outcome, c.created_at, u.username"
                        " FROM admin_changes c JOIN users u ON u.id = c.created_by"
                        " ORDER BY c.id DESC LIMIT :n"
                    ),
                    {"n": max(1, min(last, 200))},
                )
                beat = await conn.scalar(
                    text("SELECT updated_at FROM admin_state WHERE name = 'heartbeat'")
                )
        finally:
            await engine.dispose()
        typer.echo(f"argus-admin last seen: {beat or 'never'}")
        for r in rows:
            typer.echo(f"{r.id} {r.created_at:%Y-%m-%d %H:%M} {r.username} {r.key}: {r.state}"
                       f"{' (' + r.outcome + ')' if r.outcome else ''}")  # fmt: skip

    asyncio.run(main())
