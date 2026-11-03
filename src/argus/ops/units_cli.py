"""``argus units``: render ARGUS's systemd user units for this installation and install them
(D-295). A dry run unless ``--apply``; nothing is ever enabled, started, stopped or restarted here
(``argus init --start`` enables the units an installation runs)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Annotated

import typer

from argus.ops import units

units_app = typer.Typer(
    no_args_is_help=True, help="The systemd user units: render and install them (D-295)."
)

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="YAML config file (default: config/argus.yaml)."),
]


def _params(config: Path | None) -> units.UnitParams:
    from argus.cli import _load

    settings = _load(config)
    try:
        return units.params_of(settings.units)
    except units.UnitsError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None


@units_app.command("show")
def units_show(
    name: Annotated[str, typer.Argument(help="A unit, e.g. argus-web.service.")],
    config: ConfigOption = None,
) -> None:
    """Print one unit as this installation renders it."""
    params = _params(config)
    rendered = units.rendered_units(params)
    if name not in rendered:
        typer.echo(f"error: no unit {name} in deploy/systemd", err=True)
        raise typer.Exit(2)
    typer.echo(rendered[name], nl=False)


@units_app.command("install")
def units_install(
    apply: Annotated[bool, typer.Option("--apply", help="Write the changed units.")] = False,
    reload: Annotated[
        bool, typer.Option("--reload", help="Then `systemctl --user daemon-reload`.")
    ] = False,
    dest: Annotated[
        Path | None, typer.Option("--dest", help="Another unit directory (tests).")
    ] = None,
    config: ConfigOption = None,
) -> None:
    """Show what would change (a diff per unit, secrets masked); with --apply write the units
    rendered for this installation, byte for byte. New units are installed disabled: each is
    switched on at its own step (units.run). Restart a changed service at a checkpoint."""
    if reload and not apply:
        typer.echo("error: --reload goes with --apply", err=True)
        raise typer.Exit(2)
    params = _params(config)
    try:
        plan = units.plan_install(params, dest)
    except units.UnitsError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    code = report(plan, apply=apply, reload=reload)
    if code:
        raise typer.Exit(code)


def report(
    plan: units.InstallPlan,
    *,
    apply: bool,
    reload: bool,
    run: object = subprocess.run,
) -> int:
    """Print the plan, apply it when asked (and reload systemd when asked); the exit code."""
    for name in plan.changed:
        typer.echo(f"== changed: {name}")
        typer.echo(plan.diffs[name], nl=False)
    for name in plan.new:
        typer.echo(f"== new: {name} (installed disabled: it is enabled at its own step)")
    for name in plan.stray:
        typer.echo(f"== installed but not in the repository (left alone): {name}")
    for path in plan.drop_ins:
        typer.echo(f"== drop-in (changes units; not from the repository): {path}")
    typer.echo(
        f"install: {len(plan.changed)} changed, {len(plan.new)} new, {plan.same} unchanged"
        f" ({plan.dest})"
    )
    if not apply:
        if plan.to_write:
            typer.echo("dry run: nothing written; run again with --apply")
        return 0
    try:
        units.apply_install(plan)
    except (units.UnitsError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        return 1
    if not plan.to_write:
        return 0
    if reload:
        done = run(  # type: ignore[operator]
            ["systemctl", "--user", "daemon-reload"], check=False, timeout=60
        )
        if done.returncode != 0:
            typer.echo("error: systemctl --user daemon-reload failed", err=True)
            return 1
        typer.echo("install: systemd reloaded its unit files (nothing was restarted)")
    else:
        typer.echo("next: systemctl --user daemon-reload")
    for name in plan.changed:
        typer.echo(f"then, at a checkpoint: systemctl --user restart {name}   # its file changed")
    return 0
