"""``argus kibana ...``: the operator's side of the Kibana lane (Q-D2).

- ``selftest --key reader|cases|alerts``: Kibana's version and what the key holds against its
  must-hold and must-not-hold canaries. ``--dry-run`` prints the requests and sends nothing
  (the only form usable while ``kibana.enabled`` is false, and under D-109 for the SIEM).
- ``state``: Kibana stopped or not, paused classes, today's write counts, the breaker (no
  request to Kibana).
- ``sync ...``: the read-back and reconciliation (Q-D3, ``argus.kibana_sync.cli``).
- ``resume``: lift a stop (a 401) or one class's pause (a 403, a wrong answer), audited. As
  the owner only (Q-A5's rule, migration 0029): services and the runtime login may stop and
  pause, only the owner resumes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer

from argus import site
from argus.config.errors import ConfigError
from argus.gateway.cli import (
    ConfigOption,
    _run,
    _with_store,
    engine_for,
    load,
    owner_engine_for,
)
from argus.gateway.errors import GatewayError
from argus.gateway.kibana import selftest as selftest_core
from argus.gateway.kibana.paths import KEndpoint, wire_path
from argus.gateway.kibana.templates import KeyRole
from argus.gateway.kibana.writes import WriteClass
from argus.gateway.pgstore import PgStore
from argus.kibana_sync.cli import sync_app

kibana_app = typer.Typer(no_args_is_help=True, help="The Kibana lane: self-test, state (Q-D2).")
kibana_app.add_typer(sync_app, name="sync")
# the case team's six keys are tested one by one, as their own users (D-159 did on the SIEM); this
# self-test is of ARGUS's three service keys
KEYS = tuple(role.value for role in KeyRole if role is not KeyRole.TEAM)


@kibana_app.command("selftest")
def kibana_selftest(
    key: Annotated[str, typer.Option(help="reader, cases or alerts")] = "reader",
    dry_run: Annotated[bool, typer.Option("--dry-run", help="print, send nothing")] = False,
    config: ConfigOption = None,
) -> None:
    """Check one of ARGUS's Kibana keys: the pinned version, its must-hold and must-not-hold
    privileges (api:rac, alert updates, deleteCase, createConfiguration, pushCase, assignCase)."""
    if key not in KEYS:
        typer.echo(f"error: --key is one of {', '.join(KEYS)}", err=True)
        raise typer.Exit(2)
    role = KeyRole(key)
    settings = load(config)
    space = site.active().space
    body = selftest_core.request_body(role, space)
    if dry_run:
        method, path = wire_path(KEndpoint.STATUS, space)
        base = settings.kibana.shown_url + settings.kibana.base_path  # what the transport sends to
        typer.echo(f"1. Kibana {method} {base}{path} (reader key)")
        typer.echo(f"2. Elasticsearch POST {settings.siem.shown_url}/_security/user/_has_privileges"
                   f" ({key} key):")  # fmt: skip
        typer.echo(json.dumps(body, indent=2))
        typer.echo("dry run: nothing was sent")
        return
    _run(_selftest(role, settings, config))


async def _selftest(role: KeyRole, settings: object, config: Path | None) -> None:
    from argus.config.settings import Settings
    from argus.gateway.kibana.service import build_kibana_gateway
    from argus.gateway.service import collector_config, lane_plan

    assert isinstance(settings, Settings)
    engine = engine_for(settings)
    try:
        store = PgStore(engine, collector_config(settings.siem), lane_plan(settings.siem))
        try:
            gateway = build_kibana_gateway(settings, store)
        except ConfigError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(2) from None
        deadline = datetime.now(UTC) + timedelta(seconds=40)
        try:
            version, verdict = await selftest_core.run_selftest(
                gateway, role, deadline=deadline,
                accepted_residual=settings.kibana.accepted_residual,
            )  # fmt: skip
        except GatewayError as exc:
            typer.echo(f"error: {exc.reason}: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(f"Kibana {version}; the {role.value} key:")
        for item in verdict.residual:
            typer.echo(f"  residual (accepted): holds {item}")
        for problem in verdict.problems:
            typer.echo(f"  PROBLEM: {problem}")
        if verdict.problems:
            raise typer.Exit(1)
        typer.echo("  as it must be")
    finally:
        await engine.dispose()


@kibana_app.command("state")
def kibana_state(config: ConfigOption = None) -> None:
    """Kibana stopped or not, paused classes, today's writes, Kibana's breaker."""
    settings = load(config)

    async def use(store: PgStore) -> list[str]:
        lane = await store.kibana_lane()
        breaker = await store.kibana_breaker()
        c = lane.counters
        return [
            "Kibana work: " + (f"STOPPED ({lane.stopped})" if lane.stopped else "running"),
            "paused classes: "
            + (", ".join(f"{k} ({v})" for k, v in sorted(lane.paused.items())) or "none"),
            f"switched on here: {', '.join(settings.kibana.write_classes) or 'none'}",
            f"writes on {c.day or 'no day yet'}: {c.case_writes} case writes,"
            f" {c.team_writes} case team writes, {c.alert_mutations} alert mutations",
            "Kibana's breaker: "
            + (f"open until {breaker.open_until:%H:%M:%S} UTC" if breaker.open_until else "closed"),
        ]

    for line in _run(_with_store(settings, use)):
        typer.echo(line)


@kibana_app.command("resume")
def kibana_resume(
    reason: Annotated[str, typer.Option(help="why (kept in the audit trail)")],
    write_class: Annotated[
        str | None, typer.Option("--class", help="W1, W2, W3, WA or WC; omit for Kibana work")
    ] = None,
    config: ConfigOption = None,
) -> None:
    """Lift Kibana's stop (after a 401) or one write class's pause (after a 403); as the
    database owner (Q-A5)."""
    cls = None
    if write_class is not None:
        if write_class not in {c.value for c in WriteClass} - {"WT"}:
            typer.echo("error: --class is one of W1, W2, W3, WA, WC", err=True)
            raise typer.Exit(2)
        cls = WriteClass(write_class)
    settings = load(config)
    command = "kibana resume" + ("" if cls is None else f" --class {cls.value}")
    engine = owner_engine_for(settings, command)  # migration 0029 refuses any other role

    async def use(store: PgStore) -> bool:
        return await store.kibana_resume(actor="cli", reason=reason, write_class=cls)

    changed = _run(_with_store(settings, use, engine))
    what = cls.value if cls else "Kibana work"
    typer.echo(f"{what}: resumed" + ("" if changed else " (it was not stopped)"))
