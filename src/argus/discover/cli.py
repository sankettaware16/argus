"""``argus discover``: propose the ``site`` section from the Elastic ARGUS is pointed at
(P4-D1, D-238). Read-only; see ``docs/runbooks/discover.md``."""

from __future__ import annotations

import asyncio
import os
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from argus import site
from argus.config.errors import ConfigError
from argus.config.settings import SITE_FILE, SiemSettings, resolve_config_path
from argus.discover import run
from argus.discover.propose import Proposal, checked_yaml, propose, render_text
from argus.gateway.discovery import DiscoverIndices, IndicesParams
from argus.gateway.errors import GatewayError
from argus.gateway.gateway import Gateway, in_quiet_hours
from argus.gateway.health import HealthState
from argus.gateway.kibana.paths import KEndpoint, wire_path
from argus.gateway.service import PROBE_DEADLINE, build_discovery_gateway
from argus.gateway.state import DiscoveryStore
from argus.gateway.transport import wire_path as es_wire_path

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="YAML config file (default: config/argus.yaml)."),
]


def discover(
    write: Annotated[
        bool, typer.Option("--write", help=f"write the proposal to {SITE_FILE}")
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", help=f"overwrite an existing {SITE_FILE}")
    ] = False,
    max_mappings: Annotated[
        int, typer.Option(help="most candidate families whose mapping is read", min=1, max=40)
    ] = run.MAX_MAPPINGS,
    no_kibana: Annotated[bool, typer.Option("--no-kibana", help="read Elasticsearch only")] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="print the requests, send none")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Propose the `site` section (log families, the Kibana space, versions, threat intel) from a
    few read-only requests to Elasticsearch and Kibana, through the gateway. Prints the proposal
    with a confidence and the evidence for each family; `--write` saves it as config/site.yaml
    (never over an existing file without `--force`). Needs the SIEM to be NORMAL and outside the
    quiet hours (site.quiet_hours, default 00:00-01:30 UTC). Remembers nothing in ARGUS's shared
    state: a refusal (a 403) is in the output."""
    from argus.cli import _load

    settings = _load(config)
    target = resolve_config_path(config).parent / SITE_FILE
    if write and target.exists() and not force:
        typer.echo(f"error: {target} exists; --force replaces it", err=True)
        raise typer.Exit(2)
    if dry_run:
        _dry_run(
            settings.kibana.base_path,
            settings.kibana.shown_url,
            settings.siem.shown_url,
            no_kibana,
        )
        return
    now = datetime.now(UTC)
    if in_quiet_hours(now):
        quiet = site.quiet_hours()
        typer.echo(
            f"error: not between {quiet.start} and {quiet.end} UTC (the SIEM creates and deletes"
            f" indices): try again after {quiet.end}",
            err=True,
        )
        raise typer.Exit(1)
    try:
        proposal = asyncio.run(_discover(settings, max_mappings, no_kibana))
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    except _RefusedError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    except GatewayError as exc:
        typer.echo(f"error: {exc.reason}: {exc}", err=True)
        raise typer.Exit(1) from None
    typer.echo(render_text(proposal))
    if not proposal.listing_read:
        typer.echo(f"error: {run.nothing_proposed(datetime.now(UTC))}", err=True)
        raise typer.Exit(1)
    try:
        text = checked_yaml(proposal)
    except ValueError as exc:
        typer.echo(f"error: {exc}: nothing is shown as YAML and nothing is written", err=True)
        raise typer.Exit(1) from None
    typer.echo(text)
    if write:
        _write(target, text, force)
        typer.echo(f"written: {target}")


class _RefusedError(Exception):
    """The SIEM is not in the state a discovery needs."""


def _now() -> datetime:
    return datetime.now(UTC)


async def _discover(settings: object, max_mappings: int, no_kibana: bool) -> Proposal:
    from argus.cli import _engine
    from argus.config.settings import Settings

    assert isinstance(settings, Settings)
    engine = _engine(settings, "app")
    gateway, store = build_discovery_gateway(settings.siem, engine)
    try:
        kibana, note = None, "--no-kibana" if no_kibana else ""
        if not no_kibana:
            try:
                from argus.gateway.kibana.service import build_kibana_gateway

                kibana = build_kibana_gateway(settings, store, es_gateway=gateway)
            except ConfigError as exc:
                note = str(exc)
        return await discover_with(
            gateway, store, kibana, settings.siem, max_mappings=max_mappings, kibana_note=note
        )
    finally:
        await gateway.transport.aclose()  # type: ignore[attr-defined]
        await engine.dispose()


async def discover_with(
    gateway: Gateway,
    store: DiscoveryStore,
    kibana: run.KibanaReads | None,
    siem: SiemSettings,
    *,
    max_mappings: int = run.MAX_MAPPINGS,
    kibana_note: str = "",
    clock: Callable[[], datetime] = _now,
) -> Proposal:
    """The command on the gateways it is given: refuse unless the SIEM is NORMAL, make the
    reads, propose. Whatever a read meets (a 403, an error) is in the proposal's warnings and the
    ledger; nothing is remembered in the shared store (``DiscoveryStore``)."""
    memory = await run.siem_state(gateway, store, siem, clock=clock)
    if memory.state is not HealthState.NORMAL:
        raise _RefusedError(
            f"the SIEM is {memory.state} ({', '.join(memory.reasons) or 'no reason given'}):"
            " discovery runs only when it is NORMAL"
        )
    inputs = await run.collect(
        gateway, kibana, clock=clock, max_mappings=max_mappings, kibana_note=kibana_note
    )
    return propose(inputs)


def _write(target: Path, text: str, force: bool) -> None:
    """Write the proposal beside the config: to a temporary file in the same directory, then
    into place, so a failed write never leaves half a file or loses the one that was there. An
    existing file is replaced only with ``force``, and a link is never written through."""
    if os.path.islink(target):
        typer.echo(f"error: {target} is a link: not written through", err=True)
        raise typer.Exit(1)
    if target.exists() and not force:
        typer.echo(f"error: {target} exists; --force replaces it", err=True)
        raise typer.Exit(2)
    made: Path | None = None  # a file this call made and has not put in place
    try:
        if force:
            fd, name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
            made = Path(name)
            os.fchmod(fd, 0o644)
        else:  # a new file: created exclusively, so one that appeared meanwhile is never touched
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            made = target
            os.fchmod(fd, 0o644)  # whatever the umask says
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(made, target)
        made = None  # in place
    except FileExistsError:
        made = None  # not ours: the file that was there
        typer.echo(f"error: {target} exists; --force replaces it", err=True)
        raise typer.Exit(2) from None
    except OSError as exc:
        typer.echo(f"error: cannot write {target}: {exc.strerror}", err=True)
        raise typer.Exit(1) from None
    finally:
        if made is not None:
            made.unlink(missing_ok=True)


def _dry_run(base_path: str, kibana_url: str, es_url: str, no_kibana: bool) -> None:
    """Print the fixed requests; the mapping and ILM reads depend on the listing and the
    privileges, so they are described, not listed."""
    now = datetime.now(UTC)
    deadline = now + PROBE_DEADLINE
    preview = Gateway(None, None)  # type: ignore[arg-type]  # sends nothing
    typer.echo("Elasticsearch (read-only, through the gateway, purpose discover):")
    typer.echo(f"  GET {es_url}/                       (version)")
    typer.echo(f"  GET {es_url}/_license               (licence)")
    for scope in ("data", "alerts"):
        final = preview.preview(
            DiscoverIndices(), IndicesParams(scope=scope), deadline=deadline, now=now
        )
        method, path = es_wire_path(final)
        params = "&".join(f"{k}={v}" for k, v in final.url_params if k == "expand_wildcards")
        typer.echo(f"  {method} {es_url}{path}?{params}")
    typer.echo(
        f"  then GET {es_url}/<newest index>/_mapping/field/<allowlisted fields> for at most"
        f" {run.MAX_MAPPINGS} candidate families,"
    )
    typer.echo(f"  POST {es_url}/_security/user/_has_privileges (read_ilm) and, if held,")
    typer.echo(f"  GET {es_url}/_ilm/policy")
    if no_kibana:
        typer.echo("Kibana: not asked (--no-kibana)")
        return
    typer.echo("Kibana (reader key):")
    space = site.active().space
    for endpoint in (KEndpoint.STATUS, KEndpoint.SPACES, KEndpoint.FEATURES):
        method, path = wire_path(endpoint, space)
        typer.echo(f"  {method} {kibana_url}{base_path}{path}")
    typer.echo("dry run: nothing was sent")
