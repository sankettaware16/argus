"""``argus init``: set up ARGUS on this machine, in this checkout (P4-D2). Interactive, or
scripted with ``--answers FILE``; see docs/install.md."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Annotated

import typer

from argus.install.answers import InitError, ScriptedAnswers, TerminalAnswers, load_answers
from argus.install.run import Host, Options, run_init


def init(
    answers: Annotated[
        Path | None,
        typer.Option("--answers", help="A YAML file answering every question: never prompts."),
    ] = None,
    start: Annotated[
        bool, typer.Option("--start", help="Enable and start the services at the end.")
    ] = False,
    no_compose: Annotated[
        bool,
        typer.Option("--no-compose", help="Use the PostgreSQL .env names; do not run docker."),
    ] = False,
    force_trust: Annotated[
        bool, typer.Option("--force-trust", help="Pin the SIEM's and Kibana's CA again.")
    ] = False,
    force_key: Annotated[
        bool, typer.Option("--force-key", help="Replace the read-only keys in .env.")
    ] = False,
    force_site: Annotated[
        bool, typer.Option("--force-site", help="Discover again and rewrite config/site.yaml.")
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="YAML config file (default: config/argus.yaml)."),
    ] = None,
) -> None:
    """Set up ARGUS here: the prerequisites, .env with new database passwords, the database (docker
    compose, bootstrap, migrations), the SIEM's and Kibana's addresses and trust, the read-only
    keys, the organisation and its Elastic (discovery, config/site.yaml), the LLM keys (optional),
    the systemd user units, then `argus doctor` (init's exit code is doctor's). Rerun it at any
    time: it keeps what is done and repairs only what is missing."""
    root = Path.cwd().resolve()
    options = Options(
        root=root,
        config=(config or root / "config" / "argus.yaml").resolve(),
        start=start,
        compose=not no_compose,
        force_trust=force_trust,
        force_key=force_key,
        force_site=force_site,
    )
    try:
        asker = (
            ScriptedAnswers(load_answers(answers), answers)
            if answers is not None
            else TerminalAnswers()
        )
    except InitError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(exc.code) from None
    if isinstance(asker, ScriptedAnswers):
        compose = asker.confirm("database.compose", "", not no_compose)
        options = dataclasses.replace(options, compose=compose and not no_compose)
    code = run_init(options, asker, Host(say=typer.echo))
    if code:
        raise typer.Exit(code)
