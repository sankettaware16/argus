"""``argus writer run`` and ``argus kibana plan|diff|run|ramp``: the service does not run while
nothing is scheduled (exit 0, so the unit does not loop); a class that is not switched on, a key
without an expiry or one that expired stops a run before anything is built; a canary and a ramp
step are a person's at a terminal."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import typer
from pydantic import SecretStr
from typer import Typer
from typer.testing import CliRunner

from argus.config.settings import KibanaSettings, KibanaWriterSettings, Settings, WebSettings
from argus.writer import cli

pytestmark = pytest.mark.unit


def _settings(**kibana: Any) -> Settings:
    return Settings(
        kibana=KibanaSettings(**kibana), web=WebSettings(public_url="https://127.0.0.1:8765")
    )


def _app() -> Typer:
    kibana = Typer()
    cli.register(kibana)
    app = Typer()
    app.add_typer(kibana, name="kibana")
    app.add_typer(cli.writer_app, name="writer")
    return app


@pytest.mark.parametrize(
    "kibana",
    [
        {},
        {"enabled": True},
        {"enabled": True, "cases_writer_api_key": SecretStr("k" * 20), "write_classes": ("W1",)},
    ],
)
def test_the_service_does_not_run_while_nothing_is_scheduled(
    monkeypatch: pytest.MonkeyPatch, kibana: dict[str, Any]
) -> None:
    monkeypatch.setattr(cli, "load", lambda config: _settings(**kibana))
    monkeypatch.setattr(cli, "serve", lambda *a: pytest.fail("nothing runs"))
    out = CliRunner().invoke(_app(), ["writer", "run"])
    assert out.exit_code == 0, out.output
    assert "does not run" in out.output


def test_the_services_help_exists_for_its_units_exec_condition() -> None:
    assert CliRunner().invoke(_app(), ["writer", "--help"]).exit_code == 0


def test_a_run_is_refused_before_anything_is_built_when_the_class_cannot_run_here(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "load", lambda config: _settings())  # kibana is off
    monkeypatch.setattr(cli, "build_writer", lambda *a, **k: pytest.fail("nothing is built"))
    for command in (["run"], ["diff"]):
        out = CliRunner().invoke(_app(), ["kibana", *command, "--class", "W1"])
        assert out.exit_code == 2
        assert "kibana.enabled is false" in out.output
    expired = _settings(
        enabled=True,
        cases_writer_api_key=SecretStr("k" * 20),
        cases_writer_api_key_expires=(datetime.now(UTC) - timedelta(days=3)).date(),
        write_classes=("W1",),
    )
    monkeypatch.setattr(cli, "load", lambda config: expired)
    out = CliRunner().invoke(_app(), ["kibana", "run", "--class", "W1"])
    assert out.exit_code == 2
    assert "expired on" in out.output


def test_a_class_is_one_of_w1_w2_w3() -> None:
    for command in ("plan", "diff", "run", "ramp"):
        out = CliRunner().invoke(_app(), ["kibana", command, "--class", "WA"])
        assert out.exit_code == 2
        assert "--class is one of W1, W2, W3" in out.output


def test_a_canary_and_a_ramp_step_are_a_persons_at_a_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(typer.Exit) as refused:  # no terminal here
        cli._confirm("W1", "This sends one write.")
    assert refused.value.exit_code == 2
    monkeypatch.setattr(cli, "_human_at_a_terminal", lambda: True)
    monkeypatch.setattr(cli.typer, "prompt", lambda text: "w1")  # the wrong word
    with pytest.raises(typer.Exit) as wrong:
        cli._confirm("W1", "This sends one write.")
    assert wrong.value.exit_code == 1
    monkeypatch.setattr(cli.typer, "prompt", lambda text: "W1")
    cli._confirm("W1", "This sends one write.")  # typed: goes on


def test_the_writer_settings_bound_the_interval() -> None:
    assert KibanaWriterSettings().interval == timedelta(minutes=10)
    with pytest.raises(ValueError, match="interval"):
        KibanaWriterSettings(interval=timedelta(minutes=11))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="interval"):
        KibanaWriterSettings(interval=timedelta(seconds=30))  # type: ignore[arg-type]
