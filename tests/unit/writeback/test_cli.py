"""``argus writeback run``: refused, with its own reason and before anything is built or asked,
unless write-back is on, WA is switched on, the alert writer's key is installed with a recorded
expiry and a person is at a terminal; nothing is read or sent by ``plan`` and ``diff``."""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest
from typer.testing import CliRunner

from argus import writeback_cli
from argus.config.settings import Settings
from tests.conftest import plain

pytestmark = pytest.mark.unit

ON = {
    "writeback": {"enabled": True},
    "kibana": {
        "enabled": True,
        "write_classes": ["WA"],
        "alert_writer_api_key": "k" * 20,
        "alert_writer_api_key_expires": date(2099, 1, 1),
    },
}


def settings(**over: Any) -> Settings:
    data = {**ON, **over}
    return Settings.model_validate(data)


def invoke(monkeypatch: pytest.MonkeyPatch, config: Settings, *args: str, tty: bool = True) -> Any:
    monkeypatch.setattr(writeback_cli, "load", lambda path: config)
    monkeypatch.setattr(writeback_cli, "_human_at_a_terminal", lambda: tty)
    monkeypatch.setattr(
        writeback_cli, "writer_engine", lambda *a, **k: pytest.fail("nothing is built")
    )
    monkeypatch.setattr(
        writeback_cli.typer, "prompt", lambda *a, **k: pytest.fail("nothing is asked")
    )
    return CliRunner().invoke(writeback_cli.writeback_app, ["run", *args])


def test_it_is_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    out = invoke(monkeypatch, Settings())
    assert out.exit_code == 2
    assert "writeback.enabled is false" in out.output


@pytest.mark.parametrize(
    ("over", "says"),
    [
        ({"writeback": {"enabled": False}}, "writeback.enabled is false"),
        ({"kibana": {**ON["kibana"], "write_classes": []}}, "WA is not switched on"),
        ({"kibana": {**ON["kibana"], "alert_writer_api_key_expires": None}}, "no expiry"),
        ({"kibana": {**ON["kibana"], "alert_writer_api_key_expires": date(2020, 1, 1)}}, "expired"),
        ({"kibana": {**ON["kibana"], "enabled": False, "write_classes": []}}, "kibana.enabled"),
    ],
)
def test_each_missing_condition_is_named(
    monkeypatch: pytest.MonkeyPatch, over: dict[str, Any], says: str
) -> None:
    out = invoke(monkeypatch, settings(**over))
    assert out.exit_code == 2
    assert says in out.output


def test_a_run_needs_a_person_at_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    out = invoke(monkeypatch, settings(), tty=False)
    assert out.exit_code == 2
    assert "terminal" in out.output


def test_the_services_account_is_not_an_operator(monkeypatch: pytest.MonkeyPatch) -> None:
    out = invoke(monkeypatch, settings(), "--operator", "argus")
    assert out.exit_code == 2
    assert "refused before any request" in out.output


def test_the_commands_exist_with_their_options() -> None:
    runner = CliRunner()
    for command in ("plan", "diff", "run"):
        assert runner.invoke(writeback_cli.writeback_app, [command, "--help"]).exit_code == 0
    app = writeback_cli.writeback_app
    assert "--older" in plain(runner.invoke(app, ["plan", "--help"]).output)
    assert "--operator" in plain(runner.invoke(app, ["run", "--help"]).output)
