"""``argus kibana sync``: the dry runs send nothing and show the real requests (with
``kibana.base_path``); ``run`` does not run (exit 0) while the lane or the read-back is off;
the model prints the projections; the settings' bounds."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from argus.config.settings import KibanaSettings, KibanaSyncSettings, Settings
from argus.kibana_sync import cli


def _settings(**kibana: Any) -> Settings:
    return Settings(kibana=KibanaSettings(**{"url": "https://kibana.example:5601", **kibana}))


def test_the_first_reads_dry_run_sends_nothing_and_names_each_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "load", lambda config: _settings(base_path="/kibana"))
    monkeypatch.setattr(cli, "build", lambda *a: pytest.fail("nothing is built in a dry run"))
    out = CliRunner().invoke(cli.sync_app, ["first-read", "--dry-run"])
    assert out.exit_code == 0, out.output
    lines = out.output.splitlines()
    status = "https://kibana.example:5601/kibana/s/acme-soc/api/status"
    assert lines[0] == f"Kibana GET {status} (reader key)"
    assert "perPage=10" in lines[1]
    assert "reporters=argus" in lines[1]
    assert "cases/configure" in lines[2]
    assert "_license" in lines[3]
    assert "alerts.case_links" in lines[4]
    assert lines[-1] == "dry run: nothing was sent"


def test_a_cycles_dry_run_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "load", lambda config: _settings())
    monkeypatch.setattr(cli, "build", lambda *a: pytest.fail("nothing is built in a dry run"))
    out = CliRunner().invoke(cli.sync_app, ["once", "--dry-run"])
    assert out.exit_code == 0
    assert out.output.endswith("dry run: nothing was sent\n")


@pytest.mark.parametrize(
    ("kibana", "needs"),
    [
        ({}, "kibana.enabled is false"),
        ({"enabled": True, "reader_api_key": "k"}, "kibana.sync.enabled is false"),
    ],
)
def test_run_does_not_run_while_off_and_exits_cleanly(
    monkeypatch: pytest.MonkeyPatch, kibana: Any, needs: str
) -> None:
    """Exit 0: the unit restarts after a failure only, so an enabled unit of an off read-back
    stays stopped instead of starting again every 30 seconds (review, small items)."""
    monkeypatch.setattr(cli, "load", lambda config: _settings(**kibana))
    monkeypatch.setattr(cli, "build", lambda *a: pytest.fail("nothing is built while off"))
    out = CliRunner().invoke(cli.sync_app, ["run"])
    assert out.exit_code == 0
    assert needs in out.output


def test_the_model_prints_every_projection() -> None:
    out = CliRunner().invoke(cli.sync_app, ["model"])
    assert out.exit_code == 0
    assert out.output.count("fits") >= 4
    assert "DOES NOT FIT" not in out.output
    mine = CliRunner().invoke(cli.sync_app, ["model", "--open-cases", "9000", "--closed", "1"])
    assert "DOES NOT FIT" in mine.output


def test_the_settings_are_off_and_bounded() -> None:
    s = KibanaSyncSettings()
    assert not s.enabled
    assert (s.normal, s.caution, s.degraded) == (
        timedelta(minutes=10),
        timedelta(minutes=20),
        timedelta(hours=1),
    )
    assert s.clock_alarm == timedelta(seconds=30)
    config = cli.config_of(_settings(sync={"normal": "15m"}))
    assert config.intervals.normal == timedelta(minutes=15)
    assert s.diff_calls == 5
    for bad in (
        {"normal": "30s"},
        {"per_page": 101},
        {"discovery_calls": 50},
        {"diff_calls": 0},
        {"other": 1},
    ):
        with pytest.raises(ValidationError):
            KibanaSyncSettings(**bad)
