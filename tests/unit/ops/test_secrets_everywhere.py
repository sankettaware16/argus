"""Q-A2's gate: secrets redacted everywhere. Every secret setting, the writer key and the web's
login password included, stays out of what the CLI prints and what ARGUS logs."""

from __future__ import annotations

import io
import logging
from pathlib import Path

import pytest
from typer.testing import CliRunner

from argus.cli import app
from argus.observability.logs import configure_logging
from argus.observability.redaction import redact_text
from tests.unit.ops.test_settings_q_a2 import SECRETS

pytestmark = pytest.mark.unit
runner = CliRunner()


@pytest.fixture
def every_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for (section, field), value in SECRETS.items():
        monkeypatch.setenv(f"ARGUS_{section.upper()}__{field.upper()}", value)
    config = tmp_path / "argus.yaml"
    config.write_text(
        "database:\n  name: argus_unit_never_created\n  port: 1\n  connect_timeout: 1s\n"
        "logging:\n  level: DEBUG\n"
    )
    return config


def _shown(result: object) -> str:
    return getattr(result, "output", "") + getattr(result, "stderr", "")


def test_config_show_masks_every_secret(every_secret: Path) -> None:
    try:
        result = runner.invoke(app, ["config", "show", "-c", str(every_secret)])
    finally:
        configure_logging("WARNING", "console", stream=io.StringIO())
    assert result.exit_code == 0, result.output
    assert [v for v in SECRETS.values() if v in _shown(result)] == []
    assert "api_password" in result.output  # the setting is shown, masked


def test_doctor_prints_no_secret(every_secret: Path) -> None:
    try:
        result = runner.invoke(app, ["doctor", "-c", str(every_secret)])
    finally:
        configure_logging("WARNING", "console", stream=io.StringIO())
    assert result.exit_code == 1  # no database here
    assert [v for v in SECRETS.values() if v in _shown(result)] == []
    assert "FAIL  write keys" in result.output  # the writer key is in the environment


def test_every_secret_is_masked_in_the_logs(every_secret: Path) -> None:
    stream = io.StringIO()
    try:
        result = runner.invoke(app, ["config", "validate", "-c", str(every_secret)])
        assert result.exit_code == 0
        configure_logging("DEBUG", "json", stream=stream)
        log = logging.getLogger("argus.test")
        for value in SECRETS.values():
            log.warning("sending %s", value)
    finally:
        configure_logging("WARNING", "console", stream=io.StringIO())
    text = stream.getvalue()
    assert text.count("sending") == len(SECRETS)
    assert [v for v in SECRETS.values() if v in text] == []
    assert [v for v in SECRETS.values() if v in redact_text(" ".join(SECRETS.values()))] == []


def test_doctor_escapes_control_characters_from_outside(
    every_secret: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A certificate's subject or a unit file's name comes from outside ARGUS: a carriage
    return or a terminal escape in it must not forge or hide doctor's lines."""
    from argus import doctor
    from argus.doctor import CheckResult

    async def hostile(_settings: object) -> list[CheckResult]:
        return [CheckResult("unit argus-\x1b[2Kx.service", True, "ok\rFAIL  forged", warn=True)]

    monkeypatch.setattr(doctor, "_CHECKS", [hostile])
    try:
        result = runner.invoke(app, ["doctor", "-c", str(every_secret)])
    finally:
        configure_logging("WARNING", "console", stream=io.StringIO())
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output
    assert "\r" not in result.output
    assert "WARN  unit argus-\\x1b[2Kx.service  ok\\rFAIL  forged" in result.output
