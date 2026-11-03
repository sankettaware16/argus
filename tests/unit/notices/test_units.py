"""The notices' systemd units (Q-H4): a timer every 10 minutes that is off until the user
approves the relay, a oneshot service that runs ``argus notices run``, and the same pair in the
custody layout (the service as ``argus-svc``, the relay password an optional credential that no
unit names until a relay needs a login)."""

from __future__ import annotations

import configparser
import shutil
import subprocess
from pathlib import Path

import pytest

from argus.cli import app
from argus.ops import custody
from argus.ops.units import MANIFEST, UNITS_DIR, Role
from tests.conftest import REPO_ROOT
from tests.unit.ops.unit_files import render_into

pytestmark = pytest.mark.unit

CUSTODY_UNITS = REPO_ROOT / "deploy" / "custody" / "units"


def parse(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    parser.read_string(path.read_text())
    return parser


def test_the_timer_runs_every_ten_minutes_and_is_off_until_the_relay_is_approved() -> None:
    assert MANIFEST["argus-notices.timer"][0] is Role.OFF
    assert MANIFEST["argus-notices.service"][0] is Role.TRIGGERED
    for folder in (UNITS_DIR, CUSTODY_UNITS):
        timer = parse(folder / "argus-notices.timer")
        assert timer["Timer"]["OnUnitActiveSec"] == "10min"
        assert timer["Timer"]["OnBootSec"] == "5min"
        assert timer["Timer"]["Persistent"] == "true"
        assert timer["Install"]["WantedBy"] == "timers.target"


def test_the_service_runs_the_pass_once_and_ends() -> None:
    user = parse(UNITS_DIR / "argus-notices.service")
    assert user["Service"]["Type"] == "oneshot"
    assert user["Service"]["ExecStart"].endswith("argus notices run")
    assert user["Service"]["TimeoutStartSec"] == "10min"  # a relay that hangs cannot hold it
    assert "Install" not in user  # started by its timer, never enabled itself
    system = parse(CUSTODY_UNITS / "argus-notices.service")
    assert system["Service"]["ExecStart"] == "/opt/argus/current/.venv/bin/argus notices run"
    assert system["Service"]["User"] == "argus-svc"
    assert system["Service"]["TimeoutStartSec"] == "10min"
    assert (
        "Environment=ARGUS_CUSTODY__ROLE=svc"
        in (CUSTODY_UNITS / "argus-notices.service").read_text()
    )


def test_the_commands_the_units_run_exist() -> None:
    from typer.main import get_command

    group = get_command(app)
    assert "notices" in group.commands  # type: ignore[attr-defined]
    sub = group.commands["notices"]  # type: ignore[attr-defined]
    assert set(sub.commands) == {"run", "status", "test"}


def test_the_relay_password_is_an_optional_credential_no_unit_names_yet() -> None:
    svc = custody.ACCOUNTS["svc"]
    assert "notices.password" in svc.credentials
    assert "notices.password" in svc.optional
    # AR3's outside threat-intel keys (D-165) are optional credentials of the same account
    assert set(svc.optional) - {"notices.password"} == {
        "outside.virustotal_api_key",
        "outside.shodan_api_key",
        "outside.censys_api_key",
    }
    assert custody.UNITS["argus-notices.service"] == ("svc", Role.TRIGGERED)
    assert custody.UNITS["argus-notices.timer"] == (None, Role.OFF)
    text = (CUSTODY_UNITS / "argus-notices.service").read_text()
    assert "LoadCredential=notices.password" not in text
    assert "LoadCredential=database.password" in text


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="needs systemd-analyze")
def test_systemd_reads_the_units_without_a_complaint(tmp_path: Path) -> None:
    names = ["argus-notices.service", "argus-notices.timer"]
    files = [str(p) for p in render_into(tmp_path, names)]
    done = subprocess.run(  # noqa: S603 - fixed program, repository files
        ["systemd-analyze", "--user", "verify", *files],  # noqa: S607
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert (done.returncode, done.stderr.strip()) == (0, "")
