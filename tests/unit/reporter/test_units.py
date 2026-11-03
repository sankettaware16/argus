"""The Reporter's systemd units (Q-H3): a daily and a weekly timer, both off until the user has
read two reports, each starting a oneshot that runs ``argus report daily|weekly`` and ends, in
both layouts (the user's and the custody layout, whose service is ``argus-svc``)."""

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
KINDS = ("daily", "weekly")


def parse(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    parser.read_string(path.read_text())
    return parser


@pytest.mark.parametrize("kind", KINDS)
def test_each_timer_is_off_until_the_user_has_read_two_reports(kind: str) -> None:
    assert MANIFEST[f"argus-report-{kind}.timer"][0] is Role.OFF
    assert MANIFEST[f"argus-report-{kind}.service"][0] is Role.TRIGGERED
    assert custody.UNITS[f"argus-report-{kind}.timer"] == (None, Role.OFF)
    assert custody.UNITS[f"argus-report-{kind}.service"] == ("svc", Role.TRIGGERED)
    for folder in (UNITS_DIR, CUSTODY_UNITS):
        timer = parse(folder / f"argus-report-{kind}.timer")
        assert timer["Timer"]["Persistent"] == "true"
        assert timer["Install"]["WantedBy"] == "timers.target"


def test_the_reports_come_after_the_day_has_ended_and_outside_the_quiet_hours() -> None:
    """Daily at 7:45 AM IST (02:15 UTC), weekly on Mondays at 7:50 AM IST: after 01:30 UTC, when
    the day's indices exist, and before the Kibana write window opens at 02:30 UTC."""
    for folder in (UNITS_DIR, CUSTODY_UNITS):
        assert parse(folder / "argus-report-daily.timer")["Timer"]["OnCalendar"] == (
            "*-*-* 02:15:00 UTC"
        )
        assert parse(folder / "argus-report-weekly.timer")["Timer"]["OnCalendar"] == (
            "Mon *-*-* 02:20:00 UTC"
        )


@pytest.mark.parametrize("kind", KINDS)
def test_each_service_runs_the_report_once_and_ends(kind: str) -> None:
    user = parse(UNITS_DIR / f"argus-report-{kind}.service")
    assert user["Service"]["Type"] == "oneshot"
    assert user["Service"]["ExecStart"].endswith(f"argus report {kind}")
    assert "Install" not in user  # started by its timer, never enabled itself
    system = parse(CUSTODY_UNITS / f"argus-report-{kind}.service")
    assert system["Service"]["ExecStart"] == f"/opt/argus/current/.venv/bin/argus report {kind}"
    assert system["Service"]["User"] == "argus-svc"
    text = (CUSTODY_UNITS / f"argus-report-{kind}.service").read_text()
    assert "Environment=ARGUS_CUSTODY__ROLE=svc" in text


def test_the_commands_the_units_run_exist() -> None:
    from typer.main import get_command

    group = get_command(app)
    assert {"daily", "weekly"} <= set(group.commands["report"].commands)  # type: ignore[attr-defined]


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="needs systemd-analyze")
def test_systemd_reads_the_units_without_a_complaint(tmp_path: Path) -> None:
    names = [f"argus-report-{k}.{t}" for k in KINDS for t in ("service", "timer")]
    files = [str(p) for p in render_into(tmp_path, names)]
    done = subprocess.run(  # noqa: S603 - fixed program, repository files
        ["systemd-analyze", "--user", "verify", *files],  # noqa: S607
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert (done.returncode, done.stderr.strip()) == (0, "")
