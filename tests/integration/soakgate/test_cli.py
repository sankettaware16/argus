"""P4-A1: ``argus soak phase3`` end to end on a throwaway database: the table, ``--json``,
``--write``, the window options and the exit code. The command logs in as the runtime role, reads,
and sends nothing."""

from __future__ import annotations

import json
import re
import stat
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.cases.conftest import Person
from tests.integration.soakgate import kit
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration

LINE = re.compile(r"^(PASS|FAIL|PENDING|OPEN)\s+\d+  ")


@pytest.fixture
def folders(
    cli_env: Path,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    migrated_engine: AsyncEngine,
) -> Path:
    """The soak folder and the backups in ``tmp_path``, not in the checkout."""
    monkeypatch.setenv("ARGUS_SOAK__DIR", str(tmp_path / "gate" / "soak"))
    monkeypatch.setenv("ARGUS_BACKUP__DIR", str(tmp_path / "backups"))
    return tmp_path


@pytest.fixture
async def second_create(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """A create that was sent twice: line 1 fails."""
    case_id, _ = await kit.case(migrated_engine, app_engine, people["asha"], "10.9.9.9")
    await kit.post(migrated_engine, case_id, 1, kibana="k-1", opened_at=kit.DAY)
    await kit.step(migrated_engine, case_id, 1, kind="open", sent_count=2)


def test_the_table_lists_eleven_lines_and_the_legend(folders: Path) -> None:
    result = _run("soak", "phase3", "--since", "2026-10-30T12:45:00+00:00")
    assert result.exit_code == 0, result.output + result.stderr
    lines = result.stdout.splitlines()
    assert lines[0].startswith("phase3 gate: 2026-10-30 12:45 to ")
    assert len([ln for ln in lines if LINE.match(ln)]) == 11
    assert "PASS 0, FAIL 0," in result.stdout
    assert "OPEN: only a person can say" in result.stdout


def test_json_is_the_whole_result_and_nothing_else(folders: Path) -> None:
    result = _run("soak", "phase3", "--json", "--days", "3")
    assert result.exit_code == 0, result.output + result.stderr
    data = json.loads(result.stdout)
    assert data["schema"] == "soak-gate@1"
    assert data["gate"] == "phase3"
    assert [line["number"] for line in data["lines"]] == list(range(1, 12))
    assert data["window"]["days"] == pytest.approx(3.0, abs=0.01)
    assert sum(data["summary"].values()) == 11
    checks = [c for line in data["lines"] for c in line["checks"]]
    assert all({"id", "verdict", "n", "detail", "needs", "measured"} <= set(c) for c in checks)
    assert not [c for c in checks if c["verdict"] == "FAIL"]


def test_write_saves_a_private_timestamped_json_and_says_where(folders: Path) -> None:
    result = _run("soak", "phase3", "--write", "--json")
    assert result.exit_code == 0, result.output + result.stderr
    data = json.loads(result.stdout)
    saved = sorted((folders / "gate" / "soak").glob("*.json"))
    assert len(saved) == 1
    stamp = datetime.fromisoformat(data["generated_at"])
    assert saved[0].name == f"{stamp:%Y%m%dT%H%M%SZ}.json"
    assert json.loads(saved[0].read_text()) == data
    assert stat.S_IMODE(saved[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(saved[0].parent.stat().st_mode) == 0o700
    assert f"saved {saved[0]}" in result.stderr


def test_a_failing_line_exits_1_after_the_report_is_saved(
    folders: Path, second_create: None
) -> None:
    result = _run("soak", "phase3", "--write", "--since", "2026-10-30T00:00:00+00:00")
    assert result.exit_code == 1, result.output + result.stderr
    failed = [ln for ln in result.stdout.splitlines() if LINE.match(ln) and ln.startswith("FAIL")]
    assert "FAIL      1  Case-team lifecycle" in failed
    assert "No second create sent" in result.stdout
    assert len(list((folders / "gate" / "soak").glob("*.json"))) == 1


def test_a_window_that_cannot_be_is_exit_2_with_a_line_on_stderr(folders: Path) -> None:
    for args in (("--days", "0"), ("--since", "2099-01-01"), ("--since", "nonsense")):
        result = _run("soak", "phase3", *args)
        assert result.exit_code == 2, (args, result.output + result.stderr)
        assert "Traceback" not in result.output + result.stderr
