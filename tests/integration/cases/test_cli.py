"""``argus case`` and ``argus audit`` end to end on a throwaway database (Q-C1)."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import Result

from tests.conftest import plain
from tests.integration.cases.conftest import Person, investigation
from tests.integration.cases.test_opener import BEACON, _dossier, _review
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture


@pytest.fixture
async def seeded(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> dict[str, uuid.UUID]:
    beacon = await investigation(migrated_engine, rule="c2", actor=(("source.ip", "10.9.9.9"),),
                                 entities=(("ip", "77.221.155.150"),))  # fmt: skip
    await _dossier(migrated_engine, beacon, BEACON, ["77.221.155.150"])
    await _review(app_engine, people["asha"], beacon)
    other = await investigation(migrated_engine, rule="web", actor=(("source.ip", "10.9.9.8"),))
    return {"beacon": beacon, "other": other}


def _ok(result: Result) -> str:
    assert result.exit_code == 0, result.output + result.stderr
    return result.output


def test_audit_verify_and_head(cli_env: Path, seeded: dict[str, uuid.UUID]) -> None:  # noqa: F811
    out = _ok(_run("audit", "verify"))
    assert out.splitlines()[0].startswith("PASS  audit_events  ")
    assert out.splitlines()[1].startswith("PASS  case_events  0 rows chained")
    heads = _ok(_run("audit", "head")).splitlines()
    assert [line.split()[0] for line in heads] == ["audit_events", "case_events"]


def test_a_case_from_open_to_assigned_at_the_terminal(
    cli_env: Path,  # noqa: F811
    seeded: dict[str, uuid.UUID],
) -> None:
    inv = str(seeded["other"])
    out = _ok(_run("case", "open", "--as", "asha", "--investigation", inv, "--title",
                   "Odd answers from 10.9.9.8", "--severity", "high"))  # fmt: skip
    assert out.startswith("case 1 opened (")
    assert "Waiting for someone who may open cases in Kibana" in out
    assert _ok(_run("case", "take", "1", "--as", "ravi", "--version", "1")) == (
        "case 1: taken, now assigned (version 2)\n"
    )
    stale = _run("case", "release", "1", "--as", "ravi", "--version", "1")
    assert stale.exit_code == 1
    assert "refused (conflict): the case changed meanwhile" in stale.stderr
    nobody = _run("case", "release", "1", "--as", "nobody")
    assert (nobody.exit_code, "is not an active person's account" in nobody.stderr) == (1, True)
    _ok(_run("case", "assign", "1", "--to", "meera", "--as", "ravi", "--version", "2"))
    _ok(_run("case", "note", "1", "--as", "meera", "--text", "called the lab admin"))
    shown = _ok(_run("case", "show", "1"))
    assert "state assigned, severity high, version 3, owner user:3" in shown
    assert "v2 " in shown
    assert "taken by user:2" in shown
    assert _ok(_run("case", "replay", "1")) == "case 1: its 3 events rebuild it exactly\n"
    listed = _ok(_run("case", "list"))
    assert listed.split()[:4] == ["1", "assigned", "high", "v3"]
    assert _run("case", "show", "99").exit_code == 1
    assert _run("case", "show", "not-a-case").exit_code == 2


def test_backfill_is_a_dry_run_unless_applied(cli_env: Path, seeded: dict[str, uuid.UUID]) -> None:  # noqa: F811
    dry = _ok(_run("case", "backfill"))
    assert dry.splitlines()[0] == (
        "dry run: verdicts and proposals of the last 5d and since 2026-10-14"
    )
    assert "opened" in dry
    assert "planned: opened 1" in dry
    assert _ok(_run("case", "list")) == "no cases\n"
    applied = _ok(_run("case", "backfill", "--apply"))
    assert "applied: opened 1" in applied
    listed = _ok(_run("case", "list"))
    assert "Confirmed beaconing from 10.9.9.9 to 77.221.155.150 (on a threat list)" in listed
    assert "planned: nothing" in _ok(_run("case", "sync"))
    assert _run("case", "backfill", "--window", "10m").exit_code == 2
    assert _run("case", "backfill", "--since", "14-10-2026").exit_code == 2


def test_argus_approvals_at_the_terminal(
    cli_env: Path,  # noqa: F811
    seeded: dict[str, uuid.UUID],
    tmp_path: Path,
) -> None:
    """Q-C3: a key is made private; the send-time checks are a dry run without --apply and
    need the writer's key; the ledger and ARGUS's proposals say what there is."""
    key = tmp_path / "approval.key"
    made = _ok(_run("approvals", "keygen", str(key)))
    assert made.startswith("wrote approval key ")
    assert key.stat().st_mode & 0o777 == 0o600
    again = _run("approvals", "keygen", str(key))
    assert again.exit_code == 1
    assert "exists" in again.stderr
    missing = _run("approvals", "check-send")
    assert (missing.exit_code, "--key" in plain(missing.stderr)) == (2, True)
    key.chmod(0o644)
    loose = _run("approvals", "check-send", "--key", str(key))
    assert (loose.exit_code, "read by others" in loose.stderr) == (1, True)
    key.chmod(0o600)
    assert _ok(_run("approvals", "check-send", "--key", str(key))) == (
        "no closure write is waiting\n"
    )
    assert _ok(_run("approvals", "propose")) == "nothing to propose\n"
    assert _ok(_run("approvals", "apply")) == "nothing to apply\n"
    ledger = _ok(_run("approvals", "ledger"))
    assert "approvals expired unsent: not measured (no items)" in ledger
    assert "ARGUS has proposed no closure yet" in ledger
