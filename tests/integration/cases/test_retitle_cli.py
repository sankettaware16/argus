"""``argus case retitle`` end to end on a throwaway database (D-230): a person's new title with a
reason, and ``--all`` (with ``--dry-run``) making ARGUS's own titles again from the facts."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import Result

from tests.integration.cases.conftest import Person
from tests.integration.cases.test_retitle import flag_server
from tests.integration.cases.test_split import Six, make_six
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration

STALE = "Several campus devices reach outside infrastructure flagged by threat intel"
FRESH = "Amadey contact from 2 campus devices to 158.94.208.81"


def _ok(result: Result) -> str:
    assert result.exit_code == 0, result.output + result.stderr
    return result.output


@pytest.fixture
async def two(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> tuple[Six, Six]:
    """Case 1: ARGUS's suggested case, with a stale title. Case 2: a person's, same facts."""
    mine = await make_six(migrated_engine, app_engine)
    await flag_server(migrated_engine)
    theirs = await make_six(migrated_engine, app_engine, suspected=False, person=people["ravi"])
    return mine, theirs


def test_a_person_renames_a_case_at_the_terminal(cli_env: Path, two: tuple[Six, Six]) -> None:  # noqa: F811
    done = _ok(_run("case", "retitle", "1", "--title", "Amadey infection on 10.198.36.230",
                    "--as", "asha", "--reason", "known family", "--version", "1"))  # fmt: skip
    assert done == "case 1: retitled, now suspected (version 2)\n"
    shown = _ok(_run("case", "show", "1"))
    assert "Amadey infection on 10.198.36.230" in shown
    assert "retitled by user:" in shown
    assert _ok(_run("case", "replay", "1")).startswith("case 1: its 2 events rebuild it exactly")
    same = _run("case", "retitle", "1", "--title", "Amadey infection on 10.198.36.230",
                "--as", "asha", "--reason", "again")  # fmt: skip
    assert (same.exit_code, "has that title already" in same.stderr) == (1, True)
    stale = _run("case", "retitle", "1", "--title", "x", "--as", "asha", "--reason", "r",
                 "--version", "1")  # fmt: skip
    assert (stale.exit_code, "the case changed meanwhile" in stale.stderr) == (1, True)
    # ARGUS's pass leaves it: a person wrote it
    swept = _ok(_run("case", "retitle", "--all"))
    assert "Amadey infection on 10.198.36.230" not in swept
    assert "a person's title, left alone: 2" in swept


def test_the_arguments_go_together(cli_env: Path, two: tuple[Six, Six]) -> None:  # noqa: F811
    for args in (
        ("1", "--title", "x", "--as", "asha"),  # no reason
        ("1", "--reason", "x", "--as", "asha"),  # no title
        ("--title", "x", "--as", "asha", "--reason", "r"),  # no case
        ("1", "--title", "x", "--reason", "r"),  # no person
        ("1", "--title", "x", "--as", "asha", "--reason", "r", "--dry-run"),  # dry run needs --all
        ("--all", "1"),
        ("--all", "--title", "x"),
        ("--all", "--as", "asha"),
    ):
        result = _run("case", "retitle", *args)
        assert result.exit_code == 2, (args, result.output + result.stderr)
    nobody = _run("case", "retitle", "1", "--title", "x", "--as", "nobody", "--reason", "r")
    assert (nobody.exit_code, "is not an active person's account" in nobody.stderr) == (1, True)
    assert (
        _run("case", "retitle", "9", "--title", "x", "--as", "asha", "--reason", "r").exit_code == 1
    )


def test_all_dry_run_shows_old_and_new_and_writes_nothing(
    cli_env: Path,  # noqa: F811
    two: tuple[Six, Six],
) -> None:
    before = _ok(_run("case", "list"))
    out = _ok(_run("case", "retitle", "--all", "--dry-run"))
    assert "dry run: 2 cases looked at" in out.splitlines()
    assert f"  case 1: {STALE} -> {FRESH}" in out
    assert "a person's title, left alone: 1" in out
    assert "would change: 1 of 1" in out
    assert _ok(_run("case", "list")) == before  # not a title, not a version
    assert _ok(_run("case", "replay", "1")).startswith("case 1: its 1 events rebuild it exactly")


def test_all_makes_arguss_titles_again_and_a_person_keeps_theirs(
    cli_env: Path,  # noqa: F811
    two: tuple[Six, Six],
) -> None:
    out = _ok(_run("case", "retitle", "--all"))
    assert "2 cases looked at" in out.splitlines()
    assert f"  case 1: {STALE} -> {FRESH}" in out
    assert "changed: 1 of 1" in out
    listed = _ok(_run("case", "list")).splitlines()
    assert "Regular beaconing from campus hosts" in listed[0]  # case 2, a person's
    assert FRESH in listed[1]
    assert " v2 " in listed[1]
    assert _ok(_run("case", "replay", "1")).startswith("case 1: its 2 events rebuild it exactly")
    again = _ok(_run("case", "retitle", "--all"))
    assert "changed: 0 of 0" in again
    assert "->" not in again
