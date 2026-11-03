"""``argus case split`` end to end on a throwaway database (D-211): the same split the service
makes, from the terminal, with the words a person reads and the refusals they get."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import Result

from argus.cases.machine import Confirm, Notify
from argus.cases.service import CaseService
from tests.integration.cases.conftest import Person, investigation
from tests.integration.cases.test_split import A, B, S, Six, make_six
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration


def _ok(result: Result) -> str:
    assert result.exit_code == 0, result.output + result.stderr
    return result.output


@pytest.fixture
async def six(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> Six:
    return await make_six(migrated_engine, app_engine)


def test_a_device_is_split_into_a_new_case_at_the_terminal(
    cli_env: Path,  # noqa: F811
    six: Six,
) -> None:
    done = _ok(
        _run("case", "split", "1", "--as", "asha", "--investigation", str(six.b1), "--title",
             "Regular beaconing from a hostel device", "--severity", "high", "--reason",
             "two separate devices", "--version", "1")
    )  # fmt: skip
    assert done.splitlines()[0] == (
        "case 1: 1 investigation(s) moved to case 2 (opened); case 1 is suspected (version 2),"
        " case 2 is open (version 1)"
    )
    assert f"  left case 1 with them: ip {B}" in done
    assert "Waiting for someone who may open cases in Kibana" in done
    shown = _ok(_run("case", "show", "1"))
    assert f"actor: ip {A}" in shown
    assert f"indicator: ip {S}" in shown
    assert f"actor: ip {B}" not in shown
    assert "unlinked by user:" in shown
    other = _ok(_run("case", "show", "2"))
    assert f"actor: ip {B}" in other
    assert "high" in other.splitlines()[1]
    for number, events in (("1", "2"), ("2", "1")):
        assert _ok(_run("case", "replay", number)).startswith(
            f"case {number}: its {events} events rebuild it exactly"
        )


@pytest.fixture
async def lone(migrated_engine: AsyncEngine, six: Six) -> uuid.UUID:
    return await investigation(migrated_engine, actor=(("source.ip", "10.77.3.4"),))


def test_a_device_is_split_into_an_existing_case(
    cli_env: Path,  # noqa: F811
    six: Six,
    lone: uuid.UUID,
) -> None:
    _ok(_run("case", "open", "--as", "ravi", "--investigation", str(lone), "--title",
             "Another case"))  # fmt: skip
    done = _ok(
        _run("case", "split", "1", "--as", "asha", "--investigation", str(six.b1), "--into", "2",
             "--reason", "two separate devices")
    )  # fmt: skip
    assert done.splitlines()[0] == (
        "case 1: 1 investigation(s) moved to case 2 (linked); case 1 is suspected (version 2),"
        " case 2 is open (version 2)"
    )
    shown = _ok(_run("case", "show", "2"))
    assert f"actor: ip {B}" in shown
    assert "linked by user:" in shown
    # by id as well, and a closed or missing target is one refused line
    refused = _run("case", "split", "1", "--as", "asha", "--investigation", str(six.a2), "--into",
                   "99", "--reason", "x")  # fmt: skip
    assert refused.exit_code == 1
    assert "no case 99" in refused.stderr
    for number in ("1", "2"):
        assert _ok(_run("case", "replay", number)).startswith(f"case {number}: its ")


def test_the_arguments_are_checked_before_anything_is_changed(
    cli_env: Path,  # noqa: F811
    six: Six,
) -> None:
    base = ["case", "split", "1", "--as", "asha", "--investigation", str(six.b1), "--reason", "r"]
    neither = _run(*base)
    assert neither.exit_code == 2
    assert "give --title" in neither.stderr
    both = _run(*base, "--title", "t", "--into", "2")
    assert both.exit_code == 2
    assert _run(*base, "--title", "t", "--severity", "urgent").exit_code == 2
    assert _run(*base, "--into", "2", "--severity", "low").exit_code == 2
    assert _run("case", "split", "1", "--as", "asha", "--investigation", "nope", "--title", "t",
                "--reason", "r").exit_code == 2  # fmt: skip
    assert _run("case", "split", "1", "--as", "asha", "--title", "t", "--reason", "r"
                ).exit_code == 2  # at least one investigation  # fmt: skip
    assert _run("case", "split", "1", "--as", "asha", "--investigation", str(six.b1), "--title",
                "t").exit_code == 2  # a reason is required  # fmt: skip
    assert "case 2" not in _ok(_run("case", "list"))


def test_the_refusals_are_one_line_and_change_nothing(
    cli_env: Path,  # noqa: F811
    six: Six,
) -> None:
    def split(*more: str, who: str = "asha", case: str = "1") -> Result:
        return _run("case", "split", case, "--as", who, "--title", "t", "--reason", "r", *more)

    everything = split(*[a for i in (six.a1, six.a2, six.b1) for a in ("--investigation", str(i))])
    assert everything.exit_code == 1
    assert "is a merge" in everything.stderr
    assert split("--investigation", str(six.b1), "--investigation", str(six.b1)).exit_code == 2
    stranger = split("--investigation", "00000000-0000-0000-0000-000000000042")
    assert stranger.exit_code == 1
    assert "is not in this case" in stranger.stderr
    assert split("--investigation", str(six.b1), case="99").exit_code == 1
    assert split("--investigation", str(six.b1), who="nobody").exit_code == 1
    stale = split("--investigation", str(six.b1), "--version", "5")
    assert stale.exit_code == 1
    assert "the case changed meanwhile" in stale.stderr
    blank = _run("case", "split", "1", "--as", "asha", "--title", "t", "--reason", "  ",
                 "--investigation", str(six.b1))  # fmt: skip
    assert blank.exit_code == 2
    assert "a reason is required" in blank.stderr
    assert _ok(_run("case", "list")).count("\n") == 1  # still the one case


@pytest.fixture
async def notified(
    six: Six, app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> Six:
    """The suggested case, confirmed, its owner told, and the known pass has decided b1 known."""
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(people["asha"].actor(), six.case, Confirm(None), expected_version=None)
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(people["asha"].actor(), six.case, Notify("the owner", "email"),
                            expected_version=None)  # fmt: skip
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_known_matches (investigation_id, case_id, version, outcome)"
                 " VALUES (:i, :c, 1, 'known')"), {"i": six.b1, "c": six.case},
        )  # fmt: skip
    return six


def test_a_notified_case_says_the_notice_stays(
    cli_env: Path,  # noqa: F811
    notified: Six,
) -> None:
    done = _ok(
        _run("case", "split", "1", "--as", "asha", "--investigation", str(notified.b1), "--title",
             "Hostel device", "--reason", "two separate devices")
    )  # fmt: skip
    assert "note: case 1 is notified; the notice stays with it" in done
    assert "had already decided 1 known of the moved investigations" in done
    shown = _ok(_run("case", "known", "status"))
    assert "case 1" in shown
    assert "case 2" not in shown  # the new case is not notified
