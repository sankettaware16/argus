"""``argus case watch``, ``argus case contain`` and ``argus case suggestions`` end to end on a
throwaway database (Q-C2). Nothing here can reach the SIEM: the watch is off by default, "local"
asks nothing, and "on" without a key stops before it builds a gateway."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import Result

from tests.integration.cases.conftest import Person
from tests.integration.cases.watchkit import C2, H1, H2, World
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration


def _ok(result: Result) -> str:
    assert result.exit_code == 0, result.output + result.stderr
    return result.output


@pytest.fixture
async def case(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> dict[str, uuid.UUID]:
    """Case 1 (host H1, a C2) opened an hour ago, and a second host that reached the same C2
    five minutes ago."""
    world = World(migrated_engine, app_engine)
    now = datetime.now(UTC)
    first = await world.investigation(H1, [now - timedelta(minutes=50)])
    case_id = await world.open_case(people["asha"], [first], [H1], now - timedelta(hours=1))
    second = await world.investigation(H2, [now - timedelta(minutes=5)])
    return {"first": first, "second": second, "case": case_id}


def test_the_watch_is_off_until_it_is_switched_on(cli_env: Path) -> None:  # noqa: F811
    assert "the still-active watch is off" in _ok(_run("case", "watch", "run"))


def test_the_local_watch_joins_what_matches_and_reports_in_plain_words(
    cli_env: Path,  # noqa: F811
    case: dict[str, uuid.UUID],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUS_CASES__WATCH", "local")
    dry = _ok(_run("case", "watch", "run", "--dry-run"))
    assert dry.startswith("dry run: mode: local; 1 case(s) watched; 0 request(s)")
    assert "joined 1, following 0, suggested 0, cut off 0" in dry
    assert " 1 inv." in _ok(_run("case", "list"))  # a dry run changed nothing
    done = _ok(_run("case", "watch", "run"))
    assert done.startswith("mode: local; 1 case(s) watched; 0 request(s)")
    assert "joined 1, following 0, suggested 0, cut off 0" in done
    assert " 2 inv." in _ok(_run("case", "list"))
    assert "joined" not in _ok(_run("case", "watch", "run"))  # a second run joins nothing


def test_the_watch_on_without_a_key_stops_before_asking_anything(
    cli_env: Path,  # noqa: F811
    case: dict[str, uuid.UUID],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUS_CASES__WATCH", "on")
    failed = _run("case", "watch", "run")
    assert failed.exit_code == 1
    assert "siem.api_key is not set" in failed.stderr
    planned = _ok(_run("case", "watch", "run", "--dry-run"))  # a dry run builds no gateway
    assert planned.startswith("dry run: mode: on")


def test_contain_is_refused_with_the_reason_and_status_says_where_the_case_stands(
    cli_env: Path,  # noqa: F811
    case: dict[str, uuid.UUID],
) -> None:
    refused = _run("case", "contain", "1", "--as", "asha", "--attest", "the host was cleaned")
    assert refused.exit_code == 1
    assert "refused (unavailable): not contained:" in refused.stderr
    assert "not switched on yet (Q-F1)" in refused.stderr
    status = _ok(_run("case", "watch", "status", "1"))
    assert status.startswith("watch mode: off")
    assert "the watch has never run" in status  # review R17: and when it last ran, otherwise
    assert "quiet for 72 hours: no:" in status
    assert "not switched on yet (Q-F1)" in status
    missing = _run("case", "watch", "status", "99")
    assert missing.exit_code == 1


def test_a_suggestion_is_listed_until_it_is_dismissed(
    cli_env: Path,  # noqa: F811
    case: dict[str, uuid.UUID],
    migrated_engine: AsyncEngine,
) -> None:
    import asyncio

    async def plant() -> None:
        async with migrated_engine.begin() as conn:
            case_id = (await conn.execute(text("SELECT id FROM cases"))).scalar_one()
            await conn.execute(
                text(
                    "INSERT INTO case_suggestions (investigation_id, case_id, link, link_value,"
                    " kind, why) VALUES (:i, :c, 'c2', :v, 'shared', 'a content-delivery"
                    " address, not enough on its own')"
                ),
                {"i": case["second"], "c": case_id, "v": C2},
            )

    asyncio.run(plant())
    listed = _ok(_run("case", "suggestions"))
    assert f"investigation {case['second']} -> case 1 (open) [shared] a content-delivery" in listed
    needs_a_person = _run("case", "suggestions", "--dismiss", "1")
    assert needs_a_person.exit_code == 2
    assert _ok(_run("case", "suggestions", "--dismiss", "1", "--as", "asha")) == (
        "suggestion 1 dismissed\n"
    )
    assert _ok(_run("case", "suggestions")) == "no suggestions\n"
    again = _run("case", "suggestions", "--dismiss", "1", "--as", "asha")
    assert again.exit_code == 1
    assert "no open suggestion 1" in again.stderr
