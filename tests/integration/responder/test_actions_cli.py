"""``argus case actions`` end to end on a throwaway database (Q-H2). Advice only, in plain
words, and it works with every model provider down: any attempt to send a request fails the
test."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import Result

from argus.responder import store
from tests.conftest import plain
from tests.integration.cases.conftest import Person
from tests.integration.responder.kit import Scene
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration

ISOLATE, BLOCK = "c2_beacon.isolate_host", "c2_beacon.block_destination"


def _ok(result: Result) -> str:
    assert result.exit_code == 0, result.output + result.stderr
    return result.output


@pytest.fixture(autouse=True)
def nothing_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    """No provider, no SIEM, no Kibana: a request of any kind fails the test."""

    def refuse(*args: Any, **kw: Any) -> Any:
        raise AssertionError("the responder sent a request")

    monkeypatch.setattr(httpx.AsyncClient, "send", refuse)
    monkeypatch.setattr(httpx.Client, "send", refuse)


@pytest.fixture
async def case(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> uuid.UUID:
    scene = Scene(migrated_engine, app_engine)
    now = datetime.now(UTC) - timedelta(hours=3)
    return (await scene.beacon_case(people["asha"], now))[0]


@pytest.fixture
async def second(
    migrated_engine: AsyncEngine,
    app_engine: AsyncEngine,
    people: dict[str, Person],
    case: uuid.UUID,
) -> uuid.UUID:
    scene = Scene(migrated_engine, app_engine)
    now = datetime.now(UTC) - timedelta(hours=3)
    return (await scene.exposed_env_case(people["asha"], now))[0]


async def stored(engine: AsyncEngine) -> list[Any]:
    async with engine.connect() as conn:
        return list(await conn.execute(text("SELECT action, state FROM case_actions ORDER BY id")))


def test_the_listing_is_advice_only_and_writes_nothing(
    cli_env: Path,  # noqa: F811
    case: uuid.UUID,
    migrated_engine: AsyncEngine,
) -> None:
    import asyncio

    out = _ok(_run("case", "actions", "1"))
    assert "2 advised action(s); advice only, nothing runs" in out
    assert f"1. {ISOLATE}  [recommended]  Take the computers off the network" in out.replace(
        "  1.", "1."
    )
    assert "(owner: Network team)" in out
    assert asyncio.run(stored(migrated_engine)) == []


def test_recommend_request_and_report_through_the_terminal(
    cli_env: Path,  # noqa: F811
    case: uuid.UUID,
    migrated_engine: AsyncEngine,
) -> None:
    import asyncio

    assert "recorded 2 new recommendation(s)" in _ok(_run("case", "actions", "1", "--recommend"))
    assert "recorded 0 new recommendation(s)" in _ok(_run("case", "actions", "1", "--recommend"))
    asked = _ok(_run("case", "actions", "1", "--request", ISOLATE, "--as", "asha"))
    assert f"{ISOLATE}: request recorded" in asked
    assert "[requested]" in asked
    assert "Requested: the Network team was asked by Asha" in asked
    told = _ok(
        _run(
            "case",
            "actions",
            "1",
            "--done",
            BLOCK,
            "--as",
            "asha",
            "--attest",
            "The firewall rule is in place",
        )
    )
    assert f"{BLOCK}: reported done (an attestation)" in told
    assert "[reported_done]" in told
    assert "their words: The firewall rule is in place" in told
    assert "ARGUS cannot see the action" in told
    assert asyncio.run(stored(migrated_engine)) == [
        (ISOLATE, "requested"),
        (BLOCK, "reported_done"),
    ]
    # a later listing shows the same without asking anyone
    assert "[reported_done]" in _ok(_run("case", "actions", "1"))


def test_refusals_are_one_plain_line_each(
    cli_env: Path,  # noqa: F811
    case: uuid.UUID,
) -> None:
    _ok(_run("case", "actions", "1", "--recommend"))
    _ok(_run("case", "actions", "1", "--done", BLOCK, "--as", "asha", "--attest", "Done"))

    needs_a_person = _run("case", "actions", "1", "--request", ISOLATE)
    assert needs_a_person.exit_code == 2
    assert "--as" in plain(needs_a_person.stderr)
    assert _run("case", "actions", "1", "--done", ISOLATE, "--as", "asha").exit_code == 2
    two = _run("case", "actions", "1", "--recommend", "--request", ISOLATE, "--as", "asha")
    assert two.exit_code == 2

    unknown = _run("case", "actions", "1", "--request", "c2_beacon.wipe", "--as", "asha")
    assert unknown.exit_code == 2  # refused (invalid) is a usage error, as the case commands say
    assert "is not an action of the catalogue" in unknown.stderr

    again = _run("case", "actions", "1", "--done", BLOCK, "--as", "asha", "--attest", "Twice")
    assert again.exit_code == 1
    assert (
        "refused (conflict): a person cannot move an action from reported_done to" in again.stderr
    )

    stranger = _run("case", "actions", "1", "--request", ISOLATE, "--as", "nobody")
    assert stranger.exit_code == 1
    assert "refused (forbidden)" in stranger.stderr

    hostile = _run("case", "actions", "1", "--request", ISOLATE, "--as", "asha\x1b[2J")
    assert hostile.exit_code == 1
    assert "\x1b" not in hostile.stderr + hostile.output

    bell = _run("case", "actions", "1", "--done", ISOLATE, "--as", "asha", "--attest", "x\x07y")
    assert bell.exit_code == 2
    assert "cannot be shown" in bell.stderr

    assert _run("case", "actions", "99").exit_code == 1


def test_the_sync_records_advice_for_every_watched_case_and_is_idempotent(
    cli_env: Path,  # noqa: F811
    case: uuid.UUID,
    migrated_engine: AsyncEngine,
) -> None:
    import asyncio

    first = _ok(_run("case", "actions-sync"))
    assert "case 1: 2 recommended" in first
    assert _ok(_run("case", "actions-sync")).splitlines()[-1] in (
        "nothing to record",
        "watch settings unavailable: nothing can be verified",
    )
    assert asyncio.run(stored(migrated_engine)) == [
        (ISOLATE, "recommended"),
        (BLOCK, "recommended"),
    ]


def test_one_case_that_cannot_be_recorded_is_a_problem_line_and_the_rest_go_on(
    cli_env: Path,  # noqa: F811
    case: uuid.UUID,
    second: uuid.UUID,
    migrated_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review R5: the sync used to run every case in one transaction, so one case that raised
    rolled back the verdicts of all of them, every day."""
    import asyncio

    real = store.refresh

    async def refresh(conn: Any, case_id: uuid.UUID, *args: Any, **kw: Any) -> Any:
        if case_id == case:
            raise RuntimeError("boom")
        return await real(conn, case_id, *args, **kw)

    monkeypatch.setattr(store, "refresh", refresh)
    out = _ok(_run("case", "actions-sync"))
    assert "case 1: could not be recorded (RuntimeError)" in out
    assert "case 2: 2 recommended" in out
    assert [a for a, _ in asyncio.run(stored(migrated_engine))] == [
        "exposed_file.remove_file",
        "exposed_file.rotate_secrets",
    ]  # the bad case wrote nothing; the other is recorded
