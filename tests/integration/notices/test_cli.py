"""``argus notices run | status | test`` end to end on a throwaway database and a fake relay
(Q-H4): off by default and saying so, a dry run that changes nothing, the pass that sends, the
user's test message, and no secret in any output."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from typer.testing import Result

from argus.assets.classify import IpClassifier
from tests.fakesmtp import FakeSmtp
from tests.integration.cases.watchkit import World
from tests.integration.notices.test_triggers import hit
from tests.integration.test_cli_db import _SECRETS, _run, cli_env  # noqa: F401 - the fixture

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("migrated_engine")]

PASSWORD = "Synthetic-Relay-11"
assert (
    IpClassifier
)  # the campus test of the pass is the opener's (the asset map is not loaded here)


def _ok(result: Result) -> str:
    assert result.exit_code == 0, result.output + result.stderr
    return result.output


@pytest.fixture
def relay(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSmtp]:
    with FakeSmtp() as server:
        monkeypatch.setenv("ARGUS_NOTICES__RELAY_HOST", server.host)
        monkeypatch.setenv("ARGUS_NOTICES__RELAY_PORT", str(server.port))
        monkeypatch.setenv("ARGUS_NOTICES__RELAY_STARTTLS", "false")
        monkeypatch.setenv("ARGUS_NOTICES__RELAY_FROM", "argus@example.org")
        monkeypatch.setenv("ARGUS_NOTICES__RECIPIENTS", "ta@example.org,ra@example.org")
        monkeypatch.setenv("ARGUS_NOTICES__WEB_URL", "https://argus.example.org")
        yield server


@pytest.fixture
def switched_on(monkeypatch: pytest.MonkeyPatch, relay: FakeSmtp) -> FakeSmtp:
    monkeypatch.setenv("ARGUS_NOTICES__ENABLED", "true")
    return relay


async def count(world: World, sql: str) -> int:
    async with world.owner.connect() as conn:
        return int((await conn.execute(text(sql))).scalar_one())


def test_notices_are_off_and_say_so(cli_env: Path, relay: FakeSmtp) -> None:  # noqa: F811
    ran = _ok(_run("notices", "run"))
    assert ran.startswith("notices: not switched on, by your choice")
    status = _ok(_run("notices", "status"))
    assert "notices: OFF (not switched on, by your choice)" in status
    assert "recipients named (2): ta@example.org, ra@example.org" in status
    assert "last pass: " in status
    assert relay.connections == 0


def test_the_test_message_is_refused_while_notices_are_off(
    cli_env: Path,  # noqa: F811
    relay: FakeSmtp,
) -> None:
    refused = _run("notices", "test", "--to", "me@example.org")
    assert refused.exit_code == 1
    assert "not switched on, by your choice" in refused.stderr
    assert relay.connections == 0


def test_the_test_message_reaches_the_address_it_is_sent_to(
    cli_env: Path,  # noqa: F811
    switched_on: FakeSmtp,
) -> None:
    assert "handed to the relay" in _ok(_run("notices", "test", "--to", "me@example.org"))
    (got,) = switched_on.received
    assert got.rcpt_to == ["me@example.org"]
    assert dict(got.headers)["Subject"] == "ARGUS test notice"
    assert dict(got.headers)["From"] == "argus@example.org"


@pytest.mark.parametrize(
    "address",
    ["me@example.org\r\nBcc: evil@example.org", "a@example.org, b@example.org", "not an address"],
)
def test_the_test_message_refuses_a_hostile_address(
    cli_env: Path,  # noqa: F811
    switched_on: FakeSmtp,
    address: str,
) -> None:
    refused = _run("notices", "test", "--to", address)
    assert refused.exit_code == 1
    assert "one plain e-mail address" in refused.stderr
    assert switched_on.connections == 0


def test_a_dry_run_shows_what_would_go_out_and_changes_nothing(
    cli_env: Path,  # noqa: F811
    world: World,
    switched_on: FakeSmtp,
) -> None:
    import asyncio

    asyncio.run(hit(world))
    out = _ok(_run("notices", "run", "--dry-run"))
    assert out.startswith("dry run: nothing stored or sent")
    assert "1 notice(s) due" in out
    assert "would send: [ARGUS High] A campus host reached a known-bad address" in out
    assert switched_on.connections == 0
    assert asyncio.run(count(world, "SELECT count(*) FROM notices")) == 0


def test_the_pass_sends_once_and_status_says_what_it_holds(
    cli_env: Path,  # noqa: F811
    world: World,
    switched_on: FakeSmtp,
) -> None:
    import asyncio

    asyncio.run(hit(world))
    first = _ok(_run("notices", "run"))
    assert first.startswith("notices: ON")
    assert "sent 1, folded 0, failed 0" in first
    assert len(switched_on.received) == 1
    assert dict(switched_on.received[0].headers)["Subject"] == (
        "[ARGUS High] A campus host reached a known-bad address"
    )
    second = _ok(_run("notices", "run"))
    assert "sent 0" in second
    assert len(switched_on.received) == 1
    status = _ok(_run("notices", "status"))
    assert "notices: ON, through 127.0.0.1:" in status
    assert "recipients (2): ta@example.org, ra@example.org" in status
    assert "links point to: https://argus.example.org" in status
    assert "ioc_hit: 1 live, 1 told" in status
    assert "e-mails in the last hour: 1 of 10" in status
    assert (
        asyncio.run(count(world, "SELECT count(*) FROM audit_events WHERE action = 'notice.run'"))
        == 2
    )


def test_a_relay_that_fails_makes_the_command_fail_and_prints_no_secret(
    cli_env: Path,  # noqa: F811
    world: World,
    switched_on: FakeSmtp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    asyncio.run(hit(world))
    monkeypatch.setenv("ARGUS_NOTICES__RELAY_STARTTLS", "true")  # this relay cannot do TLS
    monkeypatch.setenv("ARGUS_NOTICES__USER", "argus")
    monkeypatch.setenv("ARGUS_NOTICES__PASSWORD", PASSWORD)
    _SECRETS.append(PASSWORD)
    try:
        failed = _run("notices", "run")
        status = _run("notices", "status")
        config = _run("config", "show")
    finally:
        _SECRETS.remove(PASSWORD)
    assert failed.exit_code == 1
    assert "SMTPNotSupportedError" in failed.output + failed.stderr
    assert switched_on.received == []
    assert switched_on.logins == []  # the password was not even offered without TLS
    for result in (failed, status, config):
        assert PASSWORD not in result.output + result.stderr
    assert asyncio.run(count(world, "SELECT count(*) FROM notices WHERE sent_at IS NOT NULL")) == 0


def test_doctor_has_a_notices_line_that_says_off_is_a_choice(
    cli_env: Path,  # noqa: F811
) -> None:
    shown = _run("doctor").output
    line = next(line for line in shown.splitlines() if "notices" in line and "PASS" in line)
    assert "off (notices.enabled): nothing is e-mailed, by your choice" in line


def test_a_second_pass_while_one_runs_does_nothing_and_is_not_an_error(
    cli_env: Path,  # noqa: F811
    world: World,
    switched_on: FakeSmtp,
) -> None:
    import asyncio

    from sqlalchemy import text as sql

    from argus.notices import run

    async def hold() -> object:
        conn = await world.runtime.connect()
        conn = await conn.execution_options(isolation_level="AUTOCOMMIT")
        await conn.execute(sql("SELECT pg_advisory_lock(:k)"), {"k": run.LOCK_KEY})
        return conn

    held: Any = asyncio.run(hold())  # the lock belongs to a connection of its own
    try:
        out = _ok(_run("notices", "run"))
    finally:
        asyncio.run(held.close())
    assert out.strip() == "another pass of the notices is in progress: nothing was done"
