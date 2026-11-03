"""``argus case notify``, ``block``, ``blocklist`` and ``known ...`` end to end on a throwaway
database (AR4b, D-169): the same record the web writes, from the terminal."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import Result

from tests.integration.cases.conftest import Person, investigation
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration


def _ok(result: Result) -> str:
    assert result.exit_code == 0, result.output + result.stderr
    return result.output


@pytest.fixture
async def case_one(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> uuid.UUID:
    inv = await investigation(migrated_engine, rule="c2", actor=(("source.ip", "10.9.9.9"),),
                              entities=(("ip", "77.221.155.150"),))  # fmt: skip
    return inv


def test_a_notice_a_block_and_the_block_list_at_the_terminal(
    cli_env: Path,  # noqa: F811
    case_one: uuid.UUID,
) -> None:
    _ok(_run("case", "open", "--as", "asha", "--investigation", str(case_one), "--title",
             "Regular beaconing from a campus host", "--severity", "high"))  # fmt: skip
    told = _ok(
        _run("case", "notify", "1", "--as", "asha", "--told", "Hostel 5 warden", "--how", "phone",
             "--note", "she will bring the laptop in", "--version", "1")
    )  # fmt: skip
    assert told == "case 1: owner notified (personal or unmanaged); version 2\n"
    bad = _run("case", "notify", "1", "--as", "asha", "--told", "x", "--how", "pigeon")
    assert bad.exit_code == 2
    assert "how it was told is one of" in bad.stderr
    stale = _run("case", "notify", "1", "--as", "asha", "--told", "x", "--how", "email",
                 "--version", "1")  # fmt: skip
    assert stale.exit_code == 1
    assert "the case changed meanwhile" in stale.stderr
    when = _run("case", "notify", "1", "--as", "asha", "--told", "x", "--how", "email", "--at",
                "yesterday")  # fmt: skip
    assert when.exit_code == 2
    blocked = _ok(_run("case", "block", "1", "--as", "ravi", "--by", "network team", "--where",
                       "DNS", "--version", "2"))  # fmt: skip
    assert blocked == "case 1: blocked, now open (version 3)\n"
    shown = _ok(_run("case", "show", "1"))
    assert "notified" in shown
    assert "blocked" in shown
    listing = _ok(_run("case", "blocklist", "1"))
    assert listing.startswith("Subject: Please block these at the network (ARGUS case 1)")
    assert "To the head of cybersecurity," in listing
    as_csv = _ok(_run("case", "blocklist", "1", "--format", "csv"))
    assert as_csv.splitlines()[0].startswith("type,value,kind,engines_flagging")
    assert _run("case", "blocklist", "1", "--format", "pdf").exit_code == 2
    assert _run("case", "notify", "99", "--as", "asha", "--told", "x", "--how", "email"
                ).exit_code == 1  # fmt: skip
    assert _ok(_run("case", "replay", "1")).startswith("case 1: its 3 events rebuild it exactly")


def test_the_known_status_run_and_dismiss(
    cli_env: Path,  # noqa: F811
    case_one: uuid.UUID,
) -> None:
    assert _ok(_run("case", "known", "status")) == "no notified cases\n"
    _ok(_run("case", "open", "--as", "asha", "--investigation", str(case_one), "--title",
             "Regular beaconing from a campus host", "--severity", "high"))  # fmt: skip
    _ok(_run("case", "notify", "1", "--as", "asha", "--told", "the owner", "--how", "email"))
    status = _ok(_run("case", "known", "status"))
    assert status.startswith("case 1 [personal]: still active: 0 alerts in 1 day since the owner")
    assert "0 device(s), 1 notice(s), 0 block(s)" in status
    assert _run("case", "known", "dismiss", "1", "notify_again", "--as", "asha").exit_code == 1
    assert _run("case", "known", "dismiss", "1", "nonsense", "--as", "asha").exit_code == 2


def test_a_notice_recorded_by_mistake_is_withdrawn_at_the_terminal(
    cli_env: Path,  # noqa: F811
    case_one: uuid.UUID,
) -> None:
    """D-181: ``argus case withdraw-notice`` (a reason is required; who defaults to the person)."""
    _ok(_run("case", "open", "--as", "asha", "--investigation", str(case_one), "--title",
             "Regular beaconing from a campus host", "--severity", "high"))  # fmt: skip
    nothing = _run("case", "withdraw-notice", "1", "--as", "asha", "--reason", "oops")
    assert nothing.exit_code == 1
    assert "no notice to withdraw" in nothing.stderr
    _ok(_run("case", "notify", "1", "--as", "asha", "--told", "the owner", "--how", "email"))
    assert _run("case", "withdraw-notice", "1", "--as", "asha").exit_code == 2  # a reason is needed
    done = _ok(_run("case", "withdraw-notice", "1", "--as", "asha", "--reason", "wrong case",
                    "--version", "2"))  # fmt: skip
    assert done == "case 1: notice_withdrawn, now open (version 3)\n"
    assert _ok(_run("case", "known", "status")) == "no notified cases\n"
    assert _ok(_run("case", "replay", "1")).startswith("case 1: its 3 events rebuild it exactly")
    stale = _run("case", "withdraw-notice", "1", "--as", "asha", "--reason", "x", "--version", "2")
    assert stale.exit_code == 1


def test_the_known_run_builds_the_context_the_service_builds(
    cli_env: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D-181: one builder (``raising.known_for``), with the eligibility check ``eligible=``."""
    from argus import raising
    from argus.assets.assetmap import AssetMap
    from argus.assets.store import NoAssetMapError
    from argus.cases import cli, knownrun

    seen: dict[str, object] = {}

    async def fake_run(engine: object, ctx: knownrun.Context, now: object) -> knownrun.Report:
        seen["ctx"] = ctx
        return knownrun.Report()

    real = raising.known_for

    def spy(*args: object, **more: object) -> object:
        seen["built_by_the_service_builder"] = True
        return real(*args, **more)  # type: ignore[arg-type]

    monkeypatch.setattr(cli, "privacy_map", lambda settings: AssetMap([], "0" * 64))
    monkeypatch.setattr(cli.raising, "known_for", spy)
    monkeypatch.setattr(knownrun, "run", fake_run)
    out = _ok(_run("case", "known", "run"))
    assert out == "known infections: nothing new\n"
    assert seen["built_by_the_service_builder"] is True
    ctx = seen["ctx"]
    assert isinstance(ctx, knownrun.Context)
    assert ctx.eligible is not None  # the service's check that keeps campus names out
    assert ctx.view is not None

    def no_map(settings: object) -> AssetMap:  # with a key and no map: fails closed
        raise NoAssetMapError("no asset map imported: the privacy layer needs it")

    monkeypatch.setattr(cli, "privacy_map", no_map)
    refused = _run("case", "known", "run")
    assert refused.exit_code == 1
    assert "no asset map" in refused.stderr
