"""Q-F3: ``argus investigation ...`` against a throwaway database: the gaps, the dry run of a
wave (nothing sent, nothing stored), Check more queued, and the gold measurement's baseline."""

from __future__ import annotations

import asyncio
import json
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner

from argus.cli import app
from argus.gateway.budget import BudgetConfig
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.lanes import LanePlan
from argus.gateway.pgstore import PgStore
from tests.integration.investigation.kit import FIRST, LAST, NOW, SQUID, body, seed, unknown
from tests.integration.test_cli_db import cli_env  # noqa: F401
from tests.unit.investigation.kit import C2, HOST, step

pytestmark = pytest.mark.integration
TIMELINE = [step(2, "deferred", ["timeline"])]


async def cli(*args: str, given: str | None = None) -> tuple[int, str]:
    def invoke() -> tuple[int, str]:
        result = CliRunner().invoke(app, list(args), input=given)
        return result.exit_code, result.output + result.stderr

    return await asyncio.to_thread(invoke)  # the CLI runs its own event loop


@pytest.fixture(autouse=True)
def the_kits_afternoon(monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI reads the clock through one function; the tests fix it outside the quiet hours."""
    monkeypatch.setattr("argus.investigation.cli._now", lambda: NOW)


async def normal(engine: AsyncEngine) -> None:
    """The SIEM probed a moment ago and NORMAL, as the stored health says."""
    store = PgStore(engine, BudgetConfig(), LanePlan())
    await store.save_health(HealthMemory(state=HealthState.NORMAL, probed_at=NOW))


async def count(engine: AsyncEngine, table: str) -> int:
    async with engine.connect() as conn:
        return int((await conn.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one())  # noqa: S608


@pytest.mark.usefixtures("cli_env")
async def test_gaps_shows_the_ranking(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body([unknown("proxy.regularity", "timeout"),
                                            unknown("web.successes_after",
                                                    "ingest_not_verified")], TIMELINE))  # fmt: skip
    code, out = await cli("investigation", "gaps", str(inv))
    assert code == 0, out
    assert "3 gaps, 2 closable" in out
    lines = [line for line in out.splitlines() if line[:3].strip().rstrip(".").isdigit()]
    assert [line.split("[")[1].split("]")[0] for line in lines] == [
        "floor_signal, floor", "floor_signal, floor", "deferred_step"
    ]  # fmt: skip
    assert "Checks: proxy.host." in lines[1]  # regularity (the floor's order puts it after web)
    assert "not closable" in lines[0]
    code, out = await cli("investigation", "gaps", str(inv), "--json")
    assert code == 0, out
    got = json.loads(out)
    assert [g["rank"] for g in got] == [1, 2, 3]
    assert [g["key"] for g in got] == ["signal:web.successes_after", "signal:proxy.regularity",
                                       "step:2"]  # fmt: skip
    assert got[0]["blocker"] is not None
    assert got[1]["closers"] == ["proxy.host"]


@pytest.mark.usefixtures("cli_env")
async def test_gaps_for_nothing_says_so(app_engine: AsyncEngine) -> None:
    code, out = await cli("investigation", "gaps", str(uuid.uuid4()))
    assert code == 1
    assert "no dossier" in out
    code, out = await cli("investigation", "gaps", "not-an-id")
    assert code == 2


@pytest.mark.usefixtures("cli_env")
async def test_the_dry_run_sends_and_stores_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARGUS_ENRICHMENT__PROXY_AGGREGATIONS", "true")
    inv = await seed(migrated_engine, body(steps=TIMELINE), severity="high")
    code, out = await cli("investigation", "wave", "--dry-run")
    assert code == 0, out
    assert "dry run: nothing is sent" in out
    assert "a wave would wait" in out
    assert str(inv) in out
    assert "would ask" not in out  # not normal: every check is left, with its reason
    assert "normal state" in out
    await normal(app_engine)
    code, out = await cli("investigation", "wave", "--dry-run", "--id", str(inv))
    assert code == 0, out
    assert "would wait" not in out
    assert "would ask: proxy.host [heavy] squid," in out
    assert "because: the host's proxy traffic — for: Step 2 of the rule's note" in out
    assert "1 closable gaps of 1; 1 requests (1 heavy)" in out
    for table in ("evidence", "evidence_requests", "investigation_checks"):
        assert await count(app_engine, table) == 0
    assert await count(app_engine, "dossiers") == 1


@pytest.mark.usefixtures("cli_env")
async def test_a_live_wave_needs_an_investigation_and_the_confirm_word(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    code, out = await cli("investigation", "wave")
    assert code == 2
    assert "needs --id" in out
    code, out = await cli("investigation", "wave", "--id", str(inv), given="nope\n")
    assert code == 2
    assert "not confirmed: nothing was sent" in out
    assert await count(app_engine, "investigation_checks") == 0


@pytest.mark.usefixtures("cli_env")
async def test_check_more_is_checked_planned_and_queued(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(), decided=True)
    await normal(app_engine)
    code, out = await cli("investigation", "check-more", str(inv), "logs.source_events", HOST)
    assert (code, "not a check a person may ask for" in out) == (2, True)
    code, out = await cli("investigation", "check-more", str(inv), "proxy.host", "nonsense")
    assert (code, "neither an address nor a domain" in out) == (2, True)
    code, out = await cli("investigation", "check-more", str(inv), "proxy.host", C2)
    assert code == 0, out
    assert "refused:" in out
    assert "takes an internal address, not a public one" in out
    assert await count(app_engine, "investigation_checks") == 0
    # the batch-1 checks are off until their first run passed; proxy.host is not batch-1
    code, out = await cli("investigation", "check-more", str(inv), "proxy.contact", C2,
                          "--dry-run")  # fmt: skip
    assert code == 0, out
    assert "dry run: nothing is queued or sent" in out
    assert "switched off" in out or "refused" in out or "leaves" in out
    assert await count(app_engine, "investigation_checks") == 0
    code, out = await cli("investigation", "check-more", str(inv), "ti.lookup", C2)
    assert code == 0, out
    # ti_sync is off in the test environment: refused rather than queued
    assert "refused:" in out
    assert await count(app_engine, "investigation_checks") == 0


@pytest.mark.usefixtures("cli_env")
async def test_check_more_queues_when_the_check_may_be_asked(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARGUS_ENRICHMENT__PROXY_AGGREGATIONS", "true")
    inv = await seed(migrated_engine, body(), decided=True)
    await normal(app_engine)
    code, out = await cli("investigation", "check-more", str(inv), "proxy.host", HOST)
    assert code == 0, out
    assert out.startswith("queued: ARGUS's service runs it")
    async with app_engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT kind, source, template, entity, requested_by, status"
                    " FROM investigation_checks"
                )
            )
        ).one()
    assert (row.kind, row.source, row.template, row.entity) == (
        "check",
        "person",
        "proxy.host",
        HOST,
    )
    assert row.requested_by.startswith("cli:")
    assert row.status == "queued"
    code, out = await cli("investigation", "check-more", str(inv), "proxy.host", HOST)
    assert "the same request is open already" in out
    assert await count(app_engine, "investigation_checks") == 1


@pytest.mark.usefixtures("cli_env")
async def test_check_more_queues_a_persons_check_while_the_siem_is_not_normal(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D-325: a person's request waits for the SIEM, it is not refused because of it."""
    monkeypatch.setenv("ARGUS_ENRICHMENT__PROXY_AGGREGATIONS", "true")
    inv = await seed(migrated_engine, body(), decided=True)
    store = PgStore(app_engine, BudgetConfig(), LanePlan())
    await store.save_health(HealthMemory(state=HealthState.CAUTION, probed_at=NOW))
    code, out = await cli("investigation", "check-more", str(inv), "proxy.host", HOST,
                          "--dry-run")  # fmt: skip
    assert code == 0, out
    assert "it stays queued" in out
    assert await count(app_engine, "investigation_checks") == 0
    code, out = await cli("investigation", "check-more", str(inv), "proxy.host", HOST)
    assert code == 0, out
    assert "refused" not in out
    assert out.startswith("queued: the SIEM is not in its normal state")
    assert "once the SIEM is back to normal" in out
    async with app_engine.connect() as conn:
        status = (await conn.execute(text("SELECT status FROM investigation_checks"))).scalar()
    assert status == "queued"
    # a check that cannot be asked at all is still refused, whatever the SIEM's state
    code, out = await cli("investigation", "check-more", str(inv), "proxy.host", C2)
    assert "refused:" in out
    assert await count(app_engine, "investigation_checks") == 1


async def gold(owner: AsyncEngine, answers: dict[uuid.UUID, str]) -> None:
    async with owner.begin() as conn:
        user = (
            await conn.execute(
                text(
                    "INSERT INTO users (username, display_name, password_hash)"
                    " VALUES ('asha', 'Asha', 'x') RETURNING id"
                )
            )
        ).scalar_one()
        for n, (inv, outcome) in enumerate(answers.items()):
            d = (
                await conn.execute(
                    text(
                        "SELECT version, pack, dossier_hash FROM dossiers"
                        " WHERE investigation_id = :i"
                    ),
                    {"i": inv},
                )
            ).one()
            await conn.execute(text(
                "INSERT INTO gold_items (set_name, investigation_id, version, pack, dossier_hash,"
                " rule_name, split, why, suggestion) VALUES ('v1', :i, :v, :p, :h, 'A rule',"
                " :s, '{}', CAST('{}' AS jsonb))"),
                {"i": inv, "v": d.version, "p": d.pack, "h": d.dossier_hash,
                 "s": "test" if n % 2 else "dev"})  # fmt: skip
            await conn.execute(
                text(
                    "INSERT INTO gold_labels (set_name, investigation_id, user_id, outcome)"
                    " VALUES ('v1', :i, :u, :o)"
                ),
                {"i": inv, "u": user, "o": outcome},
            )


@pytest.mark.usefixtures("cli_env")
async def test_the_measurement_without_live_sends_nothing_and_reports_the_baseline(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARGUS_ENRICHMENT__PROXY_AGGREGATIONS", "true")
    a = await seed(migrated_engine, body(steps=TIMELINE))
    b = await seed(migrated_engine, body([unknown("proxy.regularity", "timeout")]))
    c = await seed(migrated_engine, body())
    await gold(migrated_engine, {a: "benign_expected", b: "true_positive", c: "benign_policy"})
    await normal(app_engine)
    code, out = await cli("investigation", "measure")  # the test split alone: it measures
    assert code == 0, out
    assert "== test split ==" in out
    assert "dev split" not in out
    assert "Gold measurement: 1 answered items" in out
    assert "the engine cannot decide, before the wave: 1/1" in out
    code, out = await cli("investigation", "measure", "--split", "all")
    assert code == 0, out
    assert "== test split ==" in out
    assert "== dev split == the engine learns the dev answers" in out
    assert out.count("Gold measurement: ") == 2  # one block a split
    assert "Gold measurement: 2 answered items" in out  # dev: a and c
    assert "after the wave: not measured (a dry run sends nothing)" in out
    assert "true positives proposed benign before (must be 0): 0" in out
    assert "could ask something for 1 of 1 items" in out
    assert "could ask something for 1 of 2 items" in out
    code, out = await cli("investigation", "measure", "--split", "nonsense")
    assert code == 2
    for table in ("evidence", "evidence_requests", "investigation_checks"):
        assert await count(app_engine, table) == 0
    assert FIRST < LAST  # the kit's window
    assert SQUID
