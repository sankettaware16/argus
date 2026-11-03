"""``argus freshness ...`` end to end on a throwaway database (no SIEM request): status,
report, export (the margin script's input), assess and the audit sheet."""

from __future__ import annotations

import asyncio
import csv
import json
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.freshness import store
from argus.freshness.model import FAILED, OK, Reading
from argus.freshness.store import Stored
from tests.integration.context.conftest import NOW
from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401

pytestmark = pytest.mark.integration


async def run(*args: str) -> tuple[int, str]:
    return await asyncio.to_thread(_invoke, *args)


@pytest.mark.usefixtures("cli_env")
async def test_status_report_export_assess_and_the_sheet(
    app_engine: AsyncEngine, tmp_path: Path
) -> None:
    code, out = await run("freshness", "status")
    assert code == 0, out
    assert "mode: off" in out
    assert "squid: margin none (no verified zeros); watermark -; last reading - (never)" in out
    async with app_engine.begin() as conn:
        for minutes in range(0, 30, 5):
            at = NOW + timedelta(minutes=minutes)
            reading = Reading("squid", at, OK, at, at - timedelta(seconds=20))
            await store.record(conn, Stored(reading, at, took_ms=4))
        await store.record(conn, Stored(Reading("dns", NOW, FAILED), NOW, "timed_out"))
    code, out = await run("freshness", "status")
    assert code == 0, out
    assert "squid: margin none (no verified zeros); watermark 2026-10-09 12:25:00 UTC" in out
    assert "dns: margin none (no verified zeros); watermark -; last reading" in out
    assert "(failed)" in out
    code, out = await run("freshness", "report", "--days", "60")
    assert code == 0, out
    got = json.loads(out)
    by = {s["source"]: s for s in got["sources"]}
    assert by["squid"]["readings"] == 6
    assert by["squid"]["lag"]["p50_s"] == 20.0
    assert by["dns"]["outcomes"] == {"failed": 1}
    assert got["verdicts"]["signals"] == 0
    assert got["mode"] == "off"
    target = tmp_path / "readings.jsonl"
    code, out = await run("freshness", "export", "--out", str(target), "--days", "60")
    assert (code, out.strip()) == (0, f"7 readings written to {target}")
    rows = [json.loads(line) for line in target.read_text().splitlines()]
    assert {r["source"] for r in rows} == {"squid", "dns"}
    assert oct(target.stat().st_mode & 0o777) == "0o600"
    code, out = await run("freshness", "assess")
    assert code == 0, out
    assert json.loads(out)["evaluated"] == 0
    sheet = tmp_path / "audit.csv"
    code, out = await run("freshness", "audit-sheet", "--out", str(sheet))
    assert (code, out.strip()) == (0, f"0 would-be benign proposals written to {sheet}")
    with sheet.open(newline="", encoding="utf-8") as fh:
        assert next(csv.reader(fh))[0] == "investigation_id"
    code, out = await run("freshness", "audit-score", str(sheet))
    assert code == 1  # nothing audited: below the bar
    assert json.loads(out)["passes"] is False


@pytest.mark.usefixtures("cli_env")
async def test_a_margin_for_an_unknown_source_is_refused(
    app_engine: AsyncEngine, tmp_path: Path
) -> None:
    config = tmp_path / "argus.yaml"
    config.write_text('freshness:\n  mode: "shadow"\n  margins:\n    squidd: 3m\n')
    code, out = await run("freshness", "status", "--config", str(config))
    assert code == 2
    assert "squidd" in out
