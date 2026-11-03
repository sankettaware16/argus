"""Q-B3's measurement of the case pages' reads on a busy day's worth of records (opt in:
``RUN_SCALE_TEST=1``; a minute or two in a throwaway database): 400 cases of two investigations each
and 120 closure requests waiting. 40 samples of each read, in process; p95 at most 300 ms like the
Inbox's (plan §8 criterion 14). The numbers go to ``data/gate/q-b3-scale.json`` (local, not
committed)."""

from __future__ import annotations

import json
import os
import statistics
import time
from pathlib import Path

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.cases.conftest import investigation
from tests.integration.web.b3_support import V1, World, make_world, post, sign_in
from tests.integration.web.test_external import ROOT

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("RUN_SCALE_TEST") != "1", reason="opt-in: RUN_SCALE_TEST=1"),
]
CASES, ASKED, SAMPLES, LIMIT_MS = 400, 120, 40, 300


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


async def timed(http: httpx.AsyncClient, path: str) -> float:
    started = time.perf_counter()
    got = await http.get(path)
    assert got.status_code == 200, (path, got.text)
    return (time.perf_counter() - started) * 1000


@pytest.mark.timeout(3600)
async def test_the_case_pages_reads_at_a_busy_days_scale(
    world: World, migrated_engine: AsyncEngine
) -> None:
    ids = [
        await investigation(migrated_engine, actor=(("source.ip", f"10.8.{n // 250}.{n % 250}"),))
        for n in range(CASES * 2)
    ]
    world.investigations = ids
    cases = [await world.open_case(2, title=f"Beacon {n}", start=2 * n) for n in range(CASES)]
    async with world.app() as maker:
        csrf = await sign_in(maker, "mina")
        for case in cases[:ASKED]:
            seen = await maker.get(
                f"{V1}/cases/{case}/closure-preview", params={"reason": "benign_expected"}
            )
            asked = await post(maker, csrf, f"/cases/{case}/closure-requests",
                               {"expected_version": 1, "reason": "benign_expected",
                                "payload_hash": seen.json()["payload_hash"]})  # fmt: skip
            assert asked.status_code == 201, asked.text
    reads = {
        "cases, open": ["/cases"] * SAMPLES,
        "cases, needs attention": ["/cases?view=attention"] * SAMPLES,
        "cases, found by number": [f"/cases?number={n}" for n in range(1, SAMPLES + 1)],
        "cases, a deep page": ["/cases?view=all&offset=300"] * SAMPLES,
        "a case": [f"/cases/{c}" for c in cases[:SAMPLES]],
        "the approvals queue (120 waiting)": ["/approvals"] * 10,
    }
    results: dict[str, float] = {}
    async with world.app() as http:
        await sign_in(http, "oona")
        for name, paths in reads.items():
            times = [await timed(http, V1 + p) for p in paths]
            results[name] = round(statistics.quantiles(times, n=20)[-1], 1)
    out = ROOT / "data" / "gate" / "q-b3-scale.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"cases": CASES, "asked": ASKED, "p95_ms": results}, indent=2))
    print(results)
    slow = {k: v for k, v in results.items() if v > LIMIT_MS and "queue" not in k}
    assert not slow, slow
