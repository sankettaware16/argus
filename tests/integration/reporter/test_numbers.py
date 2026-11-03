"""Every number of a report equals an independent recomputation (Q-H3's gate): a seeded world
whose rows sit on and around the edges of the period, a report built as the runtime login
(``argus_runtime``), and ``oracle.expected`` computed from the raw rows with no shared SQL."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.reporter import build, render
from argus.reporter.model import Numbers, window_for
from tests.integration.reporter import oracle, seed

pytestmark = pytest.mark.integration

LAST = seed.DAY.date()
CASES = [
    ("daily", LAST),
    ("weekly", LAST),
    ("daily", (seed.DAY.replace(day=17)).date()),  # a quiet day: few lags, no p95
    ("weekly", (seed.DAY.replace(day=2)).date()),  # a week before the data: all zeros
]


@pytest.fixture
async def world(migrated_engine: AsyncEngine) -> seed.Seed:
    return await seed.seed(migrated_engine)


async def made(engine: AsyncEngine, kind: str, day) -> Numbers:  # type: ignore[no-untyped-def]
    async with build.snapshot(engine) as conn:
        return await build.build(conn, kind, day, seed.AS_AT)  # type: ignore[arg-type]


@pytest.mark.parametrize(("kind", "day"), CASES)
async def test_every_figure_equals_its_independent_recomputation(
    world: seed.Seed, migrated_engine: AsyncEngine, app_engine: AsyncEngine, kind: str, day
) -> None:  # type: ignore[no-untyped-def]
    numbers = await made(app_engine, kind, day)
    window = window_for(kind, day, seed.AS_AT)  # type: ignore[arg-type]
    want = await oracle.expected(migrated_engine, window)
    keys = [m.key for s in numbers.sections for m in s.metrics]
    assert len(keys) == len(set(keys)), "a figure's key is used twice"
    got = {key: metric.value for key, metric in numbers.metrics().items()}
    assert sorted(got) == sorted(want), "a figure without a recomputation, or the other way"
    wrong = {k: (got[k], want[k]) for k in want if got[k] != want[k]}
    assert wrong == {}
    assert {type(got[k]) for k in got if got[k] is not None} <= {int, float, str}
    # a figure's text is the figure, exactly
    body = render.text_of(numbers)
    for metric in numbers.metrics().values():
        assert f"- {metric.label}: {render.shown(metric)}\n" in body, metric.key


async def test_the_seed_exercises_the_edges(
    world: seed.Seed, migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """The recomputation is only as good as the data: the daily report has a figure in every
    family that is neither 0 nor the weekly's (so a wrong window or filter shows)."""
    daily = (await made(app_engine, "daily", LAST)).metrics()
    weekly = (await made(app_engine, "weekly", LAST)).metrics()
    differs = [k for k in daily if daily[k].value != weekly[k].value]
    for prefix in (
        "cases.",
        "active_hosts.",
        "closures.",
        "approvals.",
        "siem.",
        "kibana.",
        "guardrails.",
        "results.",
        "writeback.",
        "writes.",
        "gaps.",
    ):
        assert any(k.startswith(prefix) for k in differs), prefix
    assert daily["kibana.lag.p95"].value == 228  # 24 lags, 10 s apart
    assert daily["results.p95"].value == 1371  # 24 results, 60 s apart: 60 x (1 + 0.95 x 23)
    assert (await made(app_engine, "daily", LAST.replace(day=17))).metrics()[
        "kibana.lag.p95"
    ].value is None
