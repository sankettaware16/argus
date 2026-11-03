"""AR2c (D-168, D-170) in an assessment pass, as ``argus assess run`` takes it: the family step
comes after the evidence is read, says what it did in one line, and the campaigns it finds are
what the suggester reads. Nothing reaches the network (a scripted transport)."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import raising
from argus.cases.membership import NO_SHARED
from argus.outside.service import Outside
from tests.integration.campaigns.test_campaigns import (
    CLASSIFIER,
    NOW,
    WINDOW,
    Make,
    the_campaign,
    transport,
)
from tests.integration.cases.conftest import rows
from tests.integration.outside.conftest import Clock

pytestmark = pytest.mark.integration


async def test_the_passes_look_up_the_families_and_the_campaign_becomes_a_suggested_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    await the_campaign(migrated_engine)
    outside: Outside = make_outside(transport(), virustotal_per_minute=4)
    at, last = NOW, None
    lines: list[str] = []
    for _ in range(4):  # a pass a quarter of an hour apart: the case step runs on each
        clock.now = at
        done = await raising.run(
            app_engine, CLASSIFIER, at, suggesting=True, last=last, outside=outside,
            shared=NO_SHARED, window=WINDOW,
        )  # fmt: skip
        assert done.warned == []
        lines.extend(done.said)
        last = done.suggested_at
        at += raising.SUGGEST_EVERY
    families = [x for x in lines if x.startswith("campaigns: ")]
    assert len(families) == 4
    assert families[0].startswith(
        "campaigns: 0 found; looked up 2 (found 2, no record 0, failed 0)"
    )
    assert any(x.startswith("campaigns: 1 found") for x in families[2:])
    assert "flagged " in families[0] or "flagged " in families[1]  # the flags the answers gave
    assert sum("cases: suggested 1" in x for x in lines) == 1  # one case, once
    (case,) = await rows(app_engine, "SELECT * FROM cases")
    assert case.attention.startswith("ARGUS suggests this case: one operator, 6 campus devices: ")
    # three families; the two rare ones also get their first address looked up (D-174)
    assert len(outside.transport.sent) == 5  # type: ignore[attr-defined]


async def test_without_a_key_the_family_step_says_so_and_the_pass_goes_on(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, make_outside: Make, clock: Clock
) -> None:
    await the_campaign(migrated_engine)
    outside = make_outside(transport(), "shodan")  # no VirusTotal key
    clock.now = NOW
    done = await raising.run(
        app_engine, CLASSIFIER, NOW, suggesting=True, last=None, outside=outside,
        shared=NO_SHARED, window=WINDOW,
    )  # fmt: skip
    assert done.warned == []
    assert "campaigns: 0 found (look-ups off: no VirusTotal key)" in done.said
    assert outside.transport.sent == []  # type: ignore[attr-defined]
