"""The engine v2's replay against a database (P4-F E0): each fact counts from when the copy knew
it. A group is visible from the first of its alerts ARGUS stored, never from its event time; in
db mode an operator tie (set by the campaign analysis, after the dossier) counts from the stored
flags' last evaluation, while oracle mode knows it from the start and no-vt not at all."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.cases.membership import NO_SHARED
from argus.risk import replay, run
from tests.integration.risk.conftest import NOW, group, rule, setup

pytestmark = pytest.mark.integration
OPERATOR = replay.OPERATOR
START = NOW - timedelta(days=3)


async def load(engine: AsyncEngine, mode: str) -> replay.Loaded:
    s = setup()
    profile = site.active()
    async with engine.connect() as conn:
        return await replay.load(
            conn, start=START, end=NOW, mode=mode, config=s.config, classifier=s.classifier,
            families=profile.families, campus_domains=profile.own_domains,
            feed_modes=run.feed_modes(profile.ti_sources), shared=NO_SHARED, answers=None,
        )  # fmt: skip


def first_item(loaded: replay.Loaded, ip: str) -> str | None:
    spec: dict[str, Any] = {"x": {"ips": [ip], "found_by_people": NOW}}
    found = replay.incidents_of(spec, loaded)
    replay.replay(loaded, start=START, end=NOW, step=timedelta(hours=1),
                  config=setup().config, incidents=found)  # fmt: skip
    return found["x"].first_item


async def test_an_operator_tie_counts_from_its_flags_in_db_mode_only(
    migrated_engine: AsyncEngine,
) -> None:
    await rule(migrated_engine, "r-dns", "DNS rule", indices=("acme-logs-dns-*",))
    flagged = NOW - timedelta(hours=10)
    tied = await group(migrated_engine, "r-dns", actor="10.7.7.1", hours_ago=20,
                       flags=(OPERATOR,), raised_at=flagged)  # fmt: skip
    db = await load(migrated_engine, "db")
    operator = [o for o in db.observations if o.group == tied.id and o.source_key == "ev:operator"]
    assert [o.seen_at for o in operator] == [flagged]
    assert all(o.seen_at is None for o in db.observations if o.source_kind == "rule")
    # the tie with the rule is decisive, but only once the copy knew it
    assert first_item(db, "10.7.7.1") == flagged.isoformat()
    oracle = await load(migrated_engine, "oracle")
    assert [o.seen_at for o in oracle.observations if o.source_key == "ev:operator"] == [None]
    assert first_item(oracle, "10.7.7.1") == (NOW - timedelta(hours=20)).isoformat()
    no_vt = await load(migrated_engine, "no-vt")
    assert not [o for o in no_vt.observations if o.source_key == "ev:operator"]


async def test_a_group_is_visible_from_its_first_stored_alert(
    migrated_engine: AsyncEngine,
) -> None:
    """Alerts of a collection gap stored 12 hours late: the critical rule's match is decisive
    when ARGUS held it, not at its event time."""
    await rule(migrated_engine, "r-ioc", "IOC rule", severity="critical")
    late = await group(migrated_engine, "r-ioc", actor="10.7.7.2", severity="critical",
                       hours_ago=60, stored_after=timedelta(hours=12))  # fmt: skip
    on_time = await group(migrated_engine, "r-ioc", actor="10.7.7.3", severity="critical",
                          hours_ago=60)  # fmt: skip
    loaded = await load(migrated_engine, "db")
    first = loaded.groups[late.id].first_at
    assert loaded.groups[late.id].arrived == first + timedelta(hours=12)
    assert loaded.groups[late.id].end >= loaded.groups[late.id].arrived
    assert loaded.groups[on_time.id].arrived == first
    assert first_item(loaded, "10.7.7.2") == (NOW - timedelta(hours=48)).isoformat()
    assert first_item(loaded, "10.7.7.3") == (NOW - timedelta(hours=60)).isoformat()
