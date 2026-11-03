"""Q-F4 review F4-R2 on Postgres (throwaway databases, runtime role): a NAT named as
proxy.contact's watched host, against a destination in 50 investigations, and a shared
address as web.path_outcomes' client, passed the gate on 18e2e6c. Both are refused now."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context import batch1, paths
from argus.context.packs import TaskSpec
from tests.integration.context.test_batch1_gate import admit, at, contact, pair, plant

pytestmark = pytest.mark.integration
HOST = batch1.Refusal("too_common", "host")


async def test_a_watched_nat_against_a_popular_destination_is_refused(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await plant(migrated_engine, "203.0.113.50", 50)  # a destination in 50 investigations
    await plant(migrated_engine, "10.0.0.66", 50)  # a shared campus address (a NAT)
    assert await admit(app_engine, pair("10.0.0.66", "203.0.113.9")) == HOST  # pair: refused
    # the same NAT as proxy.contact's one watched host, against the popular destination:
    assert await admit(app_engine, contact("203.0.113.50", ("10.0.0.66",))) == HOST
    # one shared address among the watched hosts is enough
    assert await admit(app_engine, contact("203.0.113.9", ("10.0.0.7", "10.0.0.66"))) == HOST
    # watched hosts that are not shared still bound the work: the watch runs on a popular C2
    assert await admit(app_engine, contact("203.0.113.50", ("10.0.0.7",))) is None


async def test_a_shared_client_of_web_path_outcomes_is_refused(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await plant(migrated_engine, "10.0.0.66", 50)  # a shared address in 50 investigations

    def web(client: str) -> TaskSpec:
        return TaskSpec(paths.WebPathOutcomes(), paths.PathParams(
            ip=client, site="s.example.org", paths=("/login", "/wp-login.php"),
            start=at(3), end=at(9)))  # fmt: skip

    assert await admit(app_engine, web("10.0.0.66")) == HOST
    assert await admit(app_engine, web("10.0.0.67")) is None
