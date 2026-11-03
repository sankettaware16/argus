"""Q-D4 on the local Kibana 8.19.12 tier: every write class through the writer with hostile
values (the scenario of ``tests/integration/writer/scenarios.py``, which also runs against the
writable fake in every suite), and, live only, a create that lands after ARGUS's timeout, found
by its tag through the real HTTPS transport and a delaying proxy.

The writer is Postgres-bound, so these tests use the integration fixtures beside the tier's
recorded clients: Kibana and Elasticsearch are recorded (a cassette per test), the database is
real. A new cassette is recorded with ``KIBANA_TIER_RECORD=new`` while the tier runs; without the
tier the tests are skipped, like every timing test (``live_kt``)."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.gateway.budget import BudgetConfig
from argus.gateway.errors import TemplateRejectedError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.kibana.gateway import KibanaGateway, KibanaTargets
from argus.gateway.kibana.templates import KeyRole
from argus.gateway.kibana.transport import HttpxKibanaTransport, KResponse, KWire
from argus.gateway.state import MemoryStore
from argus.gateway.transport import pinned_context
from argus.writer.sender import Writer
from tests.integration.cases.conftest import VERIFIER, Person
from tests.integration.cases.conftest import api_engine as api_engine
from tests.integration.cases.conftest import people as people
from tests.integration.conftest import (
    _drop_stale_test_databases as _drop_stale_test_databases,
)
from tests.integration.conftest import _runtime_roles as _runtime_roles
from tests.integration.conftest import app_engine as app_engine
from tests.integration.conftest import db_settings as db_settings
from tests.integration.conftest import empty_engine as empty_engine
from tests.integration.conftest import make_database as make_database
from tests.integration.conftest import make_login as make_login
from tests.integration.conftest import make_writer_login as make_writer_login
from tests.integration.conftest import migrated_engine as migrated_engine
from tests.integration.conftest import test_database as test_database
from tests.integration.conftest import writer_engine as writer_engine
from tests.integration.writer import scenarios
from tests.integration.writer.fake import WritableKibana
from tests.integration.writer.kit import LINK_BASE, Rig
from tests.kibana import kit
from tests.kibana.proxy import DelayingProxy
from tests.kibana.test_lane import ALL, ROLES, SPACE, T0, TierElasticsearch, TierKibana, forget_case
from tests.kibana.tier import S, Tier
from tests.unit.gateway.fakes import FakeClock

pytestmark = pytest.mark.integration


@dataclass
class TierView:
    """Kibana's side, read through the tier's recorded clients."""

    kt: Tier

    def case(self, kibana_id: str) -> dict[str, Any]:
        reply = self.kt.kibana(ROLES[KeyRole.READER]).get(f"{S}/api/cases/{kibana_id}")
        assert reply.status == 200, reply.body
        body: dict[str, Any] = reply.body
        return body

    def comments(self, kibana_id: str) -> list[str]:
        reply = self.kt.kibana(ROLES[KeyRole.READER]).get(
            f"{S}/api/cases/{kibana_id}/comments/_find",
            params={"perPage": 100, "sortOrder": "asc"},
        )
        assert reply.status == 200, reply.body
        return [c["comment"] for c in reply.body["comments"]]

    def alert_case_ids(self, alert_id: str) -> list[str]:
        alert = next(a for a in self.alerts if a["id"] == alert_id)
        found: list[str] = kit.alert_state(self.kt, alert, "kibana.alert.case_ids")[
            "kibana.alert.case_ids"
        ]
        return found

    def add_tag(self, kibana_id: str, tag: str) -> None:
        current = self.case(kibana_id)
        reply = kit.patch_case(
            self.kt, "user:tier-analyst", kibana_id, current["version"],
            tags=[*current["tags"], tag],
        )  # fmt: skip
        assert reply.status == 200, reply.body

    def attach_actions(self, kibana_id: str) -> int:
        reply = self.kt.kibana(ROLES[KeyRole.READER]).get(
            f"{S}/api/cases/{kibana_id}/user_actions/_find",
            params={"perPage": 100, "sortOrder": "asc"},
        )
        assert reply.status == 200, reply.body
        return sum(
            1
            for a in reply.body["userActions"]
            if a["type"] == "comment" and a["payload"]["comment"].get("type") == "alert"
        )

    alerts: list[dict[str, str]] = None  # type: ignore[assignment]


def _rig(kt: Tier, owner: AsyncEngine, api: AsyncEngine, engine: AsyncEngine) -> Rig:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0), budget_config=BudgetConfig())
    es = Gateway(TierElasticsearch(kt), store, targets=Targets(), clock=clock, sleep=clock.sleep)
    gateway = KibanaGateway(
        TierKibana(kt), store, targets=KibanaTargets(space=SPACE), classes=ALL, es_gateway=es,
        clock=clock, sleep=clock.sleep,
    )  # fmt: skip
    writer = Writer(
        engine, gateway, es=es, verifier=VERIFIER, link_base=LINK_BASE, clock=clock,
        sleep=clock.sleep, wait_for_gaps=True,
    )  # fmt: skip
    rig = Rig(owner, api, engine, clock, WritableKibana(clock), store, gateway, writer, es)
    rig.healthy()
    return rig


async def test_every_class_with_hostile_values_on_the_tier(
    live_kt: Tier, api_engine: AsyncEngine, migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    pytest.importorskip("markdown_it")
    kt = live_kt
    made = kit.make_alerts(kt, "writer", 3)
    view = TierView(kt)
    view.alerts = made
    r = _rig(kt, migrated_engine, api_engine, writer_engine)
    try:
        done = await scenarios.every_class(
            r, api_engine, people, view, [(a["id"], a["index"]) for a in made], later=r.advance
        )
    finally:
        found = await r.sql(
            "SELECT kibana_case_id FROM kibana_outbox WHERE kibana_case_id IS NOT NULL"
        )
        for row in found:
            forget_case(kt, str(row.kibana_case_id))
    own = f"{LINK_BASE}/go/case/{done.case_id}"
    # what Kibana kept is what the renderer wrote, and a CommonMark reader finds it inert
    scenarios.assert_inert(done.description, done.comments, own)
    assert own in done.description


class Routed:
    """The real HTTPS transport: a case create goes through the delaying proxy, everything else
    straight to Kibana."""

    def __init__(self, direct: HttpxKibanaTransport, delayed: HttpxKibanaTransport) -> None:
        self.direct, self.delayed = direct, delayed

    def refusal(self, request: KWire) -> TemplateRejectedError | None:
        return self.direct.refusal(request)

    async def send(self, request: KWire) -> KResponse:
        late = (
            request.target == "kibana"
            and request.method == "POST"
            and request.path.endswith("/api/cases")
        )
        return await (self.delayed if late else self.direct).send(request)


async def test_a_create_landing_after_the_timeout_is_found_through_the_real_transport(
    live_kt: Tier, api_engine: AsyncEngine, migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    kt = live_kt
    paths = kt.settings.paths
    context = pinned_context(paths.ca_crt)
    keys = {
        role: SecretStr(str(kt.authorization(ROLES[role])).removeprefix("ApiKey "))
        for role in (KeyRole.READER, KeyRole.CASES)
    }
    url = httpx.URL(kt.settings.kibana_url)
    es_url = kt.settings.es_url
    direct = HttpxKibanaTransport(kt.settings.kibana_url, es_url, context, keys, space=SPACE)
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0), budget_config=BudgetConfig())
    es = Gateway(TierElasticsearch(kt), store, targets=Targets(), clock=clock, sleep=clock.sleep)
    with DelayingProxy(
        url.host, url.port or 443, paths.kibana_tls / "kibana.crt", paths.kibana_tls / "kibana.key",
        paths.ca_crt, request_delay=6.0,
    ) as proxy:  # fmt: skip
        delayed = HttpxKibanaTransport(
            f"https://127.0.0.1:{proxy.port}", es_url, context, keys, space=SPACE
        )
        gateway = KibanaGateway(
            Routed(direct, delayed), store, targets=KibanaTargets(space=SPACE), classes=ALL,
            es_gateway=es, timeout=timedelta(seconds=2), clock=clock, sleep=clock.sleep,
        )  # fmt: skip
        writer = Writer(
            writer_engine, gateway, es=es, verifier=VERIFIER, link_base=LINK_BASE, clock=clock,
            sleep=clock.sleep, wait_for_gaps=True, key_selftest=False,
        )  # fmt: skip
        r = Rig(migrated_engine, api_engine, writer_engine, clock, WritableKibana(clock), store,
                gateway, writer, es)  # fmt: skip
        r.healthy()
        from tests.integration.cases.test_service import _kibana_actor
        from tests.integration.writer.kit import mirrored_case

        case_id = await mirrored_case(
            api_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"]), alerts=0
        )
        try:
            first = await r.run("W1", limit=1)
            assert (first.sent, first.ambiguous) == (1, 1), first.lines()
            assert (await r.outbox(case_id))[0][2] == "ambiguous"
            assert await asyncio.to_thread(proxy.answered.wait, 30)  # it reaches Kibana late
            r.advance(121)
            await writer.run_lookups()  # by its tag and reporters=argus: made by argus
            assert (await r.outbox(case_id))[0][2] == "verified"
            tag = f"argus:case:{case_id}"
            found = kt.kibana(ROLES[KeyRole.READER]).get(
                f"{S}/api/cases/_find", params={"tags": tag, "reporters": "argus", "perPage": 10}
            )
            assert [c["created_by"]["username"] for c in found.body["cases"]] == ["argus"]
            assert len(found.body["cases"]) == 1  # one create ever reached Kibana
        finally:
            for row in await r.sql("SELECT kibana_case_id FROM kibana_outbox"):
                if row.kibana_case_id:
                    forget_case(kt, str(row.kibana_case_id))
    assert uuid.UUID(str(case_id))
