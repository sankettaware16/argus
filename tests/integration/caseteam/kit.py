"""The case team's test rig (AR8): Postgres as the writer's own login, the team's fake Kibana
behind the real Kibana lane, the Amadey-shaped case with its stored report, and the poster."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam import store
from argus.caseteam.sender import ALL_USERS, PostConfig, Poster, PostReport
from argus.gateway.budget import BudgetConfig
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.kibana.gateway import KibanaGateway, KibanaTargets
from argus.gateway.kibana.writes import WriteCaps, WriteClass
from argus.gateway.lanes import LanePlan
from argus.gateway.state import MemoryStore
from argus.incident import store as incident_store
from tests.integration.cases import knownkit
from tests.integration.cases.conftest import SIGNER, VERIFIER, Person
from tests.integration.caseteam.fake import SPACE, TeamKibana, WritableEs
from tests.integration.incident import kit as incident_kit
from tests.integration.writer.kit import alerts_in_kibana_index
from tests.unit.kibana_sync.fake import T0, Clock

LINK_BASE = "https://argus.example"
KIBANA_BASE = "https://kibana.example"
CONFIG = PostConfig(
    post=True,
    canary=0,
    per_day=5,
    max_alerts=25,
    alerts_per_call=5,
    link_base=LINK_BASE,
    kibana_prefixes=(KIBANA_BASE,),
    space=SPACE,
    keys=ALL_USERS,
)

__all__ = ["CONFIG", "SIGNER", "VERIFIER", "Rig", "a_case", "rig"]


@dataclass
class Rig:
    owner: AsyncEngine
    engine: AsyncEngine  # the writer's login
    clock: Clock
    kibana: TeamKibana
    lane: MemoryStore
    gateway: KibanaGateway
    poster: Poster
    config: PostConfig
    notes: dict[str, Any] = field(default_factory=dict)

    def healthy(self) -> None:
        self.lane.memory = HealthMemory(probed_at=self.clock.now + timedelta(hours=2))

    def advance(self, seconds: float) -> None:
        self.clock.now += timedelta(seconds=seconds)
        self.kibana.tick()
        self.healthy()

    async def run(self, case: uuid.UUID) -> PostReport:
        self.healthy()
        return await self.poster.run_case(case)

    async def sql(self, query: str, **params: Any) -> list[Any]:
        async with self.owner.connect() as conn:
            return list((await conn.execute(text(query), params)).all())

    async def steps(self, case: uuid.UUID) -> list[tuple[int, str, str]]:
        found = await self.sql(
            "SELECT gen, key, state FROM case_team_steps WHERE case_id = :c ORDER BY id", c=case
        )
        return [(r.gen, r.key, r.state) for r in found]

    async def states(self, case: uuid.UUID) -> dict[str, int]:
        out: dict[str, int] = {}
        for _, _, state in await self.steps(case):
            out[state] = out.get(state, 0) + 1
        return out

    async def prepared(self, case: uuid.UUID) -> Any:
        self.healthy()
        async with self.engine.connect() as conn:
            return await self.poster.prepare(conn, case)


def rig(
    owner: AsyncEngine,
    engine: AsyncEngine,
    *,
    config: PostConfig = CONFIG,
    caps: WriteCaps | None = None,
    classes: frozenset[WriteClass] = frozenset({WriteClass.WC}),
    verifier: Any = VERIFIER,
    wait_for_gaps: bool = True,
) -> Rig:
    clock = Clock(T0)
    kibana = TeamKibana(clock)
    lane = MemoryStore(
        memory=HealthMemory(probed_at=T0), budget_config=BudgetConfig(), lane_plan=LanePlan()
    )
    es = Gateway(WritableEs(kibana), lane, targets=Targets(), clock=clock, sleep=clock.sleep)
    gateway = KibanaGateway(
        kibana,
        lane,
        targets=KibanaTargets(space=SPACE),
        caps=caps,
        classes=classes,
        es_gateway=es,
        clock=clock,
        sleep=clock.sleep,
    )
    poster = Poster(
        engine,
        gateway,
        config,
        verifier=verifier,
        clock=clock,
        sleep=clock.sleep,
        wait_for_gaps=wait_for_gaps,
    )
    r = Rig(owner, engine, clock, kibana, lane, gateway, poster, config)
    r.healthy()
    return r


async def a_case(
    owner: AsyncEngine,
    app: AsyncEngine,
    person: Person,
    *,
    confirmed: bool = False,
    now: datetime | None = None,
    confidence: float | None = None,
) -> uuid.UUID:
    """The Amadey-shaped case in the database with its report written, the alerts in the space's
    alerts index; ``confirmed``: a person confirmed the report; ``confidence``: the AI
    investigator's, in its proposals."""
    case, _ = await incident_kit.amadey(owner, app, person)
    await alerts_in_kibana_index(owner)
    if confidence is not None:
        async with owner.begin() as conn:
            await conn.execute(text("UPDATE assessments SET confidence = :c"), {"c": confidence})
    stored, _ = await incident_kit.write(app, case, now or incident_kit.NOW)
    if confirmed:
        async with owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO incident_report_decisions (report_id, decision, by_user_id)"
                    " VALUES (:r, 'confirmed', :u)"
                ),
                {"r": stored.id, "u": person.user_id},
            )
    return case


async def write_again(app: AsyncEngine, case: uuid.UUID, now: datetime) -> Any:
    return await incident_kit.write(app, case, now)


async def another_case(owner: AsyncEngine, app: AsyncEngine, person: Person) -> uuid.UUID:
    """A small second case (another host), for tests that need the day's other openings."""
    inv = await knownkit.make(owner, when=datetime.now(UTC), host=knownkit.OTHER_HOST, alerts=2)
    return await knownkit.open_case(app, person, [inv], host=knownkit.OTHER_HOST)


async def posted_today(owner: AsyncEngine, case: uuid.UUID, number: int, at: datetime) -> None:
    """The case team already opened ``case`` at ``at`` (a row of its own, as a post leaves it)."""
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO case_team_posts (case_id, incident_id, kibana_case_id, opened_at,"
                " last_version) VALUES (:c, :i, :k, :t, 1)"
            ),
            {"c": case, "i": f"ACME-IR-2026-1026-{number:02d}", "k": f"kid-{number}", "t": at},
        )


async def save_version(app: AsyncEngine, case: uuid.UUID, change: Callable[[Any], Any]) -> Any:
    """The case's next report version: the newest one, changed by ``change``."""
    async with app.begin() as conn:
        newest = await incident_store.latest(conn, case)
        assert newest is not None
        stored, new = await incident_store.save(
            conn, change(newest.report), case_version=newest.case_version
        )
    assert new
    return stored


async def decide(
    owner: AsyncEngine, case: uuid.UUID, person: Person, decision: str = "confirmed"
) -> None:
    """A person's decision on the newest version of the case's report."""
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO incident_report_decisions (report_id, decision, outcome, reason,"
                " by_user_id) SELECT r.id, :d, :o, :why, :u FROM incident_reports r"
                " WHERE r.case_id = :c ORDER BY r.version DESC LIMIT 1"
            ),
            {
                "d": decision,
                "c": case,
                "u": person.user_id,
                "o": "benign_expected" if decision == "rejected" else None,
                "why": "it is the backup tool" if decision == "rejected" else None,
            },
        )


__all__ += ["another_case", "decide", "posted_today", "save_version", "store", "write_again"]
