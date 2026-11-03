"""The writer's test rig (Q-D4): Postgres as the writer's own login, the writable fake Kibana
behind the real Kibana lane, and cases with their outbox rows made through CaseService."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.model import Actor
from argus.cases.signing import Verifier
from argus.gateway.budget import BudgetConfig
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.kibana.gateway import KibanaGateway, KibanaTargets
from argus.gateway.kibana.writes import WriteCaps, WriteClass
from argus.gateway.lanes import LanePlan
from argus.gateway.state import MemoryStore
from argus.writer.sender import RunReport, Writer
from tests.integration.cases.conftest import VERIFIER, Person, investigation
from tests.integration.cases.test_service import _open
from tests.integration.writer.fake import INDEX, SPACE, WritableEs, WritableKibana
from tests.unit.kibana_sync.fake import T0, Clock

LINK_BASE = "https://argus.example"
ALL = frozenset({WriteClass.W1, WriteClass.W2, WriteClass.W3})


@dataclass
class Rig:
    owner: AsyncEngine
    app: AsyncEngine
    engine: AsyncEngine  # the writer's login
    clock: Clock
    kibana: WritableKibana
    lane: MemoryStore
    gateway: KibanaGateway
    writer: Writer
    es: Gateway
    tags: dict[uuid.UUID, str] = field(default_factory=dict)
    t0: datetime = T0
    pending_health: HealthMemory | None = None

    def healthy(self) -> None:
        memory = HealthMemory(probed_at=self.clock.now + timedelta(hours=2))
        if isinstance(self.lane, MemoryStore):
            self.lane.memory = memory
        else:
            self.pending_health = memory

    async def run(self, write_class: str = "W1", limit: int = 10, kind: str = "ramp") -> RunReport:
        self.healthy()
        if self.pending_health is not None:  # a database store keeps the health state
            await self.lane.save_health(self.pending_health)
        report = await self.writer.run_class(write_class, limit=limit, kind=kind, by="test")
        return report

    def advance(self, seconds: float) -> None:
        self.clock.now += timedelta(seconds=seconds)
        self.kibana.tick()
        self.healthy()

    async def sql(self, query: str, **params: Any) -> list[Any]:
        async with self.owner.connect() as conn:
            return list((await conn.execute(text(query), params)).all())

    async def outbox(self, case_id: uuid.UUID) -> list[tuple[str, str, str]]:
        found = await self.sql(
            "SELECT write_class, op, state FROM kibana_outbox WHERE case_id = :c ORDER BY id",
            c=case_id,
        )
        return [(r.write_class, r.op, r.state) for r in found]

    async def steps(self, case_id: uuid.UUID) -> list[tuple[str, int, str]]:
        found = await self.sql(
            "SELECT kind, seq, state FROM kibana_steps WHERE case_id = :c ORDER BY id", c=case_id
        )
        return [(r.kind, r.seq, r.state) for r in found]


def rig(
    owner: AsyncEngine,
    app: AsyncEngine,
    engine: AsyncEngine,
    *,
    classes: frozenset[WriteClass] = ALL,
    verifier: Verifier | None = VERIFIER,
    caps: WriteCaps | None = None,
    lane: Any = None,
) -> Rig:
    """``lane``: the lane's state; in memory unless a ``PgStore`` is given (the writer's own
    login then keeps the budget, the breaker, the pauses and the request ledger)."""
    clock = Clock(T0)
    kibana = WritableKibana(clock)
    lane = lane or MemoryStore(
        memory=HealthMemory(probed_at=T0), budget_config=BudgetConfig(), lane_plan=LanePlan()
    )
    es = Gateway(WritableEs(kibana), lane, targets=Targets(), clock=clock, sleep=clock.sleep)
    gateway = KibanaGateway(
        kibana, lane, targets=KibanaTargets(space=SPACE), caps=caps, classes=classes,
        es_gateway=es, clock=clock, sleep=clock.sleep,
    )  # fmt: skip
    writer = Writer(
        engine, gateway, es=es, verifier=verifier, link_base=LINK_BASE, clock=clock,
        sleep=clock.sleep, wait_for_gaps=True,
    )  # fmt: skip
    r = Rig(owner, app, engine, clock, kibana, lane, gateway, writer, es)
    r.healthy()
    return r


async def alerts_in_kibana_index(owner: AsyncEngine) -> None:
    """The seeded alerts get the space's concrete alerts index (a real attach needs one)."""
    async with owner.begin() as conn:
        await conn.execute(text("UPDATE alert_records SET index = :i"), {"i": INDEX})


async def mirrored_case(
    app: AsyncEngine, owner: AsyncEngine, person: Person, kibana_checked: Actor, *,
    alerts: int = 2, ip: str = "10.1.1.7", title: str = "Regular beaconing from a campus host",
) -> uuid.UUID:  # fmt: skip
    """A case whose create is planned (the person may open cases in Kibana)."""
    inv = await investigation(owner, alerts=alerts, actor=(("source.ip", ip),))
    await alerts_in_kibana_index(owner)
    return await _open(app, kibana_checked, [inv], title=title)


async def mirror(
    owner: AsyncEngine,
    case_id: uuid.UUID,
    kibana_id: str,
    *,
    version: str = "WzEsMV0=",
    status: str = "open",
    unmanaged: tuple[str, ...] = (),
    paused: str | None = None,
    sync_alerts: bool = False,
    deleted: bool = False,
    tags: tuple[str, ...] | None = None,
) -> None:
    """What the read-back would have kept of the Kibana case (``kibana_mirror``)."""
    mine = tags or ("argus", f"argus:case:{case_id}", "argus:owner:argus", "argus:state:open")
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO kibana_mirror (case_id, kibana_case_id, kibana_version, status, title,"
                " severity, tags, created_by, sync_alerts, unmanaged, kibana_created_at, read_at,"
                " paused_reason, deleted_at) VALUES (:c, :k, :v, :s, 't', 'high', :t,"
                " 'argus', :sync, :u, now(), now(), :p, CASE WHEN :d THEN now() END)"
                " ON CONFLICT (case_id) DO UPDATE SET kibana_version = :v, status = :s,"
                " unmanaged = :u, paused_reason = :p, sync_alerts = :sync"
            ),
            {
                "c": case_id,
                "k": kibana_id,
                "v": version,
                "s": status,
                "u": list(unmanaged),
                "p": paused,
                "sync": sync_alerts,
                "d": deleted,
                "t": list(mine),
            },
        )


async def created(
    r: Rig, people: dict[str, Person], *, alerts: int = 2, ip: str = "10.1.1.7"
) -> tuple[uuid.UUID, str]:
    """A case whose create is verified in Kibana (and its comment and alerts); (ARGUS case id,
    Kibana case id)."""
    from tests.integration.cases.test_service import _kibana_actor

    case_id = await mirrored_case(
        r.app, r.owner, people["asha"], _kibana_actor(people["asha"]), alerts=alerts, ip=ip
    )
    report = await r.run("W1", limit=1)
    assert report.stopped is None, report.lines()
    assert report.mismatches == 0, report.lines()
    rows = await r.sql(
        "SELECT kibana_case_id FROM kibana_outbox WHERE case_id = :c AND op = 'create'", c=case_id
    )
    return case_id, str(rows[0].kibana_case_id)


async def approved_closure(
    r: Rig, api: AsyncEngine, people: dict[str, Person], case_id: uuid.UUID, kid: str,
    reason: str = "benign_expected", version: str | None = None,
) -> int:  # fmt: skip
    """Asha asks to close the case, Ravi approves: the case is closed in ARGUS and its two W3
    rows wait. Returns the approval request's id."""
    from tests.integration.cases.test_closure_approval import _desk_decide
    from tests.integration.cases.test_service import _request

    seen = version if version is not None else str(r.kibana.cases[kid]["version"])
    await mirror(r.owner, case_id, kid, version=seen)
    case = (await r.sql("SELECT version FROM cases WHERE id = :c", c=case_id))[0]
    request_id = await _request(api, people["asha"], case_id, int(case.version), reason)
    assert await _desk_decide(api, people["ravi"], request_id) == "approved"
    return request_id


async def approve_resend(
    r: Rig, api: AsyncEngine, people: dict[str, Person], row_id: int, privilege: str = "createCase"
) -> int:  # fmt: skip
    """Asha asks to send an ambiguous write once more, Ravi approves; returns the request."""
    from argus.cases import approvals, identity
    from argus.cases import kibana as intent
    from argus.writer import lookup, store
    from tests.integration.cases.conftest import APPROVER, live_check
    from tests.integration.cases.test_closure_approval import _desk_decide, _provider

    async with r.engine.connect() as conn:
        row = await store.get_row(conn, row_id)
    assert row is not None
    version = (await r.sql("SELECT version FROM cases WHERE id = :c", c=row.case_id))[0].version
    ravi, asha = people["ravi"], people["asha"]
    async with r.owner.begin() as conn:
        await conn.execute(
            text("UPDATE users SET capabilities = :c WHERE id = :u"),
            {"c": sorted(APPROVER), "u": ravi.user_id},
        )
    payload = lookup.resend_payload(row)
    async with api.begin() as conn:
        now = await identity.database_clock(conn)
        request = await approvals.request(
            conn,
            session_token=asha.session_token,
            case_id=row.case_id,
            case_version=int(version),
            kind="resend",
            reason=None,
            payload=payload,
            payload_hash=intent.payload_hash(payload),
            expires=approvals.expires_at(now),
            outbox_id=row.id,
            check=live_check(asha, now).snapshot(),
        )
    decided = await _desk_decide(
        api, ravi, request, provider=_provider(ravi, kibana=frozenset({privilege}))
    )
    assert decided == "approved"
    return request


async def many_alerts(
    app: AsyncEngine,
    owner: AsyncEngine,
    kibana_checked: Actor,
    investigations: int,
    alerts: int = 2,
) -> uuid.UUID:
    """A case of several investigations (each its own actor), alerts in the Kibana index."""
    members = [
        await investigation(
            owner,
            alerts=alerts,
            actor=(("source.ip", f"10.3.{n // 250}.{n % 250 + 1}"),),
            day=n % 3,
        )
        for n in range(investigations)
    ]
    await alerts_in_kibana_index(owner)
    return await _open(app, kibana_checked, members, title="Many hosts talking to one address")


async def approve_compensation(
    r: Rig, api: AsyncEngine, people: dict[str, Person], row_id: int
) -> int:  # fmt: skip
    """Asha asks to undo a verified W2 or W3 write, Ravi approves; returns the request."""
    from argus.cases import approvals, identity
    from argus.writer import compensation, store
    from tests.integration.cases.conftest import APPROVER, live_check
    from tests.integration.cases.test_closure_approval import _desk_decide, _provider

    async with r.engine.connect() as conn:
        row = await store.get_row(conn, row_id)
        assert row is not None
        before = await compensation.before_image(conn, row_id)
    payload = compensation.build(row, before)
    assert payload is not None
    version = (await r.sql("SELECT version FROM cases WHERE id = :c", c=row.case_id))[0].version
    ravi, asha = people["ravi"], people["asha"]
    async with r.owner.begin() as conn:
        await conn.execute(
            text("UPDATE users SET capabilities = :c WHERE id = :u"),
            {"c": sorted(APPROVER), "u": ravi.user_id},
        )
    async with api.begin() as conn:
        now = await identity.database_clock(conn)
        request = await approvals.request(
            conn,
            session_token=asha.session_token,
            case_id=row.case_id,
            case_version=int(version),
            kind="compensating",
            reason=None,
            payload=payload,
            payload_hash=compensation.hashed(payload),
            expires=approvals.expires_at(now),
            outbox_id=row.id,
            check=live_check(asha, now).snapshot(),
        )
    assert await _desk_decide(api, ravi, request, provider=_provider(ravi)) == "approved"
    return request
