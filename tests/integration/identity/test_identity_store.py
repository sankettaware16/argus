"""The identity lane on Postgres as the runtime role (Q-E1, migration 0032): the identity gate
shared across processes, the share kept for re-checks across processes, ledger rows the
runtime may write, the lane running with the SIEM in STOP, and the migration up and down."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import DatabaseSettings
from argus.db import migrate
from argus.db.engine import create_engine
from argus.gateway.budget import Verdict
from argus.gateway.gateway import LaneGate
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.lanes import Lane
from argus.gateway.pgstore import PgStore, reach_from_json, reach_to_json
from argus.gateway.templates import CostClass
from argus.identity.lane import IdentityLane, IdentityUnavailableError
from argus.identity.names import Credential
from argus.identity.reach import COOLDOWNS, ReachState, Signal
from argus.identity.transport import Route
from tests.integration.gateway.test_pgstore import TIMES
from tests.unit.gateway.fakes import FakeClock
from tests.unit.identity.test_lane import ScriptedIdentity, answer, privileges_body, whoami_body

pytestmark = pytest.mark.integration
T0 = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)
ME = Credential("devuser", SecretStr("correct-horse-battery-staple"))


@settings(max_examples=30)
@given(
    level=st.integers(0, 4), opened=st.none() | TIMES, trial=st.none() | TIMES,
    tripped=st.none() | TIMES, reason=st.sampled_from([None, "unreachable", "overloaded"]),
    failures=st.lists(TIMES, max_size=3),
)  # fmt: skip
def test_the_gate_state_round_trips(
    level: int, opened: datetime | None, trial: datetime | None, tripped: datetime | None,
    reason: str | None, failures: list[datetime],
) -> None:  # fmt: skip
    state = ReachState(level, opened, trial, tripped, reason, tuple(failures))
    assert reach_from_json(json.loads(json.dumps(reach_to_json(state)))) == state
    assert reach_from_json({}) == ReachState()


async def test_the_gate_is_shared_across_processes(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    other = create_engine(db_settings, database=test_database)
    try:
        a, b = PgStore(app_engine), PgStore(other)
        assert await a.identity_reach() == ReachState()
        await a.identity_reach_report(T0, Signal.OVERLOADED)
        ok, state = await b.identity_reach_admit(T0 + timedelta(seconds=1))
        assert not ok
        assert state.reason == "overloaded"
        end = T0 + COOLDOWNS[0]
        ok, _ = await b.identity_reach_admit(end)
        assert ok  # the trial
        ok, _ = await a.identity_reach_admit(end)
        assert not ok  # one trial at a time, across processes
        await a.identity_reach_report(end + timedelta(seconds=1), Signal.ANSWERED)
        assert (await b.identity_reach()).open_until is None
    finally:
        await other.dispose()


async def test_the_share_kept_for_rechecks_across_processes(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    other = create_engine(db_settings, database=test_database)
    try:
        stores = (PgStore(app_engine), PgStore(other))
        for n in range(4):
            store = stores[n % 2]
            at = T0 + timedelta(seconds=n)
            admitted = await store.lane_admit(Lane.IDENTITY, CostClass.LIGHT, at, 1.0, f"s{n}",
                                              kept=2)  # fmt: skip
            assert admitted.verdict is Verdict.ADMITTED
            assert admitted.lease is not None
            await store.lane_settle(Lane.IDENTITY, admitted.lease, 0, T0, 1.0)
        now = T0 + timedelta(seconds=5)
        signin = await stores[1].lane_admit(Lane.IDENTITY, CostClass.LIGHT, now, 1.0, "s5",
                                            kept=2)  # fmt: skip
        assert (signin.verdict, signin.reason) == (Verdict.WAIT, "request_rate")
        recheck = await stores[0].lane_admit(Lane.IDENTITY, CostClass.LIGHT, now, 1.0, "r1")
        assert recheck.verdict is Verdict.ADMITTED
    finally:
        await other.dispose()


async def test_the_lane_on_postgres_with_siem_in_stop(app_engine: AsyncEngine) -> None:
    """The runtime role runs a whole check: gate, lane, ledger rows; the SIEM in STOP (a 401 of
    ARGUS's own key) changes nothing for it, and it changes nothing for the SIEM."""
    store = PgStore(app_engine)
    stopped = HealthMemory(state=HealthState.STOP, probed_at=T0, reasons=("auth_failed",))
    await store.save_health(stopped)
    clock = FakeClock(T0)
    transport = ScriptedIdentity(clock)
    transport.on(Route.WHOAMI, answer(whoami_body()))
    transport.on(Route.VERIFY, answer(privileges_body()))
    lane = IdentityLane(transport, store, LaneGate(store, clock=clock, sleep=clock.sleep),
                        clock=clock)  # fmt: skip
    checked = await lane.check(ME, deadline=clock.now + timedelta(seconds=30))
    assert checked.identity.username == "devuser"
    assert await store.health() == stopped
    rows = await store.requests_since(T0 - timedelta(minutes=1))
    assert [(r.template, r.outcome, r.http_status) for r in rows] == [
        ("identity.whoami", "ok", 200), ("identity.verify", "ok", 200)
    ]  # fmt: skip
    async with app_engine.connect() as conn:
        lanes = (await conn.execute(text(
            "SELECT DISTINCT lane, component, purpose FROM siem_requests"))).all()  # fmt: skip
    assert lanes == [("identity", "identity", "identity")]
    await store.set_switch("identity", stopped=True, actor="t", reason="test")
    with pytest.raises(IdentityUnavailableError, match="stopped"):
        await lane.check(ME, deadline=clock.now + timedelta(seconds=30))


async def test_the_runtime_role_cannot_add_states(app_engine: AsyncEngine) -> None:
    with pytest.raises(DBAPIError):
        async with app_engine.begin() as conn:
            await conn.execute(text("INSERT INTO siem_state (name) VALUES ('identity2')"))


async def test_migration_0032_up_and_down(migrated_engine: AsyncEngine) -> None:
    async def names() -> set[str]:
        async with migrated_engine.connect() as conn:
            return set((await conn.execute(text("SELECT name FROM siem_state"))).scalars())

    assert migrate.head_revision() >= "0032"  # 0032 is in the chain (later migrations follow)
    assert "identity" in await names()
    await migrate.downgrade(migrated_engine, "0029")
    assert "identity" not in await names()
    with pytest.raises(DBAPIError):
        async with migrated_engine.begin() as conn:
            await conn.execute(text("INSERT INTO siem_state (name) VALUES ('identity')"))
    await migrate.upgrade(migrated_engine)
    assert "identity" in await names()
    assert reach_from_json(await PgStore(migrated_engine)._read("identity")) == ReachState()
    assert await migrate.schema_drift(migrated_engine) == []
