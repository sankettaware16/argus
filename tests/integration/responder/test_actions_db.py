"""The ``case_actions`` table (migration 0044, Q-H2): the edges the database holds for everyone,
the identity of a row, what ARGUS's runtime and the web's login may write, and that the web
cannot speak in ARGUS's name."""

from __future__ import annotations

import itertools
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.model import Actor
from argus.responder import machine, store
from tests.integration.cases.conftest import Person
from tests.integration.responder.kit import Scene, at

pytestmark = pytest.mark.integration

BEACON = "c2_beacon.isolate_host"
STATES = list(machine.STATES)


@pytest.fixture
async def case_id(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> uuid.UUID:
    scene = Scene(migrated_engine, app_engine)
    return (await scene.beacon_case(people["asha"], at(0, 10)))[0]


class Walk:
    """Rows in chosen states, made along the legal edges (as the owner: the trigger is
    ENABLE ALWAYS, so it holds for the owner too)."""

    def __init__(self, engine: AsyncEngine, case_id: uuid.UUID, *, live: bool = False) -> None:
        self.engine, self.case_id, self.n, self.live = engine, case_id, 0, live
        self.clock = at(1, 0)

    def tick(self) -> datetime:
        if self.live:  # the web's login may date a report only near the database's clock
            return datetime.now(UTC)
        self.clock += timedelta(minutes=1)
        return self.clock

    async def sql(self, statement: str, **kw: Any) -> Any:
        async with self.engine.begin() as conn:
            return await conn.execute(text(statement), {"c": self.case_id, **kw})

    async def insert(self, action: str | None = None, state: str = "recommended") -> str:
        self.n += 1
        action = action or f"x{self.n}.y"
        stamp = {
            "recommended": "recommended_at, recommended_by) VALUES (:c, :a, 'x', 'o', 1, :s,"
            " :t, 'argus:responder')",
            "requested": "requested_at, requested_by) VALUES (:c, :a, 'x', 'o', 1, :s, :t,"
            " 'user:1')",
            "reported_done": "reported_at, reported_by, attestation) VALUES (:c, :a, 'x', 'o',"
            " 1, :s, :t, 'user:1', 'did it')",
        }[state]
        await self.sql(
            "INSERT INTO case_actions (case_id, action, family, owner, catalogue_version, state,"
            f" {stamp}",
            a=action, s=state, t=self.tick(),
        )  # fmt: skip
        return action

    async def move(self, action: str, to: str) -> None:
        sets = {
            "requested": "requested_at = :t, requested_by = 'user:2'",
            "reported_done": "reported_at = :t, reported_by = 'user:2', attestation = 'again'",
            "verified": "verdict_at = :t, verdict = 'quiet'",
            "not_verified": "verdict_at = :t, verdict = 'still', last_beat = :t",
            "recommended": "attestation = attestation",  # no column of advice may change
        }[to]
        await self.sql(
            f"UPDATE case_actions SET state = :s, {sets} WHERE case_id = :c AND action = :a",  # noqa: S608
            a=action, s=to, t=self.tick(),
        )  # fmt: skip

    async def reach(self, state: str) -> str:
        """A new row in ``state``, by the shortest legal path."""
        path = {
            "recommended": ["recommended"],
            "requested": ["recommended", "requested"],
            "reported_done": ["recommended", "requested", "reported_done"],
            "verified": ["recommended", "requested", "reported_done", "verified"],
            "not_verified": ["recommended", "requested", "reported_done", "not_verified"],
        }[state]
        action = await self.insert()
        for step in path[1:]:
            await self.move(action, step)
        return action


async def test_the_database_holds_exactly_the_machines_edges(
    migrated_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    allowed = machine.PERSON_EDGES, machine.ARGUS_EDGES
    walk = Walk(migrated_engine, case_id)
    for current, to in itertools.product(STATES, STATES):
        action = await walk.reach(current)
        legal = any(to in edges.get(current, ()) for edges in allowed)
        if legal:
            await walk.move(action, to)
            continue
        with pytest.raises(DBAPIError, match="cannot become"):
            await walk.move(action, to)
    # a row starts as recommended, requested or reported done, and in no other state
    for start in ("recommended", "requested", "reported_done"):
        await walk.insert(state=start)
    with pytest.raises(DBAPIError):
        await walk.sql(
            "INSERT INTO case_actions (case_id, action, family, owner, catalogue_version, state,"
            " verdict_at, verdict) VALUES (:c, 'v.v', 'x', 'o', 1, 'verified', now(), 'v')"
        )


@pytest.mark.parametrize(
    "columns",
    [
        "recommended_by = 'argus'",
        "recommended_by = 'user:3'",
        "requested_by = 'argus:responder'",
        "requested_by = 'asha'",
        "requested_by = 'user:0'",
        "requested_by = 'user:01'",
        "reported_by = 'argus:responder'",
        "attestation = ''",
        "attestation = repeat('x', 501)",
        "verdict = 'v'",  # a verdict without its time
        "last_beat = now()",  # a last beat on a state that is not "not verified"
        "reported_at = NULL",  # an attestation without its time
        "state = 'telepathy'",
    ],
)
async def test_the_tables_own_checks(
    migrated_engine: AsyncEngine, case_id: uuid.UUID, columns: str
) -> None:
    walk = Walk(migrated_engine, case_id)
    action = await walk.reach("reported_done")
    with pytest.raises(DBAPIError):
        await walk.sql(
            f"UPDATE case_actions SET {columns} WHERE case_id = :c AND action = :a",  # noqa: S608
            a=action,
        )  # fmt: skip
    with pytest.raises(DBAPIError):
        await walk.sql(
            "INSERT INTO case_actions (case_id, action, family, owner, catalogue_version, state)"
            " VALUES (:c, 'Bad.Name', 'x', 'o', 1, 'recommended')"
        )


@pytest.mark.parametrize(
    "column",
    ["case_id = gen_random_uuid()", "action = 'z.z'", "family = 'other'", "owner = 'someone'",
     "catalogue_version = 2", "recommended_at = now()", "id = id + 1000"],
)  # fmt: skip
async def test_the_identity_of_a_row_never_changes(
    migrated_engine: AsyncEngine, case_id: uuid.UUID, column: str
) -> None:
    walk = Walk(migrated_engine, case_id)
    action = await walk.reach("recommended")
    with pytest.raises(DBAPIError):
        await walk.sql(
            f"UPDATE case_actions SET {column} WHERE case_id = :c AND action = :a",  # noqa: S608
            a=action,
        )  # fmt: skip


async def test_a_new_report_clears_the_old_verdict_and_must_be_newer(
    migrated_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    walk = Walk(migrated_engine, case_id)
    action = await walk.reach("not_verified")
    row = (
        await walk.sql("SELECT * FROM case_actions WHERE case_id = :c AND action = :a", a=action)
    ).one()
    assert row.last_beat is not None
    with pytest.raises(DBAPIError, match="newer than the last"):
        await walk.sql(
            "UPDATE case_actions SET state = 'reported_done', reported_at = :t, reported_by ="
            " 'user:2', attestation = 'again' WHERE case_id = :c AND action = :a",
            a=action, t=row.reported_at,
        )  # fmt: skip
    await walk.move(action, "reported_done")
    row = (
        await walk.sql("SELECT * FROM case_actions WHERE case_id = :c AND action = :a", a=action)
    ).one()
    assert (row.state, row.verdict_at, row.verdict, row.last_beat) == (
        "reported_done",
        None,
        None,
        None,
    )
    assert row.reported_by == "user:2"
    # a verdict has to come after the report it judges
    with pytest.raises(DBAPIError, match="comes after the report"):
        await walk.sql(
            "UPDATE case_actions SET state = 'verified', verdict_at = :t, verdict = 'v'"
            " WHERE case_id = :c AND action = :a",
            a=action, t=row.reported_at - timedelta(minutes=1),
        )  # fmt: skip
    # only a new report changes who reported it
    await walk.move(action, "not_verified")
    with pytest.raises(DBAPIError, match="only a new report"):
        await walk.sql(
            "UPDATE case_actions SET reported_by = 'user:9' WHERE case_id = :c AND action = :a",
            a=action,
        )


async def test_the_runtime_role_writes_the_named_columns_and_deletes_nothing(
    app_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    walk = Walk(app_engine, case_id)
    action = await walk.reach("reported_done")
    async with app_engine.connect() as conn:
        for statement in (
            "DELETE FROM case_actions",
            "TRUNCATE case_actions",
            "UPDATE case_actions SET family = 'other'",
            "UPDATE case_actions SET created_at = now()",
            "UPDATE case_actions SET updated_at = now()",
        ):
            with pytest.raises(DBAPIError, match="permission denied"):
                await conn.execute(text(statement))
            await conn.rollback()
    await walk.move(action, "verified")  # the verdict columns are ARGUS's


# --------------------------------------------------------------------------- the web's login


async def test_the_web_login_records_only_a_persons_request_or_report(
    web_engine: AsyncEngine, migrated_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    runtime_row = Walk(migrated_engine, case_id)
    recommended = await runtime_row.reach("recommended")
    done = await runtime_row.reach("reported_done")
    verified = await runtime_row.reach("verified")
    web = Walk(web_engine, case_id, live=True)
    async with web_engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM case_actions"))).scalar_one() == 3

    # a person's request and report: an update or an insert, as user:<id>
    await web.move(recommended, "requested")
    await web.move(recommended, "reported_done")
    await web.sql(
        "INSERT INTO case_actions (case_id, action, family, owner, catalogue_version, state,"
        " requested_at, requested_by) VALUES (:c, 'w.one', 'x', 'o', 1, 'requested', now(),"
        " 'user:7')"
    )
    await web.sql(
        "INSERT INTO case_actions (case_id, action, family, owner, catalogue_version, state,"
        " reported_at, reported_by, attestation) VALUES (:c, 'w.two', 'x', 'o', 1,"
        " 'reported_done', now(), 'user:7', 'I did it')"
    )

    # ARGUS's own words are not the web's: no recommendation, no verdict, no ARGUS name
    refusals = [
        ("INSERT INTO case_actions (case_id, action, family, owner, catalogue_version, state,"
         " recommended_at, recommended_by) VALUES (:c, 'w.three', 'x', 'o', 1, 'recommended',"
         " now(), 'argus:responder')", "permission denied"),
        ("INSERT INTO case_actions (case_id, action, family, owner, catalogue_version, state)"
         " VALUES (:c, 'w.four', 'x', 'o', 1, 'recommended')", "only a person"),
        ("INSERT INTO case_actions (case_id, action, family, owner, catalogue_version, state,"
         " requested_at, requested_by) VALUES (:c, 'w.five', 'x', 'o', 1, 'requested', now(),"
         " 'argus:responder')", "people_are_users"),
        ("INSERT INTO case_actions (case_id, action, family, owner, catalogue_version, state,"
         " requested_at, requested_by) VALUES (:c, 'w.six', 'x', 'o', 1, 'requested', now(),"
         " 'asha')", "people_are_users"),
        ("UPDATE case_actions SET state = 'verified' WHERE action = :d", "only a person"),
        ("UPDATE case_actions SET state = 'not_verified' WHERE action = :d", "only a person"),
        ("UPDATE case_actions SET verdict = 'v', verdict_at = now() WHERE action = :d",
         "permission denied"),
        ("UPDATE case_actions SET last_beat = now() WHERE action = :d", "permission denied"),
        ("UPDATE case_actions SET family = 'y' WHERE action = :d", "permission denied"),
        ("UPDATE case_actions SET recommended_by = 'argus:responder' WHERE action = :d",
         "permission denied"),
        ("DELETE FROM case_actions WHERE action = :d", "permission denied"),
    ]  # fmt: skip
    for statement, why in refusals:
        with pytest.raises(DBAPIError, match=why):
            await web.sql(statement, v=verified, d=done)
    # nothing a refusal tried is there
    async with migrated_engine.connect() as conn:
        found = await conn.execute(text("SELECT action FROM case_actions WHERE action LIKE 'w.%'"))
        assert sorted(found.scalars()) == ["w.one", "w.two"]


async def test_a_page_can_use_the_same_functions_under_the_web_login(
    web_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    app_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """Q-B4's path: ``actions_for``, ``request`` and ``report_done`` as the web's own login (it
    reads what the pages read and inserts or updates only a person's columns)."""
    scene = Scene(migrated_engine, app_engine)
    case, _ = await scene.beacon_case(people["asha"], at(0, 10))
    asha: Actor = people["asha"].actor()
    async with web_engine.connect() as conn:
        views = await store.actions_for(conn, case, now=at(0, 12))
    assert [v.state for v in views] == ["recommended", "recommended"]  # computed, not stored
    now = datetime.now(UTC)  # the web's login dates a report near the database's own clock
    async with web_engine.begin() as conn:  # no row yet: the web inserts it as a person's
        await store.request(conn, case, BEACON, asha, now)
        await store.report_done(conn, case, "c2_beacon.block_destination", asha, "Blocked", now)
    async with app_engine.begin() as conn:
        await store.recommend(conn, case, now)  # the rest is ARGUS's
    async with web_engine.begin() as conn:
        await store.report_done(conn, case, BEACON, asha, "Isolated", now + timedelta(seconds=1))
    async with web_engine.connect() as conn:
        views = await store.actions_for(conn, case, now=now + timedelta(seconds=2))
    assert [v.state for v in views] == ["reported_done", "reported_done"]
    stored = await scene.stored(case)
    assert {r.action: (r.requested_by, r.reported_by) for r in stored.values()} == {
        BEACON: (asha.name, asha.name),
        "c2_beacon.block_destination": (None, asha.name),
    }
    # the audit trail names the person, not the web
    async with migrated_engine.connect() as conn:
        actors = await conn.execute(
            text("SELECT DISTINCT actor FROM audit_events WHERE action LIKE 'case.action%'")
        )
        assert set(actors.scalars()) == {asha.name}
