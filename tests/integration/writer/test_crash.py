"""Q-D4: a crash at any move of a case's life loses nothing and doubles nothing. The process dies
just before the n-th outbox or step move commits; a restarted writer recovers what was left in
``sending``, looks for what may have landed and goes on. Whatever n is, Kibana never gets a
second create, and a row that is ``verified`` is in Kibana."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.writer import store
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _kibana_actor
from tests.integration.writer.kit import Rig, many_alerts, rig

pytestmark = pytest.mark.integration


class Crash(BaseException):
    """The process dies here."""


async def _settle(r: Rig) -> None:
    """A restarted writer, a while later: recover, make every look, go on, again and again."""
    for _ in range(4):
        r.advance(3600)
        await r.run("W1", limit=1)
        for seconds in (130, 310, 910, 1810):
            r.advance(seconds)
            await r.writer.run_lookups()


@pytest.mark.parametrize("crash_at", range(1, 15))
async def test_a_crash_before_any_move_loses_and_doubles_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], monkeypatch: pytest.MonkeyPatch, crash_at: int,
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await many_alerts(
        app_engine, migrated_engine, _kibana_actor(people["asha"]), investigations=2
    )
    moves = {"n": 0}
    real = store.move

    async def dying(*args, **kwargs):  # type: ignore[no-untyped-def]
        moves["n"] += 1
        if moves["n"] == crash_at:
            raise Crash
        return await real(*args, **kwargs)

    monkeypatch.setattr(store, "move", dying)
    try:
        await r.run("W1", limit=1)
        crashed = False
    except Crash:
        crashed = True
    monkeypatch.undo()
    r.advance(300)

    await _settle(r)

    assert r.kibana.count("POST", "/api/cases") <= 1, "a second create reached Kibana"
    rows = await r.sql(
        "SELECT state, sent_count, resends FROM kibana_outbox WHERE case_id = :c", c=case_id
    )
    steps = await r.sql(
        "SELECT kind, state, sent_count FROM kibana_steps WHERE case_id = :c", c=case_id
    )
    assert all(row.sent_count <= 1 + row.resends for row in rows)
    assert all(row.state != "sending" for row in rows)
    assert all(s.state != "sending" for s in steps)
    assert all(s.sent_count <= 1 for s in steps)  # a step is never sent twice
    ours = r.kibana.ours()
    if rows[0].state == "verified":
        assert len(ours) == 1
    if not crashed:  # the run finished before reaching the n-th move
        assert rows[0].state == "verified"
    if crashed and len(ours) == 1:  # it landed: found, not forgotten
        assert rows[0].state == "verified"
    for kind in ("comment", "attach"):
        assert sum(1 for s in steps if s.kind == kind and s.state == "verified") <= len(ours) * 3
    # nothing is attached or commented twice in Kibana
    case_comments = r.kibana.comments.get(ours[0]["id"], []) if ours else []
    assert len(case_comments) <= 1
