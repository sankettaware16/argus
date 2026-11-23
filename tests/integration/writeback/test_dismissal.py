"""D-336: every decision a person makes in ARGUS reaches Kibana's alerts. A possible incident a
person dismisses closes its alerts; a decision made in one of ARGUS's own accounts needs no
operator when ``writeback.own_accounts`` is on; the timer's run (``--unattended``) plans and
sends with nobody at a terminal, once a person made the first run."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import writeback, writeback_cli
from argus.cases.machine import Dismiss, Open, Reopen
from argus.cases.model import Actor, Member
from argus.cases.service import CaseService
from argus.web import decisions
from tests.integration.cases.conftest import Person, investigation
from tests.integration.cases.test_service import _apply
from tests.integration.writeback.kit import Rig, rig
from tests.integration.writeback.test_cli_run import Lane, wire
from tests.integration.writeback.test_writeback import alerts, review, rows
from tests.integration.writer.kit import alerts_in_kibana_index

pytestmark = pytest.mark.integration

# After every dismissal's undo window (15 minutes), at an hour inside the write window.
LATER = datetime.now(UTC).replace(hour=9, minute=0, second=0, microsecond=0) + timedelta(days=2)


def settled(r: Rig) -> Rig:
    r.clock.now = LATER
    r.healthy()
    return r


async def possible_incident(
    app: AsyncEngine, owner: AsyncEngine, n: int = 3, rule: str = "rule-1"
) -> uuid.UUID:
    """A possible incident (a suspected case) ARGUS raised over one alert group of ``n`` alerts."""
    inv = await investigation(owner, rule=rule, alerts=n)
    await alerts_in_kibana_index(owner)
    async with app.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(
            Actor.argus("engine"),
            Open("Suspected beacon", "medium", "raised", (Member(inv, "actor"),),
                 suspected=True, attention="P2: the same rare destination on several days"),
        )  # fmt: skip
    return applied.case.id


async def plan(engine: AsyncEngine, **kw: Any) -> int:
    kw.setdefault("at", LATER)
    async with engine.begin() as conn:
        return await writeback.plan(conn, **kw)


async def diff(engine: AsyncEngine, **kw: Any) -> dict[str, Any]:
    async with engine.connect() as conn:
        return await writeback.diff(conn, **kw)


async def test_a_dismissed_possible_incident_closes_its_alerts_once(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = settled(rig(migrated_engine, writer_engine))
    case_id = await possible_incident(app_engine, migrated_engine)
    await _apply(app_engine, people["asha"].actor(), case_id, Dismiss("benign_expected"), 1)
    assert await plan(app_engine) == 0  # the default plan: only ELK-checked decisions
    assert await plan(app_engine, own=True) == 1
    assert await plan(app_engine, own=True) == 0
    assert await diff(app_engine, own=True) == {"closed": {"reviews": 1, "alerts": 3}}
    # without the switch the same row waits for an operator
    assert await diff(app_engine) == {"needs_operator": {"reviews": 1, "alerts": 3}}
    row = await r.row()
    assert (row.review_id, row.investigation_id, row.closure_request_id) == (None, None, None)
    assert row.case_id == case_id
    await r.seed_world()
    waits = await r.run()
    assert (waits.sent_alerts, len(waits.waiting)) == (0, 1)
    assert r.world.calls == []
    sent = await r.run(own_accounts=True)
    assert (sent.sent_alerts, sent.sent_rows) == (3, 1)
    assert all(s == "closed" for s in r.world.statuses.values())
    assert [tuple(x) for x in await rows(app_engine)] == [("sent", "closed", 3)]
    assert (await r.run(own_accounts=True)).sent_alerts == 0  # a second run writes nothing
    assert await plan(app_engine, own=True) == 0


@pytest.mark.parametrize("reason", ["duplicate", "created_in_error"])
async def test_a_dismissal_that_says_nothing_about_the_alerts_leaves_them(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person], reason: str
) -> None:
    case_id = await possible_incident(app_engine, migrated_engine)
    await _apply(
        app_engine, people["asha"].actor(), case_id,
        Dismiss(reason, "not this one"), 1,  # type: ignore[arg-type]
    )  # fmt: skip
    assert await plan(app_engine, own=True) == 0


async def test_a_reopened_case_is_not_written_and_a_second_dismissal_is(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = settled(rig(migrated_engine, writer_engine))
    asha = people["asha"].actor()
    case_id = await possible_incident(app_engine, migrated_engine)
    await _apply(app_engine, asha, case_id, Dismiss("rule_false_positive"), 1)
    assert await plan(app_engine, own=True) == 1
    await _apply(app_engine, asha, case_id, Reopen("a second look"), 2)
    await r.seed_world()
    # the plan is hours old: the sender reads the case again before anything leaves
    stale = await r.run(own_accounts=True)
    assert stale.sent_alerts == 0
    assert r.world.calls == []
    assert [tuple(x) for x in await rows(app_engine)] == [("skipped", "closed", 0)]
    await _apply(app_engine, asha, case_id, Dismiss("benign_policy"), 3)
    assert await plan(app_engine, own=True) == 1
    again = await r.run(own_accounts=True)
    assert (again.sent_alerts, again.sent_rows) == (3, 1)
    assert [x.state for x in await rows(app_engine)] == ["skipped", "sent"]


async def test_the_planner_supersedes_an_unsent_row_of_a_reopened_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha = people["asha"].actor()
    case_id = await possible_incident(app_engine, migrated_engine)
    await _apply(app_engine, asha, case_id, Dismiss("benign_expected"), 1)
    assert await plan(app_engine, own=True) == 1
    await _apply(app_engine, asha, case_id, Reopen("a second look"), 2)
    assert await plan(app_engine, own=True) == 0
    async with migrated_engine.connect() as conn:
        found = (await conn.execute(text("SELECT state, error FROM writeback_outbox"))).one()
    assert tuple(found) == ("skipped", "the case was reopened")


async def test_a_dismissal_whose_author_is_no_longer_a_person_never_reaches_kibana(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """The machine refuses a dismissal that is not a person's; a row whose author's account was
    since made a service account is still not sent (the sender reads the author every time)."""
    r = settled(rig(migrated_engine, writer_engine))
    case_id = await possible_incident(app_engine, migrated_engine)
    await _apply(app_engine, people["asha"].actor(), case_id, Dismiss("benign_expected"), 1)
    assert await plan(app_engine, own=True) == 1
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE users SET kind = 'service' WHERE id = :u"), {"u": people["asha"].user_id}
        )
    assert await diff(app_engine, own=True) == {"unsendable": {"reviews": 1, "alerts": 3}}
    await r.seed_world()
    result = await r.run(own_accounts=True)
    assert result.sent_alerts == 0
    assert r.world.calls == []
    assert [x.state for x in await rows(app_engine)] == ["skipped"]


async def test_a_review_in_arguss_own_account_needs_no_operator_when_switched_on(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = settled(rig(migrated_engine, writer_engine))
    await alerts(app_engine, 3)
    await review(app_engine, "benign_expected", ready=False)  # local mode: no ELK check
    assert await plan(app_engine) == 0
    assert await plan(app_engine, own=True) == 1
    assert await diff(app_engine, own=True) == {"closed": {"reviews": 1, "alerts": 3}}
    assert await diff(app_engine) == {"needs_operator": {"reviews": 1, "alerts": 3}}
    await r.seed_world()
    off = await r.run()  # the switch is the sender's too: off, the row waits
    assert (off.sent_alerts, len(off.waiting)) == (0, 1)
    on = await r.run(own_accounts=True)
    assert (on.sent_alerts, on.sent_rows) == (3, 1)
    row = await r.row()
    assert (row.operator, row.needs_operator) == (None, False)


async def test_a_dismissal_waits_out_its_undo_window(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    """A person may undo a dismissal for 15 minutes, and an alert closed in Kibana is not
    reopened: nothing is planned before that, and a row that exists is not sent before it."""
    assert writeback.DISMISSAL_SETTLES == decisions.UNDO_WINDOW
    r = rig(migrated_engine, writer_engine)
    case_id = await possible_incident(app_engine, migrated_engine)
    await _apply(app_engine, people["asha"].actor(), case_id, Dismiss("benign_expected"), 1)
    async with app_engine.begin() as conn:
        assert await writeback.plan(conn, own=True) == 0  # the database's clock: just dismissed
    soon = datetime.now(UTC) + timedelta(minutes=14)
    assert await plan(app_engine, own=True, at=soon) == 0
    assert await plan(app_engine, own=True) == 1
    await r.seed_world()
    r.clock.now = LATER.replace(year=LATER.year - 1)  # the sender's clock: before the dismissal
    early = await r.run(own_accounts=True)
    assert (early.sent_alerts, len(early.waiting)) == (0, 1)
    assert "undo window" in early.waiting[0]
    assert r.world.calls == []
    assert (await settled(r).run(own_accounts=True)).sent_alerts == 3


async def test_own_accounts_does_not_cover_an_elk_persons_or_a_disabled_account(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """The switch is for ARGUS's own accounts in use. A person ELK knows, whose own check did
    not show the alert-status privileges, still needs an operator; so does a disabled account."""
    r = settled(rig(migrated_engine, writer_engine))
    first = await possible_incident(app_engine, migrated_engine)
    second = await possible_incident(app_engine, migrated_engine, rule="rule-2")
    await _apply(app_engine, people["asha"].actor(), first, Dismiss("benign_expected"), 1)
    await _apply(app_engine, people["ravi"].actor(), second, Dismiss("benign_expected"), 1)
    assert await plan(app_engine, own=True) == 2
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE users SET realm = 'native', elk_username = 'asha' WHERE id = :u"),
            {"u": people["asha"].user_id},
        )
        await conn.execute(
            text("UPDATE users SET disabled = true WHERE id = :u"), {"u": people["ravi"].user_id}
        )
    assert await diff(app_engine, own=True) == {"needs_operator": {"reviews": 2, "alerts": 6}}
    await r.seed_world()
    result = await r.run(own_accounts=True)
    assert (result.sent_alerts, len(result.waiting)) == (0, 2)
    assert r.world.calls == []


# --------------------------------------------------------------------------- the timer's run


def unattended(monkeypatch: pytest.MonkeyPatch, r: Rig, app: AsyncEngine) -> Any:
    """The settings of a host whose timer sends, with the command's pieces the rig's. The
    command plans by the database's clock, so the undo window is none here."""
    monkeypatch.setattr(writeback, "DISMISSAL_SETTLES", timedelta(0))
    wired = wire(monkeypatch, r, Lane())
    on = wired.writeback.model_copy(update={"auto": True, "own_accounts": True})
    monkeypatch.setattr(writeback_cli, "create_engine", lambda *a, **k: _Kept(app))
    monkeypatch.setattr(writeback_cli, "writer_engine", lambda *a, **k: _Kept(r.engine))
    return wired.model_copy(update={"writeback": on})


class _Kept:
    """The fixture's engine, kept open when the command disposes of its own."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    def __getattr__(self, name: str) -> Any:
        return getattr(self._engine, name)

    async def dispose(self) -> None:
        return None


async def test_the_timers_run_waits_for_a_persons_first_run(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    r = settled(rig(migrated_engine, writer_engine))
    s = unattended(monkeypatch, r, app_engine)
    case_id = await possible_incident(app_engine, migrated_engine)
    await _apply(app_engine, people["asha"].actor(), case_id, Dismiss("benign_expected"), 1)
    await r.seed_world()
    assert await writeback_cli._unattended(s, None) == 0  # not a fault of the timer's unit
    assert "the first run is a person's" in capsys.readouterr().out
    assert r.world.calls == []
    assert await rows(app_engine) == []  # nothing was planned either


async def test_the_timers_run_plans_and_sends_after_the_first_run(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:  # fmt: skip
    r = settled(rig(migrated_engine, writer_engine))
    s = unattended(monkeypatch, r, app_engine)
    asha = people["asha"].actor()
    first = await possible_incident(app_engine, migrated_engine, 2)
    await _apply(app_engine, asha, first, Dismiss("benign_expected"), 1)
    assert await plan(app_engine, own=True) == 1
    await r.seed_world()
    assert (await r.run(own_accounts=True)).sent_alerts == 2  # the person's first run
    second = await possible_incident(app_engine, migrated_engine, 3, rule="rule-2")
    await _apply(app_engine, asha, second, Dismiss("rule_false_positive"), 1)
    await r.seed_world()
    r.healthy()
    code = await writeback_cli._unattended(s, None)
    out = capsys.readouterr()
    assert code == 0, out
    assert "1 items planned" in out.out
    assert "3 alerts changed in 1 calls" in out.out
    assert [x.state for x in await rows(app_engine)] == ["sent", "sent"]
