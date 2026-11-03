"""An attach while a person has Sync alerts on (D-288, on D-272). Kibana then sets each attached
alert to the case's status: for an open case that only re-opens an alert a person closed, so the
poster leaves the alerts ARGUS records as not open out of the call; for any other status it sends
nothing and skips the step. The totals the case is expected to hold follow what was left out, for
this step and every later attach of the generation. The database and the Kibana lane are stood in
for, so no request can leave."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest

from argus.caseteam import plan, policy, sender, store
from argus.caseteam.model import Author, Step
from argus.caseteam.sender import SYNC_NOT_OPEN, PostConfig, Poster, PostReport, RunStopped
from argus.caseteam.store import PostRow, StepRow
from argus.gateway.errors import GatewayError
from tests.unit.caseteam import kit as team

pytestmark = pytest.mark.unit
KID = "kibana-case-1"
IDX = ".internal.alerts-security.alerts-acme-soc-000001"
CASE = uuid.uuid4()


def ids(start: int, n: int) -> list[str]:
    return [f"{i:064x}" for i in range(start, start + n)]


def attach_row(n: int, start: int, total: int, state: str = "planned") -> StepRow:
    step = Step(
        f"attach:{n}",
        "attach",
        Author.LEAD,
        "alerts",
        payload={"alerts": [[a, IDX] for a in ids(start, 100)], "expect_total": total},
    )
    return StepRow(
        10 + n, CASE, 2, n, step.key, step.kind, step.author.value, step.part, 2,
        step.payload, None, (), "0" * 64, state, None, 0,
    )  # fmt: skip


def three() -> list[StepRow]:
    """An update round of 300 alerts in three calls, the case holding 50 already."""
    return [attach_row(1, 0, 150), attach_row(2, 100, 250), attach_row(3, 200, 350)]


def totals(rows: list[StepRow], row: StepRow) -> tuple[int, int]:
    step = store.attach_view(rows, row)
    return len(step.payload["alerts"]), step.payload["expect_total"]


def with_left(row: StepRow, *left: str) -> StepRow:
    return replace(row, kibana_ids={"left_out": list(left)})


# --------------------------------------------------------------------------- the view


def test_with_nothing_left_out_the_step_is_as_planned() -> None:
    rows = three()
    for row in rows:
        assert store.attach_view(rows, row) == row.step()
        assert store.left_out_of(row) == frozenset()


def test_alerts_left_out_lower_this_total_and_every_later_one() -> None:
    rows = three()
    rows[0] = with_left(rows[0], *ids(0, 3))
    assert totals(rows, rows[0]) == (97, 147)
    assert totals(rows, rows[1]) == (100, 247)
    assert totals(rows, rows[2]) == (100, 347)
    rows[1] = with_left(rows[1], ids(100, 1)[0])
    assert totals(rows, rows[0]) == (97, 147)  # an earlier call is not changed by a later one
    assert totals(rows, rows[1]) == (99, 246)
    assert totals(rows, rows[2]) == (100, 346)


def test_a_skipped_call_takes_all_its_alerts_off_the_later_totals() -> None:
    rows = three()
    rows[0] = with_left(replace(rows[0], state="skipped"), *ids(0, 100))
    assert totals(rows, rows[1]) == (100, 150)
    assert totals(rows, rows[2]) == (100, 250)


def test_the_call_without_its_left_out_alerts_still_names_the_rest_in_order() -> None:
    rows = three()
    rows[0] = with_left(rows[0], ids(0, 100)[5])
    step = store.attach_view(rows, rows[0])
    assert [a for a, _ in step.payload["alerts"]] == [a for a in ids(0, 100) if a != ids(0, 6)[5]]
    assert all(i == IDX for _, i in step.payload["alerts"])
    assert rows[0].payload["expect_total"] == 150  # the stored plan is as written


# --------------------------------------------------------------------------- the rig


class Conn:
    pass


class Db:
    """The generation's rows, and what the poster asks of the store."""

    def __init__(self, rows: list[StepRow], closed: set[str]) -> None:
        self.rows = rows
        self.closed = closed
        self.writes: list[tuple[int, list[str], str, bool]] = []
        self.settled: list[tuple[int, str, dict[str, Any]]] = []


class FakeEngine:
    @asynccontextmanager
    async def connect(self) -> Any:
        yield Conn()

    @asynccontextmanager
    async def begin(self) -> Any:
        yield Conn()


class Rig:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        rows: list[StepRow],
        *,
        sync: bool = True,
        status: str = "open",
        closed: set[str] | None = None,
    ) -> None:
        self.db = Db(rows, closed or set())
        self.poster = Poster(
            FakeEngine(),  # type: ignore[arg-type]
            None,
            PostConfig(post=True, keys=frozenset(a.value for a in Author)),
            clock=lambda: datetime(2026, 11, 2, 10, 0, tzinfo=UTC),
        )
        self.case: Any = {"id": KID, "status": status, "settings": {"syncAlerts": sync}}
        self.reads = 0
        self.sent: list[Any] = []
        db = self.db

        async def steps_of(conn: Any, case_id: Any, gen: Any = None) -> list[StepRow]:
            return list(db.rows)

        async def not_open(conn: Any, alert_ids: Any) -> set[str]:
            return {a for a in alert_ids if a in db.closed}

        async def leave_out(
            conn: Any, step_id: int, left: Any, why: str, *, skip: bool = False
        ) -> bool:
            db.writes.append((step_id, list(left), why, skip))
            for n, r in enumerate(db.rows):
                if r.id == step_id:
                    db.rows[n] = replace(
                        r,
                        kibana_ids={**r.kibana_ids, "left_out": list(left)},
                        state="skipped" if skip else r.state,
                        state_reason=why,
                    )
            return True

        async def settle(conn: Any, step_id: int, to: str, **kw: Any) -> bool:
            db.settled.append((step_id, to, dict(kw.get("ids") or {})))
            return True

        async def read(template: Any, params: Any) -> Any:
            self.reads += 1
            if isinstance(self.case, BaseException):
                raise self.case
            return self.case

        async def write_step(
            row: StepRow, step: Step, template: Any, params: Any, report: Any
        ) -> Any:
            self.sent.append((row.key, params))
            return Answer({"id": KID, "totalAlerts": params.expect_total})

        monkeypatch.setattr(store, "steps_of", steps_of)
        monkeypatch.setattr(store, "not_open_alerts", not_open)
        monkeypatch.setattr(store, "leave_out_alerts", leave_out)
        monkeypatch.setattr(store, "settle", settle)
        monkeypatch.setattr(self.poster, "_read", read)
        monkeypatch.setattr(self.poster, "_write_step", write_step)

    def row(self, n: int) -> StepRow:
        return next(r for r in self.db.rows if r.seq == n)

    def report(self) -> PostReport:
        return PostReport(CASE, 1, policy.Decision("update", "x"))

    def post(self) -> PostRow:
        return PostRow(CASE, "ACME-IR-2026-1102-01", KID, "active", None, None, 1, None)

    async def send(self, n: int, report: PostReport | None = None) -> PostReport:
        report = report or self.report()
        await self.poster._send(
            self.row(n), self.post(), team.amadey(), report, "ACME-IR-2026-1102-01"
        )
        return report


class Answer:
    def __init__(self, body: Any) -> None:
        self.body = body


# --------------------------------------------------------------------------- Sync alerts off


async def test_with_sync_alerts_off_nothing_changes_even_for_closed_alerts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = Rig(monkeypatch, three(), sync=False, status="closed", closed=set(ids(0, 5)))
    report = await rig.send(1)
    assert rig.reads == 1
    assert rig.db.writes == []
    [(key, params)] = rig.sent
    assert (key, len(params.alerts), params.expect_total) == ("attach:1", 100, 150)
    assert rig.db.settled[0][1] == "verified"
    assert "left_out" not in rig.db.settled[0][2]
    assert report.note is None


# --------------------------------------------------------------------------- Sync alerts on


async def test_an_open_case_leaves_out_the_closed_alerts_and_sends_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed = {ids(0, 100)[3], ids(0, 100)[40]}
    rig = Rig(monkeypatch, three(), closed=closed)
    report = await rig.send(1)
    [(key, params)] = rig.sent
    assert key == "attach:1"
    sent = [a for a, _ in params.alerts]
    assert len(sent) == 98
    assert not closed & set(sent)
    assert params.expect_total == 148  # the case will hold 2 fewer than planned
    [(step_id, left, why, skip)] = rig.db.writes
    assert (step_id, left, skip) == (11, sorted(closed), False)
    assert why == "2 closed alerts left unattached: Sync alerts is on"
    [(_, to, recorded)] = rig.db.settled
    assert to == "verified"
    assert recorded["left_out"] == sorted(closed)  # kept in the step's ids once it is verified
    assert report.note is not None
    assert "attach:1" in report.note
    assert "2 closed alerts left unattached" in report.note


async def test_the_later_calls_expect_the_lowered_totals_and_are_checked_against_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed = {ids(0, 100)[3], ids(0, 100)[40]}
    rig = Rig(monkeypatch, three(), closed=closed)
    await rig.send(1)
    await rig.send(2)  # no closed alert in the second call
    assert [(k, len(p.alerts), p.expect_total) for k, p in rig.sent] == [
        ("attach:1", 98, 148),
        ("attach:2", 100, 248),
    ]
    # an attach in doubt is settled by the look against the lowered total
    rig.case = {"id": KID, "totalAlerts": 248}
    found, got = await rig.poster._look(rig.row(2), rig.post(), team.amadey())
    assert found is True
    assert got["alerts_total"] == 248
    rig.case = {"id": KID, "totalAlerts": 247}
    assert (await rig.poster._look(rig.row(2), rig.post(), team.amadey()))[0] is False
    # the first call's look finds its own left-out alerts again for the record
    rig.case = {"id": KID, "totalAlerts": 148}
    found, got = await rig.poster._look(rig.row(1), rig.post(), team.amadey())
    assert found is True
    assert got["left_out"] == sorted(closed)


async def test_an_open_case_with_no_closed_alert_sends_the_call_as_planned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = Rig(monkeypatch, three())
    report = await rig.send(1)
    assert rig.db.writes == []
    assert [(len(p.alerts), p.expect_total) for _, p in rig.sent] == [(100, 150)]
    assert report.note is None


async def test_a_case_that_is_not_open_skips_the_attach_and_says_why(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for status in ("in-progress", "closed"):
        rig = Rig(monkeypatch, three(), status=status)
        report = await rig.send(1)
        assert rig.sent == []  # nothing is sent
        [(step_id, left, why, skip)] = rig.db.writes
        assert (step_id, left, skip) == (11, sorted(ids(0, 100)), True)
        assert why == SYNC_NOT_OPEN
        assert rig.row(1).state == "skipped"
        assert report.note is not None
        assert SYNC_NOT_OPEN in report.note
        assert report.held == []  # the run goes on
        assert report.stopped is None
        # the later calls are expected to hold nothing of it
        await rig.send(2)
        assert rig.sent == []
        assert totals(rig.db.rows, rig.row(3)) == (100, 150)


async def test_a_call_whose_alerts_are_all_closed_is_skipped_and_the_total_follows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = Rig(monkeypatch, three(), closed=set(ids(0, 100)))
    await rig.send(1)
    assert rig.sent == []
    [(_, _, why, skip)] = rig.db.writes
    assert skip is True
    assert why == "100 closed alerts left unattached: Sync alerts is on"
    await rig.send(2)
    assert [(k, p.expect_total) for k, p in rig.sent] == [("attach:2", 150)]


async def test_a_resend_leaves_out_what_closed_since_and_keeps_what_was_left_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = three()
    rows[0] = replace(with_left(rows[0], ids(0, 1)[0]), state="resend")
    rig = Rig(monkeypatch, rows, closed={ids(0, 100)[7]})
    await rig.send(1)
    [(_, left, _, _)] = rig.db.writes
    assert left == sorted([ids(0, 1)[0], ids(0, 100)[7]])
    [(_, params)] = rig.sent
    assert (len(params.alerts), params.expect_total) == (98, 148)


async def test_a_case_that_cannot_be_read_stops_the_run_before_anything_is_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = Rig(monkeypatch, three())
    rig.case = GatewayError("down")
    with pytest.raises(RunStopped, match="could not be read"):
        await rig.send(1)
    assert rig.sent == []
    assert rig.db.writes == []


def test_the_reason_a_closed_case_gives_is_the_one_the_status_command_shows() -> None:
    assert SYNC_NOT_OPEN == (
        "Sync alerts is on and the case is not open: the attach would change the alerts' status"
    )
    assert plan.PER_CALL == 100
    assert sender.SYNC_NOT_OPEN is SYNC_NOT_OPEN
