"""E3: the checking lane with a fake gateway: what a pass plans (one batched lookup an hour, only
exposure candidates), what stops it (the lane's budget, CAUTION, the quiet hours, a kill
switch), and its properties: the lane never spends more than its cap, and plain scanning never
presents. Made-up sites and addresses (ACME)."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.gateway import health as health_core
from argus.gateway.errors import (
    BudgetExhaustedError,
    DeferredError,
    OverloadedError,
    PartialResultError,
    SiemError,
    StoppedError,
    TimedOutError,
)
from argus.gateway.gateway import QUIET_PURPOSES, Result
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.lanes import Lane, lane_of
from argus.gateway.templates import COMPONENT, Purpose
from argus.risk import checking, run, webchecks
from argus.risk import observe as ob
from argus.risk.checking import Inputs, Pair, Pending
from tests.unit.gateway.fakes import FakeTransport, listing, ok, search_answer
from tests.unit.gateway.fakes import make as make_gateway
from tests.unit.risk.conftest import CONFIG, NOW, context, group, meta

pytestmark = pytest.mark.unit
EX = CONFIG.exposure
ALL = checking.TEMPLATES
DAY = NOW.date()
SITE = "dept.example.edu"


def pair(source: str = "45.138.12.7", site: str = SITE, *, paths: dict[str, int] | None = None,
         rows: int = 2, hours: float = 2.0, origin: str = "evidence",
         lookup_ok: bool | None = False) -> Pair:  # fmt: skip
    at = NOW - timedelta(hours=hours)
    return Pair(source, site, DAY, at - timedelta(minutes=30), at,
                dict(paths if paths is not None else {"/.env": 1, "/": 1}), rows, lookup_ok,
                origin)  # fmt: skip


def pending(n: int, *, hours: float = 1.0) -> list[Pending]:
    at = NOW - timedelta(hours=hours)
    return [Pending(f"45.138.{12 + i // 200}.{i % 200}", at - timedelta(minutes=5), at)
            for i in range(n)]  # fmt: skip


# --------------------------------------------------------------------------- planning


def test_one_batched_lookup_an_hour_of_at_most_fifty_sources() -> None:
    inputs = Inputs(pending=pending(70))
    asks = checking.plan(inputs, NOW, EX, ALL)
    lookups = [a for a in asks if a.kind == "sites"]
    assert len(lookups) == 1
    params = lookups[0].task.params
    assert isinstance(params, webchecks.SitesParams)
    assert len(params.ips) == 50
    assert set(lookups[0].touches) == set(params.ips)
    lately = replace(inputs, last_lookup=NOW - timedelta(minutes=20))
    assert not [a for a in checking.plan(lately, NOW, EX, ALL) if a.kind == "sites"]
    assert not checking.plan(inputs, NOW, EX, ALL - {"web.source_sites"})


def test_only_exposure_candidates_are_checked() -> None:
    plain = pair(paths={"/": 3, "/index.php": 1}, rows=4)
    candidate = pair("45.138.12.8", paths={"/.git/config": 1, "/": 1})
    asks = checking.plan(Inputs(pairs=[plain, candidate]), NOW, EX, ALL)
    assert {a.source for a in asks if a.source} == {"45.138.12.8"}
    assert {a.kind for a in asks} == {"catchall", "paths"}  # two answers: no take
    old = pair("45.138.12.9", hours=EX.candidate_hours + 1)
    assert not checking.plan(Inputs(pairs=[old]), NOW, EX, ALL)


def test_a_site_gets_one_soft_404_check_a_day_and_done_checks_are_not_asked_again() -> None:
    a, b = pair("45.138.12.7"), pair("45.138.12.8", paths={"/.env": 1, "/db.sql": 1})
    inputs = Inputs(pairs=[a, b], sources_of={(SITE, DAY): {a.source, b.source}})
    asks = checking.plan(inputs, NOW, EX, ALL)
    catch = [x for x in asks if x.kind == "catchall"]
    assert len(catch) == 1
    assert set(catch[0].touches) == {a.source, b.source}
    probes = catch[0].task.params
    assert isinstance(probes, webchecks.CatchallParams)
    assert set(probes.paths) == {"/.env", "/db.sql"}  # the sensitive ones only
    done = {("catchall", "", SITE, DAY), ("paths", a.source, SITE, DAY)}
    again = checking.plan(replace(inputs, done=done), NOW, EX, ALL)
    assert [(x.kind, x.source) for x in again] == [("paths", b.source)]


def test_many_answers_or_a_lookup_alone_ask_what_was_taken() -> None:
    many = pair(paths={f"/.git/objects/{i}": 1 for i in range(20)}, rows=20)
    looked = pair("45.138.12.8", paths={}, rows=0, origin="lookup", lookup_ok=True)
    asks = checking.plan(Inputs(pairs=[many, looked]), NOW, EX, ALL)
    takes = {a.source for a in asks if a.kind == "take"}
    assert takes == {many.source, looked.source}
    nothing = pair("45.138.12.9", paths={}, rows=0, origin="lookup", lookup_ok=False)
    assert not checking.plan(Inputs(pairs=[nothing]), NOW, EX, ALL)


def _windows(plan: list[checking.Ask]) -> dict[str, tuple[datetime, datetime]]:
    out = {}
    for a in plan:
        params: Any = a.task.params
        out[a.kind] = (params.start, params.end)
    return out


@pytest.mark.parametrize("hour", [21.75, 25.67, 33.0, 40.0])  # 21:45 to 16:00 the next day
def test_an_evening_scan_checked_later_reads_its_own_days_index(hour: float) -> None:
    """A scan from 20:30 to 21:00 UTC, checked that night or the next day (late alerts, or a
    lane refused that evening): every check reads the scan's day, never the next day's 01:00."""
    first = datetime(2026, 10, 19, 20, 30, tzinfo=UTC)
    scan = Pair("45.138.12.7", SITE, first.date(), first, first + timedelta(minutes=30),
                {f"/.git/{i}": 1 for i in range(6)}, 6)  # fmt: skip
    now = datetime(2026, 10, 19, tzinfo=UTC) + timedelta(hours=hour)
    plan = checking.plan(Inputs(pairs=[scan]), now, EX, ALL)
    windows = _windows(plan)
    assert set(windows) == {"catchall", "take", "paths"}
    for kind, (start, end) in windows.items():
        assert start == first - checking.MARGIN, kind
        assert start < scan.last_at < end, kind  # it reads the scan
        assert end.date() == first.date(), kind  # in the 19th's index
        assert end.hour < 23, kind
    assert all(a.day == first.date() for a in plan)


def test_a_check_whose_window_cannot_read_the_scan_is_not_sent() -> None:
    """23:20 to 23:40 UTC lies between two indices' one-index hours: nothing can read it."""
    first = datetime(2026, 10, 19, 23, 20, tzinfo=UTC)
    scan = Pair("45.138.12.7", SITE, first.date(), first, first + timedelta(minutes=20),
                {f"/.git/{i}": 1 for i in range(6)}, 6)  # fmt: skip
    assert checking.plan(Inputs(pairs=[scan]), datetime(2026, 10, 20, 9, tzinfo=UTC), EX,
                         ALL) == []  # fmt: skip
    later = replace(scan, last_at=datetime(2026, 10, 20, 2, 0, tzinfo=UTC))
    windows = _windows(checking.plan(Inputs(pairs=[later]), datetime(2026, 10, 20, 9, tzinfo=UTC),
                                     EX, ALL))  # fmt: skip
    assert set(windows) == {"catchall", "take", "paths"}  # it went on past 01:00: that part
    assert all(start.hour == 1 and start.date() == later.last_at.date()
               for start, _ in windows.values())  # fmt: skip


def test_the_soft_404_window_covers_the_most_scans_of_the_site_and_day() -> None:
    def at(source: str, hour: int, paths: dict[str, int]) -> Pair:
        first = datetime(2026, 10, 20, hour, 0, tzinfo=UTC)
        return Pair(source, SITE, first.date(), first, first + timedelta(minutes=20), paths, 2)

    lone = at("45.138.12.7", 9, {"/.env": 1, "/.git/config": 1, "/db.sql": 1})  # most telling
    early = [at("45.138.12.8", 2, {"/.env": 1}), at("45.138.12.9", 4, {"/.git/config": 1})]
    plan = checking.plan(Inputs(pairs=[lone, *early]), NOW, EX, ALL)
    ((start, end),) = [w for k, w in _windows(plan).items() if k == "catchall"]
    assert start == early[0].first_at - checking.MARGIN
    assert end == start + webchecks.SITE_WINDOW


def test_the_lookup_is_stored_on_the_day_its_groups_are_looked_up_by() -> None:
    """Alerts from 22:00 to 00:30 UTC are read from the first day's index; the answer is still
    the day the alert group is looked up by (its last alert's), or it would be asked again."""
    at = datetime(2026, 10, 21, 0, 30, tzinfo=UTC)
    plan = checking.plan(Inputs(pending=[Pending("45.138.12.7", at - timedelta(hours=2.5), at)]),
                         datetime(2026, 10, 21, 2, 0, tzinfo=UTC), EX, ALL)  # fmt: skip
    (lookup,) = plan
    params: Any = lookup.task.params
    assert params.end.date() == date(2026, 10, 20)  # the index that holds the readable part
    assert lookup.kind == "sites"
    assert lookup.day == at.date()


def test_the_most_telling_candidates_come_first() -> None:
    weak = pair("45.138.12.7", paths={"/.env": 1})
    strong = pair("45.138.12.8", paths={"/.env": 1, "/.git/config": 1, "/db.sql": 1}, rows=3)
    order = [p.source for p in checking.candidates(Inputs(pairs=[weak, strong]), NOW, EX)]
    assert order == [strong.source, weak.source]


# --------------------------------------------------------------------------- the gateway's rules


def test_the_check_purpose_is_its_own_lane_normal_only_and_never_in_the_quiet_hours() -> None:
    assert lane_of(Purpose.CHECK) is Lane.CHECKING
    assert COMPONENT[Purpose.CHECK] == "checking"
    assert Purpose.CHECK in QUIET_PURPOSES
    assert [health_core.allowed(s, Purpose.CHECK) for s in HealthState] == [True, False, False,
                                                                             False]  # fmt: skip


def test_a_pass_sends_nothing_unless_normal_and_outside_the_quiet_hours() -> None:
    normal, caution = HealthMemory(probed_at=NOW), HealthMemory(HealthState.CAUTION, probed_at=NOW)
    assert checking.allowed(normal, NOW) is None
    assert "CAUTION" in str(checking.allowed(caution, NOW)).upper()
    quiet = datetime(2026, 10, 20, 0, 30, tzinfo=UTC)
    assert "quiet hours" in str(checking.allowed(normal, quiet))


class Fake:
    """A gateway that answers every check with ``body`` at ``took`` ms, or raises the next of
    ``errors``."""

    def __init__(self, took: int | list[int] = 800, errors: list[Exception] | None = None,
                 body: Any = None) -> None:  # fmt: skip
        self.took = took
        self.errors = list(errors or [])
        self.body = body if body is not None else {"aggregations": {}}
        self.sent: list[tuple[str, Purpose, str]] = []

    async def run(self, template: Any, params: Any, *, purpose: Purpose, component: str,
                  deadline: datetime) -> Result:  # fmt: skip
        if self.errors:
            raise self.errors.pop(0)
        self.sent.append((type(template).name, purpose, component))
        took = self.took.pop(0) if isinstance(self.took, list) else self.took
        return Result(self.body, took, ("acme-logs-nginx-2026.10.20",))


def asks(n: int) -> list[checking.Ask]:
    inputs = Inputs(pairs=[pair(f"45.138.12.{i}", site=f"s{i}.example.edu") for i in range(n)])
    return checking.plan(inputs, NOW, EX, ALL)


async def send(gateway: Fake, plan: list[checking.Ask], *, spent: int = 0,
               **config: Any) -> checking.Report:  # fmt: skip
    report = checking.Report()
    cfg = EX.model_copy(update=config)
    await checking.send(plan, gateway, now=NOW, clock=lambda: NOW, spent_ms=spent, config=cfg,
                        report=report)  # fmt: skip
    return report


async def test_every_check_goes_on_the_checking_lane_and_the_pass_has_a_limit() -> None:
    fake = Fake()
    report = await send(fake, asks(10))
    assert len(fake.sent) == EX.pass_requests == report.sent
    assert {(p, c) for _, p, c in fake.sent} == {(Purpose.CHECK, "checking")}
    assert report.stopped == "the pass's request limit"
    assert report.spent_ms == 800 * EX.pass_requests


@pytest.mark.parametrize(
    "error",
    [BudgetExhaustedError("lane_day"), DeferredError("the SIEM is caution: check waits"),
     StoppedError("stopped by the operator's kill switch")],
)  # fmt: skip
async def test_a_refusal_ends_the_pass(error: Exception) -> None:
    fake = Fake(errors=[error])
    report = await send(fake, asks(3))
    assert fake.sent == []
    assert report.sent == 0
    assert report.stopped is not None
    assert report.stopped.startswith("refused")


@pytest.mark.parametrize(
    "error",
    [TimedOutError("slow"), PartialResultError("timed out on 1 shard"),
     OverloadedError("429"), SiemError(503, None)],
)  # fmt: skip
async def test_a_struggling_siem_ends_the_pass_and_counts_the_timeout(error: Exception) -> None:
    fake = Fake(errors=[error])
    plan = asks(2)
    report = await send(fake, plan)
    assert report.failed == 1
    assert report.sent == 0
    assert fake.sent == []  # no more heavy checks on a slow SIEM
    assert report.spent_ms == plan[0].timeout_ms
    assert "next pass tries again" in str(report.stopped)


async def test_a_request_the_siem_refused_as_wrong_counts_its_timeout_and_goes_on() -> None:
    fake = Fake(errors=[SiemError(400, "search_phase_execution_exception")])
    plan = asks(2)
    report = await send(fake, plan)
    assert report.failed == 1
    assert report.sent == len(plan) - 1
    assert report.spent_ms == plan[0].timeout_ms + 800 * (len(plan) - 1)
    assert report.stopped is None


async def test_the_lanes_day_cap_must_hold_a_whole_timeout() -> None:
    fake = Fake()
    report = await send(fake, asks(2), spent=EX.day_ms - 9_999)
    assert fake.sent == []
    assert "used up" in str(report.stopped)
    report = await send(fake, asks(2), spent=EX.day_ms - 10_000)
    assert report.sent == 1


@settings(max_examples=200, deadline=None)
@given(
    spent=st.integers(0, EX.day_ms),
    tooks=st.lists(st.integers(0, 10_000), min_size=1, max_size=60),
    cap=st.integers(0, EX.day_ms),
    limit=st.integers(1, 50),
)
async def test_the_lane_never_spends_more_than_its_cap(spent: int, tooks: list[int], cap: int,
                                                        limit: int) -> None:  # fmt: skip
    """Whatever it is asked and however long each check takes (at most its timeout), the lane's
    server time after a pass stays within its day cap, unless it was over before."""
    plan = (asks(10) * 6)[: len(tooks)]
    fake = Fake(took=list(tooks))
    report = await send(fake, plan, spent=spent, day_ms=cap, pass_requests=limit)
    assert report.spent_ms <= max(cap, spent)
    assert report.sent <= limit


# --------------------------------------------------------------------------- the real gateway


async def test_the_real_gateway_charges_the_checking_lane_and_defers_in_caution() -> None:
    transport = FakeTransport(default={**search_answer(took=1_200), "aggregations": {}})
    transport.on("_resolve/index", ok(listing("acme-logs-nginx-2026.10.20")))
    gateway, _, store, clock = make_gateway(transport)
    clock.now = NOW
    store.memory = HealthMemory(probed_at=NOW)
    plan = asks(1)[:1]
    report = await send_real(gateway, plan)
    assert report.sent == 1
    assert store.lanes.bucket(Lane.CHECKING).day_used_ms == 1_200
    assert {e.lane for e in store.ledger if e.template in checking.TEMPLATES} == {"checking"}
    store.memory = HealthMemory(HealthState.CAUTION, since=NOW, probed_at=NOW)
    report = await send_real(gateway, plan)
    assert report.sent == 0
    assert "caution" in str(report.stopped)


async def send_real(gateway: Any, plan: list[checking.Ask]) -> checking.Report:
    report = checking.Report()
    await checking.send(plan, gateway, now=gateway.clock(), clock=gateway.clock, spent_ms=0,
                        config=EX, report=report)  # fmt: skip
    return report


def test_a_stored_answer_of_each_kind() -> None:
    plan = checking.plan(Inputs(pairs=[pair(paths={f"/.git/{i}": 1 for i in range(6)}, rows=6)],
                                pending=pending(2)), NOW, EX, ALL)  # fmt: skip
    kinds = {a.kind: a for a in plan}
    assert set(kinds) == {"sites", "catchall", "take", "paths"}
    rows = {k: checking.found_of(a, Result({"aggregations": {}}, 5, ()), EX) for k, a in
            kinds.items()}  # fmt: skip
    assert [r.verdict for r in rows["sites"]] == ["none", "none"]
    assert rows["catchall"][0].verdict == "unknown"
    assert rows["catchall"][0].source is None
    assert rows["take"][0].verdict == "no_bulk"
    assert rows["paths"][0].verdict == "unknown"
    assert all(len(r.task_key or "") == 64 for rs in rows.values() for r in rs)


# --------------------------------------------------------------------------- plain scanning


NON_LANE = ("web.successes_after", "web.paths_success", "proxy.regularity", "ports.risky")


@settings(max_examples=150, deadline=None)
@given(
    groups=st.lists(
        st.tuples(
            st.integers(1, 250),  # the scanner
            st.sampled_from(["low", "medium", "high", "critical"]),
            st.integers(0, 3),  # how many sites
            st.sets(st.sampled_from(NON_LANE), max_size=3),
            st.floats(0.0, 160.0),  # hours ago
        ),
        min_size=1,
        max_size=40,
    )
)
def test_plain_scanning_never_presents(groups: list[tuple[Any, ...]]) -> None:
    """Inbound groups with any rules, severities and unverified answers, on any campus sites:
    without a verified fact no site is ever in a lane (critical rules included)."""
    obs: list[ob.Observation] = []
    for scanner, severity, sites, signals, hours in groups:
        g = group(actor=f"45.138.12.{scanner}", severity=severity, hours_ago=hours,
                  signals=dict.fromkeys(signals, 3), gid=uuid.uuid4())  # fmt: skip
        g = replace(g, sites=tuple(f"s{i}.example.edu" for i in range(sites)))
        obs += ob.observe(g, meta(rule=f"rule-{severity}", family="nginx"), context()).observations
    scored = run.evaluate_all(obs, NOW, CONFIG, {}, set())
    for ref, v in scored.verdicts.items():
        assert ref.kind == "site"
        assert v.lanes == (), (ref, v.lanes)


def test_an_exposure_fact_presents_its_site_through_the_engines_pass_code() -> None:
    g = group(actor="45.138.12.7", severity="high", signals={"exposure.bulk_take": 214})
    g = replace(g, sites=(SITE,))
    obs = list(ob.observe(g, meta(family="nginx"), context()).observations)
    scored = run.evaluate_all(obs, NOW, CONFIG, {}, set())
    ((ref, v),) = scored.verdicts.items()
    assert ref.key == f"domain:{SITE}"
    assert v.lanes == ("exposure",)
    assert scored.by_group[g.id] == [ref]
    _ = date  # dates are the pairs' days above
