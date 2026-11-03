"""The independent review's findings on Q-A3 (F1-F9), pinned: each test failed before its fix."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from argus.gateway.budget import BudgetState
from argus.gateway.errors import TimedOutError, TransportFailedError
from argus.gateway.health import HealthConfig, HealthMemory, HealthState, scale
from argus.gateway.state import LedgerEntry, MemoryStore, ProbeRow, RecentRequest
from argus.gateway.templates import CostClass
from argus.gateway.transport import WireRequest, WireResponse
from argus.measure import cli, lanes
from argus.measure.session import COMPONENT, LIMITS, MINUTE, Plan, verify
from tests.conftest import private_text
from tests.unit.gateway.fakes import FakeClock
from tests.unit.measure.fakes import T0, FakeElastic, plan_at, rig

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
CFG = HealthConfig()


def one(name: str) -> Plan:
    return Plan(tuple(item for item in plan_at().items if item.name == name)[:1])


def ledger(at: datetime, component: str, template: str, took: int,
           purpose: str = "collect") -> LedgerEntry:  # fmt: skip
    return LedgerEntry(at, component, purpose, template, 1, (), "ok", 200, took, took, 0, 1)


def reading(at: datetime, **kw: Any) -> ProbeRow:
    values: dict[str, Any] = {
        "at": at, "state": "normal", "disk_percent": 60.0, "heap_percent": 50.0,
        "load_1m": 2.0, "search_queue": 0, "search_rejected": 7, "breakers_tripped": 0,
    }  # fmt: skip
    values.update(kw)
    return ProbeRow(**values)


async def stored_verdict(r: Any, report: Any) -> Any:
    rows = await r.store.requests_since(T0 - 2 * MINUTE)
    probes = await r.store.probes_since(T0 - MINUTE)
    return verify(rows, probes, report.started, report.ended or r.clock(),
                  requests_sent=report.requests_sent)  # fmt: skip


# ------------------------------------------------- F1: the session never lets the gateway retry


async def test_f1_a_reached_503_is_not_retried_and_every_minute_stays_within_3_s() -> None:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    store.ledger.append(ledger(T0 - timedelta(seconds=20), "collector", "alerts.ids", 1_400))
    elastic = FakeElastic(clock)
    sent: list[datetime] = []

    def flaky(request: WireRequest) -> WireResponse:
        sent.append(clock())
        if len(sent) == 1:  # SIEM answers 503 after 1.25 s
            clock.advance(timedelta(milliseconds=1_250))
            return WireResponse(503, b'{"error":{"type":"unavailable"}}', 1_250.0)
        clock.advance(timedelta(milliseconds=1_300))
        raise TimedOutError()

    elastic.replies["alerts.ids"] = flaky
    r = rig(elastic=elastic, clock=clock, store=store, plan=one("alerts.ids"))
    report = await r.session.run()
    assert len(sent) == 1  # never retried into a cluster that just answered 503
    assert report.stopped == (
        "alerts.ids #1: the SIEM did not answer cleanly (transport_failure); the session never"
        " retries a request"
    )
    assert report.samples[-1].outcome == "transport_failure"
    row = next(e for e in store.ledger if e.component == COMPONENT and e.template == "alerts.ids")
    assert (row.outcome, row.took_ms, row.attempts) == ("no_retry", 1_250, 1)
    verdict = await stored_verdict(r, report)
    assert not [p for p in verdict.problems if " ms in the minute" in p], verdict.problems
    assert "requests that did not answer ok: no_retry" in verdict.problems


async def test_f1_a_reset_heavy_request_is_not_retried_either() -> None:
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    elastic.replies["proxy.host"] = TransportFailedError("reset", retriable=True)
    r = rig(elastic=elastic, clock=clock)
    report = await r.session.run()
    assert report.stopped is not None
    assert "never retries" in report.stopped
    row = next(e for e in r.store.ledger if e.template == "proxy.host")
    assert (row.outcome, row.attempts) == ("no_retry", 1)  # the cap was never asked


async def test_f1_a_gateway_retry_the_check_did_not_see_still_ends_the_session() -> None:
    """Defence in depth: should a retry ever go out without the session's check, the
    session notices it from its transport's count and ends."""
    clock = FakeClock(T0)
    elastic = FakeElastic(clock)
    first = [True]

    def reset_once(request: WireRequest) -> WireResponse:
        if first[0]:
            first[0] = False
            raise TransportFailedError("reset", retriable=True)
        elastic.replies.pop("alerts.counts")
        return WireResponse(200, json.dumps({
            "took": 5, "timed_out": False, "hits": {"hits": []},
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        }).encode(), 5.0)  # fmt: skip

    elastic.replies["alerts.counts"] = reset_once
    r = rig(elastic=elastic, clock=clock, plan=one("alerts.counts"))

    async def blind(now: datetime) -> None:
        return None

    r.session._check_for = lambda item: blind  # type: ignore[method-assign]
    report = await r.session.run()
    assert report.stopped == "alerts.counts #1: it needed a retry: the SIEM did not answer cleanly"


# ---------------------------------------- F2: every template ARGUS sends is known to the script


def _registered_in_source() -> dict[str, str]:
    """Every ``@register``-ed template's name in the package, from the source (no import)."""
    found: dict[str, str] = {}
    for path in sorted((ROOT / "src" / "argus").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            names = {d.id if isinstance(d, ast.Name) else getattr(d, "attr", "")
                     for d in node.decorator_list}  # fmt: skip
            if "register" not in names:
                continue
            for stmt in node.body:
                if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                        and isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id == "name"
                        and isinstance(stmt.value, ast.Constant)):  # fmt: skip
                    found[str(stmt.value.value)] = str(path.relative_to(ROOT))
    return found


def test_f2_the_script_knows_every_template_argus_sends_with_its_cost() -> None:
    expected = _registered_in_source()
    assert {"logs.source_events", "proxy.pair", "dns.host_domains"} <= set(expected)
    code = (
        "import json, argus.measure.cli\n"
        "from argus.gateway.templates import REGISTRY\n"
        "print(json.dumps({n: t.cost.value for n, t in REGISTRY.items()}))\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,  # noqa: S603
                         check=True, cwd=ROOT, timeout=120).stdout  # fmt: skip
    known = json.loads(out.strip().splitlines()[-1])
    missing = {name: where for name, where in expected.items() if name not in known}
    assert not missing, f"import these modules in argus.measure.session: {missing}"
    assert known["logs.source_events"] == "medium"


# --------------------------------------- F3: verify counts what reached the SIEM, listings included


def test_f3_a_reached_request_the_cap_refused_to_retry_counts_as_sent_and_failed() -> None:
    rows = [
        RecentRequest(
            T0 + timedelta(seconds=1),
            COMPONENT,
            "measure",
            "proxy.host",
            "session_cap",
            120,
            http_status=503,
            attempts=2,
        ),
        RecentRequest(
            T0 + timedelta(seconds=2), COMPONENT, "measure", "alerts.ids", "session_cap", 0
        ),  # refused unsent: not counted
        RecentRequest(T0 + timedelta(seconds=3), COMPONENT, "measure", "alerts.ids", "ok", 10),
    ]
    verdict = verify(rows, [reading(T0)], T0, T0 + MINUTE)
    assert verdict.problems == ("requests that did not answer ok: session_cap",)
    assert verdict.facts[0].endswith(": 2 requests, 1 heavy, 130 ms of server time")
    retried = RecentRequest(T0 + timedelta(seconds=30), COMPONENT, "measure", "proxy.host",
                            "timed_out", 2_300, attempts=2)  # fmt: skip
    verdict = verify([*rows, retried], [reading(T0)], T0, T0 + MINUTE)
    assert "a heavy request sent twice at 10:00:30 (a retry, under 10 s apart)" in verdict.problems
    assert verdict.facts[0].endswith(": 4 requests, 3 heavy, 2430 ms of server time")


async def test_f3_the_sessions_index_listings_are_its_own_on_the_ledger() -> None:
    r = rig()
    report = await r.session.run()
    listings = [e for e in r.store.ledger if e.template == "indices.listing"]
    assert listings
    assert {e.component for e in listings} == {COMPONENT}
    verdict = await stored_verdict(r, report)
    assert verdict.passed, verdict.problems
    assert f": {report.requests_sent} requests," in verdict.facts[0]


def test_f3_a_ledger_missing_requests_the_session_sent_fails() -> None:
    rows = [RecentRequest(T0 + timedelta(seconds=3), COMPONENT, "measure", "alerts.ids", "ok", 10)]
    verdict = verify(rows, [reading(T0)], T0, T0 + MINUTE, requests_sent=4)
    assert "the ledger holds 1 of the 4 requests the session sent" in verdict.problems


# -------------------------------------------------------- F4: §7.8's five-minute attribution


def busy_session() -> tuple[list[RecentRequest], datetime]:
    rows = [
        RecentRequest(T0 + timedelta(seconds=5), COMPONENT, "measure", "proxy.host", "ok", 1_600),
        RecentRequest(T0 + timedelta(seconds=20), COMPONENT, "measure", "alerts.ids", "ok", 100),
    ]
    return rows, T0 + MINUTE


def test_f4_caution_three_minutes_after_a_busy_minute_counts_against_the_session() -> None:
    rows, end = busy_session()
    caution = reading(end + timedelta(minutes=3), state="caution", reasons=("load",), load_1m=17.0)
    verdict = verify(rows, [reading(T0), caution], T0, end)
    assert not verdict.passed
    assert any("the SIEM is caution" in p for p in verdict.problems), verdict.problems


def test_f4_without_a_busy_minute_only_the_minute_after_counts() -> None:
    rows = [RecentRequest(T0 + timedelta(seconds=5), COMPONENT, "measure", "alerts.ids", "ok", 900)]
    end = T0 + MINUTE
    caution = reading(end + timedelta(minutes=3), state="caution", reasons=("load",), load_1m=17.0)
    verdict = verify(rows, [reading(T0), caution], T0, end, now=end + timedelta(seconds=5))
    assert verdict.passed, verdict.problems
    assert verdict.pending_until is None


def test_f4_a_busy_session_verified_early_is_provisional() -> None:
    rows, end = busy_session()
    early = verify(rows, [reading(T0)], T0, end, now=end + timedelta(seconds=10))
    assert early.passed
    assert early.pending_until == end + timedelta(minutes=5)
    later = verify(rows, [reading(T0)], T0, end, now=end + timedelta(minutes=6))
    assert later.passed
    assert later.pending_until is None


class Stored:
    def __init__(self, rows: list[RecentRequest], probes: list[ProbeRow]) -> None:
        self.rows, self.probes = rows, probes

    async def requests_since(self, since: datetime, until: datetime | None = None) -> list[Any]:
        return [r for r in self.rows if r.at >= since and (until is None or r.at < until)]

    async def probes_since(self, since: datetime, until: datetime | None = None) -> list[Any]:
        return [p for p in self.probes if p.at >= since and (until is None or p.at < until)]


async def test_f4_verify_reads_the_readings_five_minutes_on_and_says_when_it_is_final() -> None:
    rows, end = busy_session()
    caution = reading(end + timedelta(minutes=4), state="caution", reasons=("load",), load_1m=17.0)
    store: Any = Stored(rows, [reading(T0), caution])
    lines = await cli.verify_stored(store, T0, end, CFG, now=end + timedelta(minutes=10))
    assert lines[-1] == "SESSION NOT VERIFIED"
    store = Stored(rows, [reading(T0)])
    lines = await cli.verify_stored(store, T0, end, CFG, now=end + timedelta(seconds=30))
    assert lines[-1] == "SESSION VERIFIED SO FAR: run verify again after 10:06 UTC"
    lines = await cli.verify_stored(store, T0, end, CFG, now=end + timedelta(minutes=10))
    assert lines[-1] == "SESSION VERIFIED"


# ---------------------------------------------------- F5: a plan file never masks an over lane


def over_collector() -> tuple[dict[str, lanes.TemplateStats], list[lanes.Rate]]:
    stats = {"alerts.ids": lanes.TemplateStats("alerts.ids", CostClass.LIGHT, 50, 400, 900, 950)}
    return stats, [lanes.Rate("collector", "alerts.ids", 5, 10_000, 3)]  # 4,500 ms a minute


def test_f5_a_plan_naming_an_unknown_or_probe_template_is_refused() -> None:
    _, rates = over_collector()
    with pytest.raises(ValueError, match=r"unknown template collector\.'alerts\.idz'"):
        lanes.apply_plan(rates, {"collector": {"alerts.idz": {"per_minute": 0}}})
    with pytest.raises(ValueError, match="outside the bucket"):
        lanes.apply_plan(rates, {"collector": {"health.node_stats": {"per_minute": 1}}})


def test_f5_a_template_without_samples_never_turns_over_into_not_measured() -> None:
    stats, rates = over_collector()
    room = lanes.headroom([])
    planned = lanes.apply_plan(rates, {"collector": {"proxy.pair": {"per_minute": 1}}})
    result = lanes.derive(stats, planned, room)[0]
    assert result.verdict == "over"
    assert any("proxy.pair: 0 samples" in reason for reason in result.reasons)
    assert "a busy minute needs 4500 ms of its 1800 ms" in result.reasons
    fits = {"alerts.ids": lanes.TemplateStats("alerts.ids", CostClass.LIGHT, 50, 4, 9, 9)}
    assert lanes.derive(fits, planned, room)[0].verdict == "not measured"


# ------------------------------------------- F6: slow start and the signals after a budget wait


async def test_f6_nothing_is_sent_during_slow_start_after_a_budget_wait() -> None:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    r = rig(store=store, clock=clock, plan=one("alerts.ids"))
    flipped: list[datetime] = []

    async def gateway_sleep(seconds: float) -> None:
        if not flipped:  # during the budget wait the SIEM went DEGRADED and came back
            flipped.append(clock())
            store.memory = HealthMemory(state=HealthState.NORMAL, probed_at=clock(),
                                        recovered_at=clock())  # fmt: skip
        await clock.sleep(seconds)

    r.gateway.sleep = gateway_sleep
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())
    report = await r.session.run()
    assert flipped
    assert scale(store.memory, clock(), r.session.config) < 1
    assert [e for e in store.ledger if e.purpose == "measure"] == []
    assert report.stopped is not None
    assert "coming back" in report.stopped


async def test_f6_a_reading_gone_stale_during_a_budget_wait_is_probed_again_first() -> None:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    r = rig(store=store, clock=clock, plan=one("alerts.ids"))
    waited: list[datetime] = []

    async def gateway_sleep(seconds: float) -> None:
        if not waited:  # a long budget wait: the newest reading is past a minute old after it
            waited.append(clock())
            clock.advance(timedelta(seconds=70))
        await clock.sleep(seconds)

    r.gateway.sleep = gateway_sleep
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())
    report = await r.session.run()
    assert report.complete, report.stopped
    sent = next(e for e in store.ledger if e.purpose == "measure")
    newest = max(p.at for p in await store.probes_since(T0) if p.at <= sent.at)
    assert sent.at - newest <= LIMITS.probe_fresh


async def test_f6_a_caution_reading_during_a_budget_wait_stops_the_request() -> None:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    r = rig(store=store, clock=clock, plan=one("alerts.ids"))
    from argus.gateway.health import Readings

    async def gateway_sleep(seconds: float) -> None:  # a reading with a search queue meanwhile
        await clock.sleep(seconds)
        await store.record_probe(Readings(at=clock(), load_1m=2.0, search_queue=4,
                                          search_rejected=7, breakers_tripped=0,
                                          disk_percent=60.0, heap_percent=50.0),
                                 HealthMemory())  # fmt: skip

    r.gateway.sleep = gateway_sleep
    store.budget = BudgetState(tokens_ms=0.0, refilled_at=T0, day=T0.date())
    report = await r.session.run()
    assert [e for e in store.ledger if e.purpose == "measure"] == []
    assert report.stopped is not None
    assert "search queue 4" in report.stopped


# ----------------------------------------------------------- F7: the runbook says what Ctrl-C does


def test_f7_the_runbook_says_an_interrupted_session_keeps_its_file() -> None:
    text = private_text(ROOT / "docs" / "runbooks" / "measure-capacity.md")
    assert "no file is saved" not in text
    assert "marked `interrupted`" in text


# ------------------------------------------ F8: a live run needs a database production writes to


def production_probe(at: datetime, component: str = "probe") -> LedgerEntry:
    return ledger(at, component, "health.node_stats", 5, purpose="probe")


async def test_f8_a_database_that_never_saw_production_is_refused() -> None:
    blockers = await cli.readiness(MemoryStore(), T0, CFG)
    assert any("shows no running ARGUS" in b for b in blockers), blockers
    store = MemoryStore()
    store.ledger.append(production_probe(T0 - timedelta(seconds=30), component=COMPONENT))
    assert any("shows no running ARGUS" in b for b in await cli.readiness(store, T0, CFG))
    store.ledger.append(production_probe(T0 - timedelta(minutes=3)))  # too old
    assert any("shows no running ARGUS" in b for b in await cli.readiness(store, T0, CFG))
    store.ledger.append(production_probe(T0 - timedelta(seconds=50)))  # the collector's, fresh
    assert await cli.readiness(store, T0, CFG) == []


def test_f8_the_lock_is_said_to_be_per_database() -> None:
    text = private_text(ROOT / "docs" / "runbooks" / "measure-capacity.md")
    assert "in every checkout" not in text
    assert "per database" in text


# --------------------------------------------- F9: malformed files end in a plain error message


def test_f9_malformed_session_and_plan_files_are_value_errors(tmp_path: Path) -> None:
    path = tmp_path / "session.json"
    for body in ({"format": 1, "component": COMPONENT},
                 {"format": 1, "component": COMPONENT, "started": None},
                 {"format": 1, "component": COMPONENT, "started": 5},
                 {"format": 1, "component": COMPONENT, "started": T0.isoformat(), "ended": 7},
                 [1, 2]):  # fmt: skip
        path.write_text(json.dumps(body))
        with pytest.raises(ValueError, match=r"not a (usable )?session file|not usable"):
            cli.load_session(path)
    for plan in ([1], "x", {"collector": [1]}):
        with pytest.raises(ValueError, match="mapping"):
            lanes.apply_plan([], plan)  # type: ignore[arg-type]


def test_f9_main_prints_an_error_for_a_malformed_session_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from argus.config.settings import DatabaseSettings, Settings

    monkeypatch.setattr(cli, "_settings", lambda _config: Settings(database=DatabaseSettings()))

    class NoEngine:
        async def dispose(self) -> None:
            pass

    monkeypatch.setattr(cli, "create_engine", lambda *_a, **_k: NoEngine())
    path = tmp_path / "session.json"
    path.write_text(json.dumps({"format": 1, "component": COMPONENT}))
    assert cli.main(["verify", str(path)]) == 1
    assert capsys.readouterr().err.startswith("error: ")
    plan = tmp_path / "plan.json"
    plan.write_text("[1]")
    monkeypatch.setattr(cli, "PgStore", lambda _engine: Stored([], []))
    assert cli.main(["report", "--plan", str(plan)]) == 1
    assert "error: " in capsys.readouterr().err
