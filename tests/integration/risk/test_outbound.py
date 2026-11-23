"""The engine's own evidence for its outbound incidents (D-323) against the database, as the
runtime role, through the real gateway on Postgres with a scripted SIEM: a presented incident's
device is timed to its destination and the destination's campus devices counted, once a material
version; the answers reach the incident's checks, alternatives and certainty word and, through
the engine's next pass, its observations (a measured rhythm is a beacon fact), never lowering its
priority; a destination many devices reach shows as a common service; the pass's caps, the
SIEM's health and a failed request; ARGUS's own alerts answering "too common"; the grants. Made-up
addresses only (the ACME site)."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context import batch1
from argus.gateway.errors import TimedOutError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.pgstore import PgStore
from argus.gateway.transport import WireRequest, WireResponse
from argus.risk import alternatives as alt
from argus.risk import outbound, run, store
from argus.risk.config import Outbound
from tests.integration.risk.conftest import C2, NOW, all_rows, group, rule, scalar, setup
from tests.integration.risk.test_present import presenting
from tests.unit.gateway.fakes import FakeClock, FakeTransport, listing, ok

pytestmark = pytest.mark.integration
DEVICE, SERVER = "10.1.1.1", "45.138.12.9"
OUTSIDE = "flagged by outside threat intel"
ALL = ("P1", "P2", "P3", "P4")  # the test's incident is checked whatever its band
CONFIG = Outbound.model_validate({**setup().config.outbound.model_dump(), "bands": ALL})
LANE_DAY_MS = setup().config.exposure.day_ms
ON = tuple(sorted(outbound.TEMPLATES))


async def world(owner: AsyncEngine) -> None:
    """One device an outside detection flags for talking to one outside address: a decisive
    incident with no timing of its own."""
    await rule(owner, "r-c2", "C2 rule", threat=(C2,))
    await group(owner, "r-c2", actor=DEVICE, flags=(OUTSIDE,),
                fields={"destination.ip": [SERVER]})  # fmt: skip


def answer(body: dict[str, Any], took: int = 640) -> WireResponse:
    full = {"took": took, "timed_out": False,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {"hits": []}, **body}  # fmt: skip
    return ok(full)


def regular(request: WireRequest) -> dict[str, Any]:
    """A request every five minutes over the pair's whole window."""
    query = json.loads(request.body or b"{}")
    bounds = query["aggs"]["beats"]["date_histogram"]["hard_bounds"]
    from datetime import datetime

    start = datetime.fromisoformat(bounds["min"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(bounds["max"].replace("Z", "+00:00"))
    keys, at = [], start
    while at < end:
        keys.append({"key": int(at.timestamp() * 1000), "doc_count": 2})
        at += timedelta(minutes=5)
    return {"aggregations": {"requests": {"value": 2 * len(keys)}, "bytes": {"value": 512000},
                             "first": {"value": None}, "last": {"value": None},
                             "beats": {"buckets": keys}}}  # fmt: skip


def scattered(_: WireRequest) -> dict[str, Any]:
    minutes = (1, 2, 9, 10, 31, 33, 70, 140, 141, 300)
    buckets = [{"key": 1_760_918_400_000 + m * 60_000, "doc_count": 40} for m in minutes]
    return {"aggregations": {"requests": {"value": 400}, "bytes": {"value": 9000},
                             "first": {"value": None}, "last": {"value": None},
                             "beats": {"buckets": buckets}}}  # fmt: skip


def contacts(devices: int) -> dict[str, Any]:
    return {"aggregations": {"requests": {"value": 30 * devices}, "first": {"value": None},
                             "last": {"value": None}, "host_count": {"value": devices},
                             "hosts": {"buckets": [{"key": DEVICE, "doc_count": 30}],
                                       "sum_other_doc_count": 0}}}  # fmt: skip


class Siem:
    """The scripted SIEM: one daily proxy index; a pair or a contact search answered as given."""

    def __init__(self, pair: Any = regular, devices: int = 1, fail: Exception | None = None):
        self.pair, self.devices, self.fail = pair, devices, fail
        self.asked: list[str] = []

    def __call__(self, request: WireRequest) -> WireResponse:
        query = json.loads(request.body or b"{}")
        aggs = query.get("aggs") or {}
        if self.fail is not None:
            raise self.fail
        if "beats" in aggs:
            self.asked.append("pair")
            return answer(self.pair(request))
        self.asked.append("contact")
        return answer(contacts(self.devices))


async def gateway_for(
    engine: AsyncEngine, siem: Siem, *, health: HealthState = HealthState.NORMAL,
    at: timedelta = timedelta(0),
) -> tuple[Gateway, PgStore, FakeClock]:  # fmt: skip
    clock = FakeClock(now=NOW + at)
    state = PgStore(engine)
    await state.save_health(HealthMemory(state=health, probed_at=clock()))
    transport = FakeTransport(clock=clock)
    transport.on("_resolve", ok(listing("acme-logs-squid-2026.10.20")))
    transport.on("_search", siem)
    gateway = Gateway(transport, state, targets=Targets(log_sources=frozenset({"squid"})),
                      clock=clock, sleep=clock.sleep)  # fmt: skip
    return gateway, state, clock


async def check(engine: AsyncEngine, siem: Siem, *, config: Outbound = CONFIG,
                health: HealthState = HealthState.NORMAL,
                at: timedelta = timedelta(minutes=5)) -> outbound.Report:  # fmt: skip
    gateway, state, clock = await gateway_for(engine, siem, health=health, at=at)
    return await outbound.run_pass(
        engine, gateway, state.health, now=NOW + at, config=config, lane_day_ms=LANE_DAY_MS,
        enabled=ON, clock=clock, is_own=batch1.private_or(None), history=timedelta(days=5),
        check=batch1.send_check(state),
    )  # fmt: skip


async def incident(engine: AsyncEngine) -> Any:
    rows = await all_rows(engine, "SELECT * FROM risk_incidents WHERE parent_id IS NULL"
                          " AND state <> 'merged'")  # fmt: skip
    assert len(rows) == 1
    return rows[0]


def states(view: dict[str, Any]) -> dict[str, str]:
    return {a["name"]: a["state"] for a in view["alternatives"]}


async def test_a_regular_rare_beacon_is_measured_once_and_raises_the_score(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    before = await incident(migrated_engine)
    assert before.case_id is not None
    assert "regular timing" not in before.view["why_line"]
    siem = Siem()
    report = await check(app_engine, siem)
    assert (report.sent, report.stored, report.incidents) == (2, 2, 1), report.line()
    assert siem.asked == ["pair", "contact"]
    rows = await all_rows(migrated_engine, "SELECT kind, subject, verdict, facts, took_ms,"
                          " incident_version FROM risk_evidence ORDER BY kind")  # fmt: skip
    assert [(r.kind, r.subject, r.verdict) for r in rows] == [
        ("contact", SERVER, "rare"),
        ("pair", f"{DEVICE} {SERVER}", "regular"),
    ]
    assert rows[1].facts["period_s"] == 300
    assert rows[1].took_ms == 640
    ledger = await all_rows(migrated_engine, "SELECT lane, component, purpose, template"
                            " FROM siem_requests WHERE purpose <> 'probe' ORDER BY id")  # fmt: skip
    assert {(r.lane, r.component, r.purpose) for r in ledger} == {
        ("checking", outbound.COMPONENT, "check")
    }
    assert sorted(r.template for r in ledger) == ["proxy.contact", "proxy.pair"]
    # once a material version: the next pass asks nothing
    again = await check(app_engine, siem, at=timedelta(minutes=15))
    assert (again.planned, again.sent) == (0, 0)
    # the engine's next pass reads the answers: a beacon fact; the day's count is a count so far
    # (the device may be the only one yet), so no rare destination from it
    assert rows[0].facts["complete"] is False
    await run.step(app_engine, presenting(True), NOW + timedelta(minutes=20))
    kinds = await evidence_kinds(migrated_engine)
    assert "ev:beacon" in kinds
    assert "ev:rare_dest" not in kinds
    middle = await incident(migrated_engine)
    assert f"1 campus device contacted {SERVER} so far on 2026-10-20 up to" in " ".join(
        c["text"] for c in middle.view["checks"]
    )
    # the day over, its whole count is asked once more: one campus device all day is rare
    next_day = timedelta(hours=14)  # 02:00 UTC, after the quiet hours
    keep = CONFIG.model_copy(update={"reuse_hours": 48})  # the count so far is never reused
    later = await check(app_engine, siem, config=keep, at=next_day)
    assert later.by_kind.get("contact") == 1, later.line()
    (whole,) = await all_rows(migrated_engine, "SELECT facts FROM risk_evidence WHERE"
                              " kind = 'contact' ORDER BY checked_at DESC LIMIT 1")  # fmt: skip
    assert whole.facts["complete"] is True
    assert (await check(app_engine, siem, at=next_day + timedelta(minutes=10))).planned == 0
    await run.step(app_engine, presenting(True), NOW + next_day + timedelta(minutes=20))
    assert {"ev:beacon", "ev:rare_dest"} <= await evidence_kinds(migrated_engine)
    after = await incident(migrated_engine)
    assert after.priority >= before.priority
    assert "regular timing" in after.view["why_line"]
    texts = [c["text"] for c in after.view["checks"]]
    assert any(t.startswith(f"regular requests from {DEVICE} to {SERVER} about every 5 min")
               for t in texts)  # fmt: skip
    assert f"no other campus device contacted {SERVER} on 2026-10-20 (proxy logs)" in texts
    found = states(after.view)
    assert found[alt.COMMON_SERVICE] == "ruled_out"
    assert found[alt.ORDINARY_USE] == "ruled_out"
    assert after.view["certainty"] == before.view["certainty"]


async def evidence_kinds(engine: AsyncEngine) -> set[str]:
    return {
        r.source_key
        for r in await all_rows(
            engine, "SELECT source_key FROM risk_observations WHERE source_kind = 'evidence'"
        )
    }


async def test_a_popular_destination_moves_the_certainty_not_the_priority(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    before = await incident(migrated_engine)
    assert (before.view["certainty"], before.band) == ("Likely", "P2")
    assert before.title == f"Likely contact with {SERVER} from {DEVICE}"
    report = await check(app_engine, Siem(pair=scattered, devices=300))
    assert report.sent == 2
    await run.step(app_engine, presenting(True), NOW + timedelta(minutes=20))
    after = await incident(migrated_engine)
    assert (after.priority, after.band) == (before.priority, before.band)
    found = states(after.view)
    assert found[alt.COMMON_SERVICE] == "fits"
    # it never claimed a rhythm: requests at no rhythm are no alternative to it
    assert alt.ORDINARY_USE not in found
    assert after.view["certainty"] == "Unclear"
    assert after.certainty == "Unclear"
    assert after.title == f"Unclear: contact with {SERVER} from {DEVICE}"  # the word follows
    texts = [c["text"] for c in after.view["checks"]]
    assert (
        f"300 campus devices contacted {SERVER} on 2026-10-20 up to 11:50 UTC (proxy logs)" in texts
    )  # many already by midday: a common service whether or not the day is over


async def test_only_presented_incidents_and_only_in_normal_health(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, presenting(False), NOW)  # the shadow: nothing is presented
    siem = Siem()
    assert (await check(app_engine, siem)).planned == 0
    await run.step(app_engine, presenting(True), NOW + timedelta(minutes=1))
    caution = await check(app_engine, siem, health=HealthState.CAUTION)
    assert caution.sent == 0
    assert "NORMAL" in str(caution.stopped)
    quiet = await check(app_engine, siem, at=timedelta(hours=12, minutes=10))  # 00:10 UTC
    assert quiet.sent == 0
    assert "quiet hours" in str(quiet.stopped)
    off = await outbound.run_pass(
        app_engine, *(await _gw(app_engine)), now=NOW, config=CONFIG, lane_day_ms=LANE_DAY_MS,
        enabled=("proxy.host",), clock=lambda: NOW, is_own=batch1.private_or(None),
        history=timedelta(days=5),
    )  # fmt: skip
    assert off.sent == 0
    assert "switched on" in str(off.stopped)
    assert siem.asked == []


async def _gw(engine: AsyncEngine) -> tuple[Gateway, Any]:
    gateway, state, _ = await gateway_for(engine, Siem())
    return gateway, state.health


async def test_the_pass_and_the_day_limits_hold(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    one = CONFIG.model_copy(update={"pass_requests": 1})
    siem = Siem()
    first = await check(app_engine, siem, config=one)
    assert (first.sent, first.stopped) == (1, "the pass's request limit")
    second = await check(app_engine, siem, config=one, at=timedelta(minutes=15))
    assert second.sent == 1
    assert siem.asked == ["pair", "contact"]
    assert second.requests_today == 2
    async with migrated_engine.begin() as conn:  # a new material version
        await conn.execute(text("UPDATE risk_incidents SET version = version + 1"))
    reused = await check(app_engine, siem, at=timedelta(minutes=30))
    assert (reused.reused, reused.sent) == (2, 0)  # the same day's answers, no request
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE risk_incidents SET version = version + 1"))
    full = CONFIG.model_copy(update={"day_requests": 2, "reuse_hours": 0})
    third = await check(app_engine, siem, config=full, at=timedelta(minutes=45))
    assert third.sent == 0
    assert "requests" in str(third.stopped)
    assert siem.asked == ["pair", "contact"]


async def test_a_request_the_siem_did_not_answer_is_unknown_and_asked_again_later(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    broken = Siem(fail=TimedOutError("slow"))
    report = await check(app_engine, broken)
    assert report.sent == 0
    assert report.failed == 1
    assert "did not answer in full" in str(report.stopped)
    (row,) = await all_rows(migrated_engine, "SELECT kind, verdict, facts FROM risk_evidence")
    assert (row.kind, row.verdict) == ("pair", "unknown")
    assert await scalar(migrated_engine, "SELECT count(*) FROM risk_groups"
                        " WHERE signature LIKE '%-evidence%'") == 0  # fmt: skip
    soon = await check(app_engine, Siem(), at=timedelta(hours=1))
    assert list(soon.by_kind) == ["contact"]  # the pair waits its recheck
    later = await check(app_engine, Siem(), at=timedelta(hours=7))
    assert later.by_kind == {"pair": 1}
    verdicts = await all_rows(migrated_engine, "SELECT kind, verdict FROM risk_evidence"
                              " ORDER BY kind")  # fmt: skip
    assert [tuple(r) for r in verdicts] == [("contact", "rare"), ("pair", "regular")]


async def test_an_address_argus_already_sees_on_many_devices_is_not_asked_about(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    await rule(migrated_engine, "r-other", "Other rule")
    for i in range(outbound.COMMON_HOSTS):
        await group(migrated_engine, "r-other", actor=f"10.2.0.{i + 1}",
                    fields={"destination.ip": [SERVER]})  # fmt: skip
    siem = Siem()
    report = await check(app_engine, siem)
    assert (report.sent, report.from_store) == (1, 1)
    assert siem.asked == ["pair"]
    (row,) = await all_rows(migrated_engine, "SELECT verdict, facts, took_ms FROM risk_evidence"
                            " WHERE kind = 'contact'")  # fmt: skip
    assert (row.verdict, row.facts["from"], row.took_ms) == ("common", "argus", None)
    assert row.facts["devices"] >= outbound.COMMON_HOSTS


async def test_the_runtime_role_writes_only_what_it_may(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    await check(app_engine, Siem())
    for statement in ("UPDATE risk_evidence SET incident_id = incident_id",
                      "UPDATE risk_evidence SET kind = 'dns'",
                      "UPDATE risk_evidence SET subject = 'x'"):  # fmt: skip
        async with app_engine.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                await conn.execute(text(statement))
    async with app_engine.connect() as conn:
        with pytest.raises(DBAPIError, match="check"):
            await conn.execute(text(
                "INSERT INTO risk_evidence (incident_id, incident_version, kind, subject, day,"
                " template, template_version, verdict, facts, checked_at) SELECT id, 1, 'pair',"
                " 'x y', current_date, 'proxy.pair', 1, 'maybe', '{}'::jsonb, now()"
                " FROM risk_incidents LIMIT 1"))  # fmt: skip
    pruned = await outbound.run_pass(
        app_engine, *(await _gw(app_engine)), now=NOW + timedelta(days=200), config=CONFIG,
        lane_day_ms=LANE_DAY_MS, enabled=(), clock=lambda: NOW, is_own=lambda _: True,
        history=timedelta(days=5),
    )  # fmt: skip
    assert pruned.pruned == 2


async def test_the_replay_reads_the_groups_without_the_incident_evidence(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """The replay steps a clock through the alert groups: an answer asked after the fact, for a
    presented incident, has no time a step could honour, so the replay leaves it out."""
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    await check(app_engine, Siem())
    config = setup().config
    names = sorted({n for kind in config.evidence for n in kind.signals})
    async with app_engine.connect() as conn:
        ids = list((await conn.execute(text("SELECT id FROM investigations"))).scalars())
        live = await store.groups(conn, ids, names, exposure=config.exposure)
        replayed = await store.groups(conn, ids, names, exposure=config.exposure, measured=False)
    assert any("pair.period_s" in g.signals for g in live)
    assert not any("pair.period_s" in g.signals for g in replayed)
