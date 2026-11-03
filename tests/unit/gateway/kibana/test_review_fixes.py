"""Q-D2's review findings F1-F15, one regression test (or more) each: every one failed before its
fix. The Kibana lane on a fake Kibana and a fake clock (``fakes.py``), the lanes on the memory
store; the Postgres side of F2 is in tests/integration/gateway/test_pgstore_lanes.py."""

from __future__ import annotations

import json
import ssl
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import SecretStr, ValidationError

from argus.config.settings import KibanaSettings, Settings, SiemSettings
from argus.gateway.breaker import BreakerState
from argus.gateway.budget import BudgetConfig, Lease, Verdict
from argus.gateway.builtin import AlertIds, AlertIdsParams, SecurityIndexHealth
from argus.gateway.errors import BreakerOpenError, TemplateRejectedError
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.kibana import models, selftest
from argus.gateway.kibana.errors import AnswerMismatchError, KibanaResponseError
from argus.gateway.kibana.paths import KEndpoint, Target, wire_path
from argus.gateway.kibana.templates import (
    AttachAlerts,
    AttachParams,
    CaseGet,
    CaseParams,
    CommentOnCase,
    CommentParams,
    CreateCase,
    KeyRole,
    KibanaStatus,
    NoParams,
    SetAlertStatus,
    UpdateCase,
)
from argus.gateway.kibana.transport import HttpxKibanaTransport, KResponse, KWire, wire_refusal
from argus.gateway.kibana.writes import WriteClass
from argus.gateway.lanes import Lane, LanePlan, LaneSpec, plan_from
from argus.gateway.service import lane_plan
from argus.gateway.state import MemoryStore
from argus.gateway.templates import CostClass, Purpose
from argus.gateway.templates import NoParams as EsNoParams
from tests.unit.gateway.fakes import search_answer
from tests.unit.gateway.kibana.fakes import (
    ALERT_ID,
    ALERT_INDEX,
    CASE_ID,
    T0,
    WRITES,
    FakeKibana,
    answer,
    context,
    create,
    create_params,
    make,
    ready_kibana,
    reply,
    start,
    status_answer,
)

pytestmark = pytest.mark.unit
ALL = frozenset({WriteClass.W1, WriteClass.W2, WriteClass.W3, WriteClass.WA})
COMMENTS = f"/api/cases/{CASE_ID}/comments"


def deadline(clock: Any, seconds: int = 60) -> Any:
    return clock.now + timedelta(seconds=seconds)


def _case(**over: Any) -> dict[str, Any]:
    case: dict[str, Any] = answer(WRITES, "POST", "/api/cases")
    return {**case, **over}


def _attached(**over: Any) -> dict[str, Any]:
    case: dict[str, Any] = answer(WRITES, "POST", COMMENTS, 1)
    return {**case, **over}


async def _attach(gateway: Any, clock: Any, run: Any) -> Any:
    params = AttachParams(case_id=CASE_ID, alerts=((ALERT_ID, ALERT_INDEX),))
    return await gateway.write(
        AttachAlerts(), params, run=run, context=context(gateway, AttachAlerts(), params),
        component="t", deadline=deadline(clock),
    )  # fmt: skip


async def _comment(gateway: Any, clock: Any, run: Any) -> Any:
    params = CommentParams(case_id=CASE_ID, comment="Opened by ARGUS.")
    return await gateway.write(
        CommentOnCase(), params, run=run, context=context(gateway, CommentOnCase(), params),
        component="t", deadline=deadline(clock),
    )  # fmt: skip


def _patch(**over: Any) -> models.UpdatePatch:
    fields: dict[str, Any] = {"id": CASE_ID, "version": "WzEsMV0x", "severity": "high"}
    fields.update(over)
    return models.UpdatePatch(cases=(models.CaseChange(**fields),))


async def _update(gateway: Any, clock: Any, run: Any, params: models.UpdatePatch) -> Any:
    return await gateway.write(
        UpdateCase(), params, run=run, context=context(gateway, UpdateCase(), params,
                                                       WriteClass.W2),
        component="t", deadline=deadline(clock),
    )  # fmt: skip


# --------------------------------------------------------------------------- F1


@pytest.mark.parametrize("status", [400, 403, 404, 409, 429, 500, 503])
async def test_f1_an_attach_answered_with_an_error_may_have_landed(status: int) -> None:
    """Q-D1's tier saw attaches answered 400 and 403 whose attachment was saved
    (attachments__..._eleventh_attach_half_fails, action_scoped__..._attach_half_fails)."""
    kibana = ready_kibana().on("POST", COMMENTS, reply({"statusCode": status}, status))
    gateway, _, _store, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    with pytest.raises(KibanaResponseError) as caught:
        await _attach(gateway, clock, run)
    assert caught.value.maybe_applied, f"{status} on an attach reported as not applied"


@pytest.mark.parametrize(("status", "maybe"), [
    (400, False), (401, False), (403, True), (404, True), (409, True), (429, True), (503, True),
])  # fmt: skip
async def test_f1_a_creates_error_answer_says_whether_it_may_have_landed(
    status: int, maybe: bool
) -> None:
    kibana = ready_kibana()
    kibana.routes.insert(0, ("POST", "/api/cases", [reply({"statusCode": status}, status)]))
    gateway, _, _, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    with pytest.raises(KibanaResponseError) as caught:
        await create(gateway, run, clock)
    assert caught.value.maybe_applied is maybe


@pytest.mark.parametrize(("status", "maybe"), [
    (400, False), (401, False), (404, False), (406, False), (409, False),
    (302, True), (403, True), (429, True), (503, True),
])  # fmt: skip
async def test_f1_a_patchs_error_answer_says_whether_it_may_have_landed(
    status: int, maybe: bool
) -> None:
    kibana = ready_kibana()
    kibana.routes.insert(0, ("PATCH", "/api/cases", [reply({"statusCode": status}, status)]))
    gateway, _, _, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    with pytest.raises(KibanaResponseError) as caught:
        await _update(gateway, clock, run, _patch())
    assert caught.value.maybe_applied is maybe


@pytest.mark.parametrize("status", [400, 403, 404, 409, 429, 500, 503])
async def test_f1_a_comment_or_alert_status_error_may_have_landed(status: int) -> None:
    kibana = (
        ready_kibana()
        .on("POST", COMMENTS, reply({"statusCode": status}, status))
        .on("POST", "/api/detection_engine/signals/status", reply({"statusCode": status}, status))
    )
    gateway, _, store, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    with pytest.raises(KibanaResponseError) as caught:
        await _comment(gateway, clock, run)
    assert caught.value.maybe_applied
    params = models.AlertStatusChange(signal_ids=(ALERT_ID,), status="closed")
    clock.advance(timedelta(seconds=5))
    store.kibana_breaker = BreakerState()  # a 429 or 503 opened Kibana's breaker
    with pytest.raises(KibanaResponseError) as caught:
        await gateway.write(SetAlertStatus(), params, run=run,
                            context=context(gateway, SetAlertStatus(), params, WriteClass.WA),
                            component="t", deadline=deadline(clock))  # fmt: skip
    assert caught.value.maybe_applied


@pytest.mark.parametrize("status", [400, 403, 404, 409, 429, 500, 503])
async def test_f1_a_reads_error_never_says_it_landed(status: int) -> None:
    kibana = FakeKibana().on("GET", f"/api/cases/{CASE_ID}", reply({}, status))
    gateway, _, _, clock, _ = make(kibana)
    with pytest.raises(KibanaResponseError) as caught:
        await gateway.read(CaseGet(), CaseParams(case_id=CASE_ID), component="t",
                           deadline=deadline(clock))  # fmt: skip
    assert not caught.value.maybe_applied


# --------------------------------------------------------------------------- F2


async def test_f2_lanes_never_run_more_requests_at_once_than_d022() -> None:
    store = MemoryStore(memory=HealthMemory(), budget_config=BudgetConfig())
    held = 0
    for n in range(2):
        a = await store.budget_admit(CostClass.LIGHT, T0, 1.0, f"c{n}")
        held += a.verdict is Verdict.ADMITTED
    for lane in (Lane.INVESTIGATION, Lane.FRESHNESS, Lane.KIBANA_READ, Lane.KIBANA_WRITE,
                 Lane.IDENTITY):  # fmt: skip
        a = await store.lane_admit(lane, CostClass.LIGHT, T0, 1.0, f"l-{lane}")
        held += a.verdict is Verdict.ADMITTED
        assert (a.verdict, a.reason) == (Verdict.WAIT, "concurrency")
    assert held == 2


async def test_f2_the_other_lanes_share_one_slot_and_the_collector_keeps_one() -> None:
    store = MemoryStore(memory=HealthMemory(), budget_config=BudgetConfig())
    first = await store.lane_admit(Lane.KIBANA_READ, CostClass.LIGHT, T0, 1.0, "k1")
    assert first.verdict is Verdict.ADMITTED
    second = await store.lane_admit(Lane.IDENTITY, CostClass.LIGHT, T0, 1.0, "i1")
    assert (second.verdict, second.reason) == (Verdict.WAIT, "concurrency")  # the collector's
    collector = await store.budget_admit(CostClass.LIGHT, T0, 1.0, "c1")
    assert collector.verdict is Verdict.ADMITTED  # its own slot, whatever the lanes hold
    more = await store.budget_admit(CostClass.LIGHT, T0, 1.0, "c2")
    assert (more.verdict, more.reason) == (Verdict.WAIT, "concurrency")  # D-022's two in use
    assert more.retry_at is not None
    assert more.retry_at <= T0 + timedelta(minutes=2)
    assert first.lease is not None
    await store.lane_settle(Lane.KIBANA_READ, first.lease, 50, T0, 1.0)
    again = await store.budget_admit(CostClass.LIGHT, T0, 1.0, "c2")
    assert again.verdict is Verdict.ADMITTED  # the collector's second slot, as before Q-D2


async def test_f2_a_ceiling_of_one_is_one_request_at_a_time_for_everyone() -> None:
    ceiling = BudgetConfig(concurrency=1)
    plan = LanePlan(ceiling)
    store = MemoryStore(memory=HealthMemory(), budget_config=plan.config(Lane.COLLECTOR),
                        lane_plan=plan)  # fmt: skip
    a = await store.lane_admit(Lane.KIBANA_READ, CostClass.LIGHT, T0, 1.0, "k1")
    assert a.verdict is Verdict.ADMITTED
    b = await store.budget_admit(CostClass.LIGHT, T0, 1.0, "c1")
    assert (b.verdict, b.reason) == (Verdict.WAIT, "concurrency")


@settings(max_examples=200, deadline=None)
@given(
    steps=st.lists(
        st.tuples(st.sampled_from([lane for lane in Lane if lane is not Lane.MEASUREMENT]),
                  st.booleans(), st.integers(0, 90)),
        max_size=40,
    ),
    concurrency=st.integers(1, 3),
)  # fmt: skip
async def test_f2_property_never_more_at_once_than_the_ceiling(
    steps: list[tuple[Lane, bool, int]], concurrency: int
) -> None:
    """Any interleaving of admissions and settles across the lanes (time moving on, leases
    expiring): the requests held at once never exceed the ceiling's concurrency, and the lanes
    other than the collector's never hold the collector's last slot."""
    ceiling = BudgetConfig(concurrency=concurrency)
    plan = LanePlan(ceiling)
    store = MemoryStore(memory=HealthMemory(), budget_config=plan.config(Lane.COLLECTOR),
                        lane_plan=plan)  # fmt: skip
    now = T0
    held: list[tuple[Lane, Lease]] = []
    for n, (lane, settle_one, seconds) in enumerate(steps):
        now += timedelta(seconds=seconds)
        if settle_one and held:
            done, lease = held.pop(0)
            if done is Lane.COLLECTOR:
                await store.budget_settle(lease, 10, now, 1.0)
            else:
                await store.lane_settle(done, lease, 10, now, 1.0)
            continue
        if lane is Lane.COLLECTOR:
            admission = await store.budget_admit(CostClass.LIGHT, now, 1.0, f"x{n}")
        else:
            admission = await store.lane_admit(lane, CostClass.LIGHT, now, 1.0, f"x{n}")
        if admission.verdict is Verdict.ADMITTED:
            assert admission.lease is not None
            held.append((lane, admission.lease))
        live = [(x, lease) for x, lease in held if lease.expires > now]
        assert len(live) <= concurrency
        if concurrency >= 2:
            assert sum(x is not Lane.COLLECTOR for x, _ in live) <= concurrency - 1


def test_f2_a_lane_plan_may_not_exceed_the_ceilings_concurrency() -> None:
    with pytest.raises(ValueError, match="concurrency"):
        plan_from(BudgetConfig(), {"kibana_read": LaneSpec(250, 240_000, 0, concurrency=4)})
    with pytest.raises(ValidationError, match="concurrency"):
        SiemSettings(lanes={"kibana_read": {"per_minute_ms": 100, "per_day_ms": 60_000,
                                             "concurrency": 3}})  # fmt: skip


# --------------------------------------------------------------------------- F3


@pytest.mark.parametrize("state", [HealthState.NORMAL, HealthState.DEGRADED, HealthState.STOP])
async def test_f3_identity_is_only_for_the_identity_templates(state: HealthState) -> None:
    _, _, store, clock, es_gateway = make()
    store.memory = HealthMemory(state=state, probed_at=clock.now)
    es_gateway.transport.default = search_answer()  # type: ignore[attr-defined]
    before = len(es_gateway.transport.calls)  # type: ignore[attr-defined]
    with pytest.raises(TemplateRejectedError, match="purpose_mismatch"):
        await es_gateway.run(
            AlertIds(), AlertIdsParams(start=clock.now - timedelta(minutes=5), end=clock.now),
            purpose=Purpose.IDENTITY, component="anything", deadline=deadline(clock),
        )  # fmt: skip
    assert len(es_gateway.transport.calls) == before  # type: ignore[attr-defined]


async def test_f3_the_identity_templates_still_run_in_stop() -> None:
    from tests.unit.gateway.fakes import ok

    _, _, store, clock, es_gateway = make()
    store.memory = HealthMemory(state=HealthState.STOP, probed_at=clock.now)
    es_gateway.transport.on(  # type: ignore[attr-defined]
        "/_cluster/health/.security", ok({"status": "green", "timed_out": False})
    )
    await es_gateway.run(SecurityIndexHealth(), EsNoParams(), purpose=Purpose.IDENTITY,
                         component="identity", deadline=deadline(clock))  # fmt: skip
    assert store.ledger[-1].lane == "identity"


# --------------------------------------------------------------------------- F4


async def test_f4_a_create_answer_without_its_title_pauses_w1() -> None:
    kibana = ready_kibana()
    broken = {k: v for k, v in _case().items() if k != "title"}
    kibana.routes.insert(0, ("POST", "/api/cases", [reply(broken)]))
    gateway, _, store, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    with pytest.raises(AnswerMismatchError):
        await create(gateway, run, clock)
    assert store.ledger[-1].outcome == "answer_mismatch"
    assert dict(store.kibana.paused) == {"W1": "answer_mismatch"}


async def test_f4_any_crash_of_an_answer_check_is_a_wrong_answer() -> None:
    class Crashing(CaseGet):
        def check(self, params: Any, answer: Any, author: str | None) -> Any:
            return answer["no such field"]

    kibana = FakeKibana().on("GET", f"/api/cases/{CASE_ID}", reply(_case()))
    gateway, _, store, clock, _ = make(kibana)
    with pytest.raises(AnswerMismatchError):
        await gateway.read(Crashing(), CaseParams(case_id=CASE_ID), component="t",
                           deadline=deadline(clock))  # fmt: skip
    assert store.ledger[-1].outcome == "answer_mismatch"
    assert store.kibana.stopped is None  # a read's wrong answer stops nothing


# --------------------------------------------------------------------------- F5


async def test_f5_a_patch_answered_with_someone_elses_case_pauses_w2() -> None:
    patched = answer(WRITES, "PATCH", "/api/cases", 0)
    patched[0]["created_by"] = {"username": "tier-analyst"}
    kibana = ready_kibana()
    kibana.routes.insert(0, ("PATCH", "/api/cases", [reply(patched)]))
    gateway, _, store, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    with pytest.raises(AnswerMismatchError, match="someone else"):
        await _update(gateway, clock, run, _patch(severity=patched[0]["severity"]))
    assert dict(store.kibana.paused) == {"W2": "answer_mismatch"}


async def test_f5_a_comment_answered_with_someone_elses_case_pauses_its_class() -> None:
    commented = answer(WRITES, "POST", COMMENTS, 0)
    commented["created_by"] = {"username": "tier-analyst"}
    kibana = ready_kibana().on("POST", COMMENTS, reply(commented))
    gateway, _, store, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    with pytest.raises(AnswerMismatchError, match="someone else"):
        await _comment(gateway, clock, run)
    assert dict(store.kibana.paused) == {"W1": "answer_mismatch"}


async def test_f5_an_attach_answered_with_someone_elses_case_pauses_w1() -> None:
    kibana = ready_kibana().on(
        "POST", COMMENTS, reply(_attached(created_by={"username": "tier-analyst"}))
    )
    gateway, _, store, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    with pytest.raises(AnswerMismatchError, match="someone else"):
        await _attach(gateway, clock, run)
    assert dict(store.kibana.paused) == {"W1": "answer_mismatch"}


@pytest.mark.parametrize("over", [{"severity": "critical"}, {"description": "not what ARGUS sent"}])
async def test_f5_a_create_answered_with_other_values_pauses_w1(over: dict[str, Any]) -> None:
    def echo(request: KWire) -> KResponse:
        sent = json.loads(request.body or b"{}")
        return reply(_case(title=sent["title"], tags=sent["tags"], **over))

    kibana = ready_kibana()
    kibana.routes.insert(0, ("POST", "/api/cases", [echo]))
    gateway, _, store, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    with pytest.raises(AnswerMismatchError):
        await create(gateway, run, clock)
    assert dict(store.kibana.paused) == {"W1": "answer_mismatch"}


@pytest.mark.parametrize("field", ["title", "description"])
async def test_f5_a_patch_answered_without_the_text_sent_pauses_w2(field: str) -> None:
    patched = answer(WRITES, "PATCH", "/api/cases", 0)
    kibana = ready_kibana()
    kibana.routes.insert(0, ("PATCH", "/api/cases", [reply(patched)]))
    gateway, _, store, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    with pytest.raises(AnswerMismatchError, match=field):
        await _update(gateway, clock, run, _patch(severity=None, **{field: "A new text"}))
    assert dict(store.kibana.paused) == {"W2": "answer_mismatch"}


# --------------------------------------------------------------------------- F6


@pytest.mark.parametrize("index", [
    ".internal.alerts-security.alerts-acme-soc-lab-000001",  # space "acme-soc-lab"
    ".internal.alerts-security.alerts-acme-soc-x-000001",
])  # fmt: skip
async def test_f6_another_spaces_alert_index_is_refused(index: str) -> None:
    gateway, *_ = make(classes=ALL)
    params = AttachParams(case_id=CASE_ID, alerts=((ALERT_ID, index),))
    with pytest.raises(TemplateRejectedError, match="index_not_allowed"):
        gateway.final(AttachAlerts(), params)
    gateway.final(AttachAlerts(), AttachParams(case_id=CASE_ID, alerts=((ALERT_ID, ALERT_INDEX),)))


# --------------------------------------------------------------------------- F7


def _settings(**kibana: Any) -> Settings:
    return Settings.model_construct(
        siem=Settings.model_fields["siem"].default,
        kibana=KibanaSettings(**{"url": "https://kibana.example:5601", **kibana}),
    )


async def test_f7_the_kibana_timeout_setting_is_used() -> None:
    from argus.gateway.kibana.service import build_kibana_gateway
    from tests.unit.gateway.fakes import FakeClock

    clock = FakeClock(T0)
    fake = ready_kibana()
    fake.clock = clock
    store = MemoryStore(memory=HealthMemory(probed_at=T0), budget_config=BudgetConfig())
    gateway = build_kibana_gateway(_settings(enabled=True, timeout="5s"), store, sender=fake)
    gateway.clock, gateway.sleep = clock, clock.sleep
    await gateway.read(KibanaStatus(), NoParams(), component="t", deadline=deadline(clock))
    assert fake.calls[0].timeout_s == 5.0
    _, _, _, _, es_gateway = make()
    gateway.es_gateway = es_gateway
    es_gateway.clock = clock
    gateway.classes = frozenset({WriteClass.W1})
    run = await start(gateway, clock)
    params = create_params()
    await gateway.write(CreateCase(), params, run=run,
                        context=context(gateway, CreateCase(), params), component="t",
                        deadline=clock.now + timedelta(seconds=6))  # fmt: skip
    assert fake.calls[-1].timeout_s == 5.0  # 6 s left is enough for a 5 s timeout


# --------------------------------------------------------------------------- F8


class _Split:
    """Reads to the fake Kibana; writes to the real transport, which holds the reader key only."""

    def __init__(self, fake: FakeKibana) -> None:
        self.fake = fake
        self.real = HttpxKibanaTransport(
            "https://kibana.invalid:5601", "https://es.invalid:9200",
            ssl.create_default_context(), {KeyRole.READER: SecretStr("x")},
            space="acme-soc",
        )  # fmt: skip
        self.calls = fake.calls

    def refusal(self, request: KWire) -> str | None:
        return self.real.refusal(request)

    async def send(self, request: KWire) -> KResponse:
        if request.key is KeyRole.READER:
            return await self.fake.send(request)
        return await self.real.send(request)


async def test_f8_a_missing_key_takes_no_cap_place_and_no_ledger_row() -> None:
    fake = ready_kibana()
    gateway, _, store, clock, _ = make(fake, classes=ALL)
    split = _Split(fake)
    gateway.transport = split
    run = await start(gateway, clock)
    rows = len(store.ledger)
    try:
        with pytest.raises(TemplateRejectedError, match="no_key"):
            await create(gateway, run, clock)
    finally:
        await split.real.aclose()
    assert len(store.ledger) == rows
    assert store.kibana.counters.case_writes == 0
    assert store.lanes.bucket(Lane.KIBANA_WRITE).leases == ()


def test_f8_a_write_class_needs_its_writers_key() -> None:
    with pytest.raises(ValidationError, match="cases_writer_api_key"):
        KibanaSettings(enabled=True, write_classes=("W1",))
    with pytest.raises(ValidationError, match="alert_writer_api_key"):
        KibanaSettings(enabled=True, write_classes=("WA",),
                       cases_writer_api_key=SecretStr("w"))  # fmt: skip
    KibanaSettings(enabled=True, write_classes=("W1", "W3"), cases_writer_api_key=SecretStr("w"))


# --------------------------------------------------------------------------- F9


@pytest.mark.parametrize("role", list(KeyRole))
def test_f9_the_selftest_asks_the_destructive_index_privileges(role: KeyRole) -> None:
    body = selftest.request_body(role, "acme-soc")
    asked = {p for entry in body["index"] for p in entry["privileges"]}
    assert {"manage", "delete_index", "all", "create_index"} <= asked
    answer_ = {
        "cluster": dict.fromkeys(selftest.CLUSTER_CANARIES, False),
        "application": {selftest.APP: {"space:acme-soc": {
            **dict.fromkeys(selftest.PROFILES[role].must_app, True),
            **dict.fromkeys(selftest.PROFILES[role].must_not_app, False)}}},
        "index": {selftest.alerts_alias("acme-soc"): {
            **dict.fromkeys(selftest.PROFILES[role].must_index, True),
            **dict.fromkeys(selftest.PROFILES[role].must_not_index, False), "manage": True}},
    }  # fmt: skip
    verdict = selftest.judge(role, "acme-soc", answer_)
    assert verdict.problems == ("holds manage on the alerts",)


# --------------------------------------------------------------------------- F10


def _siem_breaker_open(store: MemoryStore, clock: Any) -> BreakerState:
    store.breaker = BreakerState(level=1, open_until=clock.now + timedelta(minutes=5),
                                 last_trip=clock.now)  # fmt: skip
    return store.breaker


async def test_f10_siems_open_breaker_stops_the_self_check_sent_to_elasticsearch() -> None:
    kibana = ready_kibana().on("POST", "/_security/user/_has_privileges", reply({"ok": True}))
    gateway, kibana, store, clock, _ = make(kibana)
    before = _siem_breaker_open(store, clock)
    with pytest.raises(BreakerOpenError):
        await gateway.key_privileges(
            KeyRole.READER, selftest.request_body(KeyRole.READER, "acme-soc"),
            component="selftest", deadline=deadline(clock),
        )  # fmt: skip
    assert not [c for c in kibana.calls if c.target == "es"]
    assert store.breaker == before  # peeked, no trial taken


async def test_f10_siems_open_breaker_stops_kibana_reads_and_writes() -> None:
    kibana = ready_kibana().on(
        "POST", "/api/detection_engine/signals/status",
        reply({"updated": 1, "total": 1, "failures": [], "version_conflicts": 0}),
    )  # fmt: skip
    gateway, kibana, store, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    sent = len(kibana.calls)
    before = _siem_breaker_open(store, clock)
    params = models.AlertStatusChange(signal_ids=(ALERT_ID,), status="closed")
    with pytest.raises(BreakerOpenError):
        await gateway.write(SetAlertStatus(), params, run=run,
                            context=context(gateway, SetAlertStatus(), params, WriteClass.WA),
                            component="t", deadline=deadline(clock))  # fmt: skip
    with pytest.raises(BreakerOpenError):
        await create(gateway, run, clock)
    with pytest.raises(BreakerOpenError):
        await gateway.read(KibanaStatus(), NoParams(), component="t", deadline=deadline(clock))
    assert len(kibana.calls) == sent
    assert store.kibana.counters.case_writes == 0  # no cap place taken
    assert store.breaker == before


async def test_f10_siems_breaker_opening_during_a_budget_wait_stops_the_request() -> None:
    from argus.gateway.budget import BudgetState

    gateway, kibana, store, clock, _ = make()
    store.lanes = type(store.lanes)(
        {Lane.KIBANA_READ: BudgetState(tokens_ms=-100.0, refilled_at=clock.now,
                                       day=clock.now.date())}
    )  # fmt: skip
    real_sleep = clock.sleep

    async def sleep_then_trip(seconds: float) -> None:
        _siem_breaker_open(store, clock)
        await real_sleep(seconds)

    gateway.sleep = sleep_then_trip
    with pytest.raises(BreakerOpenError):
        await gateway.read(KibanaStatus(), NoParams(), component="t", deadline=deadline(clock))
    assert kibana.calls == []
    assert store.lanes.bucket(Lane.KIBANA_READ).leases == ()


# --------------------------------------------------------------------------- F11


def test_f11_an_identity_lane_setting_keeps_six_checks_a_minute() -> None:
    s = SiemSettings(lanes={"identity": {"per_minute_ms": 200, "per_day_ms": 120_000}})
    assert lane_plan(s).spec(Lane.IDENTITY).per_minute_requests == 6
    with pytest.raises(ValidationError, match="6"):
        SiemSettings(lanes={"identity": {"per_minute_ms": 200, "per_day_ms": 120_000,
                                          "per_minute_requests": 7}})  # fmt: skip
    slower = SiemSettings(lanes={"identity": {"per_minute_ms": 200, "per_day_ms": 120_000,
                                               "per_minute_requests": 2}})  # fmt: skip
    assert lane_plan(slower).spec(Lane.IDENTITY).per_minute_requests == 2


# --------------------------------------------------------------------------- F12


def test_f12_doctor_checks_the_kibana_keys_expiries() -> None:
    from argus.ops.checks import key_expiry_results

    settings = _settings(
        enabled=True, reader_api_key=SecretStr("k"), reader_api_key_expires=date(2026, 1, 1),
        cases_writer_api_key=SecretStr("w"), cases_writer_api_key_expires=date(2026, 11, 1),
        alert_writer_api_key=SecretStr("a"),
    )  # fmt: skip
    results = {r.name: r for r in key_expiry_results(settings, datetime(2026, 10, 23, tzinfo=UTC))}
    reader = results["Kibana reader key expiry"]
    assert (reader.ok, "expired" in reader.detail) == (False, True)
    writer = results["Kibana cases writer key expiry"]
    assert (writer.ok, writer.warn) == (True, True)
    alerts = results["Kibana alert writer key expiry"]
    assert alerts.warn
    assert "kibana.alert_writer_api_key_expires" in alerts.detail


# --------------------------------------------------------------------------- F13


@pytest.mark.parametrize("path", [
    "/s/acme-soc/api/detection_engine/signals/assignees",
    "/s/acme-soc/api/detection_engine/rules/_bulk_action",
    "/s/acme-soc/api/detection_engine/rules/_bulk_delete",
    "/s/acme-soc/api/saved_objects/_import",
    "/s/acme-soc/api/cases/abc/comments/_find",  # a real route, but a GET's
    "/s/acme-soc/api/status/extra",
])  # fmt: skip
def test_f13_the_transport_refuses_any_route_wire_path_cannot_build(path: str) -> None:
    wire = KWire("kibana", KeyRole.CASES, "POST", path, (), b"{}", "x", 15.0)
    assert wire_refusal(wire, "acme-soc") is not None, f"POST {path} would be sent"


@pytest.mark.parametrize("endpoint", list(KEndpoint))
def test_f13_every_route_wire_path_builds_passes_the_transport(endpoint: KEndpoint) -> None:
    for target in (Target(), Target(case_id="c-1"), Target(alert_id="a" * 64)):
        try:
            method, path = wire_path(endpoint, "acme-soc", target)
        except ValueError:
            continue
        team_only = endpoint in (
            KEndpoint.CASE_FILES,
            KEndpoint.ALERTS_TAGS,
            KEndpoint.CASE_COMMENT_EDIT,
        )
        key = KeyRole.TEAM if team_only else KeyRole.READER
        wire = KWire("kibana", key, method, path, (), None, "x", 15.0)
        assert wire_refusal(wire, "acme-soc") is None
        other = "GET" if method != "GET" else "POST"
        moved = KWire("kibana", key, other, path, (), None, "x", 15.0)
        assert wire_refusal(moved, "acme-soc") is not None  # another method on it


# --------------------------------------------------------------------------- F14


@pytest.mark.parametrize("field", ["title", "description"])
@pytest.mark.parametrize("value", ["   ", "a\x00b"])
def test_f14_a_patchs_texts_follow_the_creates_rules(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        models.CaseChange(id=CASE_ID, version="WzEsMV0x", **{field: value})


# --------------------------------------------------------------------------- F15


def test_f15_the_dry_run_prints_the_base_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from argus.gateway.kibana import cli

    monkeypatch.setattr(cli, "load", lambda config: _settings(base_path="/kibana"))
    out = CliRunner().invoke(cli.kibana_app, ["selftest", "--dry-run"]).output
    line = next(x for x in out.splitlines() if x.startswith("1. Kibana"))
    assert "https://kibana.example:5601/kibana/s/acme-soc/api/status" in line


def test_the_status_fake_is_kibanas_shape() -> None:
    assert status_answer()["status"]["overall"]["level"] == "available"
