"""The Kibana lane end to end on a fake Kibana and a fake clock (Q-D2): reads, class-gated
writes, the gate's fault injection (a reset after sending gives no second request; a Kibana 401
leaves collection running; a mid-run switch stops the next request; an unpinned version refuses
writes), DQ9 (b), Kibana's breaker, the caps and the ledger."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from argus.gateway.breaker import BreakerState
from argus.gateway.builtin import AlertIds, AlertIdsParams
from argus.gateway.errors import (
    BreakerOpenError,
    DeadlinePassedError,
    DeferredError,
    StoppedError,
    TemplateRejectedError,
)
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.kibana import models
from argus.gateway.kibana.errors import (
    AnswerMismatchError,
    KibanaAuthError,
    KibanaConflictError,
    KibanaForbiddenError,
    KibanaNoChangeError,
    KibanaNotFoundError,
    KibanaOverloadedError,
    KibanaRejectedError,
    KibanaServerError,
    KibanaStoppedError,
    UnknownOutcomeError,
    WriteRefusedError,
)
from argus.gateway.kibana.gateway import WriteContext, WriteRun
from argus.gateway.kibana.templates import (
    AttachAlerts,
    AttachParams,
    CaseGet,
    CaseParams,
    CasesFind,
    CloseCase,
    CommentOnCase,
    CommentParams,
    CreateCase,
    FindParams,
    KibanaStatus,
    NoParams,
    SetAlertStatus,
    UpdateCase,
)
from argus.gateway.kibana.writes import WriteClass
from argus.gateway.lanes import Lane
from argus.gateway.templates import Purpose
from tests.unit.gateway.fakes import search_answer
from tests.unit.gateway.kibana.fakes import (
    ALERT_ID,
    ALERT_INDEX,
    ARGUS_CASE,
    CASE_ID,
    READS,
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
W1 = frozenset({WriteClass.W1})
ALL = frozenset({WriteClass.W1, WriteClass.W2, WriteClass.W3, WriteClass.WA})
SEC = timedelta(seconds=1)


def deadline(clock: Any, seconds: int = 60) -> Any:
    return clock.now + timedelta(seconds=seconds)


async def read_case(gateway: Any, clock: Any) -> Any:
    return await gateway.read(
        CaseGet(), CaseParams(case_id=CASE_ID), component="test", deadline=deadline(clock)
    )


# --------------------------------------------------------------------------- reads


async def test_a_read_goes_to_the_space_with_the_reader_key_and_is_ledgered() -> None:
    kibana = FakeKibana().on("GET", f"/api/cases/{CASE_ID}", reply(answer(READS, "GET", "")))
    kibana.routes[0] = ("GET", f"/api/cases/{CASE_ID}", [reply(_case())])
    gateway, kibana, store, clock, _ = make(kibana)
    result = await read_case(gateway, clock)
    assert result.body["id"] == CASE_ID
    call = kibana.calls[0]
    assert (call.method, call.path, call.key.value) == (
        "GET", f"/s/acme-soc/api/cases/{CASE_ID}", "reader",
    )  # fmt: skip
    assert call.body is None
    entry = store.ledger[-1]
    assert (entry.target, entry.lane, entry.outcome, entry.purpose) == (
        "kibana", "kibana_read", "ok", "kibana_read",
    )  # fmt: skip
    assert (entry.outbox_id, entry.write_class, entry.payload_hash) == (None, None, None)
    assert entry.health == "normal"
    assert entry.took_ms == 50  # max(round trip 20 ms, the estimate 50 ms)
    assert store.lanes.bucket(Lane.KIBANA_READ).day_used_ms == 50
    assert store.budget.day_used_ms == 0  # the collector's lane is untouched


def _case(**over: Any) -> dict[str, Any]:
    case: dict[str, Any] = answer(WRITES, "POST", "/api/cases")
    case = {**case, **over}
    return case


async def test_every_recorded_read_answer_passes_its_check() -> None:
    """The real answers of Q-D1's read cassette are what the templates accept."""
    find = answer(READS, "GET", "/api/cases/_find")
    actions = answer(READS, "GET", "/user_actions/_find")
    comments = answer(READS, "GET", "/comments/_find")
    from argus.gateway.kibana.templates import (
        AlertCases,
        AlertParams,
        CaseAlerts,
        CaseComments,
        CasePageParams,
        CasesConfigure,
        CaseUserActions,
    )

    page = CasePageParams(case_id=CASE_ID)
    assert CasesFind().check(FindParams(), find, "argus")["total"] == 1
    assert CaseUserActions().check(page, actions, None)["total"] == 4
    assert CaseComments().check(page, comments, None)["total"] >= 1
    assert CasesConfigure().check(NoParams(), [], None) == []
    alerts = answer(READS, "GET", "/alerts")
    assert CaseAlerts().check(CaseParams(case_id=CASE_ID), alerts, None)[0]["id"] == ALERT_ID
    linked = answer(READS, "GET", f"/api/cases/alerts/{ALERT_ID}")
    assert AlertCases().check(AlertParams(alert_id=ALERT_ID), linked, None)[0]["id"]
    assert KibanaStatus().check(NoParams(), status_answer(), None) == ("8.19.12", "available")


async def test_a_write_template_is_never_sent_as_a_read() -> None:
    gateway, kibana, *_ = make()
    with pytest.raises(TemplateRejectedError, match="not_a_read"):
        await gateway.read(
            CreateCase(), create_params(), component="t", deadline=deadline(_c(gateway))
        )
    assert kibana.calls == []


def _c(gateway: Any) -> Any:
    return gateway.clock


async def test_reads_follow_siem_health_and_the_kibana_switch() -> None:
    gateway, kibana, store, clock, _ = make(
        FakeKibana().on("GET", f"/api/cases/{CASE_ID}", reply(_case(id=CASE_ID)))
    )
    store.memory = HealthMemory(state=HealthState.DEGRADED, probed_at=clock.now)
    await read_case(gateway, clock)  # DEGRADED: a read at a tenth of the share
    store.memory = HealthMemory(state=HealthState.STOP, probed_at=clock.now)
    with pytest.raises(StoppedError):
        await read_case(gateway, clock)
    store.memory = HealthMemory(probed_at=clock.now)
    store.stopped.add("kibana")
    with pytest.raises(StoppedError):
        await read_case(gateway, clock)
    store.stopped = {"global"}
    with pytest.raises(StoppedError):
        await read_case(gateway, clock)
    assert len(kibana.calls) == 1


# --------------------------------------------------------------------------- write gating


async def test_a_write_goes_out_once_with_its_outbox_hash_and_class() -> None:
    gateway, kibana, store, clock, _ = make(classes=W1)
    run = await start(gateway, clock)
    result = await create(gateway, run, clock)
    assert result.body["settings"] == {"syncAlerts": False}
    sent = [c for c in kibana.calls if c.method == "POST"]
    assert len(sent) == 1
    assert (sent[0].path, sent[0].key.value) == ("/s/acme-soc/api/cases", "cases")
    entry = store.ledger[-1]
    params = create_params()
    assert (entry.outbox_id, entry.write_class, entry.lane, entry.target) == (
        "outbox-1", "W1", "kibana_write", "kibana",
    )  # fmt: skip
    assert entry.payload_hash == gateway.payload_hash(CreateCase(), params)
    assert entry.purpose == "kibana_write"
    assert store.kibana.counters.case_writes == 1


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"classes": frozenset()}, "class_off"),
        ({"outbox": ""}, "no_outbox"),
        ({"hash": "0" * 64}, "payload_changed"),
    ],
)
async def test_a_write_is_refused_before_sending(change: dict[str, Any], reason: str) -> None:
    gateway, kibana, _, clock, _ = make(classes=change.get("classes", W1))
    run = await start(gateway, clock)
    params = create_params()
    ctx = context(gateway, CreateCase(), params, outbox=change.get("outbox", "o-1"))
    if "hash" in change:
        ctx = WriteContext(WriteClass.W1, "o-1", change["hash"])
    before = len(kibana.calls)
    with pytest.raises(WriteRefusedError) as caught:
        await gateway.write(CreateCase(), params, run=run, context=ctx, component="t",
                            deadline=deadline(clock))  # fmt: skip
    assert caught.value.reason == reason
    assert len(kibana.calls) == before


async def test_a_write_names_a_class_its_template_belongs_to() -> None:
    gateway, _, _, clock, _ = make(classes=ALL)
    run = await start(gateway, clock)
    params = create_params()
    ctx = context(gateway, CreateCase(), params, WriteClass.W2)
    with pytest.raises(WriteRefusedError, match="wrong_class"):
        await gateway.write(CreateCase(), params, run=run, context=ctx, component="t",
                            deadline=deadline(clock))  # fmt: skip
    with pytest.raises(TemplateRejectedError, match="not_a_write"):
        await gateway.write(CaseGet(), CaseParams(case_id=CASE_ID), run=run, context=ctx,
                            component="t", deadline=deadline(clock))  # fmt: skip


async def test_a_closure_needs_its_approval() -> None:
    gateway, kibana, _, clock, _ = make(classes=ALL)
    run = await start(gateway, clock)
    params = _close_params()
    with pytest.raises(WriteRefusedError, match="no_approval"):
        await gateway.write(CloseCase(), params, run=run,
                            context=context(gateway, CloseCase(), params, WriteClass.W3),
                            component="t", deadline=deadline(clock))  # fmt: skip
    assert not [c for c in kibana.calls if c.method == "PATCH"]


def _close_params() -> models.ClosePatch:
    tags = ("run:run1", "t:run1-3c58a9",  # people's tags (here the tier's run tags) are kept
            "argus", ARGUS_CASE, "argus:state:closed", "argus:closed",
            "argus:reason:rule_false_positive")  # fmt: skip
    change = models.CaseChange(id=CASE_ID, version="WzEsMV07", status="closed", tags=tags)
    return models.ClosePatch(cases=(change,))


async def test_writes_only_with_a_run_this_gateway_started() -> None:
    gateway, kibana, _, clock, _ = make(classes=W1)
    forged = WriteRun("r", "8.19.12", False, ("basic", "active"), clock.now)
    params = create_params()
    with pytest.raises(WriteRefusedError, match="no_run"):
        await gateway.write(CreateCase(), params, run=forged,
                            context=context(gateway, CreateCase(), params),
                            component="t", deadline=deadline(clock))  # fmt: skip
    run = await start(gateway, clock)
    clock.advance(timedelta(minutes=31))
    gateway.state.memory = HealthMemory(probed_at=clock.now)  # type: ignore[attr-defined]
    with pytest.raises(WriteRefusedError, match="run_stale"):
        await create(gateway, run, clock)
    assert not [c for c in kibana.calls if c.method == "POST"]


async def test_an_unpinned_kibana_version_refuses_writes() -> None:
    kibana = ready_kibana()
    kibana.routes[0] = ("GET", "/api/status", [reply(status_answer("8.19.13"))])
    gateway, kibana, _, clock, _ = make(kibana, classes=W1)
    with pytest.raises(WriteRefusedError) as caught:
        await start(gateway, clock)
    assert caught.value.reason == "version_not_pinned"
    assert [c.method for c in kibana.calls] == ["GET"]  # the status read only, no write


async def test_a_run_needs_kibana_available() -> None:
    kibana = ready_kibana()
    kibana.routes[0] = ("GET", "/api/status", [reply(status_answer(level="degraded"))])
    gateway, *_, clock, _ = make(kibana, classes=W1)
    with pytest.raises(WriteRefusedError) as caught:
        await start(gateway, clock)
    assert caught.value.reason == "kibana_not_available"
    # the licence's levels have their own tests (test_kibana_licence.py)


async def test_a_required_custom_field_without_default_blocks_creates_only() -> None:
    kibana = ready_kibana()
    blocking = [{"customFields": [{"key": "k", "required": True, "defaultValue": None}]}]
    kibana.routes[1] = ("GET", "/api/cases/configure", [reply(blocking)])
    gateway, kibana, _, clock, _ = make(kibana, classes=W1)
    run = await start(gateway, clock)
    assert run.creates_blocked
    with pytest.raises(WriteRefusedError, match="creates_blocked"):
        await create(gateway, run, clock)


async def test_writes_need_normal_health_and_the_window() -> None:
    gateway, kibana, store, clock, _ = make(classes=W1)
    run = await start(gateway, clock)
    store.memory = HealthMemory(state=HealthState.CAUTION, probed_at=clock.now)
    with pytest.raises(DeferredError):
        await create(gateway, run, clock)
    store.memory = HealthMemory(probed_at=clock.now)
    late = clock.now.replace(hour=18)
    gateway2, kibana2, store2, clock2, _ = make(classes=W1)
    clock2.now = late
    store2.memory = HealthMemory(probed_at=late)
    run2 = await start(gateway2, clock2)
    with pytest.raises(WriteRefusedError, match="outside_window"):
        await create(gateway2, run2, clock2)
    assert not [c for c in kibana.calls + kibana2.calls if c.method == "POST"]


async def test_alert_tags_are_never_written() -> None:
    gateway, *_, clock, _ = make(classes=ALL)
    run = await start(gateway, clock)
    params = models.AlertStatusChange(signal_ids=(ALERT_ID,), status="closed")
    ctx = WriteContext(WriteClass.WT, "o", gateway.payload_hash(SetAlertStatus(), params))
    with pytest.raises(WriteRefusedError, match="wrong_class"):
        await gateway.write(SetAlertStatus(), params, run=run, context=ctx, component="t",
                            deadline=deadline(clock))  # fmt: skip


# --------------------------------------------------------------------------- the gate's faults


async def test_a_reset_after_sending_gives_no_second_request() -> None:
    kibana = ready_kibana()
    kibana.routes.insert(0, ("POST", "/api/cases", [UnknownOutcomeError("reset")]))
    gateway, kibana, store, clock, _ = make(kibana, classes=W1)
    run = await start(gateway, clock)
    with pytest.raises(UnknownOutcomeError) as caught:
        await create(gateway, run, clock)
    assert caught.value.maybe_applied
    assert len([c for c in kibana.calls if c.method == "POST"]) == 1
    assert store.ledger[-1].outcome == "unknown_outcome"
    assert store.ledger[-1].attempts == 1
    # the same outbox row is not sent again by ARGUS: the caps took its place already
    assert store.kibana.counters.case_writes == 1
    with pytest.raises(WriteRefusedError, match="case_gap"):
        await create(gateway, run, clock)  # and a resend 0 s later is refused anyway


async def test_a_timeout_is_charged_its_whole_timeout_to_its_own_lane() -> None:
    kibana = ready_kibana()
    kibana.routes.insert(0, ("POST", "/api/cases",
                             [UnknownOutcomeError("slow", timed_out=True)]))  # fmt: skip
    gateway, _, store, clock, _ = make(kibana, classes=W1)
    run = await start(gateway, clock)
    with pytest.raises(UnknownOutcomeError):
        await create(gateway, run, clock)
    assert store.ledger[-1].took_ms == 15_000
    assert store.lanes.bucket(Lane.KIBANA_WRITE).day_used_ms == 15_000
    assert store.budget.day_used_ms < 1_000  # the collector's lane: only the licence read


async def test_no_connection_is_charged_nothing() -> None:
    kibana = ready_kibana()
    kibana.routes.insert(0, ("GET", f"/api/cases/{CASE_ID}",
                             [UnknownOutcomeError("refused", reached=False)]))  # fmt: skip
    gateway, _, store, clock, _ = make(kibana)
    with pytest.raises(UnknownOutcomeError) as caught:
        await read_case(gateway, clock)
    assert not caught.value.maybe_applied
    assert store.ledger[-1].took_ms == 0


async def test_a_kibana_401_stops_kibana_and_collection_keeps_running() -> None:
    kibana = FakeKibana().on("GET", f"/api/cases/{CASE_ID}", reply({"statusCode": 401}, 401))
    gateway, kibana, store, clock, es_gateway = make(kibana)
    with pytest.raises(KibanaAuthError):
        await read_case(gateway, clock)
    assert store.kibana.stopped == "401"
    assert store.memory.state is HealthState.NORMAL  # the SIEM is not in STOP
    with pytest.raises(KibanaStoppedError):
        await read_case(gateway, clock)
    assert len(kibana.calls) == 1
    es_gateway.transport.default = search_answer()  # type: ignore[attr-defined]
    result = await es_gateway.run(
        AlertIds(), AlertIdsParams(start=clock.now - timedelta(minutes=5), end=clock.now),
        purpose=Purpose.COLLECT, component="collector", deadline=deadline(clock),
    )  # fmt: skip
    assert result.body["hits"]["hits"] == []


async def test_a_write_403_pauses_only_its_class() -> None:
    kibana = ready_kibana()
    kibana.routes.insert(0, ("POST", "/api/cases", [reply({"statusCode": 403}, 403)]))
    kibana.on("POST", f"/api/cases/{CASE_ID}/comments",
              reply(answer(WRITES, "POST", f"/api/cases/{CASE_ID}/comments", 0)))  # fmt: skip
    gateway, kibana, store, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    with pytest.raises(KibanaForbiddenError):
        await create(gateway, run, clock)
    assert dict(store.kibana.paused) == {"W1": "403"}
    assert store.kibana.stopped is None
    clock.advance(5 * SEC)
    with pytest.raises(WriteRefusedError, match="class_paused"):
        await create(gateway, run, clock)
    params = CommentParams(case_id=CASE_ID, comment="Opened by ARGUS: decisions are made in ARGUS.")
    await gateway.write(CommentOnCase(), params, run=run,
                        context=context(gateway, CommentOnCase(), params, WriteClass.W2),
                        component="t", deadline=deadline(clock))  # fmt: skip
    await read_case_ok(gateway, kibana, clock)


async def read_case_ok(gateway: Any, kibana: FakeKibana, clock: Any) -> None:
    kibana.on("GET", f"/api/cases/{CASE_ID}", reply(_case(id=CASE_ID)))
    await read_case(gateway, clock)


async def test_a_read_403_stops_kibana_work() -> None:
    gateway, *_, store, clock, _ = make(
        FakeKibana().on("GET", f"/api/cases/{CASE_ID}", reply({}, 403))
    )
    with pytest.raises(KibanaForbiddenError):
        await read_case(gateway, clock)
    assert store.kibana.stopped == "403 on a read"


async def test_a_mid_run_switch_stops_the_next_request() -> None:
    gateway, kibana, store, clock, _ = make(classes=W1)
    run = await start(gateway, clock)
    await create(gateway, run, clock)
    store.stopped.add("cases")
    clock.advance(5 * SEC)
    with pytest.raises(StoppedError):
        await create(gateway, run, clock, create_params("[ARGUS 8] another"))
    assert len([c for c in kibana.calls if c.method == "POST"]) == 1


async def test_a_switch_thrown_while_waiting_for_the_budget_stops_the_request() -> None:
    gateway, kibana, store, clock, _ = make(classes=W1)
    run = await start(gateway, clock)
    from argus.gateway.budget import BudgetState

    store.lanes = type(store.lanes)(
        {
            Lane.KIBANA_WRITE: BudgetState(
                tokens_ms=-100.0, refilled_at=clock.now, day=clock.now.date()
            )
        }
    )
    real_sleep = clock.sleep

    async def sleep_then_stop(seconds: float) -> None:
        store.stopped.add("global")
        await real_sleep(seconds)

    gateway.sleep = sleep_then_stop
    with pytest.raises(StoppedError):
        await create(gateway, run, clock)
    assert not [c for c in kibana.calls if c.method == "POST"]
    assert store.lanes.bucket(Lane.KIBANA_WRITE).leases == ()


@pytest.mark.parametrize(
    ("status", "error", "maybe"),
    [
        (404, "KibanaNotFoundError", False),
        (406, "KibanaNoChangeError", False),
        (409, "KibanaConflictError", False),
        (400, "KibanaRejectedError", False),
        (302, "KibanaRejectedError", True),  # not proven to come before any change (F1)
        (500, "KibanaServerError", True),
    ],
)
async def test_answers_become_typed_errors(status: int, error: str, maybe: bool) -> None:
    kibana = ready_kibana()
    kibana.routes.insert(0, ("PATCH", "/api/cases", [reply({"message": "x"}, status)]))
    gateway, _, store, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    params = _update_params()
    with pytest.raises(KIBANA_ANSWERS) as caught:
        await gateway.write(UpdateCase(), params, run=run,
                            context=context(gateway, UpdateCase(), params, WriteClass.W2),
                            component="t", deadline=deadline(clock))  # fmt: skip
    assert type(caught.value).__name__ == error
    assert caught.value.maybe_applied is maybe  # type: ignore[attr-defined]
    assert store.kibana.paused == {}  # none of these pauses the class
    assert issubclass(type(caught.value), KIBANA_ANSWERS)


KIBANA_ANSWERS = (
    KibanaConflictError, KibanaNoChangeError, KibanaRejectedError, KibanaServerError,
    KibanaNotFoundError,
)  # fmt: skip


def _update_params(**over: Any) -> models.UpdatePatch:
    fields: dict[str, Any] = {"id": CASE_ID, "version": "WzEsMV01", "severity": "high"}
    fields.update(over)
    return models.UpdatePatch(cases=(models.CaseChange(**fields),))


async def test_429_opens_kibanas_breaker_not_siems() -> None:
    kibana = FakeKibana().on("GET", f"/api/cases/{CASE_ID}", reply({}, 429))
    gateway, kibana, store, clock, _ = make(kibana)
    with pytest.raises(KibanaOverloadedError):
        await read_case(gateway, clock)
    assert store.kibana_breaker.open_until is not None
    assert store.breaker == BreakerState()
    with pytest.raises(BreakerOpenError):
        await read_case(gateway, clock)
    assert len(kibana.calls) == 1


async def test_a_wrong_answer_to_a_write_pauses_its_class() -> None:
    kibana = ready_kibana()
    synced = _case(settings={"syncAlerts": True})
    kibana.routes.insert(0, ("POST", "/api/cases", [reply(synced)]))
    gateway, _, store, clock, _ = make(kibana, classes=W1)
    run = await start(gateway, clock)
    with pytest.raises(AnswerMismatchError) as caught:
        await create(gateway, run, clock)
    assert caught.value.maybe_applied
    assert dict(store.kibana.paused) == {"W1": "answer_mismatch"}


async def test_a_case_by_someone_else_is_a_wrong_answer() -> None:
    kibana = ready_kibana()
    other = _case(created_by={"username": "tier-analyst"})
    kibana.routes.insert(0, ("POST", "/api/cases", [reply(other)]))
    gateway, _, store, clock, _ = make(kibana, classes=W1)
    run = await start(gateway, clock)
    with pytest.raises(AnswerMismatchError, match="someone else"):
        await create(gateway, run, clock)
    assert dict(store.kibana.paused) == {"W1": "answer_mismatch"}


# --------------------------------------------------------------------------- caps


async def test_case_writes_keep_three_seconds_apart_and_ten_a_run() -> None:
    gateway, kibana, store, clock, _ = make(classes=W1)
    run = await start(gateway, clock)
    for n in range(10):
        store.memory = HealthMemory(probed_at=clock.now)  # the probe keeps running meanwhile
        await create(gateway, run, clock, create_params(f"[ARGUS {n}] case"))
        if n == 0:
            with pytest.raises(WriteRefusedError, match="case_gap"):
                await create(gateway, run, clock, create_params("[ARGUS x] too soon"))
        clock.advance(3 * SEC)
    with pytest.raises(WriteRefusedError, match="run_cap"):
        await create(gateway, run, clock, create_params("[ARGUS 11] eleventh"))
    assert len([c for c in kibana.calls if c.method == "POST"]) == 10
    store.memory = HealthMemory(probed_at=clock.now)
    run2 = await start(gateway, clock)
    await create(gateway, run2, clock, create_params("[ARGUS 12] next run"))


async def test_attachments_count_as_alert_mutations() -> None:
    kibana = ready_kibana().on(
        "POST", f"/api/cases/{CASE_ID}/comments",
        reply(answer(WRITES, "POST", f"/api/cases/{CASE_ID}/comments", 1)),
    )  # fmt: skip
    gateway, kibana, store, clock, _ = make(kibana, classes=W1)
    run = await start(gateway, clock)
    params = AttachParams(case_id=CASE_ID, alerts=((ALERT_ID, ALERT_INDEX),))

    async def attach() -> Any:
        return await gateway.write(AttachAlerts(), params, run=run,
                                   context=context(gateway, AttachAlerts(), params),
                                   component="t", deadline=deadline(clock))  # fmt: skip

    await attach()
    assert store.kibana.counters.alert_mutations == 1
    clock.advance(10 * SEC)
    with pytest.raises(WriteRefusedError, match="alert_gap"):  # ≥ 60 s between alert calls
        await attach()
    clock.advance(60 * SEC)
    await attach()
    body = next(c for c in kibana.calls if c.path.endswith("/comments")).body
    assert body is not None
    assert b'"alertId":["' + ALERT_ID.encode() in body


async def test_ledger_rows_of_writes_hold_the_approval_health_and_switches() -> None:
    kibana = ready_kibana()
    kibana.routes.insert(0, ("PATCH", "/api/cases",
                             [reply(answer(WRITES, "PATCH", "/api/cases", 2))]))  # fmt: skip
    gateway, _, store, clock, _ = make(kibana, classes=ALL)
    store.stopped.add("collector")
    run = await start(gateway, clock)
    params = _close_params()
    await gateway.write(CloseCase(), params, run=run,
                        context=context(gateway, CloseCase(), params, WriteClass.W3,
                                        approval="approval-7"),
                        component="writer", deadline=deadline(clock))  # fmt: skip
    entry = store.ledger[-1]
    assert (entry.write_class, entry.approval_id, entry.health, entry.switches) == (
        "W3", "approval-7", "normal", ("collector",),
    )  # fmt: skip


def test_the_tier_cassette_constants_are_consistent() -> None:
    assert answer(WRITES, "POST", "/api/cases")["id"] == CASE_ID
    assert KibanaStoppedError.reason == "kibana_stopped"


async def test_a_status_change_answered_with_sync_alerts_on_pauses_its_class() -> None:
    """DQ6 (a): someone switched Sync alerts on in Kibana; the status change may have rewritten
    the alerts' status, so the answer is wrong and W2 pauses."""
    synced = answer(WRITES, "PATCH", "/api/cases", 1)
    synced[0]["settings"] = {"syncAlerts": True}
    kibana = ready_kibana()
    kibana.routes.insert(0, ("PATCH", "/api/cases", [reply(synced)]))
    gateway, _, store, clock, _ = make(kibana, classes=ALL)
    run = await start(gateway, clock)
    params = models.UpdatePatch(
        cases=(models.CaseChange(id=CASE_ID, version="WzEsMV02", status="in-progress"),)
    )
    with pytest.raises(AnswerMismatchError, match="Sync alerts"):
        await gateway.write(UpdateCase(), params, run=run,
                            context=context(gateway, UpdateCase(), params, WriteClass.W2),
                            component="t", deadline=deadline(clock))  # fmt: skip
    assert dict(store.kibana.paused) == {"W2": "answer_mismatch"}


async def test_a_write_goes_out_only_with_its_whole_timeout_ahead() -> None:
    """A write sent with 3 s left would be cut short while Kibana goes on with it: an unknown
    outcome made by ARGUS itself. It is refused before sending, and keeps no place in the caps."""
    gateway, kibana, store, clock, _ = make(classes=W1)
    run = await start(gateway, clock)
    params = create_params()
    with pytest.raises(DeadlinePassedError, match="15 s"):
        await gateway.write(CreateCase(), params, run=run,
                            context=context(gateway, CreateCase(), params), component="t",
                            deadline=clock.now + timedelta(seconds=14))  # fmt: skip
    assert not [c for c in kibana.calls if c.method == "POST"]
    assert store.kibana.counters.case_writes == 0
    assert store.lanes.bucket(Lane.KIBANA_WRITE).leases == ()
    kibana.on("GET", f"/api/cases/{CASE_ID}", reply(_case(id=CASE_ID)))
    await gateway.read(CaseGet(), CaseParams(case_id=CASE_ID), component="t",
                       deadline=clock.now + timedelta(seconds=2))  # fmt: skip
