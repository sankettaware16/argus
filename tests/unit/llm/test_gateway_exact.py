"""The LLM gateway's exact values and edges (P5): the waits, the messages, what the ledger
holds for each outcome and what each failure leaves charged. Quick tests: the simulated days
are in test_gateway.py."""

from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import timedelta

import pytest

from argus.llm import budget
from argus.llm.gateway import (
    Call,
    CallEntry,
    Completion,
    LlmGateway,
    MemoryLlmStore,
    NoCapacity,
    Refused,
    body_for,
)
from argus.llm.privacy import Privacy, Request
from argus.llm.providers import LlmConfig, Tier
from argus.llm.wire import LlmReply, TransportError
from tests.unit.llm.test_gateway import KEYS, NOW, Clock, Fake, config, make, ok
from tests.unit.llm.test_privacy import dossier

pytestmark = pytest.mark.unit
PAID = {"PAID_KEY": KEYS["PAID_KEY"]}


@pytest.fixture
def call(privacy: Privacy) -> Call:
    return Call(privacy.request([dossier()]), "Assess the item. Answer in JSON.", "assess")


def paid_only(**limits: int) -> LlmConfig:
    paid = config().providers[0].model_dump()
    return config(providers=[{**paid, "limits": limits or {"tpd": 10**6}}])


def test_the_records_are_immutable(call: Call) -> None:
    entry = CallEntry(NOW, uuid.uuid4(), 0, "p", "m", "small", "t", "normal", "ok")
    done = Completion("x", "p", "m", 1, 1, 0.0, 1, uuid.uuid4())
    for record in (call, done, entry):
        name = dataclasses.fields(record)[0].name
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(record, name, None)


def test_no_capacity_says_why() -> None:
    caught = NoCapacity(NOW, "paid: minute limit")
    assert str(caught) == "paid: minute limit"
    assert caught.until == NOW


async def test_a_stopped_gateway_waits_a_minute(call: Call) -> None:
    gw, _, store, _ = make()
    await store.change(lambda s: (None, dataclasses.replace(s, stopped=True)))
    with pytest.raises(NoCapacity) as caught:
        await gw.complete(call)
    assert caught.value.until == NOW + timedelta(seconds=60)
    assert str(caught.value) == "stopped (argus llm resume)"


async def test_the_ledger_entry_of_a_request_the_validator_refuses(privacy: Privacy) -> None:
    leaky = Request("host 10.20.3.4 called", (), (), (), (), privacy.ours)
    gw, _, store, _ = make()
    with pytest.raises(Refused):
        await gw.complete(Call(leaky, "Answer in JSON.", "assess"))
    (entry,) = store.ledger
    assert (entry.provider, entry.model, entry.attempt, entry.outcome) == ("-", "-", 0, "blocked")
    assert entry.http_status is None
    assert (entry.input_tokens, entry.output_tokens, entry.latency_ms) == (0, 0, 0)
    assert entry.request_bytes == 0
    assert entry.cost_usd == 0.0
    assert entry.request_sha256 == ""


async def test_the_ledger_entry_of_a_body_the_validator_refuses(call: Call) -> None:
    gw, _, store, _ = make()
    with pytest.raises(Refused):
        await gw.complete(Call(call.request, "Ask moodle.example.edu about it", "assess"))
    (entry,) = store.ledger
    assert (entry.provider, entry.model, entry.attempt) == ("paid", "p-small", 0)


async def test_without_usage_the_estimate_is_the_body_and_32(call: Call) -> None:
    body = json.dumps({"choices": [{"message": {"content": "{}"}}]}).encode()
    gw, _, _, _ = make(Fake({"paid": [LlmReply(200, body, 1.0)]}))
    done = await gw.complete(call)
    assert done.input_tokens == len(body_for(config().providers[0], call)) + 32


async def test_zero_tokens_are_a_count(call: Call) -> None:
    gw, _, _, _ = make(Fake({"paid": [ok(usage={"prompt_tokens": 0, "completion_tokens": 0})]}))
    done = await gw.complete(call)
    assert (done.input_tokens, done.output_tokens) == (0, 0)


async def test_an_account_out_of_credit_waits_six_hours(call: Call) -> None:
    quota = json.dumps({"error": {"code": "insufficient_quota"}}).encode()
    gw, _, store, _ = make(Fake({"paid": [LlmReply(429, quota, 1.0)]}))
    await gw.complete(call)
    assert (await store.state()).cooldowns == {"paid/p-small": NOW + timedelta(hours=6)}


async def test_a_refused_key_waits_an_hour(call: Call) -> None:
    gw, _, store, _ = make(Fake({"paid": [LlmReply(401, b"", 1.0)]}))
    await gw.complete(call)
    assert (await store.state()).cooldowns == {"paid": NOW + timedelta(hours=1)}


async def test_no_answer_defers_a_minute_and_says_so(call: Call) -> None:
    gw, _, _, _ = make(Fake({"paid": [TransportError("x")]}), keys=PAID)
    with pytest.raises(NoCapacity) as caught:
        await gw.complete(call)
    assert caught.value.until == NOW + timedelta(seconds=60)
    assert str(caught.value) == "paid: no answer"


async def test_the_reasons_of_every_provider_are_joined(call: Call) -> None:
    fake = Fake({"paid": [LlmReply(503, b"", 1.0)], "free": [LlmReply(503, b"", 1.0)]})
    gw, _, _, _ = make(fake)
    with pytest.raises(NoCapacity) as caught:
        await gw.complete(call)
    assert str(caught.value) == "paid: server_error (503); free: server_error (503)"


async def test_no_provider_for_the_tier(call: Call) -> None:
    gw, _, _, _ = make()
    with pytest.raises(Refused) as caught:
        await gw.complete(Call(call.request, "x", "t", tier=Tier.MEDIUM))
    assert str(caught.value) == "no provider is configured for this tier with a key"


async def test_a_provider_without_budget_sends_nothing_and_counts_no_attempt(call: Call) -> None:
    state = budget.State(cooldowns={"paid": NOW + timedelta(hours=1)})
    store = MemoryLlmStore(state)
    gw = LlmGateway(config(), KEYS, Fake(), store, Clock())
    done = await gw.complete(call)
    assert done.provider == "free"
    (entry,) = store.ledger
    assert (entry.provider, entry.attempt) == ("free", 1)


async def test_no_answer_keeps_the_cost_estimate_reserved(call: Call) -> None:
    cfg = paid_only()
    gw, _, store, _ = make(Fake({"paid": [TransportError("x")]}), cfg, PAID)
    with pytest.raises(NoCapacity):
        await gw.complete(call)
    paid = cfg.providers[0]
    size = len(body_for(paid, call))
    expected = paid.models[Tier.SMALL].cost(size + 32, 1000)
    assert (await store.state()).spent_usd == pytest.approx(expected, rel=1e-9)


@pytest.mark.parametrize(
    "reply",
    [LlmReply(429, b"{}", 1.0), LlmReply(401, b"", 1.0), LlmReply(503, b"", 1.0),
     LlmReply(400, b"", 1.0)],
)  # fmt: skip
async def test_a_refusal_leaves_nothing_charged(call: Call, reply: LlmReply) -> None:
    gw, _, store, _ = make(Fake({"paid": [reply]}), paid_only(), PAID)
    with pytest.raises((NoCapacity, Refused)):
        await gw.complete(call)
    state = await store.state()
    w = state.windows["paid"]
    assert (w.day_requests, w.day_tokens, w.minute_tokens) == (1, 0, 0)
    assert state.spent_usd == 0.0


async def test_a_bad_answer_closes_the_breaker_on_trial(call: Call) -> None:
    tripped = budget.overload(budget.State(), "paid", NOW - timedelta(minutes=5))
    store = MemoryLlmStore(tripped)
    fake = Fake({"paid": [LlmReply(200, b"{}", 1.0), ok()]})
    gw = LlmGateway(config(), KEYS, fake, store, Clock())
    assert (await gw.complete(call)).provider == "free"  # the trial: a bad answer
    assert (await gw.complete(call)).provider == "paid"  # it answered: the breaker is closed


async def test_a_provider_cannot_inflate_its_own_count(privacy: Privacy) -> None:
    """The estimate is an upper bound: larger counts are clamped (review, 2026-10-21)."""
    from argus.llm.gateway import MESSAGE_OVERHEAD, Call
    from tests.unit.llm.test_gateway import Fake, body_for, config, make, ok
    from tests.unit.llm.test_privacy import dossier

    call = Call(privacy.request([dossier()]), "Answer in JSON.", "assess", max_output=100)
    huge = ok(usage={"prompt_tokens": 10**12, "completion_tokens": 10**9})
    gw, _, store, _ = make(Fake({"paid": [huge]}))
    done = await gw.complete(call)
    size = len(body_for(config().providers[0], call)) + MESSAGE_OVERHEAD
    assert (done.input_tokens, done.output_tokens) == (size, 100)
    assert done.cost_usd == (size * 1.0 + 100 * 2.0) / 1e6
    assert store.ledger[0].input_tokens == size


async def test_a_connection_that_never_reached_the_provider_costs_nothing(
    privacy: Privacy,
) -> None:
    """The outage of 10-18 to 10-21 (D-096): refused or timed-out connections kept their
    reservations and used up the month's paid share without a cent billed."""
    from argus.llm.wire import TransportError
    from tests.unit.llm.test_gateway import Fake, make, ok
    from tests.unit.llm.test_privacy import dossier

    call = Call(privacy.request([dossier()]), "Answer in JSON.", "assess")
    never = Fake({"paid": [TransportError("ConnectTimeout", reached=False)], "free": [ok()]})
    gw, _, store, _ = make(never)
    await gw.complete(call)
    state = await store.state()
    assert state.spent_usd == 0.0  # the paid call's reservation was released
    assert state.breakers["paid"].is_open(NOW)  # and the provider still cools down
    maybe = Fake({"paid": [TransportError("ReadTimeout")], "free": [ok()]})
    gw, _, store, _ = make(maybe)
    await gw.complete(call)
    assert (await store.state()).spent_usd > 0  # it may have been charged: kept
    from argus.llm.providers import LlmConfig
    from tests.unit.llm.test_gateway import config

    data = config().model_dump(mode="json")
    data["providers"][0]["models"]["small"]["limits"] = {"tpm": 10**6, "tpd": 10**7}
    limited = LlmConfig.model_validate(data)
    again = Fake({"paid": [TransportError("ConnectError", reached=False)], "free": [ok()]})
    gw, _, store, _ = make(again, limited)
    await gw.complete(call)
    window = (await store.state()).windows["paid/p-small"]
    assert (window.minute_requests, window.minute_tokens, window.day_tokens) == (1, 0, 0)
    timed = Fake({"paid": [TimeoutError()], "free": [ok()]})
    gw, _, store, _ = make(timed)
    await gw.complete(call)
    assert (await store.state()).spent_usd > 0  # a bare timeout may have been charged too
