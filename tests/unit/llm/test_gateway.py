"""The LLM gateway (P5): validation before sending, provider order and fallback, Retry-After,
breakers, the kill switch, the ledger (no content), deferral, and the cost cap."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import SecretStr

from argus.llm import budget
from argus.llm.gateway import (
    AUTH_WAIT,
    DEFAULT_WAIT,
    MESSAGE_OVERHEAD,
    QUOTA_WAIT,
    Call,
    LlmGateway,
    MemoryLlmStore,
    NoCapacity,
    Refused,
    body_for,
    retry_after,
    stop,
)
from argus.llm.privacy import Privacy, Request
from argus.llm.providers import LlmConfig, Tier
from argus.llm.wire import LlmReply, LlmWire, TransportError
from tests.unit.llm.test_privacy import RAW, dossier

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
KEYS = {"PAID_KEY": SecretStr("sk-paid-123456"), "FREE_KEY": SecretStr("free-abcdef")}


def config(**over: Any) -> LlmConfig:
    data: dict[str, Any] = {
        "monthly_cap_usd": 1.0,
        "providers": [
            {
                "name": "paid",
                "base_url": "https://paid.example/v1",
                "keys": ["PAID_KEY"],
                "max_tokens_field": "max_completion_tokens",
                "models": {
                    "small": {
                        "name": "p-small",
                        "input_per_m": 1.0,
                        "output_per_m": 2.0,
                        "extra": {"reasoning_effort": "low"},
                    },
                    "large": {"name": "p-large", "input_per_m": 10.0, "output_per_m": 20.0},
                },
            },
            {
                "name": "free",
                "base_url": "https://free.example/openai",
                "keys": ["MISSING_KEY", "FREE_KEY"],
                "models": {"small": {"name": "f-small", "limits": {"rpm": 10, "tpd": 1_000_000}}},
            },
        ],
    }
    data.update(over)
    return LlmConfig.model_validate(data)


def ok(text: str = '{"ok": true}', usage: Any = None) -> LlmReply:
    body: dict[str, Any] = {"choices": [{"message": {"content": text}}]}
    body["usage"] = usage if usage is not None else {"prompt_tokens": 400, "completion_tokens": 50}
    return LlmReply(200, json.dumps(body).encode(), 123.4)


@dataclass
class Fake:
    """Replies per provider, in order (the last one repeats); records what was sent."""

    replies: dict[str, list[LlmReply | Exception]] = field(default_factory=dict)
    sent: list[tuple[LlmWire, str]] = field(default_factory=list)

    async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        self.sent.append((wire, key.get_secret_value()))
        queue = self.replies.get(wire.provider) or [ok()]
        reply = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(reply, Exception):
            raise reply
        return reply


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


def make(
    fake: Fake | None = None, cfg: LlmConfig | None = None, keys: dict[str, SecretStr] = KEYS
) -> tuple[LlmGateway, Fake, MemoryLlmStore, Clock]:
    fake = fake or Fake()
    store = MemoryLlmStore()
    clock = Clock()
    return LlmGateway(cfg or config(), keys, fake, store, clock), fake, store, clock


@pytest.fixture
def call(privacy: Privacy) -> Call:
    return Call(privacy.request([dossier()]), "Assess the item. Answer in JSON.", "assess")


async def test_a_call_goes_to_the_first_provider(call: Call) -> None:
    gw, fake, store, _ = make()
    done = await gw.complete(call)
    assert (done.provider, done.model, done.text) == ("paid", "p-small", '{"ok": true}')
    assert (done.input_tokens, done.output_tokens, done.latency_ms) == (400, 50, 123)
    assert done.cost_usd == pytest.approx((400 * 1.0 + 50 * 2.0) / 1e6)
    (wire, key), = fake.sent  # fmt: skip
    assert wire.url == "https://paid.example/v1/chat/completions"
    assert key == "sk-paid-123456"
    assert wire.timeout_s == 60.0
    (entry,) = store.ledger
    assert (entry.provider, entry.model, entry.outcome, entry.attempt) == ("paid", "p-small",
                                                                           "ok", 1)  # fmt: skip
    assert (entry.tier, entry.purpose, entry.priority) == ("small", "assess", "normal")
    assert entry.request_bytes == len(wire.body)
    assert len(entry.request_sha256) == 64
    assert entry.call_id == done.call_id
    assert entry.http_status == 200
    assert (entry.input_tokens, entry.output_tokens, entry.latency_ms) == (400, 50, 123)
    assert entry.cost_usd == done.cost_usd


def test_the_body_is_an_openai_chat_body(call: Call) -> None:
    cfg = config()
    body = json.loads(body_for(cfg.providers[0], call))
    assert body == {
        "model": "p-small",
        "messages": [
            {"role": "system", "content": call.instructions},
            {"role": "user", "content": call.request.text},
        ],
        "max_completion_tokens": 1000,
        "reasoning_effort": "low",
        "response_format": {"type": "json_object"},
    }
    free = json.loads(body_for(cfg.providers[1], Call(call.request, "x", "t", json=False)))
    assert free["max_tokens"] == 1000
    assert "response_format" not in free
    no_json = cfg.providers[1].model_copy(update={"json_mode": False})
    assert "response_format" not in json.loads(body_for(no_json, call))
    raw = body_for(cfg.providers[0], Call(Request("é", (), (), (), (), call.request.campus),
                                          "x", "t"))  # fmt: skip
    assert "é".encode() in raw
    assert b", " not in raw


async def test_the_ledger_never_holds_the_content(call: Call) -> None:
    gw, _, store, _ = make()
    await gw.complete(call)
    text = repr(store.ledger)
    for value in [*RAW, call.request.text[:40], "Assess the item", "sk-paid"]:
        assert value not in text


async def test_a_request_that_fails_the_validator_is_never_sent(privacy: Privacy) -> None:
    leaky = Request("host 10.20.3.4 called", (), (), (), (), privacy.campus)
    gw, fake, store, _ = make()
    with pytest.raises(Refused, match="did not pass the validator"):
        await gw.complete(Call(leaky, "Answer in JSON.", "assess"))
    assert fake.sent == []
    assert [e.outcome for e in store.ledger] == ["blocked"]
    assert (store.ledger[0].provider, store.ledger[0].attempt) == ("-", 0)


async def test_the_instructions_are_checked_too(call: Call) -> None:
    gw, fake, store, _ = make()
    with pytest.raises(Refused, match="body did not pass"):
        await gw.complete(Call(call.request, "Ask moodle.example.edu about it", "assess"))
    assert fake.sent == []
    assert store.ledger[0].outcome == "blocked"
    assert store.ledger[0].provider == "paid"
    assert len(store.ledger[0].request_sha256) == 64
    assert (await store.state()).windows == {}


@pytest.mark.parametrize(
    ("reply", "outcome", "breaker", "cooldown"),
    [
        (LlmReply(500, b"oops", 5.0), "server_error", "paid/p-small", None),
        (LlmReply(503, b"", 5.0), "server_error", "paid/p-small", None),
        (TransportError("ReadTimeout"), "no_answer: ReadTimeout", "paid/p-small", None),
        (TimeoutError(), "no_answer: ", "paid/p-small", None),
        (TransportError("ConnectError", reached=False), "no_answer: ConnectError", "paid", None),
        (LlmReply(429, b"{}", 5.0, "7"), "rate_limited", None, ("paid/p-small", 7)),
        (LlmReply(401, b"", 5.0), "unauthorized", None, ("paid", AUTH_WAIT.total_seconds())),
        (LlmReply(403, b"", 5.0), "unauthorized", None, ("paid", AUTH_WAIT.total_seconds())),
        (LlmReply(400, b"bad", 5.0), "rejected", None, None),
        (LlmReply(200, b"not json", 5.0), "bad_answer", None, None),
    ],
)
async def test_a_failure_falls_back_to_the_next_provider(
    call: Call,
    reply: LlmReply | Exception,
    outcome: str,
    breaker: str | None,
    cooldown: tuple[str, float] | None,
) -> None:
    """Answers trip the model's breaker, transport the provider's (Q-G1; D-100 noted it)."""
    gw, fake, store, _ = make(Fake({"paid": [reply]}))
    done = await gw.complete(call)
    assert done.provider == "free"
    assert [w.provider for w, _ in fake.sent] == ["paid", "free"]
    assert fake.sent[1][1] == "free-abcdef"  # the first key that is present
    first, second = store.ledger
    assert (first.outcome, first.attempt, second.outcome, second.attempt) == (outcome, 1,
                                                                              "ok", 2)  # fmt: skip
    assert first.call_id == second.call_id
    assert first.request_bytes > 0
    if isinstance(reply, LlmReply):
        assert first.http_status == reply.status
        assert first.latency_ms == 5
    state = await store.state()
    tripped = {name for name, b in state.breakers.items() if b.is_open(NOW)}
    assert tripped == ({breaker} if breaker else set())
    if cooldown is None:
        assert state.cooldowns == {}
    else:
        assert state.cooldowns == {cooldown[0]: NOW + timedelta(seconds=cooldown[1])}


async def test_what_a_failure_leaves_charged(call: Call) -> None:
    # refused: nothing but the request; no answer or a bad answer: the whole estimate
    for reply, charged in [(LlmReply(500, b"", 1.0), 0), (TransportError("x"), None),
                           (LlmReply(200, b"{}", 1.0), None)]:  # fmt: skip
        cfg = config(providers=[{**config().providers[0].model_dump(), "limits": {"tpd": 10**6}}])
        gw, _, store, _ = make(Fake({"paid": [reply]}), cfg)
        with pytest.raises(NoCapacity if charged == 0 or isinstance(reply, Exception) else Refused):
            await gw.complete(call)
        w = (await store.state()).windows["paid"]
        estimate = len(body_for(cfg.providers[0], call)) + MESSAGE_OVERHEAD + 1000
        assert w.day_requests == 1
        assert w.day_tokens == (estimate if charged is None else 0)


async def test_settling_uses_the_providers_count_or_the_estimate(call: Call) -> None:
    cfg = config(providers=[{**config().providers[0].model_dump(), "limits": {"tpd": 10**6}}])
    gw, _, store, _ = make(cfg=cfg)
    await gw.complete(call)
    assert (await store.state()).windows["paid"].day_tokens == 450
    assert (await store.state()).spent_usd == pytest.approx(500e-6)
    gw, _, store, _ = make(Fake({"paid": [ok(usage={"prompt_tokens": True})]}), cfg)
    done = await gw.complete(call)
    size = len(body_for(cfg.providers[0], call)) + MESSAGE_OVERHEAD
    assert (done.input_tokens, done.output_tokens) == (size, 1000)
    assert (await store.state()).windows["paid"].day_tokens == size + 1000


async def test_a_rate_limit_cools_the_model_down_until_retry_after(call: Call) -> None:
    gw, fake, _, clock = make(Fake({"paid": [LlmReply(429, b"{}", 1.0, "120"), ok()]}))
    assert (await gw.complete(call)).provider == "free"
    clock.now = NOW + timedelta(seconds=119)
    assert (await gw.complete(call)).provider == "free"
    clock.now = NOW + timedelta(seconds=120)
    assert (await gw.complete(call)).provider == "paid"
    assert [w.provider for w, _ in fake.sent] == ["paid", "free", "free", "paid"]


async def test_a_rate_limit_without_retry_after_waits_a_minute(call: Call) -> None:
    gw, _, store, _ = make(Fake({"paid": [LlmReply(429, b"{}", 1.0)]}))
    await gw.complete(call)
    assert (await store.state()).cooldowns == {"paid/p-small": NOW + DEFAULT_WAIT}


async def test_an_account_out_of_credit_waits_hours(call: Call) -> None:
    for error in ({"code": "insufficient_quota"}, {"type": "insufficient_quota"},
                  {"code": "credit_balance_exhausted"}):  # fmt: skip
        quota = json.dumps({"error": error}).encode()
        gw, _, store, _ = make(Fake({"paid": [LlmReply(429, quota, 1.0)]}))
        await gw.complete(call)
        assert (await store.state()).cooldowns == {"paid/p-small": NOW + QUOTA_WAIT}
    for body in (b"[]", b"{", json.dumps({"error": "insufficient_quota"}).encode()):
        gw, _, store, _ = make(Fake({"paid": [LlmReply(429, body, 1.0)]}))
        await gw.complete(call)
        assert (await store.state()).cooldowns == {"paid/p-small": NOW + DEFAULT_WAIT}


async def test_when_every_provider_waits_the_call_is_deferred(call: Call) -> None:
    fake = Fake({"paid": [LlmReply(429, b"{}", 1.0, "300")],
                 "free": [LlmReply(503, b"", 1.0)]})  # fmt: skip
    gw, _, _, clock = make(fake)
    with pytest.raises(NoCapacity) as caught:
        await gw.complete(call)
    assert caught.value.until == NOW + DEFAULT_WAIT  # the sooner of the two
    assert "paid: rate_limited (429)" in str(caught.value)
    assert "free: server_error (503)" in str(caught.value)
    clock.now = NOW + timedelta(seconds=10)
    with pytest.raises(NoCapacity) as caught:  # nothing is sent while both wait
        await gw.complete(call)
    assert len(fake.sent) == 2
    assert caught.value.until == NOW + timedelta(minutes=5)
    assert "paid: paid/p-small: cooling down" in str(caught.value)
    assert "free: free/f-small: breaker open" in str(caught.value)


async def test_a_rate_limit_far_away_waits_at_most_a_day(call: Call) -> None:
    gw, _, _, _ = make(Fake({"paid": [LlmReply(429, b"{}", 1.0, str(10**7))],
                             "free": [LlmReply(429, b"{}", 1.0, str(10**7))]}))  # fmt: skip
    with pytest.raises(NoCapacity) as caught:
        await gw.complete(call)
    assert caught.value.until == NOW + budget.MAX_COOLDOWN


async def test_when_every_provider_refuses_the_call_is_refused(call: Call) -> None:
    gw, fake, _, _ = make(Fake({"paid": [LlmReply(400, b"", 1.0)],
                                "free": [LlmReply(422, b"", 1.0)]}))  # fmt: skip
    with pytest.raises(Refused, match=r"paid: rejected \(400\); free: rejected \(422\)"):
        await gw.complete(call)
    assert len(fake.sent) == 2


async def test_a_tier_no_provider_has_is_refused(call: Call) -> None:
    gw, fake, _, _ = make()
    with pytest.raises(Refused, match="no provider is configured"):
        await gw.complete(Call(call.request, "x", "t", tier=Tier.MEDIUM))
    assert fake.sent == []
    done = await gw.complete(Call(call.request, "x", "t", tier=Tier.LARGE))
    assert done.model == "p-large"


async def test_providers_without_a_key_or_disabled_are_skipped(call: Call) -> None:
    gw, _, _, _ = make(keys={"FREE_KEY": KEYS["FREE_KEY"]})
    assert (await gw.complete(call)).provider == "free"
    providers = config().providers
    cfg = config(providers=[{**providers[0].model_dump(), "enabled": False},
                            providers[1].model_dump()])  # fmt: skip
    gw, _, _, _ = make(cfg=cfg)
    assert (await gw.complete(call)).provider == "free"
    gw, _, _, _ = make(keys={})
    with pytest.raises(Refused):
        await gw.complete(call)


async def test_a_call_skips_the_providers_it_avoids(call: Call) -> None:
    """AR1: after an unusable answer the agent asks again at another provider."""
    gw, fake, store, _ = make()
    done = await gw.complete(replace(call, avoid=frozenset({"paid"})))
    assert done.provider == "free"
    assert [w.provider for w, _ in fake.sent] == ["free"]
    assert [e.provider for e in store.ledger] == ["free"]
    assert (await gw.complete(call)).provider == "paid"  # only that call avoided it
    with pytest.raises(Refused, match="paid: skipped, its answer was unusable"):
        await gw.complete(replace(call, avoid=frozenset({"paid", "free"})))
    assert len(fake.sent) == 2


async def test_the_kill_switch_defers_and_sends_nothing(call: Call) -> None:
    gw, fake, store, _ = make()
    assert await stop(store, True) is True
    assert await stop(store, True) is False
    with pytest.raises(NoCapacity, match="stopped") as caught:
        await gw.complete(call)
    assert caught.value.until == NOW + DEFAULT_WAIT
    assert fake.sent == []
    assert store.ledger == []
    assert await stop(store, False) is True
    assert (await gw.complete(call)).provider == "paid"


async def test_the_monthly_cap_moves_calls_to_the_free_provider(call: Call) -> None:
    paid = config().providers[0]
    estimate = paid.models[Tier.SMALL].cost(len(body_for(paid, call)) + MESSAGE_OVERHEAD, 1000)
    # NORMAL may use 0.8 of the cap: room for one estimate, not for one more after it settles
    gw, _fake, store, _ = make(cfg=config(monthly_cap_usd=(estimate + 250e-6) / 0.8))
    providers = [(await gw.complete(call)).provider for _ in range(3)]
    assert providers == ["paid", "free", "free"]
    assert (await store.state()).spent_usd == pytest.approx(500e-6)
    high = Call(call.request, call.instructions, "assess", priority=budget.Priority.HIGH)
    assert (await gw.complete(high)).provider == "paid"


async def test_a_minute_limit_defers_until_the_next_minute(call: Call) -> None:
    gw, fake, _, clock = make(keys={"FREE_KEY": KEYS["FREE_KEY"]})
    for _ in range(8):  # rpm 10 at margin 0.8
        await gw.complete(call)
    with pytest.raises(NoCapacity) as caught:
        await gw.complete(call)
    assert caught.value.until == NOW + timedelta(minutes=1)
    assert len(fake.sent) == 8
    clock.now = NOW + timedelta(minutes=1)
    assert (await gw.complete(call)).provider == "free"


async def test_a_call_too_large_for_every_provider_is_refused(call: Call) -> None:
    providers = config().providers
    cfg = config(providers=[{**providers[1].model_dump(),
                             "models": {"small": {"name": "f",
                                                  "limits": {"tpm": 100}}}}])  # fmt: skip
    gw, fake, _, _ = make(cfg=cfg)
    with pytest.raises(Refused, match="too large"):
        await gw.complete(call)
    assert fake.sent == []


@pytest.mark.parametrize(
    ("text", "usage"),
    [("", None), ("   ", None), (None, None), (5, None), ("x", ["not", "a", "dict"])],
)
async def test_an_empty_or_malformed_answer_is_a_bad_answer(
    call: Call, text: Any, usage: Any
) -> None:
    body: dict[str, Any] = {"choices": [{"message": {"content": text}}]}
    if usage is not None:
        body["usage"] = usage
    gw, _, store, _ = make(Fake({"paid": [LlmReply(200, json.dumps(body).encode(), 1.0)]}))
    assert (await gw.complete(call)).provider == "free"
    assert store.ledger[0].outcome == "bad_answer"


@pytest.mark.parametrize(
    "body", [b'{"choices": []}', b"{}", b'{"choices": [{"message": null}]}', b"[1]"]
)
async def test_an_answer_without_a_message_is_a_bad_answer(call: Call, body: bytes) -> None:
    gw, _, store, _ = make(Fake({"paid": [LlmReply(200, body, 1.0)]}))
    assert (await gw.complete(call)).provider == "free"
    assert store.ledger[0].outcome == "bad_answer"


@pytest.mark.parametrize(
    ("usage", "expected"),
    [
        ({"prompt_tokens": 7, "completion_tokens": 3}, (7, 3)),
        ({"prompt_tokens": -1, "completion_tokens": 3}, (None, 3)),
        ({"prompt_tokens": 7.5, "completion_tokens": False}, (None, None)),
        ({}, (None, None)),
    ],
)
async def test_token_counts_are_taken_only_when_sane(
    call: Call, usage: dict[str, Any], expected: tuple[int | None, int | None]
) -> None:
    gw, _, _, _ = make(Fake({"paid": [ok(usage=usage)]}))
    done = await gw.complete(call)
    size = len(body_for(config().providers[0], call)) + MESSAGE_OVERHEAD
    assert (done.input_tokens, done.output_tokens) == (
        expected[0] if expected[0] is not None else size,
        expected[1] if expected[1] is not None else 1000,
    )


async def test_no_usage_at_all_uses_the_estimate(call: Call) -> None:
    body = json.dumps({"choices": [{"message": {"content": "{}"}}]}).encode()
    gw, _, _, _ = make(Fake({"paid": [LlmReply(200, body, 1.0)]}))
    done = await gw.complete(call)
    assert done.output_tokens == 1000


async def test_priority_and_purpose_reach_the_ledger(call: Call) -> None:
    gw, _, store, _ = make()
    await gw.complete(Call(call.request, "x", "evaluate", Tier.LARGE, budget.Priority.LOW,
                           max_output=10, timeout_s=5.0))  # fmt: skip
    entry = store.ledger[0]
    assert (entry.purpose, entry.priority, entry.tier) == ("evaluate", "low", "large")


def test_retry_after_reads_seconds_and_dates() -> None:
    assert retry_after("30", NOW) == NOW + timedelta(seconds=30)
    assert retry_after("1.5", NOW) == NOW + timedelta(seconds=1.5)
    assert retry_after("-4", NOW) == NOW
    assert retry_after("Fri, 16 Oct 2026 12:05:00 GMT", NOW) == NOW + timedelta(minutes=5)
    assert retry_after("Fri, 16 Oct 2026 11:00:00 GMT", NOW) == NOW
    assert retry_after("Fri, 16 Oct 2026 12:05:00", NOW) == NOW + timedelta(minutes=5)
    for junk in (None, "", "soon", "Fri, 99 Oct"):
        assert retry_after(junk, NOW) is None


@pytest.mark.parametrize("seed", range(12))
async def test_simulated_days_never_exceed_a_budget(call: Call, seed: int) -> None:
    """Random traffic over three simulated days, with rate limits and failures: the ledger
    shows no limit exceeded, per minute or per day, and the month's cost under its cap."""
    import random

    rng = random.Random(seed)
    providers = config().providers
    cfg = config(
        monthly_cap_usd=0.05,
        providers=[
            {**providers[0].model_dump(), "limits": {"rpm": 5, "tpm": 20_000, "rpd": 300}},
            {**providers[1].model_dump(),
             "models": {"small": {"name": "f-small",
                                  "limits": {"rpm": 4, "tpm": 12_000, "rpd": 200,
                                             "tpd": 500_000}}}},
        ],
    )  # fmt: skip
    script: Callable[[], LlmReply | Exception] = lambda: rng.choice(  # noqa: E731
        [ok(usage={"prompt_tokens": rng.randint(100, 900),
                   "completion_tokens": rng.randint(1, 900)})] * 8
        + [LlmReply(429, b"{}", 1.0, str(rng.randint(1, 90))), LlmReply(500, b"", 1.0),
           TransportError("x")]
    )  # fmt: skip

    class Random(Fake):
        async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
            self.sent.append((wire, key.get_secret_value()))
            reply = script()
            if isinstance(reply, Exception):
                raise reply
            return reply

    small = Request("Assess I1.", ("I1",), (), (), (), call.request.campus)
    gw, _fake, store, clock = make(Random(), cfg)
    priorities = list(budget.Priority)
    end = NOW + timedelta(days=3)
    while clock.now < end:
        clock.now += timedelta(seconds=rng.choice([1, 2, 5, 20, 60, 600]))
        c = Call(small, "x", "t", priority=rng.choice(priorities),
                 max_output=rng.choice([100, 1000]))  # fmt: skip
        with contextlib.suppress(NoCapacity):
            await gw.complete(c)
    sent = [e for e in store.ledger if e.attempt > 0]
    assert len(sent) > 100
    free = cfg.providers[1].models[Tier.SMALL].limits
    for name, lim, margin in (("paid", cfg.providers[0].limits, 0.8),
                              ("free", free, 0.8)):  # fmt: skip
        assert lim is not None
        rows = [e for e in sent if e.provider == name]
        per_minute: dict[datetime, list[Any]] = {}
        per_day: dict[Any, list[Any]] = {}
        for e in rows:
            per_minute.setdefault(e.at.replace(second=0, microsecond=0), []).append(e)
            per_day.setdefault(e.at.date(), []).append(e)
        assert max(len(v) for v in per_minute.values()) <= int((lim.rpm or 0) * margin)
        assert max(len(v) for v in per_day.values()) <= int((lim.rpd or 0) * margin)
        for v in per_minute.values():
            assert sum(e.input_tokens + e.output_tokens for e in v) <= (lim.tpm or 0) * margin
    assert sum(e.cost_usd for e in sent) <= cfg.monthly_cap_usd
    assert all(e.attempt <= 2 for e in store.ledger)
