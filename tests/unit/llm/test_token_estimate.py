"""A provider's prompt-token estimate (P4-E2): ``bytes_per_token`` counts a prompt in the
rate-limit windows only, while the cost reserved and the counts believed stay one byte a token;
each paid provider's own caps through the gateway; and the ledger carrying what an attempt leaves
charged, so a reconcile keeps it."""

from __future__ import annotations

import contextlib
import json
import math
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import SecretStr, ValidationError

from argus.agent.agent import MAX_OUTPUT
from argus.llm import budget
from argus.llm.gateway import (
    MESSAGE_OVERHEAD,
    Call,
    CallEntry,
    LlmGateway,
    MemoryLlmStore,
    NoCapacity,
    Refused,
    body_for,
    estimate,
)
from argus.llm.privacy import Privacy, Request
from argus.llm.providers import DEFAULT_PATH, LlmConfig, Tier, load_config
from argus.llm.wire import LlmReply, TransportError
from tests.unit.llm.test_gateway import Clock, Fake, ok

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
KEYS = {k: SecretStr(f"test-{k.lower()}-0000") for k in ("FREE_KEY", "OPENAI_KEY", "ANTHRO_KEY")}
BAD = LlmReply(200, b"{}", 1.0)  # an answer that is none: the provider did the work


def free(**over: Any) -> dict[str, Any]:
    return {"name": "groq", "base_url": "https://free.example/v1", "keys": ["FREE_KEY"],
            "models": {"small": {"name": "f-small", "limits": {"tpm": 8000, "tpd": 200_000}},
                       "medium": {"name": "f-medium", "limits": {"tpm": 8000}}},
            **over}  # fmt: skip


def paid(name: str = "openai", key: str = "OPENAI_KEY", **over: Any) -> dict[str, Any]:
    return {"name": name, "base_url": f"https://{name}.example/v1", "keys": [key],
            "models": {"small": {"name": f"{name}-small", "input_per_m": 1.0,
                                 "output_per_m": 4.0},
                       "medium": {"name": f"{name}-medium", "input_per_m": 2.0,
                                  "output_per_m": 8.0}},
            "limits": {"tpd": 10**7}, **over}  # fmt: skip


def llm(*providers: dict[str, Any], **over: Any) -> LlmConfig:
    return LlmConfig.model_validate({"monthly_cap_usd": 80.0, "providers": list(providers),
                                     **over})  # fmt: skip


def gateway(cfg: LlmConfig, fake: Fake) -> tuple[LlmGateway, MemoryLlmStore, Clock]:
    store, clock = MemoryLlmStore(), Clock()
    return LlmGateway(cfg, KEYS, fake, store, clock), store, clock


def call(privacy: Privacy, size: int, tier: Tier = Tier.SMALL) -> Call:
    """An assess call whose instructions make its body about ``size`` bytes."""
    request = Request("Assess I1.", ("I1",), (), (), (), privacy.ours)
    words = "Weigh the evidence. " * (size // 20)
    return Call(request, words, "assess", tier, max_output=MAX_OUTPUT[tier])


# -- the estimate ----------------------------------------------------------------------------


def test_the_estimate_counts_the_prompt_at_the_providers_bytes_a_token() -> None:
    one, two, odd = (llm(free(bytes_per_token=b)).providers[0] for b in (1, 2, 2.5))
    assert estimate(one, 5000, 1500) == 5000 + MESSAGE_OVERHEAD + 1500
    assert estimate(two, 5000, 1500) == 2500 + MESSAGE_OVERHEAD + 1500
    assert estimate(two, 5001, 1500) == 2501 + MESSAGE_OVERHEAD + 1500  # rounded up
    assert estimate(odd, 7001, 0) == 2801 + MESSAGE_OVERHEAD
    assert estimate(two, 0, 0) == MESSAGE_OVERHEAD


@pytest.mark.parametrize("value", [0.5, 0.99, 4.01, 10])
def test_bytes_per_token_is_between_one_and_four(value: float) -> None:
    with pytest.raises(ValidationError, match="bytes_per_token"):
        llm(free(bytes_per_token=value))


def test_bytes_per_token_defaults_to_one_byte_a_token() -> None:
    assert llm(free()).providers[0].bytes_per_token == 1.0
    assert llm(free(bytes_per_token=4)).providers[0].bytes_per_token == 4.0


@given(st.floats(1.0, 4.0), st.floats(1.0, 4.0), st.integers(0, 200_000), st.integers(0, 40_000))
def test_the_estimate_lies_between_four_bytes_and_one_byte_a_token(
    a: float, b: float, body_bytes: int, cap: int
) -> None:
    low, high = sorted((a, b))
    dense, sparse = (llm(free(bytes_per_token=x)).providers[0] for x in (low, high))
    upper = body_bytes + MESSAGE_OVERHEAD + cap
    assert estimate(sparse, body_bytes, cap) <= estimate(dense, body_bytes, cap) <= upper
    assert estimate(sparse, body_bytes, cap) >= math.ceil(body_bytes / 4) + MESSAGE_OVERHEAD + cap


# -- in the gateway --------------------------------------------------------------------------


@settings(deadline=None)
@given(st.floats(1.0, 4.0), st.integers(0, 6000), st.sampled_from([Tier.SMALL, Tier.MEDIUM]))
async def test_bytes_per_token_never_lowers_the_cost_reserved(
    privacy: Privacy, bytes_per_token: float, size: int, tier: Tier
) -> None:
    held = {}
    for bpt in (1.0, bytes_per_token):
        cfg = llm(paid(bytes_per_token=bpt))
        gw, store, _ = gateway(cfg, Fake({"openai": [BAD]}))
        c = call(privacy, size, tier)
        with pytest.raises(Refused, match="bad_answer"):
            await gw.complete(c)
        provider = cfg.providers[0]
        model = provider.models[tier]
        body = len(body_for(provider, c))
        cap = model.output_cap(c.max_output)
        state = await store.state()
        assert state.spent_usd == model.cost(body + MESSAGE_OVERHEAD, cap)  # a byte a token
        assert state.provider_spent_usd == {"openai": state.spent_usd}
        assert state.windows["openai"].day_tokens == estimate(provider, body, cap)
        held[bpt] = state.spent_usd
    assert held[bytes_per_token] == held[1.0]


@pytest.mark.parametrize("kind", ["above the estimate", "the bound", "above the bound", "none"])
async def test_a_providers_count_is_believed_up_to_one_byte_a_token(
    privacy: Privacy, kind: str
) -> None:
    """At four bytes a token the window holds less than the byte bound; a provider's count
    above that estimate is believed, one above the byte bound is not (settled counts stay
    honest, and so does the cost)."""
    cfg = llm(paid(bytes_per_token=4))
    provider = cfg.providers[0]
    c = call(privacy, 4000)
    size = len(body_for(provider, c)) + MESSAGE_OVERHEAD
    assert estimate(provider, size - MESSAGE_OVERHEAD, 0) < 1500 <= size
    reported = {"above the estimate": 1500, "the bound": size, "above the bound": size + 999,
                "none": None}[kind]  # fmt: skip
    believed = 1500 if kind == "above the estimate" else size
    usage: dict[str, Any] = {"completion_tokens": 7}
    if reported is not None:
        usage["prompt_tokens"] = reported
    gw, store, _ = gateway(cfg, Fake({"openai": [ok(usage=usage)]}))
    done = await gw.complete(c)
    assert (done.input_tokens, done.output_tokens) == (believed, 7)
    assert done.cost_usd == provider.models[Tier.SMALL].cost(believed, 7)
    state = await store.state()
    assert state.windows["openai"].day_tokens == believed + 7
    assert state.spent_usd == pytest.approx(done.cost_usd)


@pytest.mark.parametrize("tier", [Tier.SMALL, Tier.MEDIUM])
async def test_a_prompt_of_seven_thousand_bytes_fits_groqs_minute_at_two_bytes_a_token(
    privacy: Privacy, tier: Tier
) -> None:
    """Production's ledger: at one byte a token nothing above about 4,900 bytes ever went to
    groq (tpm 8000 at margin 0.8: 6,400 a minute), and paid OpenAI took the work."""
    c = call(privacy, 7000, tier)
    for bpt, first in ((1, "openai"), (2, "groq")):
        gw, _, _ = gateway(llm(free(bytes_per_token=bpt), paid()), Fake())
        assert 7000 <= len(body_for(gw.config.providers[0], c)) <= 7400
        assert (await gw.complete(c)).provider == first


async def test_the_settled_count_replaces_the_estimate_in_the_minute(privacy: Privacy) -> None:
    cfg = llm(free(bytes_per_token=2), paid())
    groq = cfg.providers[0]
    c = call(privacy, 4500)
    reserved = estimate(groq, len(body_for(groq, c)), MAX_OUTPUT[Tier.SMALL])
    assert reserved <= 6400 < 2 * reserved  # two estimates never share a minute
    usage = {"prompt_tokens": 1300, "completion_tokens": 700}  # the ledger's usual call
    gw, store, _ = gateway(cfg, Fake({"groq": [ok(usage=usage)]}))
    assert (await gw.complete(c)).provider == "groq"
    assert (await store.state()).windows["groq/f-small"].minute_tokens == 2000
    assert (await gw.complete(c)).provider == "groq"  # 2,000 settled and one estimate fit
    assert (await gw.complete(c)).provider == "openai"  # not a third


# -- each paid provider's own caps -----------------------------------------------------------


async def test_a_provider_at_its_own_cap_hands_the_call_to_the_next_paid_one(
    privacy: Privacy,
) -> None:
    c = call(privacy, 2000)
    model = llm(paid()).providers[0].models[Tier.SMALL]
    reserve = model.cost(len(body_for(llm(paid()).providers[0], c)) + MESSAGE_OVERHEAD,
                         MAX_OUTPUT[Tier.SMALL])  # fmt: skip
    used = model.cost(400, 50)  # what ok() settles
    # NORMAL may use 0.8 of a cap: one reservation, not one more after the first settled
    own = (reserve + used / 2) / 0.8
    cfg = llm(paid(monthly_cap_usd=own), paid("anthropic", "ANTHRO_KEY", monthly_cap_usd=own))
    gw, store, _ = gateway(cfg, Fake())
    assert (await gw.complete(c)).provider == "openai"
    assert (await gw.complete(c)).provider == "anthropic"
    with pytest.raises(NoCapacity) as caught:
        await gw.complete(c)
    assert caught.value.until == datetime(2026, 11, 1, tzinfo=UTC)
    assert str(caught.value) == ("openai: openai: monthly cost cap;"
                                 " anthropic: anthropic: monthly cost cap")  # fmt: skip
    state = await store.state()
    assert state.provider_spent_usd == pytest.approx({"openai": used, "anthropic": used})
    assert state.spent_usd == pytest.approx(2 * used)
    high = Call(c.request, c.instructions, "assess", max_output=c.max_output,
                priority=budget.Priority.HIGH)  # fmt: skip
    # HIGH may use the whole cap: room for one more
    assert (await gw.complete(high)).provider == "openai"


async def test_a_call_dearer_than_a_providers_own_cap_goes_on_to_the_next(
    privacy: Privacy,
) -> None:
    cfg = llm(paid(monthly_cap_usd=0.0001), paid("anthropic", "ANTHRO_KEY"))
    gw, _, _ = gateway(cfg, Fake())
    done = await gw.complete(call(privacy, 2000))
    assert done.provider == "anthropic"
    cfg = llm(paid(monthly_cap_usd=0.0001))
    gw, _, _ = gateway(cfg, Fake())
    with pytest.raises(Refused, match="openai: openai: costs more than the monthly cap"):
        await gw.complete(call(privacy, 2000))


# -- what a reconcile keeps ------------------------------------------------------------------


def cut_off() -> LlmReply:
    """A 200 answer cut off at its cap (finish_reason "length"): billed, never usable."""
    body = {"choices": [{"message": {"content": '{"verdict": "tr'}, "finish_reason": "length"}],
            "usage": {"prompt_tokens": 400, "completion_tokens": 1500}}  # fmt: skip
    return LlmReply(200, json.dumps(body).encode(), 9.0)


# Each attempt's outcome and what it leaves charged: the whole reservation ("kept"), nothing, or
# the answer's own cost. Factories: an exception is raised fresh each time.
ATTEMPTS: list[tuple[str, Callable[[], LlmReply | Exception], str]] = [
    ("truncated", cut_off, "kept"),
    ("bad_answer", lambda: BAD, "kept"),
    ("timed_out", lambda: TransportError("ReadTimeout"), "kept"),  # it reached the provider
    ("deadline", TimeoutError, "kept"),
    ("never_reached", lambda: TransportError("ConnectError", reached=False), "none"),
    ("tls_failed", lambda: TransportError("t", reached=False, kind="tls_failed"), "none"),
    ("server_error", lambda: LlmReply(502, b"", 1.0), "none"),
    ("rate_limited", lambda: LlmReply(429, b"{}", 1.0), "none"),
    ("ok", ok, "settled"),
]


def reconciled(ledger: list[CallEntry]) -> dict[str, float]:
    """What a reconcile sets each provider's month to (``PgLlmStore.reconcile``): the sum of
    its ledger rows' costs."""
    out: dict[str, float] = {}
    for entry in ledger:
        out[entry.provider] = out.get(entry.provider, 0.0) + entry.cost_usd
    return out


@pytest.mark.parametrize(("reply", "left"), [a[1:] for a in ATTEMPTS], ids=[a[0] for a in ATTEMPTS])
async def test_the_ledger_carries_what_an_attempt_leaves_charged(
    privacy: Privacy, reply: Callable[[], LlmReply | Exception], left: str
) -> None:
    """The review of P4-E2: an attempt cut off, malformed, or with no answer once it reached the
    provider keeps its reservation in the budget; its ledger row carries it, so a reconcile (the
    ledger's sums) keeps it in the provider's own spend and in the overall one."""
    c = call(privacy, 2000)
    cfg = llm(paid(monthly_cap_usd=40.0, daily_cap_usd=1.5), free())
    gw, store, clock = gateway(cfg, Fake({"openai": [reply()]}))
    done = await gw.complete(c)
    assert done.provider == ("openai" if left == "settled" else "groq")
    openai = cfg.providers[0]
    model = openai.models[Tier.SMALL]
    reserved = model.cost(len(body_for(openai, c)) + MESSAGE_OVERHEAD,
                          model.output_cap(c.max_output))  # fmt: skip
    first = store.ledger[0]
    assert first.provider == "openai"
    want = {"kept": reserved, "none": 0.0, "settled": done.cost_usd}[left]
    assert first.cost_usd == want
    state, ledger = await store.state(), reconciled(store.ledger)
    for provider in ("openai", "groq"):
        own = ledger.get(provider, 0.0)
        assert budget.spend(state, clock.now, provider) == pytest.approx((own, own))
    assert budget.spend(state, clock.now) == pytest.approx((want, want))


@settings(deadline=None)
@given(st.lists(st.tuples(st.sampled_from(ATTEMPTS), st.sampled_from(ATTEMPTS),
                          st.integers(1, 400)), min_size=1, max_size=20))  # fmt: skip
async def test_after_any_attempts_a_reconcile_changes_no_spend(
    privacy: Privacy, plan: list[tuple[Any, Any, int]]
) -> None:
    """Whatever two capped paid providers answer, each one's own spend and the overall spend
    are what the ledger's rows sum to: a reconcile has nothing to drop but what a crash left."""
    c = call(privacy, 2000)
    cfg = llm(paid(monthly_cap_usd=0.2, daily_cap_usd=0.05),
              paid("anthropic", "ANTHRO_KEY", monthly_cap_usd=0.3, daily_cap_usd=0.03),
              free())  # fmt: skip
    fake = Fake({"openai": [a[1]() for a, _, _ in plan], "anthropic": [b[1]() for _, b, _ in plan]})
    gw, store, clock = gateway(cfg, fake)
    for _, _, step in plan:  # at most 8,000 s: the same UTC day
        with contextlib.suppress(NoCapacity, Refused):
            await gw.complete(c)
        clock.now += timedelta(seconds=step)
    state, ledger = await store.state(), reconciled(store.ledger)
    for provider in ("openai", "anthropic", "groq"):
        own = ledger.get(provider, 0.0)
        assert budget.spend(state, clock.now, provider) == pytest.approx((own, own), abs=1e-9)
    total = sum(ledger.values())
    assert budget.spend(state, clock.now) == pytest.approx((total, total), abs=1e-9)


# -- the shipped configuration ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("tier", "at_one", "at_two"), [(Tier.SMALL, 4868, 9736), (Tier.MEDIUM, 4368, 8736)]
)
def test_the_shipped_groq_counts_two_bytes_a_token(tier: Tier, at_one: int, at_two: int) -> None:
    """The largest body an assess call may have at groq and still fit a minute with its
    answer's cap (config/llm.yaml's comment): tpm 8000 at margin 0.8."""
    shipped = load_config(DEFAULT_PATH)
    groq = next(p for p in shipped.providers if p.name == "groq")
    assert groq.bytes_per_token == 2
    assert {p.bytes_per_token for p in shipped.providers if p.name != "groq"} == {1.0}
    model = groq.models[tier]
    assert model.limits is not None
    assert model.limits.tpm is not None
    minute = math.floor(model.limits.tpm * shipped.margin)
    cap = model.output_cap(MAX_OUTPUT[tier])
    assert (minute, cap) == (6400, {Tier.SMALL: 1500, Tier.MEDIUM: 2000}[tier])
    one = groq.model_copy(update={"bytes_per_token": 1.0})
    for provider, largest in ((one, at_one), (groq, at_two)):
        assert estimate(provider, largest, cap) <= minute < estimate(provider, largest + 1, cap)
    for body in (4500, 7000):  # the usual assess prompts
        assert estimate(groq, body, cap) <= minute
