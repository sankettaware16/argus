"""The LLM gateway v2 (Q-G1) with a fake transport: routing by task, campus-only calls, the
context check, room for thinking, cut-off answers, per-model breakers, the lease, slowness,
alarms, the probe in the gateway, the evaluation budget and the output modes. Properties:
tasks never leave their allowlist; campus-only calls never reach the cloud; an off, slow or
misconfigured local provider defers within an hour."""

from __future__ import annotations

import contextlib
import json
import math
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, time, timedelta
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import SecretStr

from argus.gateway import breaker as breaker_core
from argus.llm import budget
from argus.llm.gateway import (
    AUTH_WAIT,
    LOADING_WAIT,
    PROBE_EVERY,
    Call,
    LlmGateway,
    MemoryLlmStore,
    NoCapacity,
    Refused,
    body_for,
)
from argus.llm.privacy import Privacy, Request
from argus.llm.providers import (
    CONTEXT_OVERHEAD,
    HELPER_TASKS,
    NEVER_SELF_HOSTED,
    TASKS,
    LlmConfig,
    Tier,
)
from argus.llm.wire import LlmReply, LlmWire, TransportError
from tests.unit.llm.test_gateway import Clock, ok

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
KEYS = {"CLOUD_KEY": SecretStr("sk-cloud-123456"), "LOCAL_KEY": SecretStr("local-abcdef12")}
MODELS = json.dumps({"object": "list", "data": [{"id": "cp"}]}).encode()


def cloud(**over: Any) -> dict[str, Any]:
    return {"name": "cloud", "base_url": "https://cloud.example/v1", "keys": ["CLOUD_KEY"],
            "models": {"small": {"name": "c-small"}, "medium": {"name": "c-medium"}},
            **over}  # fmt: skip


def local(**over: Any) -> dict[str, Any]:
    return {"name": "local", "trust": "self_hosted", "base_url": "https://127.0.0.1:28443/v1",
            "keys": ["LOCAL_KEY"], "ca_file": "/nonexistent/local.crt", "timeout_s": 600,
            "concurrency": 1, "tasks": ["evaluate", "ping"], "probe": False,
            "models": {"small": {"name": "cp", "context_tokens": 16384, "thinking_tokens": 2048,
                                 "max_output": 6144}},
            "limits": {"rpm": 100, "rpd": 300}, **over}  # fmt: skip


# a campus provider serving a promoted helper task (Q-G2: never assess on campus)
TRIAGE: dict[str, Any] = {"tasks": ["triage"], "promoted": {"triage": "D-900"},
                          "licence": "D-901"}  # fmt: skip


def config(*providers: dict[str, Any], **over: Any) -> LlmConfig:
    return LlmConfig.model_validate({"providers": list(providers) or [cloud()], **over})


@dataclass
class Fake:
    """Replies per provider in order (the last repeats), for posts and probes; what was sent."""

    replies: dict[str, list[LlmReply | Exception]] = field(default_factory=dict)
    probes: dict[str, list[LlmReply | Exception]] = field(default_factory=dict)
    sent: list[LlmWire] = field(default_factory=list)
    asked: list[LlmWire] = field(default_factory=list)
    clock: Clock | None = None
    takes: timedelta = timedelta(0)  # how long a call takes on the clock

    @staticmethod
    def _next(queue: list[LlmReply | Exception], default: LlmReply) -> LlmReply:
        reply = (queue.pop(0) if len(queue) > 1 else queue[0]) if queue else default
        if isinstance(reply, Exception):
            raise reply
        return reply

    async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        self.sent.append(wire)
        if self.clock is not None:
            self.clock.now += self.takes
        return self._next(self.replies.get(wire.provider, []), ok())

    async def get(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        self.asked.append(wire)
        return self._next(self.probes.get(wire.provider, []), LlmReply(200, MODELS, 3.0))


def make(
    cfg: LlmConfig, fake: Fake | None = None, state: budget.State | None = None
) -> tuple[LlmGateway, Fake, MemoryLlmStore, Clock]:
    fake = fake or Fake()
    store = MemoryLlmStore(state)
    clock = Clock()
    fake.clock = clock
    return LlmGateway(cfg, KEYS, fake, store, clock), fake, store, clock


def small(privacy: Privacy) -> Request:
    return Request("Assess I1.", ("I1",), (), (), (), privacy.ours)


def reply(content: Any, finish: str | None = "stop", reasoning: str | None = None) -> LlmReply:
    message: dict[str, Any] = {"content": content}
    if reasoning is not None:
        message["reasoning_content"] = reasoning
    choice: dict[str, Any] = {"message": message}
    if finish is not None:
        choice["finish_reason"] = finish
    body = {"choices": [choice], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
    return LlmReply(200, json.dumps(body).encode(), 50.0)


# -- routing ---------------------------------------------------------------------------------


async def test_a_task_outside_a_providers_allowlist_never_goes_to_it(privacy: Privacy) -> None:
    gw, fake, _, _ = make(config(local(), cloud()))
    done = await gw.complete(Call(small(privacy), "x", "assess"))
    assert done.provider == "cloud"
    assert [w.provider for w in fake.sent] == ["cloud"]
    done = await gw.complete(Call(small(privacy), "x", "ping"))
    assert done.provider == "local"


async def test_a_campus_only_call_never_reaches_the_cloud(privacy: Privacy) -> None:
    gw, fake, _, _ = make(config(cloud(), local(**TRIAGE)))
    done = await gw.complete(Call(small(privacy), "x", "triage", self_hosted_only=True))
    assert done.provider == "local"
    gw, fake, _, _ = make(config(cloud()))
    with pytest.raises(Refused, match="cloud: not self-hosted"):
        await gw.complete(Call(small(privacy), "x", "triage", self_hosted_only=True))
    assert fake.sent == []


async def test_a_campus_only_call_waits_for_the_campus_machine(privacy: Privacy) -> None:
    fake = Fake({"local": [TransportError("ConnectError", reached=False)]})
    gw, fake, _, _ = make(config(cloud(), local(**TRIAGE)), fake)
    with pytest.raises(NoCapacity) as caught:
        await gw.complete(Call(small(privacy), "x", "triage", self_hosted_only=True))
    assert [w.provider for w in fake.sent] == ["local"]
    assert "cloud: not self-hosted" in str(caught.value)
    assert caught.value.until == NOW + timedelta(seconds=60)


# -- size, thinking and answers -------------------------------------------------------------


def test_the_thinking_room_is_added_and_capped(privacy: Privacy) -> None:
    cfg = config(local())
    body = json.loads(body_for(cfg.providers[0], Call(small(privacy), "x", "ping",
                                                      max_output=1500)))  # fmt: skip
    assert body["max_tokens"] == 1500 + 2048
    body = json.loads(body_for(cfg.providers[0], Call(small(privacy), "x", "ping",
                                                      max_output=5000)))  # fmt: skip
    assert body["max_tokens"] == 6144


async def test_a_call_too_large_for_the_context_is_not_sent(privacy: Privacy) -> None:
    call = Call(small(privacy), "x", "ping", max_output=200)
    size = len(body_for(config(local()).providers[0], call))
    exact = math.ceil(size / 2) + CONTEXT_OVERHEAD + 200 + 2048  # two bytes a token
    for context, fits in ((exact - 1, False), (exact, True)):
        cfg = config(local(models={"small": {"name": "cp", "context_tokens": context,
                                             "thinking_tokens": 2048}}))  # fmt: skip
        gw, fake, store, _ = make(cfg)
        if fits:
            assert (await gw.complete(call)).provider == "local"
            continue
        with pytest.raises(Refused, match="local: too large for its context"):
            await gw.complete(call)
        assert fake.sent == []
        assert store.ledger == []


async def test_llama_servers_context_overflow_is_too_large_and_free(privacy: Privacy) -> None:
    overflow = LlmReply(400, json.dumps({"error": {"code": 400,
                        "type": "exceed_context_size_error"}}).encode(), 9.0)  # fmt: skip
    gw, _, store, _ = make(config(local()), Fake({"local": [overflow]}))
    with pytest.raises(Refused, match=r"local: too_large \(400\)"):
        await gw.complete(Call(small(privacy), "x", "ping"))
    state = await store.state()
    assert state.windows["local"].day_tokens == 0
    assert state.cooldowns == {}
    assert all(not b.is_open(NOW) for b in state.breakers.values())


@pytest.mark.parametrize(
    ("answer", "outcome"),
    [
        (reply('{"a": 1', "length"), "truncated"),
        (reply("", "length", "still thinking ..."), "truncated"),
        (reply(None, "length", "still thinking ..."), "truncated"),
        (reply("<think>reasoning that never ends", "stop"), "truncated"),
        (reply("", "stop", "it thought and said nothing"), "bad_answer"),
        (reply(None, None, "only reasoning"), "bad_answer"),
    ],
)
async def test_a_cut_off_or_empty_answer_is_never_taken(
    privacy: Privacy, answer: LlmReply, outcome: str
) -> None:
    gw, _, store, _ = make(config(local()), Fake({"local": [answer]}))
    with pytest.raises(Refused, match=outcome):
        await gw.complete(Call(small(privacy), "x", "ping"))
    assert store.ledger[-1].outcome == outcome


async def test_the_reasoning_is_never_the_answer(privacy: Privacy) -> None:
    for answer in (reply('{"ok": true}', "stop", "I will say ok"),
                   reply('<think>I will say ok</think>\n{"ok": true}', "stop")):  # fmt: skip
        gw, _, _, _ = make(config(local()), Fake({"local": [answer]}))
        done = await gw.complete(Call(small(privacy), "x", "ping"))
        assert done.text.strip() == '{"ok": true}'


def test_a_schema_goes_only_to_providers_that_take_one(privacy: Privacy) -> None:
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    call = Call(small(privacy), "x", "ping", schema=schema)
    takes = config(local(schema_output=True)).providers[0]
    assert json.loads(body_for(takes, call))["response_format"] == {
        "type": "json_schema", "json_schema": {"name": "answer", "strict": True,
                                               "schema": schema}}  # fmt: skip
    plain = config(local()).providers[0]
    assert json.loads(body_for(plain, call))["response_format"] == {"type": "json_object"}
    no_json = replace(call, json=False)
    assert "response_format" not in json.loads(body_for(takes, no_json))


async def test_the_timeout_is_the_providers_or_less(privacy: Privacy) -> None:
    gw, fake, _, _ = make(config(local(), cloud(timeout_s=120)))
    await gw.complete(Call(small(privacy), "x", "ping"))
    await gw.complete(Call(small(privacy), "x", "ping", timeout_s=30.0))
    await gw.complete(Call(small(privacy), "x", "assess", timeout_s=900.0))
    assert [w.timeout_s for w in fake.sent] == [600, 30.0, 120]


# -- breakers, slowness, alarms -------------------------------------------------------------


async def test_a_model_that_fails_does_not_close_its_sibling(privacy: Privacy) -> None:
    """D-100: gemini-3.5-flash's 503s closed flash-lite too, the breaker being per provider."""
    fake = Fake({"cloud": [LlmReply(503, b"", 1.0)]})
    gw, fake, store, _ = make(config(cloud()), fake)
    with pytest.raises(NoCapacity):
        await gw.complete(Call(small(privacy), "x", "assess", tier=Tier.MEDIUM))
    fake.replies["cloud"] = [ok()]
    done = await gw.complete(Call(small(privacy), "x", "assess", tier=Tier.SMALL))
    assert done.model == "c-small"
    with pytest.raises(NoCapacity, match="cloud/c-medium: breaker open"):
        await gw.complete(Call(small(privacy), "x", "assess", tier=Tier.MEDIUM))
    state = await store.state()
    assert state.breakers["cloud/c-medium"].is_open(NOW)
    assert not state.breakers["cloud"].is_open(NOW)


async def test_no_connection_closes_the_whole_provider(privacy: Privacy) -> None:
    fake = Fake({"cloud": [TransportError("ConnectError", reached=False)]})
    gw, fake, _, _ = make(config(cloud()), fake)
    with pytest.raises(NoCapacity):
        await gw.complete(Call(small(privacy), "x", "assess", tier=Tier.MEDIUM))
    with pytest.raises(NoCapacity, match="cloud: breaker open"):
        await gw.complete(Call(small(privacy), "x", "assess", tier=Tier.SMALL))
    assert len(fake.sent) == 1


async def test_a_slow_model_cools_down_for_half_an_hour(privacy: Privacy) -> None:
    slow = LlmReply(200, ok().body, 130_000.0)  # p50 above 120 s
    gw, fake, store, clock = make(config(local()), Fake({"local": [slow]}))
    for _ in range(3):
        await gw.complete(Call(small(privacy), "x", "ping"))
        clock.now += timedelta(minutes=3)
    state = await store.state()
    until = state.cooldowns["local/cp"]
    assert until == clock.now - timedelta(minutes=3) + budget.SLOW_WAIT
    assert "local/cp" not in state.latency  # judged again on new calls
    with pytest.raises(NoCapacity) as caught:
        await gw.complete(Call(small(privacy), "x", "ping"))
    assert caught.value.until == until
    assert caught.value.until - clock.now < timedelta(hours=1)
    assert len(fake.sent) == 3
    fast = await (make(config(local()), Fake({"local": [LlmReply(200, ok().body, 119_000.0)]})))[
        0
    ].complete(Call(small(privacy), "x", "ping"))
    assert fast.provider == "local"


async def test_a_refused_key_waits_an_hour_and_raises_an_alarm(privacy: Privacy) -> None:
    gw, _, store, _ = make(config(local()), Fake({"local": [LlmReply(401, b"refused", 1.0)]}))
    with pytest.raises(NoCapacity) as caught:
        await gw.complete(Call(small(privacy), "x", "ping"))
    assert caught.value.until == NOW + AUTH_WAIT
    alarm = (await store.state()).alarms["local"]
    assert (alarm.kind, alarm.at) == ("unauthorized", NOW)
    gw.transport.replies["local"] = [ok()]  # type: ignore[attr-defined]
    gw.clock.now = NOW + AUTH_WAIT  # type: ignore[attr-defined]
    await gw.complete(Call(small(privacy), "x", "ping"))
    assert (await store.state()).alarms == {}  # an answer clears it


async def test_a_certificate_failure_waits_an_hour_and_raises_an_alarm(privacy: Privacy) -> None:
    tls = TransportError("tls_failed", reached=False, kind="tls_failed")
    gw, _, store, _ = make(config(local()), Fake({"local": [tls]}))
    with pytest.raises(NoCapacity, match="local: tls_failed") as caught:
        await gw.complete(Call(small(privacy), "x", "ping"))
    assert caught.value.until == NOW + AUTH_WAIT
    state = await store.state()
    assert state.alarms["local"].kind == "tls_failed"
    assert state.windows["local"].day_tokens == 0  # it never reached it: nothing is used


async def test_llama_server_loading_waits_a_minute(privacy: Privacy) -> None:
    loading = LlmReply(
        503,
        json.dumps(
            {"error": {"code": 503, "message": "Loading model", "type": "unavailable_error"}}
        ).encode(),
        2.0,
    )
    gw, _, store, _ = make(config(local(probe=True)), Fake({"local": [loading]}))
    with pytest.raises(NoCapacity, match="loading") as caught:
        await gw.complete(Call(small(privacy), "x", "ping"))
    assert caught.value.until == NOW + LOADING_WAIT
    assert not (await store.state()).breakers["local/cp"].is_open(NOW)
    # a cloud provider's 503 of that type is its model's failure, not a machine loading
    gw, _, store, _ = make(config(cloud()), Fake({"cloud": [loading]}))
    with pytest.raises(NoCapacity, match=r"server_error \(503\)"):
        await gw.complete(Call(small(privacy), "x", "assess"))
    assert (await store.state()).breakers["cloud/c-small"].is_open(NOW)


# -- the probe in the gateway --------------------------------------------------------------


async def test_the_probe_goes_first_and_is_believed_five_minutes(privacy: Privacy) -> None:
    gw, fake, store, clock = make(config(local(probe=True)))
    await gw.complete(Call(small(privacy), "x", "ping"))
    clock.now += PROBE_EVERY - timedelta(seconds=1)
    await gw.complete(Call(small(privacy), "x", "ping"))
    assert len(fake.asked) == 1
    clock.now += PROBE_EVERY - timedelta(seconds=1)  # the last answer counts as up, too
    await gw.complete(Call(small(privacy), "x", "ping"))
    assert len(fake.asked) == 1
    clock.now += PROBE_EVERY * 2
    await gw.complete(Call(small(privacy), "x", "ping"))
    assert len(fake.asked) == 2
    assert fake.asked[0].url == "https://127.0.0.1:28443/v1/models"
    assert fake.asked[0].body == b""
    outcomes = [e.outcome for e in store.ledger]
    assert outcomes == ["probe: up", "ok", "ok", "ok", "probe: up", "ok"]


@pytest.mark.parametrize(
    ("probe", "waits", "alarm"),
    [
        (LlmReply(401, b"refused", 1.0), AUTH_WAIT, "unauthorized"),
        (LlmReply(200, json.dumps({"data": [{"id": "other"}]}).encode(), 1.0), AUTH_WAIT,
         "model_mismatch"),
        (TransportError("tls_failed", reached=False, kind="tls_failed"), AUTH_WAIT, "tls_failed"),
        (LlmReply(503, b"{}", 1.0), LOADING_WAIT, None),
        (TransportError("ConnectError", reached=False), breaker_core.COOLDOWNS[0], None),
        (LlmReply(404, b"", 1.0), breaker_core.COOLDOWNS[0], None),
        (LlmReply(200, b"not json", 1.0), breaker_core.COOLDOWNS[0], None),
    ],
)  # fmt: skip
async def test_a_probe_that_is_not_up_sends_nothing_and_defers(
    privacy: Privacy, probe: LlmReply | Exception, waits: timedelta, alarm: str | None
) -> None:
    gw, fake, store, clock = make(config(local(probe=True)), Fake(probes={"local": [probe]}))
    with pytest.raises(NoCapacity) as caught:
        await gw.complete(Call(small(privacy), "x", "ping"))
    assert fake.sent == []
    assert caught.value.until == NOW + waits
    state = await store.state()
    assert (state.alarms["local"].kind if alarm else None) == alarm
    clock.now += timedelta(seconds=30)  # still waiting: no second probe
    with pytest.raises(NoCapacity):
        await gw.complete(Call(small(privacy), "x", "ping"))
    assert len(fake.asked) == 1


# -- the lease --------------------------------------------------------------------------------


async def test_a_held_lease_defers_and_a_crashed_holders_expires(privacy: Privacy) -> None:
    held = budget.State(leases={"local": {"other-process/1": NOW + timedelta(minutes=11)}})
    gw, fake, store, clock = make(config(local()), state=held)
    with pytest.raises(NoCapacity, match=r"local: busy \(1 of 1 calls\)") as caught:
        await gw.complete(Call(small(privacy), "x", "ping"))
    assert caught.value.until == NOW + budget.LEASE_RETRY
    assert fake.sent == []
    assert (await store.state()).windows == {}  # no budget reserved while it waits
    clock.now = NOW + timedelta(minutes=11)  # the holder never released: it expired
    assert (await gw.complete(Call(small(privacy), "x", "ping"))).provider == "local"
    assert (await store.state()).leases == {}


async def test_the_lease_is_held_during_the_call_and_released_after_any_outcome(
    privacy: Privacy,
) -> None:
    seen: list[dict[str, Any]] = []

    class Watching(Fake):
        async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
            seen.append(dict((await store.state()).leases))
            return await super().send(wire, key)

    for outcome in (ok(), LlmReply(500, b"", 1.0), TransportError("x"), RuntimeError("bug")):
        seen.clear()
        gw, _, store, _ = make(config(local()), Watching({"local": [outcome]}))
        with contextlib.suppress(NoCapacity, RuntimeError):
            await gw.complete(Call(small(privacy), "x", "ping"))
        (during,) = seen
        (until,) = during["local"].values()
        assert until == NOW + timedelta(seconds=600 + 60)
        assert (await store.state()).leases == {}


# -- the evaluation budget -------------------------------------------------------------------


async def test_evaluation_runs_overnight_at_low_priority_within_a_day_cap(
    privacy: Privacy,
) -> None:
    cfg = config(cloud(), evaluation={"window_utc": ["17:30", "00:00"], "calls_per_day": 2})
    gw, fake, store, clock = make(cfg)
    with pytest.raises(NoCapacity, match="overnight") as caught:
        await gw.complete(Call(small(privacy), "x", "evaluate"))
    assert caught.value.until == datetime(2026, 10, 16, 17, 30, tzinfo=UTC)
    assert fake.sent == []
    await gw.complete(Call(small(privacy), "x", "assess"))  # other tasks: any time
    clock.now = datetime(2026, 10, 16, 23, 0, tzinfo=UTC)
    for _ in range(2):
        await gw.complete(Call(small(privacy), "x", "evaluate", priority=budget.Priority.HIGH))
    assert {e.priority for e in store.ledger if e.purpose == "evaluate"} == {"low"}
    with pytest.raises(NoCapacity, match="evaluate:cloud: day limit") as caught:
        await gw.complete(Call(small(privacy), "x", "evaluate"))
    assert caught.value.until == datetime(2026, 10, 17, tzinfo=UTC)
    clock.now = datetime(2026, 10, 17, 0, 10, tzinfo=UTC)  # the window ends at midnight
    with pytest.raises(NoCapacity, match="overnight") as caught:
        await gw.complete(Call(small(privacy), "x", "evaluate"))
    assert caught.value.until == datetime(2026, 10, 17, 17, 30, tzinfo=UTC)  # a separate night
    clock.now = datetime(2026, 10, 17, 17, 30, tzinfo=UTC)
    assert (await gw.complete(Call(small(privacy), "x", "evaluate"))).provider == "cloud"


@pytest.mark.parametrize(
    ("window", "at", "opens"),
    [
        (None, time(12), None),
        (("17:30", "00:00"), time(17, 30), None),
        (("17:30", "00:00"), time(23, 59, 59), None),
        (("17:30", "00:00"), time(0, 0), datetime(2026, 10, 16, 17, 30, tzinfo=UTC)),
        (("17:30", "00:00"), time(17, 29), datetime(2026, 10, 16, 17, 30, tzinfo=UTC)),
        (("01:30", "05:00"), time(5), datetime(2026, 10, 17, 1, 30, tzinfo=UTC)),
        (("01:30", "05:00"), time(1, 29), datetime(2026, 10, 16, 1, 30, tzinfo=UTC)),
        (("01:30", "05:00"), time(1, 30), None),
    ],
)
def test_the_evaluation_window(
    window: tuple[str, str] | None, at: time, opens: datetime | None
) -> None:
    cfg = config(evaluation={"window_utc": window})
    now = datetime.combine(NOW.date(), at, UTC)
    assert cfg.evaluation.opens(now) == opens


# -- properties ------------------------------------------------------------------------------

task_lists = st.one_of(st.none(), st.lists(st.sampled_from(sorted(TASKS)), min_size=1,
                                           max_size=4, unique=True))  # fmt: skip
failures = st.sampled_from([
    ok(), LlmReply(500, b"", 1.0), LlmReply(429, b"{}", 1.0, "30"), LlmReply(401, b"", 1.0),
    LlmReply(400, b"", 1.0), TransportError("x"), TransportError("y", reached=False),
    TransportError("t", reached=False, kind="tls_failed"), LlmReply(200, b"{}", 1.0),
])  # fmt: skip


@settings(deadline=None)
@given(
    st.lists(st.tuples(task_lists, st.booleans(), failures), min_size=1, max_size=4),
    st.lists(st.tuples(st.sampled_from([*sorted(TASKS), "other"]), st.booleans()), min_size=1,
             max_size=6),
)  # fmt: skip
async def test_tasks_stay_in_their_allowlists_and_campus_calls_on_campus(
    privacy: Privacy,
    providers: list[tuple[list[str] | None, bool, LlmReply | Exception]],
    calls: list[tuple[str, bool]],
) -> None:
    specs = []
    for i, (tasks, ours, _) in enumerate(providers):
        if ours:  # Q-G2: never verdicts or tuning; a helper task only once promoted
            allowed = [t for t in tasks or () if t not in NEVER_SELF_HOSTED] or ["ping"]
            earned = {t: "D-900" for t in allowed if t in HELPER_TASKS}
            spec = local(name=f"p{i}", tasks=allowed, promoted=earned,
                         licence="D-901" if earned else None)  # fmt: skip
        else:
            spec = cloud(name=f"p{i}", tasks=tasks)
        specs.append(spec)
    cfg = config(*specs)
    fake = Fake({f"p{i}": [reply_] for i, (_, _, reply_) in enumerate(providers)})
    gw, fake, _, clock = make(cfg, fake)
    by_name = {p.name: p for p in cfg.providers}
    for purpose, self_hosted_only in calls:
        before = len(fake.sent)
        with contextlib.suppress(NoCapacity, Refused):
            await gw.complete(Call(small(privacy), "x", purpose, self_hosted_only=self_hosted_only))
        for wire in fake.sent[before:]:
            provider = by_name[wire.provider]
            assert provider.serves(purpose)
            assert not self_hosted_only or provider.trust == "self_hosted"
        clock.now += timedelta(seconds=7)


off_or_wrong = st.sampled_from([
    TransportError("ConnectError", reached=False), TransportError("ReadTimeout"),
    TransportError("t", reached=False, kind="tls_failed"), LlmReply(401, b"refused", 1.0),
    LlmReply(503, json.dumps({"error": {"type": "unavailable_error"}}).encode(), 1.0),
    LlmReply(502, b"", 1.0), LlmReply(200, ok().body, 400_000.0),
])  # fmt: skip
probes = st.sampled_from([
    LlmReply(200, MODELS, 1.0), LlmReply(401, b"", 1.0), LlmReply(503, b"", 1.0),
    LlmReply(200, b'{"data": [{"id": "x"}]}', 1.0), TransportError("c", reached=False),
    TransportError("t", reached=False, kind="tls_failed"),
])  # fmt: skip


@settings(deadline=None)
@given(st.lists(off_or_wrong, min_size=1, max_size=12), st.lists(probes, min_size=1, max_size=6),
       st.booleans(), st.lists(st.integers(1, 3600), min_size=12, max_size=12))  # fmt: skip
async def test_an_off_slow_or_misconfigured_local_model_defers_within_an_hour(
    privacy: Privacy,
    replies: list[LlmReply | Exception],
    probe_replies: list[LlmReply | Exception],
    probing: bool,
    gaps: list[int],
) -> None:
    """Plan exit criterion 13: nothing fails or waits beyond the one-hour deferral."""
    fake = Fake({"local": list(replies)}, {"local": list(probe_replies)}, takes=timedelta(0))
    gw, fake, _, clock = make(config(local(probe=probing)), fake)
    for gap in gaps:
        outcome: Exception | None = None
        try:
            await gw.complete(Call(small(privacy), "x", "ping"))
        except (NoCapacity, Refused) as exc:
            outcome = exc
        if isinstance(outcome, NoCapacity):
            assert outcome.until - clock.now <= timedelta(hours=1)
        elif isinstance(outcome, Refused):  # only an answer that can never succeed
            assert "truncated" in str(outcome) or "bad_answer" in str(outcome)
        clock.now += timedelta(seconds=gap)
