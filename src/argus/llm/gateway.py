"""The LLM gateway: the only way ARGUS calls a model. A ``Call`` carries a privacy ``Request``; it
is refused unless the egress validator passes it and each provider's exact body. Providers are
tried in the configured order, each only when the kill switch, task allowlist, tier, probe, budget,
cool-downs, breakers and lease allow; a failure cools a model or provider down and goes on to the
next. Every attempt is recorded in the ledger (never its content). When no provider can take the
call it raises ``NoCapacity`` (try again at a time), when none ever could, ``Refused``."""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Protocol, TypeVar

from pydantic import SecretStr

from argus.gateway import breaker as breaker_core
from argus.llm import budget
from argus.llm.privacy import Request
from argus.llm.probe import ALARMS, ProbeState, probe, tls_detail
from argus.llm.providers import EVALUATE, PING, LlmConfig, ProviderConfig, Tier, Trust
from argus.llm.wire import LlmReply, LlmTransport, LlmWire, TransportError

T = TypeVar("T")
MESSAGE_OVERHEAD = 32  # tokens a provider adds around the messages, an upper bound
DEFAULT_WAIT = timedelta(seconds=60)
QUOTA_WAIT = timedelta(hours=6)  # a paid account out of credit
AUTH_WAIT = timedelta(hours=1)  # a refused key, a certificate or a model not as pinned
PROBE_EVERY = timedelta(minutes=5)  # an "up" probe is believed this long
LOADING_WAIT = timedelta(seconds=60)
# A reply from the model that is no usable answer (an evaluation counts each). Not: a
# quota (429), a key refused, the model loading, or a connection that never reached it.
UNUSABLE = frozenset({"truncated", "bad_answer", "too_large", "server_error", "rejected"})


class LlmError(Exception):
    def __init__(self, why: str = "", failed: int = 0) -> None:
        super().__init__(why)
        # calls of this one that reached a model and came back with no usable answer (timed
        # out, a server error, cut off, malformed, refused by the model): an evaluation counts
        # each as an unusable call
        self.failed = failed


class Refused(LlmError):  # noqa: N818 - an outcome, not a crash
    """This call cannot be sent, now or later (blocked by the validator, too large, stopped
    for good, or refused by every provider)."""


class NoCapacity(LlmError):  # noqa: N818
    """No provider can take this call now; try again at ``until``."""

    def __init__(self, until: datetime, why: str, failed: int = 0) -> None:
        super().__init__(why, failed)
        self.until = until


@dataclass(frozen=True)
class Call:
    request: Request
    instructions: str  # the system prompt: ARGUS's own text, checked like the rest
    purpose: str  # the task: "assess", "evaluate", "ping", "tune" (providers' allowlists)
    tier: Tier = Tier.SMALL
    priority: budget.Priority = budget.Priority.NORMAL
    max_output: int = 1000  # the answer's tokens; a thinking model's room is added
    json: bool = True
    timeout_s: float | None = None  # None: the provider's; else at most the provider's
    campus_only: bool = False  # never to a cloud provider
    schema: Mapping[str, Any] | None = None  # a JSON schema, for providers that take one
    avoid: frozenset[str] = frozenset()  # providers to skip: the ones whose answer was unusable


@dataclass(frozen=True)
class Completion:
    text: str  # still pseudonymized: the caller validates and reveals
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    latency_ms: int
    call_id: uuid.UUID


@dataclass(frozen=True)
class CallEntry:
    at: datetime
    call_id: uuid.UUID
    attempt: int
    provider: str
    model: str
    tier: str
    purpose: str
    priority: str
    outcome: str
    http_status: int | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0
    request_bytes: int = 0
    request_sha256: str = ""


class LlmStore(Protocol):
    async def change(self, fn: Callable[[budget.State], tuple[T, budget.State]]) -> T: ...
    async def state(self) -> budget.State: ...
    async def record(self, entry: CallEntry) -> None: ...


class MemoryLlmStore:
    """The store inside one process (tests, tools)."""

    def __init__(self, state: budget.State | None = None) -> None:
        self._state = state or budget.State()
        self._lock = asyncio.Lock()
        self.ledger: list[CallEntry] = []

    async def change(self, fn: Callable[[budget.State], tuple[T, budget.State]]) -> T:
        async with self._lock:
            result, self._state = fn(self._state)
            return result

    async def state(self) -> budget.State:
        return self._state

    async def record(self, entry: CallEntry) -> None:
        self.ledger.append(entry)


def retry_after(value: str | None, now: datetime) -> datetime | None:
    """``Retry-After`` as a time: seconds or an HTTP date; None if absent or unreadable."""
    if not value:
        return None
    try:
        return now + timedelta(seconds=max(0.0, float(value)))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(when, now)


def body_for(provider: ProviderConfig, call: Call) -> bytes:
    model = provider.models[call.tier]
    body: dict[str, Any] = {
        "model": model.name,
        "messages": [
            {"role": "system", "content": call.instructions},
            {"role": "user", "content": call.request.text},
        ],
        provider.max_tokens_field: model.output_cap(call.max_output),
        **model.extra,
    }
    if call.json and call.schema is not None and provider.schema_output:
        body["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "answer", "strict": True, "schema": dict(call.schema)},
        }
    elif call.json and provider.json_mode:
        body["response_format"] = {"type": "json_object"}
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def timeout_for(provider: ProviderConfig, call: Call, body_bytes: int) -> float | None:
    """A call's deadline: from its size where the model's speed is measured, else the
    provider's; at most the call's own. None: it would need longer than the provider allows,
    so it is never sent."""
    model = provider.models[call.tier]
    timeout = provider.timeout_s
    deadline = model.deadline_s(body_bytes, model.output_cap(call.max_output))
    if deadline is not None:
        if deadline > provider.timeout_s:
            return None
        timeout = deadline
    return timeout if call.timeout_s is None else min(call.timeout_s, timeout)


def lease_s(provider: ProviderConfig, call: Call) -> float | None:
    """How long ``call``'s slot is held at ``provider`` (its deadline and a minute), or None
    if it would not be sent there (a latency is judged against it)."""
    if call.tier not in provider.models:
        return None
    timeout = timeout_for(provider, call, len(body_for(provider, call)))
    return None if timeout is None else provider.lease_for(timeout).total_seconds()


THINK_OPEN, THINK_CLOSE = "<think>", "</think>"


def _without_thinking(text: str) -> str | None:
    """The answer after a leading ``<think>`` block (a server that did not keep the reasoning
    apart); None if the block never closes (the cap ran out while it was still thinking)."""
    stripped = text.lstrip()
    if not stripped.startswith(THINK_OPEN):
        return text
    end = stripped.find(THINK_CLOSE)
    return None if end < 0 else stripped[end + len(THINK_CLOSE) :]


@dataclass(frozen=True)
class _Parsed:
    text: str | None  # None: no usable answer
    input_tokens: int | None
    output_tokens: int | None
    truncated: bool  # the answer's cap ran out (finish_reason "length")


def _answer(reply: LlmReply) -> _Parsed | None:
    """The answer of an OpenAI-compatible reply, or None if it is not one. The reasoning
    (``reasoning_content``) is never the answer."""
    try:
        data = json.loads(reply.body)
        choice = data["choices"][0]
        text = choice["message"]["content"]
        finish = choice.get("finish_reason")
        usage = data.get("usage") or {}
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return None
    if not isinstance(usage, dict):
        return None
    tin, tout = usage.get("prompt_tokens"), usage.get("completion_tokens")
    ok = [t if isinstance(t, int) and not isinstance(t, bool) and t >= 0 else None
          for t in (tin, tout)]  # fmt: skip
    answer = _without_thinking(text) if isinstance(text, str) else None
    truncated = finish == "length" or (isinstance(text, str) and answer is None)
    if truncated or answer is None or not answer.strip():
        return _Parsed(None, ok[0], ok[1], truncated)
    return _Parsed(answer, ok[0], ok[1], False)


def _error_type(reply: LlmReply) -> str:
    """The ``error.type`` of an error body (llama-server, OpenAI), or ""."""
    try:
        error = json.loads(reply.body).get("error") or {}
    except (ValueError, AttributeError):
        return ""
    return str(error.get("type") or "") if isinstance(error, dict) else ""


def _quota(reply: LlmReply) -> bool:
    try:
        error = json.loads(reply.body).get("error") or {}
    except (ValueError, AttributeError):
        return False
    # OpenAI's out-of-credit codes: the older and the current name
    return isinstance(error, dict) and bool(
        {"insufficient_quota", "credit_balance_exhausted"}
        & {str(error.get("code")), str(error.get("type"))}
    )


class LlmGateway:
    def __init__(
        self,
        config: LlmConfig,
        keys: Mapping[str, SecretStr],
        transport: LlmTransport,
        store: LlmStore,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.config = config
        self.keys = dict(keys)
        self.transport = transport
        self.store = store
        self.clock = clock
        self.budget = config.budget_config()

    def _key(self, provider: ProviderConfig) -> SecretStr | None:
        return next((self.keys[k] for k in provider.keys if k in self.keys), None)

    async def aclose(self) -> None:
        close = getattr(self.transport, "aclose", None)
        if close is not None:
            await close()

    async def complete(self, call: Call) -> Completion:
        call_id = uuid.uuid4()
        verdict = call.request.validate()
        if not verdict.allowed:
            await self._note(call, call_id, "-", "-", 0, "blocked")
            raise Refused(f"the request did not pass the validator: {verdict.audit()}")
        if (await self.store.state()).stopped:
            raise NoCapacity(self.clock() + DEFAULT_WAIT, "stopped (argus llm resume)")
        if call.purpose == EVALUATE:  # the evaluation budget: low priority, overnight
            call = replace(call, priority=budget.Priority.LOW)
            opens = self.config.evaluation.opens(self.clock())
            if opens is not None:
                raise NoCapacity(opens, f"evaluation runs overnight only (from {opens:%H:%M} UTC)")
        waits: list[datetime] = []
        why: list[str] = []
        attempt = failed = 0
        for provider in self.config.providers:
            key = self._key(provider)
            if not provider.enabled or call.tier not in provider.models or key is None:
                continue
            if provider.name in call.avoid:
                why.append(f"{provider.name}: skipped, its answer was unusable")
                continue
            if not provider.serves(call.purpose):
                why.append(f"{provider.name}: not for {call.purpose}")
                continue
            if call.campus_only and provider.trust is not Trust.CAMPUS:
                why.append(f"{provider.name}: not on campus")
                continue
            if provider.trust is Trust.CAMPUS and provider.licence is None and call.purpose != PING:
                # the licence must be confirmed before any call with real data; the
                # connection test sends none
                why.append(f"{provider.name}: its licence is not confirmed (licence: D-NNN)")
                continue
            if provider.schema_required and (call.schema is None or not call.json):
                why.append(f"{provider.name}: needs a JSON schema")  # no plain JSON mode
                continue
            result = await self._attempt(call, call_id, provider, key, attempt + 1)
            if isinstance(result, Completion):
                return result
            sent, reason, wait, unusable = result
            attempt += sent
            failed += unusable
            why.append(f"{provider.name}: {reason}")
            if wait is not None:
                waits.append(wait)
        if waits:
            raise NoCapacity(min(waits), "; ".join(why), failed)
        raise Refused("; ".join(why) or "no provider is configured for this tier with a key",
                      failed)  # fmt: skip

    def _buckets(self, provider: ProviderConfig, call: Call) -> tuple[budget.Bucket, ...]:
        buckets = provider.buckets(call.tier)
        per_day = self.config.evaluation.calls_per_day
        if call.purpose == EVALUATE and per_day is not None:
            own = budget.Bucket(f"evaluate:{provider.name}", budget.Limits(rpd=per_day), True)
            buckets = (*buckets, own)
        return buckets

    async def _probe(
        self, call: Call, call_id: uuid.UUID, provider: ProviderConfig, key: SecretStr
    ) -> tuple[str, datetime] | None:
        """None if the provider is up (probed recently, or now); else why and when to retry."""
        now = self.clock()
        state = await self.store.state()
        last = state.probed.get(provider.name)
        if last is not None and now - last < PROBE_EVERY:
            return None
        cooling = state.cooldowns.get(provider.name)
        breaker = state.breakers.get(provider.name, breaker_core.BreakerState())
        if (cooling is not None and now < cooling) or not breaker_core.peek(breaker, now):
            return None  # admission refuses it, without a probe
        result = await probe(provider, key, self.transport)
        done = self.clock()
        name = provider.name
        await self._note(call, call_id, name, "-", 0, f"probe: {result.state}",
                         latency_ms=result.latency_ms)  # fmt: skip
        if result.state is ProbeState.UP:
            await self._update(lambda s: budget.clear_alarm(budget.probed_up(s, name, done), name))
            return None
        if result.state in ALARMS:
            until = done + AUTH_WAIT
            await self._update(lambda s: budget.raise_alarm(
                budget.cool_down(s, name, until, done), name, result.state.value, result.detail,
                done,
            ))  # fmt: skip
        elif result.state is ProbeState.LOADING:
            until = done + LOADING_WAIT
            await self._update(lambda s: budget.cool_down(s, name, until, done))
        else:  # down: the provider's breaker (5, 15, then 60 minutes)
            await self._update(lambda s: budget.overload(s, name, done))
            state = await self.store.state()
            until = state.breakers[name].open_until or done + DEFAULT_WAIT
        return f"{result.state}: {result.detail}", until

    async def _attempt(
        self,
        call: Call,
        call_id: uuid.UUID,
        provider: ProviderConfig,
        key: SecretStr,
        attempt: int,
    ) -> Completion | tuple[int, str, datetime | None, int]:
        """One provider: the completion, or (calls sent, why not, when to try again, calls
        that reached the model and gave no usable answer)."""
        model = provider.models[call.tier]
        body = body_for(provider, call)
        cap = model.output_cap(call.max_output)
        sha = hashlib.sha256(body).hexdigest()
        check = call.request.check(body)
        if not check.allowed:
            await self._note(call, call_id, provider.name, model.name, 0, "blocked",
                             request_sha256=sha)  # fmt: skip
            raise Refused(f"the body did not pass the validator: {check.audit()}")
        if not model.fits(len(body), cap):
            return 0, "too large for its context", None, 0
        timeout = timeout_for(provider, call, len(body))
        if timeout is None:
            return 0, "too slow for its time limit", None, 0
        if provider.probe:
            down = await self._probe(call, call_id, provider, key)
            if down is not None:
                return 0, down[0], down[1], 0
        ask = budget.Ask(
            provider.name, model.name, self._buckets(provider, call),
            len(body) + MESSAGE_OVERHEAD + cap,
            model.cost(len(body) + MESSAGE_OVERHEAD, cap), call.priority,
        )  # fmt: skip
        holder = f"{call_id}/{attempt}"
        at = self.clock()
        expires = at + provider.lease_for(timeout)

        def take(s: budget.State) -> tuple[budget.Admission, budget.State]:
            admission, after = budget.admit(s, ask, at, self.budget)
            if not admission.ok or provider.concurrency is None:
                return admission, after
            leased, held = budget.lease(after, provider.name, holder, provider.concurrency,
                                        at, expires)  # fmt: skip
            return (leased, s) if not leased.ok else (admission, held)

        admission = await self.store.change(take)
        if not admission.ok:
            return 0, admission.why, admission.until, 0
        try:
            return await self._send(call, call_id, provider, key, attempt, body, sha, ask, at,
                                    timeout)  # fmt: skip
        finally:
            if provider.concurrency is not None:
                await self._update(lambda s: budget.release(s, provider.name, holder))

    async def _send(
        self,
        call: Call,
        call_id: uuid.UUID,
        provider: ProviderConfig,
        key: SecretStr,
        attempt: int,
        body: bytes,
        sha: str,
        ask: budget.Ask,
        at: datetime,
        deadline_s: float,
    ) -> Completion | tuple[int, str, datetime | None, int]:
        model = provider.models[call.tier]
        name, model_key = provider.name, f"{provider.name}/{model.name}"
        size = len(body) + MESSAGE_OVERHEAD
        cap = ask.tokens - size
        slow_ms = round(provider.slow_s * 1000)

        def counted(tin: int | None, tout: int | None) -> tuple[int, int]:
            # the estimate is an upper bound: a provider's larger count is not believed
            tin = size if tin is None else min(tin, size)
            return tin, cap if tout is None else min(tout, cap)

        def beyond(latency_ms: int, tin: int, tout: int) -> int:
            """How much longer than its measured speed says the call took: a model
            is slow when that is above slow_s; without a measured speed, its latency."""
            return max(0, latency_ms - round(model.expected_s(tin, tout) * 1000))

        sent = {"request_bytes": len(body), "request_sha256": sha}
        wire = LlmWire(name, f"{provider.base_url}/chat/completions", body, deadline_s)
        try:
            reply = await self.transport.send(wire, key)
        except (TransportError, TimeoutError) as exc:
            done = self.clock()
            kind = getattr(exc, "kind", "no_answer")
            if kind == "tls_failed":  # never reached: nothing used; an alarm, an hour's wait
                until = done + AUTH_WAIT
                detail = tls_detail(exc) if isinstance(exc, TransportError) else "tls_failed"
                await self._update(lambda s: budget.raise_alarm(budget.cool_down(
                    budget.settle(s, ask, at, 0, 0.0), name, until, done
                ), name, "tls_failed", detail, done))  # fmt: skip
                await self._note(call, call_id, name, model.name, attempt, "tls_failed", **sent)
                return 1, "tls_failed", until, 0
            elapsed = round((done - at).total_seconds() * 1000)
            reached = bool(getattr(exc, "reached", True))
            if reached:  # it may have been charged: the estimate stays
                await self._update(lambda s: budget.observe(
                    budget.overload(s, model_key, done), model_key, elapsed, slow_ms, done
                ))  # fmt: skip
            else:  # no connection: nothing was used; the transport's breaker
                await self._update(lambda s: budget.overload(
                    budget.settle(s, ask, at, 0, 0.0), name, done
                ))  # fmt: skip
            await self._note(call, call_id, name, model.name, attempt,
                             f"no_answer: {exc}", **sent)  # fmt: skip
            return 1, "no answer", done + DEFAULT_WAIT, int(reached)
        done = self.clock()
        latency = round(reply.elapsed_ms)
        status = reply.status
        parsed = _answer(reply) if status == 200 else None
        if parsed is not None and parsed.text is not None:
            text = parsed.text
            tin, tout = counted(parsed.input_tokens, parsed.output_tokens)
            cost = model.cost(tin, tout)
            late = beyond(latency, tin, tout)

            def answered(s: budget.State) -> budget.State:
                s = budget.settle(s, ask, at, tin + tout, cost)
                s = budget.success(budget.success(s, name, done), model_key, done)
                s = budget.clear_alarm(budget.observe(s, model_key, late, slow_ms, done), name)
                return budget.probed_up(s, name, done) if provider.probe else s

            await self._update(answered)
            await self._note(call, call_id, name, model.name, attempt, "ok",
                             http_status=status, input_tokens=tin, output_tokens=tout,
                             cost_usd=cost, latency_ms=latency, **sent)  # fmt: skip
            return Completion(text, name, model.name, tin, tout, cost, latency, call_id)
        wait: datetime | None = None

        def replied(s: budget.State) -> budget.State:
            """Any HTTP reply proves the connection: the provider's breaker trial passes, so
            one model's failure never holds its siblings; the call used nothing."""
            return budget.success(budget.settle(s, ask, at, 0, 0.0), name, done)

        if status == 200:
            # the reservation stays: the provider did the work
            outcome = "truncated" if parsed is not None and parsed.truncated else "bad_answer"
            tokens = (parsed.input_tokens, parsed.output_tokens) if parsed else (None, None)
            late = beyond(latency, *counted(*tokens))
            await self._update(lambda s: budget.observe(budget.success(
                budget.success(s, name, done), model_key, done
            ), model_key, late, slow_ms, done))  # fmt: skip
        elif status == 429:
            outcome = "rate_limited"
            default = QUOTA_WAIT if _quota(reply) else DEFAULT_WAIT
            until = retry_after(reply.retry_after, done) or done + default
            wait = min(until, done + budget.MAX_COOLDOWN)
            await self._update(lambda s: budget.cool_down(replied(s), model_key, until, done))
        elif status in (401, 403):
            outcome = "unauthorized"
            wait = done + AUTH_WAIT
            await self._update(lambda s: budget.raise_alarm(budget.cool_down(
                replied(s), name, done + AUTH_WAIT, done
            ), name, "unauthorized", f"the key was refused ({status})", done))  # fmt: skip
        elif status == 400 and _error_type(reply) == "exceed_context_size_error":
            outcome = "too_large"  # llama-server: the prompt and the cap exceed the context
            await self._update(replied)
        elif status == 503 and provider.probe and _error_type(reply) == "unavailable_error":
            outcome = "loading"  # llama-server (a probed machine) is loading the model
            wait = done + LOADING_WAIT
            await self._update(lambda s: budget.cool_down(
                replied(s), name, done + LOADING_WAIT, done
            ))  # fmt: skip
        elif status >= 500:
            outcome = "server_error"
            wait = done + DEFAULT_WAIT
            await self._update(lambda s: budget.overload(replied(s), model_key, done))
        else:
            outcome = "rejected"
            await self._update(replied)
        await self._note(call, call_id, name, model.name, attempt, outcome,
                         http_status=status, latency_ms=latency, **sent)  # fmt: skip
        return 1, f"{outcome} ({status})", wait, int(outcome in UNUSABLE)

    async def _note(
        self,
        call: Call,
        call_id: uuid.UUID,
        provider: str,
        model: str,
        attempt: int,
        outcome: str,
        **kw: Any,
    ) -> None:
        await self.store.record(CallEntry(
            at=self.clock(), call_id=call_id, attempt=attempt, provider=provider, model=model,
            tier=call.tier.value, purpose=call.purpose, priority=call.priority.value,
            outcome=outcome, **kw,
        ))  # fmt: skip

    async def _update(self, fn: Callable[[budget.State], budget.State]) -> None:
        await self.store.change(lambda s: (None, fn(s)))


async def stop(store: LlmStore, stopped: bool) -> bool:
    """The kill switch; True if it changed."""

    def flip(s: budget.State) -> tuple[bool, budget.State]:
        return s.stopped != stopped, replace(s, stopped=stopped)

    return await store.change(flip)
