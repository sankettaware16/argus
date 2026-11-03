"""The LLM gateway's budgets: per-minute and per-day requests and tokens per provider and model,
the monthly cost cap, cool-downs from ``Retry-After``, breakers, the kill switch, leases,
latencies and alarms. Admission reserves an upper-bound estimate (a body byte is at most a token,
plus the answer's cap) that settling replaces with the provider's count; a priority may use only
its share of each limit; windows are fixed UTC and ARGUS uses ``margin`` of each limit. Pure:
(state, request, now) in, (admission, state) out; the store keeps the state in Postgres."""

from __future__ import annotations

import math
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from typing import Any

from argus.gateway import breaker as breaker_core

MAX_COOLDOWN = timedelta(days=1)
LEASE_RETRY = timedelta(seconds=60)  # a busy provider is asked again at the latest then
SLOW_SAMPLES = 5  # the latencies kept per model
SLOW_MIN_SAMPLES = 3  # a model is judged slow on at least this many
SLOW_WAIT = timedelta(minutes=30)  # a slow model's cool-down


class Priority(StrEnum):
    HIGH = "high"  # floor signals, new security alerts
    NORMAL = "normal"
    LOW = "low"  # evaluation, backfill


@dataclass(frozen=True)
class Limits:
    rpm: int | None = None
    rpd: int | None = None
    tpm: int | None = None
    tpd: int | None = None


@dataclass(frozen=True)
class Window:
    minute: datetime | None = None
    minute_requests: int = 0
    minute_tokens: int = 0
    day: date | None = None
    day_requests: int = 0
    day_tokens: int = 0

    def at(self, now: datetime) -> Window:
        minute = now.replace(second=0, microsecond=0)
        w = self
        if w.minute != minute:
            w = replace(w, minute=minute, minute_requests=0, minute_tokens=0)
        if w.day != now.date():
            w = replace(w, day=now.date(), day_requests=0, day_tokens=0)
        return w


@dataclass(frozen=True)
class Alarm:
    kind: str  # "tls_failed", "unauthorized", "model_mismatch"
    at: datetime
    detail: str


@dataclass(frozen=True)
class State:
    windows: dict[str, Window] = field(default_factory=dict)  # "provider" or "provider/model"
    cooldowns: dict[str, datetime] = field(default_factory=dict)  # the same names
    breakers: dict[str, breaker_core.BreakerState] = field(default_factory=dict)  # the same
    month: str = ""
    spent_usd: float = 0.0  # this month, paid providers, reserved and settled
    stopped: bool = False
    day: str = ""  # the UTC day of day_spent_usd
    day_spent_usd: float = 0.0
    leases: dict[str, dict[str, datetime]] = field(default_factory=dict)  # provider: holder→end
    probed: dict[str, datetime] = field(default_factory=dict)  # provider: its last "up" probe
    latency: dict[str, tuple[int, ...]] = field(default_factory=dict)  # "provider/model": ms
    alarms: dict[str, Alarm] = field(default_factory=dict)  # provider: the latest alarm


@dataclass(frozen=True)
class Bucket:
    name: str
    limits: Limits
    exact: bool = False  # True: the limits as written (ARGUS's own caps): no margin, no share


@dataclass(frozen=True)
class Ask:
    provider: str
    model: str
    buckets: tuple[Bucket, ...]
    tokens: int  # the upper bound
    cost_usd: float  # the upper bound
    priority: Priority


@dataclass(frozen=True)
class Admission:
    ok: bool
    until: datetime | None = None  # when to try again (None: never, for this ask)
    why: str = ""


@dataclass(frozen=True)
class Config:
    monthly_cap_usd: float = 10.0
    margin: float = 0.8
    shares: dict[Priority, float] = field(
        default_factory=lambda: {Priority.HIGH: 1.0, Priority.NORMAL: 0.8, Priority.LOW: 0.5}
    )
    daily_cap_usd: float | None = None  # None: no daily cap


def month_of(now: datetime) -> str:
    return now.strftime("%Y-%m")


def _next_minute(now: datetime) -> datetime:
    return now.replace(second=0, microsecond=0) + timedelta(minutes=1)


def _next_day(now: datetime) -> datetime:
    return datetime.combine(now.date() + timedelta(days=1), datetime.min.time(), UTC)


def _next_month(now: datetime) -> datetime:
    first = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return (first + timedelta(days=32)).replace(day=1)


def _cap(limit: int | None, share: float) -> int | None:
    return None if limit is None else math.floor(limit * share)


def admit(state: State, ask: Ask, now: datetime, config: Config) -> tuple[Admission, State]:
    """May this call go now? If so its estimate is reserved in every bucket it counts in."""
    if state.stopped:
        return Admission(False, None, "stopped"), state
    spent = state.spent_usd if state.month == month_of(now) else 0.0
    today = now.date().isoformat()
    day_spent = state.day_spent_usd if state.day == today else 0.0
    share = config.shares[ask.priority]
    waits: list[datetime] = []
    reasons: list[str] = []
    windows = dict(state.windows)
    for bucket in ask.buckets:
        w = windows.get(bucket.name, Window()).at(now)
        windows[bucket.name] = w
        lim = bucket.limits
        margin, day_share = (1.0, 1.0) if bucket.exact else (config.margin, config.margin * share)
        rpm, tpm = _cap(lim.rpm, margin), _cap(lim.tpm, margin)
        rpd, tpd = _cap(lim.rpd, day_share), _cap(lim.tpd, day_share)
        if (tpm is not None and ask.tokens > tpm) or (tpd is not None and ask.tokens > tpd):
            return Admission(False, None, f"{bucket.name}: too large"), state
        if (rpm is not None and w.minute_requests + 1 > rpm) or (
            tpm is not None and w.minute_tokens + ask.tokens > tpm
        ):
            waits.append(_next_minute(now))
            reasons.append(f"{bucket.name}: minute limit")
        if (rpd is not None and w.day_requests + 1 > rpd) or (
            tpd is not None and w.day_tokens + ask.tokens > tpd
        ):
            waits.append(_next_day(now))
            reasons.append(f"{bucket.name}: day limit")
    for name in (ask.provider, f"{ask.provider}/{ask.model}"):
        until = state.cooldowns.get(name)
        if until is not None and now < until:
            waits.append(until)
            reasons.append(f"{name}: cooling down")
    if ask.cost_usd > 0:
        cap = config.monthly_cap_usd * share
        if ask.cost_usd > cap:
            return Admission(False, None, "costs more than the monthly cap"), state
        if spent + ask.cost_usd > cap:
            waits.append(_next_month(now))
            reasons.append("monthly cost cap")
        if config.daily_cap_usd is not None:
            day_cap = config.daily_cap_usd * share
            if ask.cost_usd > day_cap:
                return Admission(False, None, "costs more than the daily cap"), state
            if day_spent + ask.cost_usd > day_cap:
                waits.append(_next_day(now))
                reasons.append("daily cost cap")
    names = (ask.provider, f"{ask.provider}/{ask.model}")  # transport, then the model's answers
    for name in names:
        breaker = state.breakers.get(name, breaker_core.BreakerState())
        if not breaker_core.peek(breaker, now):
            waits.append(max(t for t in (breaker.open_until, breaker.trial_until, now) if t))
            reasons.append(f"{name}: breaker open")
    if waits:
        return Admission(False, max(waits), "; ".join(reasons)), state
    breakers = dict(state.breakers)
    for name in names:
        _, breakers[name] = breaker_core.admit(breakers.get(name, breaker_core.BreakerState()), now)
    for bucket in ask.buckets:
        w = windows[bucket.name]
        windows[bucket.name] = replace(
            w,
            minute_requests=w.minute_requests + 1,
            minute_tokens=w.minute_tokens + ask.tokens,
            day_requests=w.day_requests + 1,
            day_tokens=w.day_tokens + ask.tokens,
        )
    return Admission(True), replace(
        state,
        windows=windows,
        breakers=breakers,
        month=month_of(now),
        spent_usd=spent + ask.cost_usd,
        day=today,
        day_spent_usd=day_spent + ask.cost_usd,
    )


def settle(
    state: State,
    ask: Ask,
    admitted_at: datetime,
    tokens: int,
    cost_usd: float,
) -> State:
    """Replace the reservation made at ``admitted_at`` by what the call really used, in the
    windows that still hold it (a window that has rolled over keeps its reservation)."""
    windows = dict(state.windows)
    minute = admitted_at.replace(second=0, microsecond=0)
    for bucket in ask.buckets:
        w = windows.get(bucket.name)
        if w is None:
            continue
        if w.minute == minute:
            w = replace(w, minute_tokens=max(0, w.minute_tokens - ask.tokens + tokens))
        if w.day == admitted_at.date():
            w = replace(w, day_tokens=max(0, w.day_tokens - ask.tokens + tokens))
        windows[bucket.name] = w
    spent = state.spent_usd
    if state.month == month_of(admitted_at):
        spent = max(0.0, spent - ask.cost_usd + cost_usd)
    day_spent = state.day_spent_usd
    if state.day == admitted_at.date().isoformat():
        day_spent = max(0.0, day_spent - ask.cost_usd + cost_usd)
    return replace(state, windows=windows, spent_usd=spent, day_spent_usd=day_spent)


def cool_down(state: State, name: str, until: datetime, now: datetime) -> State:
    """A provider asked us to wait (``Retry-After``), for itself or one model (``name`` is
    "provider" or "provider/model"); never longer than a day. Past cool-downs are dropped."""
    until = min(until, now + MAX_COOLDOWN)
    current = state.cooldowns.get(name)
    if current is not None and current >= until:
        return state
    kept = {k: v for k, v in state.cooldowns.items() if v > now}
    return replace(state, cooldowns={**kept, name: until})


def overload(state: State, name: str, now: datetime) -> State:
    """A server error or no answer: the breaker of ``name`` trips (5, 15, then 60 minutes).
    ``name`` is "provider" for the transport (no connection, TLS) or "provider/model" for the
    model's answers (a 5xx, a timeout after the request was sent)."""
    b = state.breakers.get(name, breaker_core.BreakerState())
    return replace(state, breakers={**state.breakers, name: breaker_core.on_overload(b, now)})


def success(state: State, name: str, now: datetime) -> State:
    """An answer came back: a passed trial closes the breaker of ``name``."""
    b = state.breakers.get(name, breaker_core.BreakerState())
    return replace(state, breakers={**state.breakers, name: breaker_core.on_success(b, now)})


def lease(
    state: State, provider: str, holder: str, slots: int, now: datetime, until: datetime
) -> tuple[Admission, State]:
    """Take one of the provider's ``slots`` for a call until ``until``. Every ARGUS process
    shares the state, so the slots hold across processes; a holder that crashed never releases
    its slot, and it expires at its ``until``."""
    held = {h: end for h, end in state.leases.get(provider, {}).items() if end > now}
    if len(held) >= slots:
        retry = min(min(held.values()), now + LEASE_RETRY)
        return Admission(False, retry, f"{provider}: busy ({len(held)} of {slots} calls)"), state
    return Admission(True), replace(
        state, leases={**state.leases, provider: {**held, holder: until}}
    )


def release(state: State, provider: str, holder: str) -> State:
    held = state.leases.get(provider, {})
    if holder not in held:
        return state
    rest = {h: end for h, end in held.items() if h != holder}
    leases = {k: v for k, v in state.leases.items() if k != provider}
    if rest:
        leases[provider] = rest
    return replace(state, leases=leases)


def observe(state: State, name: str, latency_ms: int, slow_ms: int, now: datetime) -> State:
    """A call's latency for ``name`` ("provider/model"). When the median of the last
    ``SLOW_SAMPLES`` (at least ``SLOW_MIN_SAMPLES``) is above ``slow_ms`` the model is slow: it
    cools down for ``SLOW_WAIT`` and is judged again on new calls."""
    recent = (*state.latency.get(name, ()), max(0, latency_ms))[-SLOW_SAMPLES:]
    ordered = sorted(recent)
    if len(recent) >= SLOW_MIN_SAMPLES and ordered[len(ordered) // 2] > slow_ms:
        cooled = cool_down(state, name, now + SLOW_WAIT, now)
        return replace(cooled, latency={k: v for k, v in state.latency.items() if k != name})
    return replace(state, latency={**state.latency, name: recent})


def raise_alarm(state: State, provider: str, kind: str, detail: str, now: datetime) -> State:
    return replace(state, alarms={**state.alarms, provider: Alarm(kind, now, detail[:300])})


def clear_alarm(state: State, provider: str) -> State:
    if provider not in state.alarms:
        return state
    return replace(state, alarms={k: v for k, v in state.alarms.items() if k != provider})


def probed_up(state: State, provider: str, now: datetime) -> State:
    return replace(state, probed={**state.probed, provider: now})


def probe_up(state: State, provider: str, now: datetime) -> tuple[Alarm | None, State]:
    """A probe a person ran (``argus llm probe``) found the provider up: its alarm and its own
    cool-down end (a model's, such as a slow one's, stays) and it is believed up from ``now``.
    Returns the alarm it cleared, if any."""
    alarm = state.alarms.get(provider)
    cooldowns = {k: v for k, v in state.cooldowns.items() if k != provider}
    cleared = replace(clear_alarm(state, provider), cooldowns=cooldowns)
    return alarm, probed_up(cleared, provider, now)


# -- JSON, for the store -------------------------------------------------------------------


def _t(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _pt(value: Any) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def to_json(state: State) -> dict[str, Any]:
    return {
        "windows": {
            k: {
                "minute": _t(w.minute),
                "minute_requests": w.minute_requests,
                "minute_tokens": w.minute_tokens,
                "day": None if w.day is None else w.day.isoformat(),
                "day_requests": w.day_requests,
                "day_tokens": w.day_tokens,
            }
            for k, w in state.windows.items()
        },
        "cooldowns": {k: v.isoformat() for k, v in state.cooldowns.items()},
        "breakers": {
            k: {
                "level": b.level,
                "open_until": _t(b.open_until),
                "trial_until": _t(b.trial_until),
                "last_trip": _t(b.last_trip),
            }
            for k, b in state.breakers.items()
        },
        "month": state.month,
        "spent_usd": state.spent_usd,
        "stopped": state.stopped,
        "day": state.day,
        "day_spent_usd": state.day_spent_usd,
        "leases": {
            p: {h: end.isoformat() for h, end in held.items()} for p, held in state.leases.items()
        },
        "probed": {k: v.isoformat() for k, v in state.probed.items()},
        "latency": {k: list(v) for k, v in state.latency.items()},
        "alarms": {
            k: {"kind": a.kind, "at": a.at.isoformat(), "detail": a.detail}
            for k, a in state.alarms.items()
        },
    }


def from_json(data: dict[str, Any]) -> State:
    return State(
        windows={
            k: Window(
                minute=_pt(w["minute"]),
                minute_requests=w["minute_requests"],
                minute_tokens=w["minute_tokens"],
                day=None if w["day"] is None else date.fromisoformat(w["day"]),
                day_requests=w["day_requests"],
                day_tokens=w["day_tokens"],
            )
            for k, w in (data.get("windows") or {}).items()
        },
        cooldowns={k: datetime.fromisoformat(v) for k, v in (data.get("cooldowns") or {}).items()},
        breakers={
            k: breaker_core.BreakerState(
                level=b["level"],
                open_until=_pt(b["open_until"]),
                trial_until=_pt(b["trial_until"]),
                last_trip=_pt(b["last_trip"]),
            )
            for k, b in (data.get("breakers") or {}).items()
        },
        month=data.get("month", ""),
        spent_usd=float(data.get("spent_usd", 0.0)),
        stopped=bool(data.get("stopped", False)),
        day=str(data.get("day", "")),
        day_spent_usd=float(data.get("day_spent_usd", 0.0)),
        leases={
            p: {h: datetime.fromisoformat(end) for h, end in held.items()}
            for p, held in (data.get("leases") or {}).items()
        },
        probed={k: datetime.fromisoformat(v) for k, v in (data.get("probed") or {}).items()},
        latency={k: tuple(int(x) for x in v) for k, v in (data.get("latency") or {}).items()},
        alarms={
            k: Alarm(a["kind"], datetime.fromisoformat(a["at"]), a["detail"])
            for k, a in (data.get("alarms") or {}).items()
        },
    )
