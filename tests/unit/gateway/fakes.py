"""A scripted transport and a fake clock for gateway tests."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from argus.gateway.errors import TransportFailedError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.state import MemoryStore
from argus.gateway.transport import WireRequest, WireResponse

T0 = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
SQUID_TODAY = "acme-logs-squid-2026.10.09"
SQUID_YESTERDAY = "acme-logs-squid-2026.10.08"


def search_answer(hits: list[Any] | None = None, took: int = 5) -> dict[str, Any]:
    return {
        "took": took,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {"hits": hits or []},
    }


def listing(*names: str) -> dict[str, Any]:
    return {"indices": [{"name": name} for name in names]}


Reply = WireResponse | Exception | Callable[[WireRequest], WireResponse]


@dataclass
class FakeTransport:
    """Answers by path prefix (first match), else 200 with ``default``; records every call."""

    routes: list[tuple[str, list[Reply]]] = field(default_factory=list)
    default: Any = field(default_factory=search_answer)
    calls: list[WireRequest] = field(default_factory=list)
    clock: FakeClock | None = None
    latency: timedelta = timedelta(milliseconds=5)

    def on(self, path_part: str, *replies: Reply) -> FakeTransport:
        self.routes.append((path_part, list(replies)))
        return self

    async def send(self, request: WireRequest) -> WireResponse:
        self.calls.append(request)
        if self.clock is not None:
            self.clock.advance(self.latency)
        for part, replies in self.routes:
            if part in request.path and replies:
                reply = replies.pop(0) if len(replies) > 1 else replies[0]
                if isinstance(reply, Exception):
                    raise reply
                if callable(reply):
                    return reply(request)
                return reply
        return ok(self.default)


def ok(body: Any, status: int = 200) -> WireResponse:
    return WireResponse(status, json.dumps(body).encode(), 5.0)


def failure(retriable: bool = True) -> TransportFailedError:
    return TransportFailedError("reset", retriable=retriable)


@dataclass
class FakeClock:
    now: datetime = T0
    slept: list[float] = field(default_factory=list)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += timedelta(seconds=seconds)


def make(
    transport: FakeTransport | None = None, store: MemoryStore | None = None, **kw: Any
) -> tuple[Gateway, FakeTransport, MemoryStore, FakeClock]:
    clock = FakeClock()
    transport = transport or FakeTransport()
    transport.clock = clock
    store = store or MemoryStore(memory=HealthMemory(probed_at=T0))  # probed just now
    gateway = Gateway(transport, store, targets=Targets(), clock=clock, sleep=clock.sleep, **kw)
    return gateway, transport, store, clock
