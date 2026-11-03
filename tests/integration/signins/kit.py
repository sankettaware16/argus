"""A small world for the sign-in pass: two campus hosts with investigations on 28 October, one of
them a member of an open case, and a gateway that answers from a script. Synthetic names only."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from argus.assets.classify import IpClassifier
from argus.config.settings import Settings, SigninsSettings
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.state import MemoryStore
from tests.integration.cases.knownkit import make
from tests.unit.gateway.fakes import FakeClock, FakeTransport, listing, ok
from tests.unit.signins import kit

NOW = datetime(2026, 10, 29, 6, 0, tzinfo=UTC)
CLASSIFIER = IpClassifier(None, ())
HOST_A, HOST_B, HOST_C = "10.1.2.3", "10.1.2.4", "10.1.2.5"
INDEX = "acme-logs-sso-2026.10.28"


def settings(**more: Any) -> Settings:
    """Settings with the sign-in pass on (and the knobs of the test)."""
    return Settings(signins=SigninsSettings(enabled=True, **more))


async def world(owner: Any) -> dict[str, uuid.UUID]:
    """Three investigations on 28 Oct, 13:00 to 13:30 UTC; A is raised, B is unraised."""
    when = datetime(2026, 10, 28, 13, 30, tzinfo=UTC)
    return {
        "a": await make(owner, when=when, host=HOST_A),
        "b": await make(owner, when=when, host=HOST_B, flags=()),
        "c": await make(owner, when=when - timedelta(hours=1), host=HOST_C, flags=()),
    }


class Wire:
    """The gateway, its scripted transport and its clock."""

    def __init__(
        self, *replies: Any, indices: Sequence[str] = (INDEX,), now: datetime = NOW
    ) -> None:
        self.clock = FakeClock(now=now)
        self.transport = FakeTransport()
        self.transport.clock = self.clock
        self.transport.on("/_resolve/index", ok(listing(*indices)))
        for reply in replies:
            self.transport.on("/_search", reply)
        self.state = MemoryStore(memory=HealthMemory(probed_at=now))
        self.gateway = Gateway(
            self.transport,
            self.state,
            targets=Targets(log_sources=frozenset({"sso"})),
            clock=self.clock,
            sleep=self.clock.sleep,
        )

    def at(self, now: datetime) -> None:
        """Move the clock; the collector's probe has just been made (a stale one is STOP)."""
        self.clock.now = now
        self.state.memory = HealthMemory(probed_at=now)

    def searches(self) -> list[Any]:
        return [c for c in self.transport.calls if c.path.endswith("/_search")]

    def asked(self) -> list[dict[str, Any]]:
        import json

        return [json.loads(c.body or b"{}") for c in self.searches()]


def reply(*sightings: Any) -> Any:
    """A whole answer holding these sightings (each keyed by its own address)."""
    by_address: dict[str, list[Any]] = {}
    for s in sightings:
        by_address.setdefault(s.address, []).append(s)
    return ok(kit.answer(by_address))
