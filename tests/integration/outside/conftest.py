"""The outside lookups on a throwaway database as the runtime login, with a scripted transport and
a clock the test moves. Nothing here reaches the network."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.config.settings import OutsideSettings
from argus.llm.detect import OwnSpace
from argus.llm.privacy import Privacy, load_policy
from argus.outside.eligible import Eligibility
from argus.outside.providers import Prepared, Reply, TransportError
from argus.outside.service import Outside
from tests.integration.web.conftest import client, seeded  # noqa: F401 - fixtures

KEYS = {"virustotal": "Synthetic-VT-Key-31", "shodan": "Synthetic-Shodan-Key-32",
        "censys": "Synthetic-Censys-Key-33"}  # fmt: skip
CAMPUS_NET = ipaddress.ip_network("198.51.100.0/24")
START = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)

VT_BAD = {"data": {"attributes": {"last_analysis_stats": {
    "malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 26, "timeout": 0},
    "as_owner": "Private Layer INC", "country": "CH", "asn": 51852}}}  # fmt: skip
VT_CLEAN = {"data": {"attributes": {"last_analysis_stats": {
    "malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 24, "timeout": 1}}}}  # fmt: skip
SHODAN_HOST = {"ip_str": "45.33.32.156", "ports": [22, 80], "org": "Acme", "data": []}


@dataclass
class Clock:
    now: datetime = START
    slept: list[float] = field(default_factory=list)

    def __call__(self) -> datetime:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += timedelta(seconds=seconds)

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


def json_reply(status: int, body: Any = None, retry: str | None = None) -> Reply:
    return Reply(status, json.dumps(body if body is not None else {}).encode(), retry)


class Transport:
    """Replies in order (the last one repeats); records what was sent."""

    def __init__(self, *replies: Reply | Exception | Callable[[Prepared], Reply]) -> None:
        self.replies = list(replies) or [json_reply(200, VT_BAD)]
        self.sent: list[Prepared] = []

    async def get(self, request: Prepared, timeout_s: float) -> Reply:
        self.sent.append(request)
        got = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(got, Exception):
            raise got
        return got(request) if callable(got) else got


def settings(*sources: str, **more: Any) -> OutsideSettings:
    keys = {f"{s}_api_key": SecretStr(KEYS[s]) for s in sources}
    return OutsideSettings(**keys, **more)


def eligibility() -> Eligibility:
    """The check as production builds it: the privacy layer's own campus view per item."""
    classifier = IpClassifier(None, (CAMPUS_NET,))
    ours = OwnSpace(networks=(CAMPUS_NET,), domains=("example.edu",))
    return Eligibility(classifier, ours, Privacy(load_policy(), classifier, ours).ours_for)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def make_outside(app_engine: AsyncEngine, clock: Clock) -> Callable[..., Outside]:
    def make(transport: Transport, *sources: str, **more: Any) -> Outside:
        return Outside(
            app_engine, settings(*(sources or ("virustotal",)), **more), transport,
            eligibility(), clock=clock, sleep=clock.sleep,
        )  # fmt: skip

    return make


__all__ = ["Clock", "Transport", "TransportError", "eligibility", "json_reply", "settings"]
