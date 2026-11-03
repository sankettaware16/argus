"""Fixtures for the notices' integration tests (Q-H4): the case kit of Q-C1/Q-C2 (people, an
API login, a small world of investigations and cases), a fake SMTP relay on the loopback, and a
pass configuration pointed at it. Time is always passed in."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.notices import mail, run
from tests.fakesmtp import FakeSmtp
from tests.integration.cases.conftest import api_engine, people  # noqa: F401 - fixtures
from tests.integration.cases.watchkit import World

BASE = "https://argus.example.org"
RECIPIENTS = ("ta@example.org", "ra@example.org")
SENDER = "argus@example.org"


@pytest.fixture
def smtp() -> Iterator[FakeSmtp]:
    with FakeSmtp() as server:
        yield server


def config_for(server: FakeSmtp, **changes: object) -> run.Config:
    """A switched-on configuration whose relay is ``server``."""
    base: dict[str, object] = {
        "enabled": True,
        "recipients": RECIPIENTS,
        "relay": mail.Relay(server.host, server.port, False, timeout=5),
        "sender": SENDER,
        "base": BASE,
        "host": server.host,
        "port": server.port,
    }
    return run.Config(**{**base, **changes})  # type: ignore[arg-type]


@pytest.fixture
def world(migrated_engine: AsyncEngine, app_engine: AsyncEngine) -> World:
    return World(migrated_engine, app_engine)
