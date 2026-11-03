"""Fixtures of the case team's integration tests: the people the case record's tests use, and the
web's own database login (what records a person's approval)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import DatabaseSettings
from argus.db.engine import create_engine
from tests.integration.cases.conftest import api_engine, people  # noqa: F401  (the fixtures)


@pytest.fixture
async def web_engine(
    make_api_login: Callable[[], Awaitable[DatabaseSettings]],
    test_database: str,
    migrated_engine: AsyncEngine,
) -> AsyncIterator[AsyncEngine]:
    """The web's login (``argus_web``): the role that signs and records approvals."""
    login = await make_api_login()
    engine = create_engine(login, database=test_database, role="api")
    try:
        yield engine
    finally:
        await engine.dispose()
